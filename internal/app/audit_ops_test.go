// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// ---------- helpers ----------

type fwdBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *fwdBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *fwdBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// captureStdout redirects the stdout sink for one test.
func captureStdout(t *testing.T) *fwdBuffer {
	buf := &fwdBuffer{}
	old := forwardStdout
	forwardStdout = buf
	t.Cleanup(func() { forwardStdout = old })
	return buf
}

// stopForwarder stops the test server's workers at the end of the test.
func stopForwarder(t *testing.T, e *env) {
	t.Cleanup(func() {
		e.s.fwd.mu.Lock()
		e.s.fwd.stopped = true
		if e.s.fwd.cancel != nil {
			e.s.fwd.cancel()
		}
		e.s.fwd.mu.Unlock()
	})
}

func fastForwardRetry(t *testing.T) {
	oldMin, oldMax := forwardBackoffMin, forwardBackoffMax
	forwardBackoffMin, forwardBackoffMax = 5*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { forwardBackoffMin, forwardBackoffMax = oldMin, oldMax })
}

func lastAudit(e *env) store.AuditRecord {
	e.t.Helper()
	recs, err := e.s.auditRows(ports.AuditFilter{}, true, 1, 0)
	if err != nil || len(recs) != 1 {
		e.t.Fatalf("last record: %v %d", err, len(recs))
	}
	return recs[0]
}

func writeTokenFile(t *testing.T, mode os.FileMode, token string) string {
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------- 1. backup download ----------

func TestBackupDownloadIsRecordedBeforeServing(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	b := e.do("POST", "/api/backups", admin, nil)
	e.want(b, 201, "backup")
	name := b.S("name")
	d := e.do("GET", "/api/backups/"+name, admin, nil)
	e.want(d, 200, "download")
	rows := auditRowsWhere(e, "action='backup_downloaded'")
	if len(rows) != 2 || rows[0].Outcome != "attempted" || rows[1].Outcome != "ok" || rows[0].Target != name ||
		rows[0].Detail != "size="+strconv.Itoa(len(d.Body))+" bytes" || rows[0].Role != "admin" || rows[0].Category != "security" {
		t.Fatalf("%+v", rows)
	}
	// A backup that does not exist is a plain 404 and no record.
	e.want(e.do("GET", "/api/backups/sendora-plain-20200101-000000.db", admin, nil), 404, "missing")
	if n := len(auditRowsWhere(e, "action='backup_downloaded'")); n != 2 {
		t.Fatalf("missing backup recorded: %d", n)
	}
	// Without a record there is no download.
	fail := func() error { return errors.New("forced audit failure") }
	e.s.audit.hook.Store(&fail)
	r := e.do("GET", "/api/backups/"+name, admin, nil)
	e.s.audit.hook.Store(nil)
	if r.Code != 503 || bytes.HasPrefix(r.Body, []byte("SQLite format 3")) {
		t.Fatalf("served without a record: %d", r.Code)
	}
}

// ---------- 2. logout and session expiry ----------

func TestLogoutIsRecordedWithActor(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "lou", false)
	// Access token only.
	l := idleLogin(e, "lou")
	e.want(e.do("POST", "/api/auth/logout", l.S("access_token"), nil), 200, "logout with token")
	// Refresh cookie only.
	l = idleLogin(e, "lou")
	e.want(e.do("POST", "/api/auth/logout", "", nil, "Cookie", idleCookie(t, l)), 200, "logout with cookie")
	rows := auditRowsWhere(e, "action='logout'")
	if len(rows) != 2 || rows[0].ActorNm != "lou" || rows[1].ActorNm != "lou" || rows[0].Category != "auth" || rows[0].Role != "user" {
		t.Fatalf("%+v", rows)
	}
	// Invalid credentials never make logout fail; nobody is named.
	e.want(e.do("POST", "/api/auth/logout", "garbage", nil, "Cookie", "refresh=nonsense"), 200, "logout with junk")
	if n := len(auditRowsWhere(e, "action='logout'")); n != 2 {
		t.Fatalf("junk logout named someone: %d", n)
	}
	if rows := auditRowsWhere(e, "action='POST /api/auth/logout'"); len(rows) != 1 || rows[0].Role != "anonymous" {
		t.Fatalf("%+v", rows)
	}
}

func TestRefreshRecordsIdleAndAbsoluteExpiry(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "ida", false)
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"idle_logout_minutes": 30}), 200, "idle window")

	l := idleLogin(e, "ida")
	eByName(e.s.St, `UPDATE refresh_tokens SET issued_at=? WHERE user_id=(SELECT id FROM users WHERE username='ida')`, time.Now().Add(-3*time.Hour))
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", idleCookie(t, l)), 401, "idle")
	if rows := auditRowsWhere(e, "action='session_expired_idle'"); len(rows) != 1 || rows[0].ActorNm != "ida" || rows[0].Category != "auth" {
		t.Fatalf("%+v", rows)
	}

	// Absolute limit: started more than 30 days ago, token row still valid.
	l = idleLogin(e, "ida")
	eByName(e.s.St, `UPDATE refresh_tokens SET session_started=? WHERE user_id=(SELECT id FROM users WHERE username='ida')`, time.Now().Add(-31*24*time.Hour))
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", idleCookie(t, l)), 401, "absolute")
	// Absolute limit: token row past its expiry, not yet removed by maintenance.
	l = idleLogin(e, "ida")
	eByName(e.s.St, `UPDATE refresh_tokens SET expires_at=? WHERE user_id=(SELECT id FROM users WHERE username='ida')`, time.Now().Add(-time.Minute))
	c := idleCookie(t, l)
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", c), 401, "expired row")
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", c), 401, "again")
	rows := auditRowsWhere(e, "action='session_expired'")
	if len(rows) != 2 || rows[0].ActorNm != "ida" || rows[1].ActorNm != "ida" {
		t.Fatalf("each expiry is recorded once: %+v", rows)
	}
}

// ---------- 3. download addresses ----------

func TestDownloadIPStoredOnlyWhileAuditIPIsOn(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	sh := e.share(admin, map[string]string{"a.txt": "abc"}, nil)
	e.want(sh, 201, "share")
	dl := func() { e.want(e.do("GET", "/api/shares/"+sh.S("long_id")+"/download", "", nil), 200, "download") }
	ips := func() []string {
		rows, _ := e.s.St.DB.Query(`SELECT ip FROM downloads ORDER BY id`)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var ip string
			rows.Scan(&ip)
			out = append(out, ip)
		}
		return out
	}
	dl()
	if got := ips(); len(got) != 1 || got[0] != "" {
		t.Fatalf("address stored while audit_log_ip is off: %q", got)
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_log_ip": true}), 200, "on")
	dl()
	if got := ips(); len(got) != 2 || got[1] == "" {
		t.Fatalf("address not stored while on: %q", got)
	}
	// Switching it off empties stored addresses at the next maintenance run.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_log_ip": false}), 200, "off")
	e.s.maintain()
	for _, ip := range ips() {
		if ip != "" {
			t.Fatalf("address kept after switching off: %q", ips())
		}
	}
}

// ---------- 4. system actions ----------

func TestAutomaticBackupsAreAuditedAsSystem(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.s.St.SetSetting("backup_keep", "1")
	// pruneBackups only removes encrypted-style names; plant an old one.
	old := "sendora-encrypted-20200101-000000-aaaaaaaaaaaa.db"
	os.WriteFile(filepath.Join(e.s.St.DataDir, "backups", old), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(e.s.St.DataDir, "backups", "sendora-encrypted-20200102-000000-bbbbbbbbbbbb.db"), []byte("x"), 0o600)
	if !e.s.autoBackup() {
		t.Fatal("backup failed")
	}
	created := auditRowsWhere(e, "action='backup_created_auto'")
	if len(created) != 1 || created[0].Category != "system" || created[0].Role != "system" || created[0].ActorNm != "system" || created[0].Target == "" {
		t.Fatalf("%+v", created)
	}
	if pruned := auditRowsWhere(e, "action='backup_pruned'"); len(pruned) != 1 || pruned[0].Target != old || pruned[0].Category != "system" {
		t.Fatalf("%+v", pruned)
	}
	// A failing backup: the backups directory is replaced by a file.
	dir := filepath.Join(e.s.St.DataDir, "backups")
	os.RemoveAll(dir)
	os.WriteFile(dir, []byte("not a directory"), 0o600)
	defer func() { os.Remove(dir); os.Mkdir(dir, 0o700) }()
	if e.s.autoBackup() {
		t.Fatal("backup should fail")
	}
	if rows := auditRowsWhere(e, "action='backup_failed_auto'"); len(rows) != 1 || rows[0].Outcome != "failed" || rows[0].Category != "system" || strings.Contains(rows[0].Detail, e.s.St.DataDir) {
		t.Fatalf("%+v", rows)
	}
}

func TestCleanupJobsAreAuditedAsSystem(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	// An expired share past the clean-up age.
	sh := e.share(admin, map[string]string{"a.txt": "abc"}, nil)
	e.want(sh, 201, "share")
	e.s.St.DB.Exec(`UPDATE shares SET status='expired', expires_at=? WHERE id=?`, time.Now().AddDate(0, 0, -30), int64(sh.J()["id"].(float64)))
	// An unverified self-registration older than 48 hours.
	if _, err := rawExec(e.t, e.s.St, `INSERT INTO users(username,email,password_hash,pending_registration,email_verified,created_at) VALUES('pending1','p1@x.io','x',1,0,?)`,
		time.Now().UTC().Add(-72*time.Hour).Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	// A guest whose single-use invitation expired unused.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_reverse_shares": "true"}), 200, "reverse shares")
	inv := e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{"open": true, "max_uploads": 2, "days": 1, "name": "Drop"})
	e.want(inv, 201, "invite")
	u := inv.S("url")
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": u[strings.LastIndex(u, "/")+1:]}), 200, "accept")
	e.s.St.DB.Exec(`UPDATE reverse_invites SET expires_at=? WHERE parent_id IS NOT NULL`, time.Now().Add(-time.Hour))

	e.s.maintain()
	purged := auditRowsWhere(e, "action='share_files_purged'")
	if len(purged) != 1 || purged[0].Category != "system" || purged[0].Role != "system" || !strings.HasPrefix(purged[0].Detail, "1 shares removed, 0 failed") {
		t.Fatalf("%+v", purged)
	}
	removed := auditRowsWhere(e, "action='account_removed_auto'")
	if len(removed) != 2 {
		t.Fatalf("%+v", removed)
	}
	var reasons, targets []string
	for _, r := range removed {
		if r.Category != "system" || r.ActorNm != "system" || !strings.HasPrefix(r.Target, "user#") {
			t.Fatalf("%+v", r)
		}
		reasons, targets = append(reasons, r.Detail), append(targets, r.Target)
	}
	joined := strings.Join(reasons, "|")
	if !strings.Contains(strings.Join(targets, "|"), "(pending1)") || !strings.Contains(joined, "email not verified") || !strings.Contains(joined, "guest invitation expired") {
		t.Fatalf("%+v", removed)
	}
}

// ---------- 5. forwarding ----------

func TestForwardStdoutWritesOneJSONLinePerRecord(t *testing.T) {
	buf := captureStdout(t)
	e := newEnv(t)
	stopForwarder(t, e)
	e.setup()
	e.s.St.SetSetting("audit_forward_stdout", "true")
	e.s.logEvent(0, "system", "shares_expired", "", "1 shares")
	want := lastAudit(e)
	waitFor(t, "stdout line", func() bool { return strings.Contains(buf.String(), want.Hash) })
	var got store.AuditRecord
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var env struct {
			Rec *store.AuditRecord `json:"sendora_audit"`
		}
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("not one JSON object per line: %q", line)
		}
		if env.Rec != nil && env.Rec.Seq == want.Seq {
			got = *env.Rec
		}
	}
	if got != want || got.PrevHash == "" {
		t.Fatalf("forwarded %+v, stored %+v", got, want)
	}
}

// readSyslogFrames reads octet-counted frames from a connection.
func readSyslogFrames(t *testing.T, conn net.Conn, out chan<- string) {
	rd := bufio.NewReader(conn)
	for {
		lenText, err := rd.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSuffix(lenText, " "))
		if err != nil {
			out <- "BAD LENGTH " + lenText
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(rd, msg); err != nil {
			return
		}
		out <- string(msg)
	}
}

func checkSyslogFrame(t *testing.T, frame string, want store.AuditRecord) {
	t.Helper()
	// <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	parts := strings.SplitN(frame, " ", 8)
	if len(parts) != 8 || parts[0] != "<110>1" || parts[1] != want.TS || parts[3] != "sendora" || parts[4] != strconv.Itoa(os.Getpid()) || parts[5] != "audit" || parts[6] != "-" {
		t.Fatalf("bad RFC 5424 header: %q", frame)
	}
	var env struct {
		Rec store.AuditRecord `json:"sendora_audit"`
	}
	if err := json.Unmarshal([]byte(parts[7]), &env); err != nil || env.Rec != want {
		t.Fatalf("message %q (%v)", parts[7], err)
	}
}

func syslogListen(t *testing.T, ln net.Listener) chan string {
	frames := make(chan string, 100)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go readSyslogFrames(t, c, frames)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return frames
}

func nextFrameFor(t *testing.T, frames chan string, hash string) string {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case f := <-frames:
			if strings.Contains(f, hash) {
				return f
			}
		case <-timeout:
			t.Fatal("no syslog frame")
		}
	}
}

func TestForwardSyslogTCPUsesRFC5424OctetCounting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	frames := syslogListen(t, ln)
	e := newEnv(t)
	stopForwarder(t, e)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_forward_syslog": ln.Addr().String(), "audit_forward_syslog_tls": false}), 200, "syslog")
	e.s.logEvent(0, "system", "shares_expired", "", "1 shares")
	want := lastAudit(e)
	checkSyslogFrame(t, nextFrameFor(t, frames, want.Hash), want)
}

func TestForwardSyslogTLSVerifiesTheServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler()) // only for its certificate
	defer srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: srv.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	frames := syslogListen(t, ln)
	fastForwardRetry(t)
	e := newEnv(t)
	stopForwarder(t, e)
	admin := e.setup()
	// Untrusted certificate: refused, reported as a TLS error.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_forward_syslog": ln.Addr().String()}), 200, "syslog tls")
	waitFor(t, "tls error", func() bool {
		st := e.s.fwd.status(e.s)[sinkSyslog].(map[string]any)
		return st["last_error"] == "tls" && st["enabled"] == true
	})
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	old := forwardRootCAs
	forwardRootCAs = pool
	defer func() { forwardRootCAs = old }()
	// Trusted: a new sink (the setting switched off and on again) delivers.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_forward_syslog": ""}), 200, "off")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_forward_syslog": ln.Addr().String()}), 200, "on")
	e.s.logEvent(0, "system", "shares_expired", "", "1 shares")
	want := lastAudit(e)
	checkSyslogFrame(t, nextFrameFor(t, frames, want.Hash), want)
}

func TestForwardWebhookPostsBatchesWithTokenAndRetries(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var auths []string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		calls++
		auths = append(auths, r.Header.Get("Authorization"))
		if calls == 1 {
			w.WriteHeader(500) // first attempt fails: retried
			return
		}
		bodies = append(bodies, string(b))
	}))
	defer srv.Close()
	t.Setenv(forwardTokenEnv, writeTokenFile(t, 0o400, "hook-secret-token"))
	fastForwardRetry(t)
	e := newEnv(t)
	stopForwarder(t, e)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_forward_webhook_url": srv.URL + "/hook"}), 200, "webhook")
	e.s.logEvent(0, "system", "shares_expired", "", "1 shares")
	want := lastAudit(e)
	waitFor(t, "webhook delivery", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.Contains(strings.Join(bodies, ""), want.Hash)
	})
	mu.Lock()
	var batch []map[string]json.RawMessage
	for _, b := range bodies {
		var x []map[string]json.RawMessage
		if err := json.Unmarshal([]byte(b), &x); err != nil {
			t.Fatalf("not a JSON array: %s", b)
		}
		batch = append(batch, x...)
	}
	for _, a := range auths {
		if a != "Bearer hook-secret-token" {
			t.Fatalf("authorization %q", a)
		}
	}
	mu.Unlock()
	found := false
	for _, item := range batch {
		var rec store.AuditRecord
		if raw, ok := item["sendora_audit"]; ok && json.Unmarshal(raw, &rec) == nil && rec == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("record not in the batches")
	}
	st := e.s.fwd.status(e.s)[sinkWebhook].(map[string]any)
	if st["failed"].(int64) < 1 || st["last_error"] != "http_status_500" || st["last_success"] == nil || st["enabled"] != true {
		t.Fatalf("%+v", st)
	}
	// The status endpoints show it, without the token.
	s := e.do("GET", "/api/audit/status", admin, nil)
	if !strings.Contains(string(s.Body), `"webhook"`) || strings.Contains(string(s.Body), "hook-secret-token") {
		t.Fatalf("%s", s.Body)
	}
	if l := e.do("GET", "/api/logs/status", admin, nil); !strings.Contains(string(l.Body), `"forwarding"`) {
		t.Fatalf("%s", l.Body)
	}
}

func TestForwardWebhookTokenFileMustBePrivate(t *testing.T) {
	hits := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); hits++; mu.Unlock() }))
	defer srv.Close()
	t.Setenv(forwardTokenEnv, writeTokenFile(t, 0o644, "world-readable"))
	fastForwardRetry(t)
	e := newEnv(t)
	stopForwarder(t, e)
	e.setup()
	e.s.St.SetSetting("audit_forward_webhook_url", srv.URL)
	e.s.logEvent(0, "system", "shares_expired", "", "1 shares")
	waitFor(t, "token error", func() bool {
		return e.s.fwd.status(e.s)[sinkWebhook].(map[string]any)["last_error"] == "token_file"
	})
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatal("sent with a rejected token file")
	}
	if err := CheckSecretFiles(); err == nil {
		t.Fatal("start-up check must refuse the token file too")
	}
}

func TestForwardQueueOverflowDropsWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	oldMax, oldBatch := forwardQueueMax, forwardBatchMax
	forwardQueueMax, forwardBatchMax = 3, 1
	defer func() { forwardQueueMax, forwardBatchMax = oldMax, oldBatch }()
	e := newEnv(t)
	stopForwarder(t, e)
	e.setup()
	e.s.St.SetSetting("audit_forward_webhook_url", srv.URL)
	start := time.Now()
	for i := 0; i < 30; i++ {
		e.s.logEvent(0, "system", "shares_expired", "", "1 shares")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("writing records waited for the stalled sink: %s", d)
	}
	st := e.s.fwd.status(e.s)[sinkWebhook].(map[string]any)
	if st["dropped"].(int64) < 20 || st["queued"].(int64) > 3 {
		t.Fatalf("%+v", st)
	}
	// Every record is still in the local chain.
	if s := chainStatus(e); !s.OK {
		t.Fatalf("%+v", s)
	}
}

func TestForwardHeartbeatCarriesChainHead(t *testing.T) {
	buf := captureStdout(t)
	old := forwardHeartbeatEvery
	forwardHeartbeatEvery = 30 * time.Millisecond
	defer func() { forwardHeartbeatEvery = old }()
	e := newEnv(t)
	e.setup()
	e.s.St.SetSetting("audit_forward_stdout", "true")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.s.fwd.startHeartbeat(e.s, ctx)
	heads := func() []chainHead {
		var out []chainHead
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var env struct {
				Head *chainHead `json:"sendora_audit_chain_head"`
			}
			if json.Unmarshal([]byte(line), &env) == nil && env.Head != nil {
				out = append(out, *env.Head)
			}
		}
		return out
	}
	waitFor(t, "periodic heartbeat", func() bool {
		h := heads()
		return len(h) >= 2 && h[0].Reason == "start" && h[len(h)-1].Reason == "periodic"
	})
	e.s.recordStop() // system_stop, then the final head
	h := heads()
	last := lastAudit(e)
	if final := h[len(h)-1]; final.Reason != "stop" || final.LastSeq != last.Seq || final.Hash != last.Hash || last.Action != "system_stop" {
		t.Fatalf("final head %+v, chain ends at %d %s (%s)", final, last.Seq, last.Hash, last.Action)
	}
	// The heartbeat is not part of the chain.
	if n := len(auditRowsWhere(e, "action LIKE '%chain_head%'")); n != 0 {
		t.Fatal("heartbeat stored in the chain")
	}
	if s := chainStatus(e); !s.OK {
		t.Fatalf("%+v", s)
	}
}

func TestForwardRemovedSinkReceivesTheChange(t *testing.T) {
	var mu sync.Mutex
	var got strings.Builder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got.Write(b)
		mu.Unlock()
	}))
	defer srv.Close()
	e := newEnv(t)
	stopForwarder(t, e)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_forward_webhook_url": srv.URL}), 200, "on")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_forward_webhook_url": ""}), 200, "off")
	off := auditRowsWhere(e, "action='settings_changed' AND detail LIKE '%audit_forward_webhook_url%' AND outcome='ok'")
	if len(off) != 2 {
		t.Fatalf("%+v", off)
	}
	var hash string
	e.s.St.DB.QueryRow(`SELECT hash FROM audit_log WHERE seq=?`, off[1].Seq).Scan(&hash)
	waitFor(t, "the switch-off record at the old destination", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.Contains(got.String(), hash)
	})
	if e.s.fwd.status(e.s)[sinkWebhook].(map[string]any)["enabled"] != false {
		t.Fatal("still enabled")
	}
}

func TestForwardTargetsAreValidatedAndGuarded(t *testing.T) {
	e := newEnv(t)
	stopForwarder(t, e)
	admin := e.setup()
	for _, c := range []struct {
		key, val string
		code     int
	}{
		{"audit_forward_webhook_url", "http://collector.example.com/x", 400},
		{"audit_forward_webhook_url", "https://169.254.169.254/latest", 400},
		{"audit_forward_webhook_url", "https://user:pw@collector.example.com/", 400},
		{"audit_forward_webhook_url", "ftp://collector.example.com/", 400},
		{"audit_forward_webhook_url", "https://collector.example.com/ingest?index=a", 200},
		{"audit_forward_webhook_url", "http://127.0.0.1:9000/hook", 200},
		{"audit_forward_webhook_url", "", 200},
		{"audit_forward_syslog", "169.254.169.254:514", 400},
		{"audit_forward_syslog", "[fe80::1]:514", 400},
		{"audit_forward_syslog", "logs.example.com", 400},
		{"audit_forward_syslog", "logs.example.com:0", 400},
		{"audit_forward_syslog", "10.1.2.3:6514", 200},
		{"audit_forward_syslog", "", 200},
		{"audit_forward_syslog_tls", "maybe", 400},
		{"audit_forward_stdout", "true", 200},
		{"audit_forward_stdout", "false", 200},
	} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{c.key: c.val}), c.code, c.key+"="+c.val)
	}
	// The dial guard runs on the resolved address.
	for addr, blocked := range map[string]bool{"169.254.169.254:80": true, "[fd00:ec2::254]:80": true, "100.100.100.200:80": true,
		"0.0.0.0:514": true, "127.0.0.1:514": false, "10.0.0.5:514": false, "192.168.1.10:6514": false} {
		err := forwardDialControl("tcp", addr, nil)
		if (err != nil) != blocked || (err != nil && !errors.Is(err, errBlockedTarget)) {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if forwardErrClass(fmt.Errorf("dial: %w", errBlockedTarget)) != "blocked_target" {
		t.Fatal("error class")
	}
}

// ---------- 6. readiness and metrics ----------

func TestReadinessReportsEachCheck(t *testing.T) {
	e := newEnv(t)
	e.setup()
	r := e.do("GET", "/api/health/ready", "", nil)
	e.want(r, 200, "ready")
	checks := r.J()["checks"].(map[string]any)
	for _, k := range []string{"database", "audit_log", "disk", "backup", "audit_chain"} {
		if checks[k] != "ok" {
			t.Fatalf("%s: %s", k, r.Body)
		}
	}
	notReady := func(check, what string) {
		t.Helper()
		r := e.do("GET", "/api/health/ready", "", nil)
		if r.Code != 503 || r.J()["status"] != "fail" || r.J()["checks"].(map[string]any)[check] != "fail" {
			t.Fatalf("%s: %d %s", what, r.Code, r.Body)
		}
	}
	// Audit log not writable: the last append failed.
	fail := func() error { return errors.New("forced audit failure") }
	e.s.audit.hook.Store(&fail)
	e.s.logEvent(0, "system", "shares_expired", "", "")
	e.s.audit.hook.Store(nil)
	notReady("audit_log", "audit write failed")
	e.s.logEvent(0, "system", "shares_expired", "", "")
	e.want(e.do("GET", "/api/health/ready", "", nil), 200, "recovered")
	// Disk below the threshold.
	oldFree := readyMinFreeBytes
	readyMinFreeBytes = 1 << 62
	notReady("disk", "disk")
	readyMinFreeBytes = oldFree
	// Backups enabled but the newest is too old, after the start-up grace.
	e.s.Started = time.Now().Add(-2 * readyBackupGrace)
	notReady("backup", "stale backup")
	e.s.St.SetSetting("backups_enabled", "false")
	e.want(e.do("GET", "/api/health/ready", "", nil), 200, "backups off")
	if _, ok := e.do("GET", "/api/health/ready", "", nil).J()["checks"].(map[string]any)["backup"]; ok {
		t.Fatal("backup check while backups are off")
	}
	// Broken chain.
	e.s.St.DB.Exec(`UPDATE audit_log SET detail='tampered' WHERE seq=1`)
	notReady("audit_chain", "tampered chain")
	// Liveness stays up.
	e.want(e.do("GET", "/api/health", "", nil), 200, "liveness")
}

func TestMetricsNeedTheTokenFile(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.want(e.do("GET", "/api/metrics", "", nil), 404, "off by default")

	t.Setenv(metricsTokenEnv, writeTokenFile(t, 0o644, "metrics-token-value"))
	e.want(e.do("GET", "/api/metrics", "metrics-token-value", nil), 503, "world-readable token file")

	t.Setenv(metricsTokenEnv, writeTokenFile(t, 0o400, "metrics-token-value"))
	e.want(e.do("GET", "/api/metrics", "", nil), 401, "no token")
	e.want(e.do("GET", "/api/metrics", "wrong", nil), 401, "wrong token")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "WrongPassword9"}), 401, "failed login")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"}), 200, "login")
	r := e.do("GET", "/api/metrics", "metrics-token-value", nil)
	e.want(r, 200, "metrics")
	body := string(r.Body)
	if !strings.HasPrefix(r.Hdr.Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", r.Hdr.Get("Content-Type"))
	}
	for _, want := range []string{
		"# TYPE sendora_logins_total counter", `sendora_logins_total{result="ok"} 1`, `sendora_logins_total{result="failed"} 1`,
		"sendora_mfa_failures_total 0", "sendora_audit_write_failures_total 0",
		`sendora_audit_forward_dropped_total{sink="webhook"} 0`, `sendora_audit_forward_failed_total{sink="syslog"} 0`,
		"sendora_decrypt_failures_total 0", "sendora_ip_bans_total 0", "sendora_downloads_started_total 0", "sendora_uploads_completed_total 0",
		"# TYPE sendora_upload_sessions_active gauge", "sendora_upload_sessions_active 0", "sendora_verified_download_slots_in_use 0",
		`sendora_audit_forward_queue_length{sink="stdout"} 0`,
	} {
		if !strings.Contains(body, want+"\n") && !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	// Every sample line is "name{labels} value".
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 || !strings.HasPrefix(f[0], "sendora_") {
			t.Fatalf("bad sample %q", line)
		}
		if _, err := strconv.ParseInt(f[1], 10, 64); err != nil {
			t.Fatalf("bad value %q", line)
		}
	}
}
