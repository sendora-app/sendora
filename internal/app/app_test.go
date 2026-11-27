// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sendora-app/sendora/internal/store"
)

type env struct {
	t   *testing.T
	s   *Server
	ts  *httptest.Server
	jar map[string]string
	// host, when set, is sent as the Host header (multi-tenant tests).
	host string
	// dbKey is the database key of an encrypted env (newEncryptedEnv).
	dbKey []byte
}

func init() {
	// Every test instance would print its own throwaway setup code.
	setupCodeLog = func(string, ...any) {}
}

func newEnv(t *testing.T) *env {
	// Address blocking has its own tests; flooding tests elsewhere must not trip it.
	t.Setenv("SENDORA_DISABLE_IP_BANS", "true")
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	legacyTestDefaults(t, st)
	s := New(st, fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}, "test")
	ctx, cancel := context.WithCancel(context.Background())
	s.RunDownloadMail(ctx)
	t.Cleanup(cancel)
	// Failed sign-ins are deliberately slow; on a slow test machine 61 of them
	// can take longer than a minute, so budgets must not reset mid-test.
	s.rateWindow = time.Hour
	// Fixtures use simple passwords; the screening has its own tests (password_check_test.go).
	s.passwordScreenOff = true
	ts := httptest.NewServer(s.Router())
	t.Cleanup(ts.Close)
	return &env{t: t, s: s, ts: ts}
}

type resp struct {
	Code int
	Body []byte
	Hdr  http.Header
}

func (r resp) J() map[string]any {
	m := map[string]any{}
	json.Unmarshal(r.Body, &m)
	return m
}
func (r resp) S(k string) string { return fmt.Sprint(r.J()[k]) }

func (e *env) do(method, path, token string, body any, hdr ...string) resp {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case io.Reader:
		rd = b
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	if e.host != "" {
		req.Host = e.host
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	if _, ok := body.(map[string]any); ok {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, b, res.Header}
}

func (e *env) want(r resp, code int, what string) {
	e.t.Helper()
	if r.Code != code {
		e.t.Fatalf("%s: want %d got %d body=%s", what, code, r.Code, r.Body)
	}
}

func (e *env) setup() string {
	r := e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "admin", "password": "password123", "email": "admin@x.io"})
	e.want(r, 200, "setup")
	return r.S("access_token")
}

func (e *env) mkUser(admin string, name string, isAdmin bool) string {
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": name, "password": "password123", "email": name + "@x.io", "admin": isAdmin}), 201, "create user")
	r := e.do("POST", "/api/auth/login", "", map[string]any{"username": name, "password": "password123"})
	e.want(r, 200, "login "+name)
	return r.S("access_token")
}

// upload files (name -> content) and complete; returns complete response
func (e *env) share(tok string, files map[string]string, opts map[string]any) resp {
	var meta []map[string]any
	var order []string
	for n, c := range files {
		meta = append(meta, map[string]any{"name": n, "full_path": n, "size": len(c)})
		order = append(order, n)
	}
	// keep index order stable with meta
	order = order[:0]
	for _, m := range meta {
		order = append(order, m["name"].(string))
	}
	r := e.do("POST", "/api/uploads", tok, map[string]any{"files": meta})
	e.want(r, 201, "create upload")
	id := r.S("id")
	for i, n := range order {
		e.want(e.do("PATCH", fmt.Sprintf("/api/uploads/%s/files/%d", id, i), tok, []byte(files[n]), "Upload-Offset", "0"), 200, "chunk")
	}
	if opts == nil {
		opts = map[string]any{}
	}
	return e.do("POST", "/api/uploads/"+id+"/complete", tok, opts)
}

func TestDownloadOutboxBackpressureAndRetry(t *testing.T) {
	liftDownloadMailThrottle(t)
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	legacyTestDefaults(t, st)
	defer st.DB.Close()
	s := New(st, fstest.MapFS{"index.html": {Data: []byte("spa")}}, "test")
	s.passwordScreenOff = true
	ts := httptest.NewServer(s.Router())
	defer ts.Close()
	e := &env{t: t, s: s, ts: ts}
	admin := e.setup()
	share := e.share(admin, map[string]string{"a.txt": "abc"}, nil)
	public := "/api/shares/" + share.S("long_id") + "/download"
	for i := 0; i < downloadMailCapacity; i++ {
		if _, err := st.DB.Exec(`INSERT INTO download_mail_outbox(share_id,status,recipient,language,data,next_attempt) VALUES(?,'pending','admin@x.io','en','{}',?)`, share.J()["id"], time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	r := e.do("GET", public, "", nil)
	e.want(r, 503, "explicit outbox overload")
	if r.Hdr.Get("Retry-After") != "30" {
		t.Fatal("missing overload retry")
	}
	var count int
	qByName(st, `SELECT download_count FROM shares WHERE long_id=?`, share.S("long_id")).Scan(&count)
	if count != 0 {
		t.Fatal("overload consumed reservation", count)
	}
	st.DB.Exec(`DELETE FROM download_mail_outbox`)
	e.want(e.do("GET", public, "", nil, "Range", "bytes=99-"), 416, "range rejection releases queued mail")
	st.DB.QueryRow(`SELECT COUNT(*) FROM download_mail_outbox`).Scan(&count)
	if count != 0 {
		t.Fatal("unstarted range retained job")
	}
	e.want(e.do("GET", public, "", nil), 200, "durable queued start")
	var data, status string
	st.DB.QueryRow(`SELECT data,status FROM download_mail_outbox`).Scan(&data, &status)
	if status != "pending" || !strings.Contains(data, "StartedAt") || !strings.Contains(data, "a.txt") {
		t.Fatal(status, data)
	}
	// Reconstructing the server preserves pending jobs without capturing requests.
	s = New(st, fstest.MapFS{"index.html": {Data: []byte("spa")}}, "test")
	for i := 1; i <= 3; i++ {
		st.DB.Exec(`UPDATE download_mail_outbox SET next_attempt=?`, time.Now().Add(-time.Second))
		if !s.processDownloadMail(context.Background()) {
			t.Fatal("pending retry not processed")
		}
		var attempts int
		var failure string
		st.DB.QueryRow(`SELECT attempts,status,last_error FROM download_mail_outbox`).Scan(&attempts, &status, &failure)
		if attempts != i || failure == "" || (i == 3 && status != "failed") {
			t.Fatal(attempts, status, failure)
		}
	}
	if s.processDownloadMail(context.Background()) {
		t.Fatal("failed job retried without bound")
	}
	for i := 0; i < 1000; i++ {
		st.DB.Exec(`INSERT INTO download_mail_outbox(share_id,status,recipient,language,data,next_attempt) VALUES(1,'failed','admin@x.io','en','{}',?)`, time.Now())
	}
	st.DB.Exec(`INSERT INTO download_mail_outbox(share_id,status,recipient,language,data,attempts,next_attempt) VALUES(1,'pending','admin@x.io','en','{}',2,?)`, time.Now().Add(-time.Second))
	s.processDownloadMail(context.Background())
	st.DB.QueryRow(`SELECT COUNT(*) FROM download_mail_outbox WHERE status='failed'`).Scan(&count)
	if count != 1000 {
		t.Fatal("failure retention unbounded", count)
	}
	// No recipient means no mail job, even with pending capacity saturated.
	eByName(st, `UPDATE users SET email='' WHERE username='admin'`)
	for i := 0; i < downloadMailCapacity; i++ {
		st.DB.Exec(`INSERT INTO download_mail_outbox(share_id,status,recipient,language,data,next_attempt) VALUES(1,'pending','admin@x.io','en','{}',?)`, time.Now().Add(time.Hour))
	}
	e.want(e.do("GET", public, "", nil), 200, "owner without email bypasses queue")
	st.DB.Exec(`DELETE FROM download_mail_outbox WHERE status='pending'`)
	eByName(st, `UPDATE users SET email='admin@x.io' WHERE username='admin'`)
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.want(e.do("GET", public, "", nil), 200, "failed record does not consume capacity")
	if !s.processDownloadMail(context.Background()) {
		t.Fatal("delivery not processed")
	}
	sink.wait(t, "Download count: 3") // 0.1.5: the refused range above no longer consumes a download
	st.DB.QueryRow(`SELECT COUNT(*) FROM download_mail_outbox WHERE status='pending'`).Scan(&count)
	if count != 0 {
		t.Fatal("delivered job not removed")
	}
	// Failure recording a start must fail before returning file bytes.
	st.DB.Exec(`CREATE TRIGGER fail_download_history BEFORE INSERT ON downloads BEGIN SELECT RAISE(ABORT,'test'); END`)
	e.want(e.do("GET", public, "", nil), 503, "history failure aborts file response")
	st.DB.QueryRow(`SELECT COUNT(*) FROM download_mail_outbox WHERE status='reserved'`).Scan(&count)
	if count != 0 {
		t.Fatal("failed start retained reservation")
	}
}

func TestLargeZIPUsesBoundedFileDescriptors(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	share := e.share(admin, map[string]string{"source.txt": "payload"}, nil)
	sid := int64(share.J()["id"].(float64))
	file := e.s.shareFiles(sid)[0]
	// Reuse one source inode for 1500 entries: an implementation retaining one
	// descriptor per entry exceeds typical process budgets without large fixtures.
	for i := 0; i < 1500; i++ {
		name := fmt.Sprintf("entry%04d.txt", i)
		if _, err := e.s.St.DB.Exec(`INSERT INTO files(share_id,name,full_path,size,disk_path) VALUES(?,?,?,?,?)`, sid, name, name, file.Size, file.diskPath); err != nil {
			t.Fatal(err)
		}
	}
	r := e.do("GET", "/api/shares/"+share.S("long_id")+"/download", "", nil)
	e.want(r, 200, "large ZIP")
	zr, err := zip.NewReader(bytes.NewReader(r.Body), int64(len(r.Body)))
	if err != nil || len(zr.File) != 1501 {
		t.Fatal("incomplete large ZIP", err)
	}
}

func TestSetupAndAuth(t *testing.T) {
	e := newEnv(t)
	if !e.do("GET", "/api/bootstrap", "", nil).J()["setup_needed"].(bool) {
		t.Fatal("setup_needed expected")
	}
	e.want(e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "a", "password": "short"}), 400, "short pw")
	tok := e.setup()
	e.want(e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "b", "password": "password123"}), 403, "second setup")
	if e.do("GET", "/api/bootstrap", "", nil).J()["setup_needed"].(bool) {
		t.Fatal("setup_needed should be false")
	}
	e.want(e.do("GET", "/api/users/me", "", nil), 401, "no token")
	e.want(e.do("GET", "/api/users/me", "garbage", nil), 401, "bad token")
	e.want(e.do("GET", "/api/users/me", tok, nil), 200, "me")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "wrong"}), 401, "bad login")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin@x.io", "password": "password123"}), 200, "login by email")

	// alg=none token rejected
	none := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5fQ."
	e.want(e.do("GET", "/api/users/me", none, nil), 401, "alg none")

	// refresh cookie rotation
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"password123"}`))
	res, _ := http.DefaultClient.Do(req)
	var ck *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "refresh" {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly {
		t.Fatal("refresh cookie missing/not httponly")
	}
	rf := func() int {
		rq, _ := http.NewRequest("POST", e.ts.URL+"/api/auth/refresh", nil)
		rq.AddCookie(ck)
		rs, _ := http.DefaultClient.Do(rq)
		if rs.StatusCode == 200 {
			for _, c := range rs.Cookies() {
				if c.Name == "refresh" {
					defer func(n *http.Cookie) { ck = n }(c)
				}
			}
		}
		return rs.StatusCode
	}
	old := ck
	if rf() != 200 {
		t.Fatal("refresh failed")
	}
	ck = old
	if rf() != 401 {
		t.Fatal("old refresh token must be invalid after rotation")
	}
	e.want(e.do("POST", "/api/auth/refresh", "", nil), 401, "refresh no cookie")
}

func TestUsersAndPermissions(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	e.want(e.do("GET", "/api/users", bob, nil), 403, "non-admin list users")
	e.want(e.do("GET", "/api/settings", bob, nil), 403, "non-admin settings")
	e.want(e.do("GET", "/api/stats", bob, nil), 403, "non-admin stats")
	e.want(e.do("GET", "/api/backups", bob, nil), 403, "non-admin backups")
	e.want(e.do("GET", "/api/shares/all", admin, nil), 404, "admin has no all-shares list")
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "bob", "password": "password123"}), 400, "dup user")
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "x", "password": "123"}), 400, "short pw")

	// profile password change
	e.want(e.do("PUT", "/api/users/me", bob, map[string]any{"name": "Bob", "email": "bob@x.io", "password": "newpassword1", "current_password": "wrong"}), 400, "wrong current pw")
	changed := e.do("PUT", "/api/users/me", bob, map[string]any{"name": "Bob", "email": "bob@x.io", "password": "newpassword1", "current_password": "password123"})
	e.want(changed, 200, "change pw")
	e.want(e.do("GET", "/api/users/me", bob, nil), 401, "old access revoked")
	bob = changed.S("access_token")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "newpassword1"}), 200, "login new pw")
	e.want(e.do("PUT", "/api/users/me", bob, map[string]any{"name": "Bob", "email": "not-an-email"}), 400, "bad email")

	// admin can't demote or delete self
	me := e.do("GET", "/api/users/me", admin, nil).J()["user"].(map[string]any)
	id := int(me["id"].(float64))
	e.want(e.do("PUT", "/api/users/"+strconv.Itoa(id), admin, map[string]any{"name": "A", "admin": false}), 400, "self demote")
	e.want(e.do("DELETE", "/api/users/"+strconv.Itoa(id), admin, nil), 400, "self delete")

	// force reset
	var bobID int
	for _, u := range func() []any { var l []any; json.Unmarshal(e.do("GET", "/api/users", admin, nil).Body, &l); return l }() {
		if u.(map[string]any)["username"] == "bob" {
			bobID = int(u.(map[string]any)["id"].(float64))
		}
	}
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/force-reset-password", bobID), admin, nil), 200, "force reset")
	u := e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "newpassword1"}).J()["user"].(map[string]any)
	if u["must_change_password"] != true {
		t.Fatal("must_change_password expected")
	}
	e.want(e.do("GET", "/api/shares", bob, nil), 401, "forced reset revokes old access")
	forced := e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "newpassword1"}).S("access_token")
	e.want(e.do("GET", "/api/shares", forced, nil), 403, "forced change blocks account APIs")
	changed = e.do("PUT", "/api/users/me", forced, map[string]any{"password": "changedpassword1", "name": "Bob", "email": "bob@x.io"})
	e.want(changed, 200, "forced password change")
	bob = changed.S("access_token")
	// delete user removes shares + files
	r := e.share(bob, map[string]string{"f.txt": "x"}, nil)
	e.want(r, 201, "bob share")
	e.want(e.do("DELETE", fmt.Sprintf("/api/users/%d", bobID), admin, nil), 200, "delete bob")
	e.want(e.do("GET", "/api/shares/"+r.S("long_id"), "", nil), 404, "share gone after user delete")
}

func TestUploadValidationAndResume(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	e.want(e.do("POST", "/api/uploads", "", map[string]any{"files": []any{}}), 401, "unauth upload")
	e.want(e.do("POST", "/api/uploads", tok, map[string]any{"files": []any{}}), 400, "empty files")
	e.want(e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "a", "full_path": "a", "size": -1}}}), 400, "negative size")
	e.s.St.SetSetting("max_share_size", "1")
	e.want(e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "a", "full_path": "a", "size": 2 * 1024 * 1024}}}), 413, "too large")
	e.s.St.SetSetting("max_share_size", "2048")

	r := e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "big.bin", "full_path": "dir/../../etc/big.bin", "size": 10}, {"name": "empty.txt", "full_path": "empty.txt", "size": 0}}})
	e.want(r, 201, "create")
	id := r.S("id")
	p := fmt.Sprintf("/api/uploads/%s/files/0", id)
	// missing offset
	e.want(e.do("PATCH", p, tok, []byte("abc")), 400, "no offset")
	// first chunk
	e.want(e.do("PATCH", p, tok, []byte("01234"), "Upload-Offset", "0"), 200, "chunk1")
	// wrong offset => 409 with received
	c := e.do("PATCH", p, tok, []byte("xx"), "Upload-Offset", "2")
	e.want(c, 409, "offset mismatch")
	if c.S("received") != "5" {
		t.Fatal("received should be 5", c.S("received"))
	}
	// status
	st := e.do("GET", "/api/uploads/"+id, tok, nil)
	if !strings.Contains(string(st.Body), `"received":5`) {
		t.Fatal(string(st.Body))
	}
	// too much data
	e.want(e.do("PATCH", p, tok, []byte("56789EXTRA"), "Upload-Offset", "5"), 413, "overflow")
	// incomplete completion
	e.want(e.do("POST", "/api/uploads/"+id+"/complete", tok, map[string]any{}), 400, "incomplete")
	// resume and finish (after overflow, received must be intact)
	st = e.do("GET", "/api/uploads/"+id, tok, nil)
	t.Log(string(st.Body))
	e.want(e.do("PATCH", p, tok, []byte("56789"), "Upload-Offset", "5"), 200, "chunk2")

	// other user cannot touch session
	bob := e.mkUser(tok, "bob", false)
	e.want(e.do("GET", "/api/uploads/"+id, bob, nil), 404, "foreign session")
	e.want(e.do("PATCH", p, bob, []byte("z"), "Upload-Offset", "10"), 404, "foreign patch")

	// empty file needs no chunk
	done := e.do("POST", "/api/uploads/"+id+"/complete", tok, map[string]any{"name": "t"})
	e.want(done, 201, "complete with empty file")
	lid := done.S("long_id")
	sh := e.do("GET", "/api/shares/"+lid, "", nil)
	if !strings.Contains(string(sh.Body), `"full_path":"etc/big.bin"`) {
		t.Fatalf("path traversal not sanitised: %s", sh.Body)
	}
	d := e.do("GET", "/api/shares/"+lid+"/download/etc/big.bin", "", nil)
	e.want(d, 200, "file download")
	if string(d.Body) != "0123456789" {
		t.Fatalf("content mismatch %q", d.Body)
	}
	if !strings.Contains(d.Hdr.Get("Content-Disposition"), "big.bin") || d.Hdr.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("headers", d.Hdr)
	}
	e.want(e.do("GET", "/api/shares/"+lid+"/download/../../../etc/passwd", "", nil), 404, "traversal download")
	// session removed
	e.want(e.do("GET", "/api/uploads/"+id, tok, nil), 404, "session cleaned")
}

func TestShareLifecycle(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	bob := e.mkUser(tok, "bob", false)

	// multi-file => zip, protected, limited
	r := e.share(tok, map[string]string{"a.txt": "AAA", "b.txt": "BBB"}, map[string]any{"name": "My Share", "password": "secret12", "download_limit": 3, "description": "d"})
	e.want(r, 201, "share")
	lid := r.S("long_id")
	pub := e.do("GET", "/api/shares/"+lid, "", nil)
	if pub.J()["files"] != nil || pub.J()["password_protected"] != true {
		t.Fatal("protected share leaked files: ", string(pub.Body))
	}
	e.want(e.do("GET", "/api/shares/"+lid+"/download", "", nil), 401, "download w/o pw")
	e.want(e.do("POST", "/api/shares/"+lid+"/unlock", "", map[string]any{"password": "nope"}), 401, "bad pw")
	tk := e.do("POST", "/api/shares/"+lid+"/unlock", "", map[string]any{"password": "secret12"}).S("token")
	if tk == "" {
		t.Fatal("no token")
	}
	// token for another share is rejected
	r2 := e.share(tok, map[string]string{"c.txt": "C"}, map[string]any{"password": "other123"})
	e.want(e.do("GET", "/api/shares/"+r2.S("long_id")+"/download?token="+tk, "", nil), 401, "cross-share token")
	e.want(e.do("GET", "/api/shares/"+lid+"/download?token=junk", "", nil), 401, "junk token")

	z := e.do("GET", "/api/shares/"+lid+"/download?token="+tk, "", nil)
	e.want(z, 200, "zip")
	zr, err := zip.NewReader(bytes.NewReader(z.Body), int64(len(z.Body)))
	if err != nil || len(zr.File) != 2 {
		t.Fatal("bad zip", err)
	}
	e.want(e.do("POST", "/api/shares/"+lid+"/download", "", nil, "X-Share-Token", tk), 200, "POST download w/ header")
	e.want(e.do("GET", "/api/shares/"+lid+"/download?token="+tk, "", nil), 200, "3rd")
	// limit reached
	e.want(e.do("GET", "/api/shares/"+lid+"/download?token="+tk, "", nil), 410, "limit reached")
	e.want(e.do("GET", "/api/shares/"+lid, "", nil), 410, "read limited")

	// owner views; bob cannot manage tok's share
	list := e.do("GET", "/api/shares", tok, nil)
	var shares []map[string]any
	json.Unmarshal(list.Body, &shares)
	var sid int
	for _, s := range shares {
		if s["long_id"] == lid {
			sid = int(s["id"].(float64))
		}
	}
	sp := func(a string) string { return fmt.Sprintf("/api/shares/%d/%s", sid, a) }
	e.want(e.do("POST", sp("extend"), bob, map[string]any{"days": 3}), 404, "bob extend")
	e.want(e.do("DELETE", fmt.Sprintf("/api/shares/%d", sid), bob, nil), 404, "bob delete")
	// raise limit reactivates
	e.want(e.do("POST", sp("download-limit"), tok, map[string]any{"limit": 10}), 200, "raise limit")
	e.want(e.do("GET", "/api/shares/"+lid+"/download?token="+tk, "", nil), 200, "works again")
	// expire
	e.want(e.do("POST", sp("expire"), tok, nil), 200, "expire")
	e.want(e.do("GET", "/api/shares/"+lid, "", nil), 410, "expired")
	// extend revives
	e.want(e.do("POST", sp("extend"), tok, map[string]any{"days": 5}), 200, "extend")
	e.want(e.do("POST", sp("extend"), tok, map[string]any{"days": 0}), 400, "extend 0")
	// non-admin max expiry
	e.s.St.SetSetting("max_expiry_time", "10")
	e.want(e.do("POST", sp("extend"), tok, map[string]any{"days": 11}), 200, "admin bypasses max")
	e.want(e.do("GET", "/api/shares/"+lid, "", nil), 200, "revived (password-protected stub)")
}

func TestExpiryClamp(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	bob := e.mkUser(tok, "bob", false)
	e.s.St.SetSetting("max_expiry_time", "10")
	r := e.share(bob, map[string]string{"a": "1"}, map[string]any{"expires_in_days": 999})
	e.want(r, 201, "share")
	var l []map[string]any
	json.Unmarshal(e.do("GET", "/api/shares", bob, nil).Body, &l)
	exp, _ := time.Parse(time.RFC3339, l[0]["expires_at"].(string))
	if d := time.Until(exp); d > 10*24*time.Hour+time.Minute {
		t.Fatalf("expiry not clamped: %v", d)
	}
	sid := int(l[0]["id"].(float64))
	e.want(e.do("POST", fmt.Sprintf("/api/shares/%d/extend", sid), bob, map[string]any{"days": 11}), 400, "bob extend over max")
	// prune
	e.want(e.do("POST", fmt.Sprintf("/api/shares/%d/expire", sid), bob, nil), 200, "expire")
	p := e.do("POST", "/api/shares/prune-expired", bob, nil)
	if p.S("removed") != "1" {
		t.Fatal("prune", string(p.Body))
	}
}

func TestReverseShare(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	inv := e.do("POST", "/api/reverse-shares/invite", tok, map[string]any{"name": "Guesty", "message": "hi"})
	e.want(inv, 201, "invite")
	itok := inv.S("url")[strings.LastIndex(inv.S("url"), "/")+1:]
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": "bad"}), 404, "bad invite")
	acc := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok})
	e.want(acc, 200, "accept")
	g := acc.S("access_token")
	// guest cannot use account APIs
	e.want(e.do("GET", "/api/users", g, nil), 403, "guest users")
	e.want(e.do("POST", "/api/reverse-shares/invite", g, map[string]any{}), 403, "guest invite")
	// guest login via password blocked
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": acc.J()["user"].(map[string]any)["username"], "password": ""}), 401, "guest login")
	// re-accept same invite gives same guest user
	acc2 := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok})
	if acc2.J()["user"].(map[string]any)["id"] != acc.J()["user"].(map[string]any)["id"] {
		t.Fatal("guest user should be reused")
	}
	// upload, ignoring password option
	r := e.share(g, map[string]string{"g.txt": "guest data"}, map[string]any{"password": "xxxxxxxx", "name": "from guest"})
	e.want(r, 201, "guest complete")
	// invite now used
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 404, "used invite")
	e.want(e.do("POST", "/api/uploads", g, map[string]any{"files": []map[string]any{{"name": "a", "full_path": "a", "size": 1}}}), 403, "second upload")
	// share belongs to inviter, no password
	var l []map[string]any
	json.Unmarshal(e.do("GET", "/api/shares", tok, nil).Body, &l)
	if len(l) != 1 || l[0]["password_protected"] != false {
		t.Fatalf("owner shares: %v", l)
	}
	// expired invite
	inv2 := e.do("POST", "/api/reverse-shares/invite", tok, map[string]any{})
	t2 := inv2.S("url")[strings.LastIndex(inv2.S("url"), "/")+1:]
	e.s.St.DB.Exec(`UPDATE reverse_invites SET expires_at=? WHERE token=?`, time.Now().Add(-time.Hour), t2)
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": t2}), 404, "expired invite")
	// feature flag
	e.s.St.SetSetting("allow_reverse_shares", "false")
	e.want(e.do("POST", "/api/reverse-shares/invite", tok, map[string]any{}), 403, "disabled")
}

func TestAdminSettingsThemesBranding(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	// settings
	e.want(e.do("PUT", "/api/settings", tok, map[string]any{"application_name": "Acme", "smtp_pass": "s3cret", "allow_self_registration": true, "default_expiry_time": 5, "jwt_secret": "evil", "nonexistent": "x"}), 200, "put settings")
	s := e.do("GET", "/api/settings", tok, nil).J()
	if s["application_name"] != "Acme" || s["smtp_pass"] != "" || s["smtp_pass_set"] != true || s["allow_self_registration"] != "true" || s["default_expiry_time"] != "5" {
		t.Fatalf("settings: %v", s)
	}
	if _, ok := s["jwt_secret"]; ok {
		t.Fatal("jwt_secret leaked")
	}
	if e.s.St.Setting("jwt_secret") == "evil" || e.s.St.Setting("nonexistent") != "" {
		t.Fatal("protected/unknown keys written")
	}
	e.do("PUT", "/api/settings", tok, map[string]any{"smtp_pass": ""})
	if e.s.St.Setting("smtp_pass") != "s3cret" {
		t.Fatal("blank secret must keep old value")
	}
	if e.do("GET", "/api/bootstrap", "", nil).S("application_name") != "Acme" {
		t.Fatal("bootstrap name")
	}
	tp := e.do("GET", "/api/email-templates", tok, nil).J()
	if len(tp) < 6 {
		t.Fatal("templates", tp)
	}
	e.want(e.do("PUT", "/api/email-templates", tok, map[string]any{"tpl_verify_email": "{{.Code"}), 400, "bad template")
	e.want(e.do("PUT", "/api/email-templates", tok, map[string]any{"tpl_verify_email": "Code {{.Code}}", "application_name": "hacked"}), 400, "unknown template key")
	e.want(e.do("PUT", "/api/email-templates", tok, map[string]any{"tpl_verify_email": "Code {{.Code}}"}), 200, "good template")
	if e.s.St.Setting("application_name") != "Acme" {
		t.Fatal("template endpoint wrote non-template key")
	}

	// themes
	act := e.do("GET", "/api/themes/active", "", nil)
	if act.J()["name"] != "Light" {
		t.Fatal("default theme", string(act.Body))
	}
	good := map[string]any{"primary": "#112233", "bg": "#fff", "surface": "#ffffff", "text": "#000", "muted": "#666", "border": "#ccc", "danger": "#f00"}
	e.want(e.do("POST", "/api/themes", tok, map[string]any{"name": "Mine", "data": good}), 200, "save theme")
	bad := map[string]any{}
	for k, v := range good {
		bad[k] = v
	}
	bad["primary"] = "red;}body{display:none"
	e.want(e.do("POST", "/api/themes", tok, map[string]any{"name": "Evil", "data": bad}), 400, "css injection")
	e.want(e.do("POST", "/api/themes", tok, map[string]any{"name": "Mine", "data": good}), 400, "dup name")
	var th []map[string]any
	json.Unmarshal(e.do("GET", "/api/themes", tok, nil).Body, &th)
	var mine, light int
	for _, x := range th {
		if x["name"] == "Mine" {
			mine = int(x["id"].(float64))
		}
		if x["name"] == "Light" {
			light = int(x["id"].(float64))
		}
	}
	e.want(e.do("DELETE", fmt.Sprintf("/api/themes/%d", light), tok, nil), 400, "delete bundled")
	e.want(e.do("POST", fmt.Sprintf("/api/themes/%d/activate", mine), tok, nil), 200, "activate")
	if e.do("GET", "/api/themes/active", "", nil).S("name") != "Mine" {
		t.Fatal("active theme")
	}
	e.want(e.do("DELETE", fmt.Sprintf("/api/themes/%d", mine), tok, nil), 400, "delete active")
	e.want(e.do("POST", "/api/themes/999/activate", tok, nil), 404, "activate missing")
	// activation failure must not leave zero active
	if e.do("GET", "/api/themes/active", "", nil).S("name") != "Mine" {
		t.Fatal("active theme lost after failed activate")
	}
	e.want(e.do("PUT", "/api/themes", tok, nil), 405, "")
}

func mpart(field, filename string, data []byte) (io.Reader, string) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fw, _ := w.CreateFormFile(field, filename)
	fw.Write(data)
	w.Close()
	return &b, w.FormDataContentType()
}

func TestBranding(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")
	b, ct := mpart("file", "x.png", png)
	e.want(e.do("POST", "/api/settings/branding/logo", tok, b, "Content-Type", ct), 200, "logo")
	l := e.do("GET", "/api/branding/logo", "", nil)
	e.want(l, 200, "serve logo")
	if l.Hdr.Get("Content-Type") != "image/png" {
		t.Fatal(l.Hdr)
	}
	if !e.do("GET", "/api/bootstrap", "", nil).J()["has_logo"].(bool) {
		t.Fatal("has_logo")
	}
	// svg served sandboxed
	b, ct = mpart("file", "x.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	e.want(e.do("POST", "/api/settings/branding/favicon", tok, b, "Content-Type", ct), 200, "svg favicon")
	f := e.do("GET", "/api/branding/favicon", "", nil)
	if !strings.Contains(f.Hdr.Get("Content-Security-Policy"), "sandbox") || f.Hdr.Get("Content-Type") != "image/svg+xml" {
		t.Fatal("svg not sandboxed", f.Hdr)
	}
	// non-image rejected
	b, ct = mpart("file", "x.png", []byte("<html><script>alert(1)</script></html>"))
	e.want(e.do("POST", "/api/settings/branding/logo", tok, b, "Content-Type", ct), 400, "html as png")
	b, ct = mpart("file", "x.png", png)
	e.want(e.do("POST", "/api/settings/branding/nope", tok, b, "Content-Type", ct), 404, "bad kind")
	// svg not allowed as background
	b, ct = mpart("file", "x.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`))
	e.want(e.do("POST", "/api/backgrounds", tok, b, "Content-Type", ct), 400, "svg background")
	b, ct = mpart("file", "x.png", png)
	bg := e.do("POST", "/api/backgrounds", tok, b, "Content-Type", ct)
	e.want(bg, 201, "background")
	e.want(e.do("GET", "/api/backgrounds/"+bg.S("name"), "", nil), 200, "serve bg")
	if !strings.Contains(string(e.do("GET", "/api/backgrounds", "", nil).Body), bg.S("name")) {
		t.Fatal("bg list")
	}
	e.want(e.do("GET", "/api/backgrounds/..%2f..%2fsendora.db", "", nil), 404, "bg traversal")
	e.want(e.do("DELETE", "/api/backgrounds/"+bg.S("name"), tok, nil), 200, "del bg")
	e.want(e.do("DELETE", "/api/settings/branding/logo", tok, nil), 200, "del logo")
	e.want(e.do("GET", "/api/branding/logo", "", nil), 404, "logo gone")
	// non-admin
	bob := e.mkUser(tok, "bob", false)
	b, ct = mpart("file", "x.png", png)
	e.want(e.do("POST", "/api/backgrounds", bob, b, "Content-Type", ct), 403, "bob bg")
}

func TestBackups(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	r := e.do("POST", "/api/backups", tok, nil)
	e.want(r, 201, "create")
	n := r.S("name")
	if !strings.Contains(string(e.do("GET", "/api/backups", tok, nil).Body), n) {
		t.Fatal("not listed")
	}
	d := e.do("GET", "/api/backups/"+n, tok, nil)
	e.want(d, 200, "download")
	if !bytes.HasPrefix(d.Body, []byte("SQLite format 3")) {
		t.Fatal("not sqlite")
	}
	e.want(e.do("GET", "/api/backups/..%2fjwt", tok, nil), 404, "traversal")
	e.want(e.do("GET", "/api/backups/sendora.db", tok, nil), 404, "live db not downloadable")
	e.want(e.do("DELETE", "/api/backups/"+n, tok, nil), 200, "delete")
	e.want(e.do("GET", "/api/backups/"+n, tok, nil), 404, "gone")
}

// ---- fake SMTP ----

type smtpSink struct {
	mu   sync.Mutex
	msgs []string
	ln   net.Listener
}

func newSMTP(t *testing.T) *smtpSink {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpSink{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				rd := bufio.NewReader(c)
				fmt.Fprint(c, "220 hi\r\n")
				var data bool
				var buf strings.Builder
				for {
					line, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					if data {
						if line == ".\r\n" {
							data = false
							s.mu.Lock()
							s.msgs = append(s.msgs, buf.String())
							s.mu.Unlock()
							fmt.Fprint(c, "250 ok\r\n")
						} else {
							buf.WriteString(line)
						}
						continue
					}
					cmd := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
						fmt.Fprint(c, "250 hi\r\n")
					case strings.HasPrefix(cmd, "DATA"):
						data = true
						buf.Reset()
						fmt.Fprint(c, "354 go\r\n")
					case strings.HasPrefix(cmd, "QUIT"):
						fmt.Fprint(c, "221 bye\r\n")
						return
					default:
						fmt.Fprint(c, "250 ok\r\n")
					}
				}
			}()
		}
	}()
	return s
}

func (s *smtpSink) wait(t *testing.T, contains string) string {
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		for _, m := range s.msgs {
			parts := strings.SplitN(m, "\r\n\r\n", 2)
			if len(parts) == 2 {
				decoded, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(parts[1])))
				m = parts[0] + "\r\n\r\n" + string(decoded)
			}
			if strings.Contains(m, contains) {
				s.mu.Unlock()
				return m
			}
		}
		s.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no mail containing %q; got %v", contains, s.msgs)
	return ""
}

func (e *env) useSMTP(sink *smtpSink) {
	host, port, _ := net.SplitHostPort(sink.ln.Addr().String())
	e.s.St.SetSetting("smtp_host", host)
	e.s.St.SetSetting("smtp_port", port)
	e.s.St.SetSetting("smtp_tls", "none")
	e.s.St.SetSetting("smtp_from", "files@x.io")
}

func TestEmailFlows(t *testing.T) {
	e := newEnv(t)
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.BaseURL = "https://files.example.com"
	tok := e.setup()

	// test email
	e.want(e.do("POST", "/api/email-templates/test", tok, nil), 200, "test mail")
	sink.wait(t, "SMTP works")

	// password reset
	e.want(e.do("POST", "/api/auth/forgot-password", "", map[string]any{"email": "nobody@x.io"}), 200, "forgot unknown (no enumeration)")
	e.want(e.do("POST", "/api/auth/forgot-password", "", map[string]any{"email": "admin@x.io"}), 200, "forgot")
	m := sink.wait(t, "https://files.example.com/reset-password/")
	i := strings.Index(m, "/reset-password/")
	rt := strings.TrimSpace(strings.Split(m[i+len("/reset-password/"):], "\r\n")[0])
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": "bad", "password": "newpassword1"}), 400, "bad token")
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": rt, "password": "short"}), 400, "short")
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": rt, "password": "newpassword1"}), 200, "reset")
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": rt, "password": "newpassword2"}), 400, "token reuse")
	relogged := e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "newpassword1"})
	e.want(relogged, 200, "login after reset")
	tok = relogged.S("access_token")

	// registration + verification
	e.s.St.SetSetting("allow_self_registration", "false")
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "carl", "email": "carl@x.io", "password": "password123"}), 403, "reg disabled")
	e.s.St.SetSetting("allow_self_registration", "true")
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "carl", "email": "nope", "password": "password123"}), 400, "bad email")
	reg := e.do("POST", "/api/auth/register", "", map[string]any{"username": "carl", "email": "carl@x.io", "password": "password123"})
	e.want(reg, 201, "register")
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "carl", "email": "c2@x.io", "password": "password123"}), 400, "dup username")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "carl", "password": "password123"}), 403, "login unverified")
	m = sink.wait(t, "verification code is")
	code := strings.TrimSpace(strings.Split(m[strings.Index(m, "code is ")+8:], "\r\n")[0])
	e.want(e.do("POST", "/api/auth/verify-email", "", map[string]any{"email": "carl@x.io", "code": "000000"}), 400, "wrong code")
	v := e.do("POST", "/api/auth/verify-email", "", map[string]any{"email": "carl@x.io", "code": code})
	e.want(v, 200, "verify")
	e.want(e.do("GET", "/api/users/me", v.S("access_token"), nil), 200, "carl me")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "carl", "password": "password123"}), 200, "login verified")
	// public registration cannot bypass ownership verification through legacy settings
	e.s.St.SetSetting("require_email_verification", "false")
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "dina", "email": "d@x.io", "password": "password123"}), 201, "registration still verifies")

	// share created + invite mails, header injection safe
	r := e.share(tok, map[string]string{"a.txt": "1"}, map[string]any{"name": "N", "recipients": []string{"r1@x.io", "bad address"}, "message": "yo"})
	e.want(r, 201, "share w/ recipients")
	m = sink.wait(t, "r1@x.io")
	if !strings.Contains(m, "https://files.example.com/share/"+r.S("long_id")) || !strings.Contains(m, "yo") {
		t.Fatalf("share mail: %s", m)
	}
	e.want(e.do("POST", "/api/reverse-shares/invite", tok, map[string]any{"name": "G\r\nBcc: evil@x.io", "email": "g@x.io"}), 201, "invite")
	m = sink.wait(t, "g@x.io")
	if strings.Contains(strings.SplitN(m, "\r\n\r\n", 2)[0], "Bcc:") {
		t.Fatal("header injection")
	}
	// download notification to owner on first download
	e.want(e.do("GET", "/api/shares/"+r.S("long_id")+"/download", "", nil), 200, "dl")
	sink.wait(t, "started.")
}

func TestSMTPNotConfigured(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	r := e.do("POST", "/api/email-templates/test", tok, nil)
	e.want(r, 400, "no smtp")
}

func TestProviders(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	e.want(e.do("POST", "/api/auth-providers", tok, map[string]any{"name": "x", "type": "oidc", "client_id": "c"}), 400, "no issuer")
	e.want(e.do("POST", "/api/auth-providers", tok, map[string]any{"name": "x", "type": "weird", "client_id": "c"}), 400, "bad type")
	r := e.do("POST", "/api/auth-providers", tok, map[string]any{"name": "GH", "type": "github", "client_id": "c", "client_secret": "sec", "enabled": true, "allow_registration": true})
	e.want(r, 201, "create")
	uuid := r.S("uuid")
	pub := e.do("GET", "/api/auth/providers", "", nil)
	if strings.Contains(string(pub.Body), "sec") || !strings.Contains(string(pub.Body), "GH") {
		t.Fatal("public providers", string(pub.Body))
	}
	adm := e.do("GET", "/api/auth-providers", tok, nil)
	if strings.Contains(string(adm.Body), `"client_secret":"sec"`) || !strings.Contains(string(adm.Body), `"client_secret_set":true`) {
		t.Fatal("secret leaked/unset flag", string(adm.Body))
	}
	if !strings.Contains(string(adm.Body), "/api/auth/oidc/"+uuid+"/callback") {
		t.Fatal("callback url")
	}
	// start redirects to github with state cookie
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, _ := cl.Get(e.ts.URL + "/api/auth/oidc/" + uuid + "/start")
	if res.StatusCode != 302 || !strings.Contains(res.Header.Get("Location"), "github.com/login/oauth/authorize") {
		t.Fatal("start", res.StatusCode, res.Header.Get("Location"))
	}
	// callback without matching state is refused
	res, _ = cl.Get(e.ts.URL + "/api/auth/oidc/" + uuid + "/callback?state=x&code=y")
	if !strings.Contains(res.Header.Get("Location"), "auth_error") {
		t.Fatal("callback must fail", res.Header.Get("Location"))
	}
	// disabled provider hidden & unusable
	pid := 1
	e.want(e.do("PUT", fmt.Sprintf("/api/auth-providers/%d", pid), tok, map[string]any{"name": "GH", "type": "github", "client_id": "c", "enabled": false}), 200, "disable")
	if strings.Contains(string(e.do("GET", "/api/auth/providers", "", nil).Body), "GH") {
		t.Fatal("disabled shown")
	}
	// empty secret in update keeps old
	var s string
	e.s.St.DB.QueryRow(`SELECT client_secret FROM auth_providers WHERE id=1`).Scan(&s)
	if s != "sec" {
		t.Fatal("secret overwritten")
	}
	// external user resolution
	p, _ := e.s.providerByUUID(uuid)
	p.AllowRegistration, p.TrustEmail = true, true
	u1, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "42", Email: "admin@x.io", EmailVerified: true, Username: "ghadmin"})
	if u1 != nil {
		t.Fatal("email alone must not link to existing admin", u1)
	}
	u2, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "43", Email: "admin@x.io", EmailVerified: false, Username: "admin"})
	if u2 == nil || u2.Username == "admin" || u2.Admin {
		t.Fatal("unverified email must not take over account", u2)
	}
	u3, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "43", Username: "ignored"})
	if u3.ID != u2.ID {
		t.Fatal("same sub must map to same user")
	}
	p.AllowRegistration = false
	if u, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "99", Username: "new"}); u != nil {
		t.Fatal("registration disabled")
	}
	// unlink guard: oauth-only user can't unlink only login method
	tk2 := e.s.accessToken(u2)
	e.want(e.do("DELETE", "/api/users/me/providers/1", tk2, nil), 400, "unlink only method")
	e.want(e.do("DELETE", "/api/users/me/providers/1", tok, nil), 200, "admin unlink")
}

func TestJobsAndStats(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	sink := newSMTP(t)
	e.useSMTP(sink)
	r := e.share(tok, map[string]string{"a": "1"}, map[string]any{"expires_in_days": 1, "name": "soon"})
	e.want(r, 201, "share")
	e.s.BaseURL = "https://files.example.test" // expiry links need a public URL
	e.s.maintain()
	sink.wait(t, "expires on")
	// expired share files deleted after retention
	e.s.St.DB.Exec(`UPDATE shares SET expires_at=?`, time.Now().Add(-30*24*time.Hour))
	e.s.maintain()
	e.want(e.do("GET", "/api/shares/"+r.S("long_id"), "", nil), 404, "cleaned")
	st := e.do("GET", "/api/stats", tok, nil)
	e.want(st, 200, "stats")
	// stale upload sessions removed
	up := e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "a", "full_path": "a", "size": 5}}})
	e.s.St.DB.Exec(`UPDATE upload_sessions SET created_at=?`, time.Now().Add(-48*time.Hour))
	e.s.maintain()
	e.want(e.do("GET", "/api/uploads/"+up.S("id"), tok, nil), 404, "stale cleaned")
}

func TestSPAAndMisc(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/share/abc", "", nil)
	e.want(r, 200, "spa fallback")
	if !strings.Contains(string(r.Body), "spa") {
		t.Fatal("spa body")
	}
	e.want(e.do("GET", "/api/nope", "", nil), 404, "api 404")
	e.want(e.do("GET", "/", "", nil), 200, "index")
	e.want(e.do("GET", "/api/health", "", nil), 200, "health")
	// huge JSON body rejected
	big := bytes.Repeat([]byte("a"), 2<<20)
	e.want(e.do("POST", "/api/auth/login", "", append([]byte(`{"username":"`), big...)), 400, "big body")
}

func TestSecurityRegressions(t *testing.T) {
	t.Run("bcrypt byte limit", func(t *testing.T) {
		e := newEnv(t)
		long := strings.Repeat("a", 73)
		e.want(e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "admin", "password": long}), 400, "long setup password")
		tok := e.setup()
		e.want(e.do("POST", "/api/users", tok, map[string]any{"username": "bad", "password": long}), 400, "long account password")
		e.want(e.do("PUT", "/api/users/me", tok, map[string]any{"password": long}), 400, "long profile password")
		r := e.share(tok, map[string]string{"a": "data"}, map[string]any{"password": long})
		e.want(r, 400, "long share password")
		var n int
		e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM shares`).Scan(&n)
		if n != 0 {
			t.Fatal("unprotected share created")
		}
	})
	t.Run("atomic setup", func(t *testing.T) {
		e := newEnv(t)
		var wg sync.WaitGroup
		codes := make(chan int, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				codes <- e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": fmt.Sprintf("admin%d", i), "password": "password123"}).Code
			}(i)
		}
		wg.Wait()
		close(codes)
		n := 0
		for code := range codes {
			if code == 200 {
				n++
			} else if code != 403 {
				t.Fatalf("unexpected setup response %d", code)
			}
		}
		if n != 1 {
			t.Fatalf("%d admins created", n)
		}
	})
	t.Run("atomic refresh", func(t *testing.T) {
		e := newEnv(t)
		e.setup()
		r := e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"})
		cookie := r.Hdr.Get("Set-Cookie")
		cookie = strings.Split(cookie, ";")[0]
		var wg sync.WaitGroup
		codes := make(chan int, 12)
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); codes <- e.do("POST", "/api/auth/refresh", "", nil, "Cookie", cookie).Code }()
		}
		wg.Wait()
		close(codes)
		n := 0
		for code := range codes {
			if code == 200 {
				n++
			} else if code != 401 {
				t.Fatalf("unexpected refresh response %d", code)
			}
		}
		if n != 1 {
			t.Fatalf("refresh token reused %d times", n)
		}
	})
	t.Run("canonical email origin", func(t *testing.T) {
		e := newEnv(t)
		e.setup()
		r := httptest.NewRequest("POST", "http://attacker.example/api/auth/forgot-password", strings.NewReader(`{"email":"admin@x.io"}`))
		r.Header.Set("X-Forwarded-Proto", "https")
		e.s.forgotPassword(httptest.NewRecorder(), r)
		var n int
		e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM password_resets`).Scan(&n)
		if n != 0 {
			t.Fatal("reset token generated using attacker Host")
		}
		for _, base := range []string{"https://files.example", "http://localhost:8080"} {
			e.s.BaseURL = base
			if got, ok := e.s.emailBaseURL(r); !ok || got != base {
				t.Fatalf("valid origin refused %s", base)
			}
		}
		for _, base := range []string{"http://files.example", "https://user@files.example", "javascript:alert(1)", "https://files.example?next=x"} {
			e.s.BaseURL = base
			if _, ok := e.s.emailBaseURL(r); ok {
				t.Fatalf("unsafe origin accepted %s", base)
			}
		}
	})
	t.Run("verification attempt budget survives resend and restart", func(t *testing.T) {
		e := newEnv(t)
		e.useSMTP(newSMTP(t))
		e.setup()
		e.s.St.SetSetting("allow_self_registration", "true")
		e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "new", "email": "new@x.io", "password": "password123"}), 201, "register")
		e.s.St.DB.Exec(`UPDATE email_verifications SET code='123456'`)
		for i := 0; i < 5; i++ {
			e.want(e.do("POST", "/api/auth/verify-email", "", map[string]any{"email": "new@x.io", "code": "000000"}), 400, "wrong verification")
		}
		e.want(e.do("POST", "/api/auth/resend-verification", "", map[string]any{"email": "new@x.io"}), 200, "resend")
		e.s.St.DB.Exec(`UPDATE email_verifications SET code='123456'`)
		e.want(e.do("POST", "/api/auth/verify-email", "", map[string]any{"email": "new@x.io", "code": "123456"}), 429, "blocked after resend")
		other := New(e.s.St, e.s.Static, "test")
		w := httptest.NewRecorder()
		other.verifyEmail(w, httptest.NewRequest("POST", "/api/auth/verify-email", strings.NewReader(`{"email":"new@x.io","code":"123456"}`)))
		if w.Code != 429 {
			t.Fatalf("budget lost across restart %d", w.Code)
		}
		e.s.St.DB.Exec(`UPDATE verification_attempts SET expires_at=?`, time.Now().Add(-time.Second))
		e.want(e.do("POST", "/api/auth/verify-email", "", map[string]any{"email": "new@x.io", "code": "123456"}), 200, "verification after cooldown")
	})
	t.Run("Range consumes limit and maintenance reactivation", func(t *testing.T) {
		e := newEnv(t)
		tok := e.setup()
		r := e.share(tok, map[string]string{"a": "data"}, map[string]any{"download_limit": 1})
		lid := r.S("long_id")
		e.want(e.do("GET", "/api/shares/"+lid+"/download/a", "", nil, "Range", "bytes=0-"), 206, "range download")
		e.want(e.do("GET", "/api/shares/"+lid+"/download/a", "", nil, "Range", "bytes=0-"), 410, "range cannot bypass limit")
		e.s.maintain()
		e.want(e.do("POST", "/api/shares/"+r.S("id")+"/download-limit", tok, map[string]any{"limit": 3}), 200, "raise maintained limit")
		e.want(e.do("GET", "/api/shares/"+lid, "", nil), 200, "revived")
		e.want(e.do("POST", "/api/shares/"+r.S("id")+"/expire", tok, nil), 200, "manual expiry")
		e.want(e.do("POST", "/api/shares/"+r.S("id")+"/download-limit", tok, map[string]any{"limit": 5}), 200, "raise manually expired limit")
		e.want(e.do("GET", "/api/shares/"+lid, "", nil), 410, "manual expiry preserved")
	})
}

func TestUploadMutationRegressions(t *testing.T) {
	t.Run("concurrent chunks", func(t *testing.T) {
		e := newEnv(t)
		tok := e.setup()
		r := e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "a", "size": 10}}})
		p := "/api/uploads/" + r.S("id") + "/files/0"
		var wg sync.WaitGroup
		codes := make(chan int, 2)
		for _, data := range []string{"AAAAA", "BBBBB"} {
			wg.Add(1)
			go func(data string) {
				defer wg.Done()
				codes <- e.do("PATCH", p, tok, []byte(data), "Upload-Offset", "0").Code
			}(data)
		}
		wg.Wait()
		close(codes)
		ok, conflict := 0, 0
		for code := range codes {
			if code == 200 {
				ok++
			}
			if code == 409 {
				conflict++
			}
		}
		if ok != 1 || conflict != 1 {
			t.Fatalf("responses success=%d conflict=%d", ok, conflict)
		}
	})
	t.Run("completion failure keeps original parts", func(t *testing.T) {
		e := newEnv(t)
		tok := e.setup()
		r := e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "a", "size": 1}, {"name": "b", "size": 1}}})
		id := r.S("id")
		for i := 0; i < 2; i++ {
			e.want(e.do("PATCH", fmt.Sprintf("/api/uploads/%s/files/%d", id, i), tok, []byte("x"), "Upload-Offset", "0"), 200, "chunk")
		}
		second := filepath.Join(e.s.uploadDir(id), "1.part")
		if err := os.Remove(second); err != nil {
			t.Fatal(err)
		}
		e.want(e.do("POST", "/api/uploads/"+id+"/complete", tok, map[string]any{}), 500, "missing part")
		if data, err := os.ReadFile(filepath.Join(e.s.uploadDir(id), "0.part")); err != nil || string(data) != "x" {
			t.Fatalf("original lost %q %v", data, err)
		}
		if err := os.WriteFile(second, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := e.s.St.DB.Exec(`CREATE TRIGGER fail_file BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
			t.Fatal(err)
		}
		e.want(e.do("POST", "/api/uploads/"+id+"/complete", tok, map[string]any{}), 500, "metadata insert failure")
		e.s.St.DB.Exec(`DROP TRIGGER fail_file`)
		var n int
		e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM shares`).Scan(&n)
		if n != 0 {
			t.Fatal("failed completion left share")
		}
		e.want(e.do("POST", "/api/uploads/"+id+"/complete", tok, map[string]any{}), 201, "retry succeeds")
	})
}

func TestConcurrentDownloadsLimit(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	r := e.share(tok, map[string]string{"a": "1"}, map[string]any{"download_limit": 3})
	lid := r.S("long_id")
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.do("GET", "/api/shares/"+lid+"/download", "", nil).Code == 200 {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 3 {
		t.Fatalf("download limit 3 but %d succeeded", ok)
	}
}

// legacyTestDefaults restores the pre-0.1.5 defaults (short minimum passwords, MFA
// off) so that the many tests that sign in with short passwords keep exercising
// their own behaviour. The new defaults have their own tests (defaults_test.go).
// Password maximum age and history are off as well, so tests that change a
// password back to "password123" keep working (password_rotation_test.go tests them).
func legacyTestDefaults(t *testing.T, st *store.Store) {
	t.Helper()
	for k, v := range map[string]string{"account_password_min_length": "8", "share_password_min_length": "8", "mfa_policy": "off",
		"account_password_max_age_days": "0", "account_password_history": "0"} {
		if err := st.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
}
