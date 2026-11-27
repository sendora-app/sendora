// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sendora-app/sendora/internal/store"
)

func logCapture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// ---------- A: verified download resource limits ----------

func TestVerifiedDownloadRefusedWithoutFreeSpace(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{"a.txt": "abc"}, nil)
	e.want(created, 201, "share")
	url := "/api/shares/" + created.S("long_id") + "/download"
	var asked string
	old := freeSpaceFn
	freeSpaceFn = func(dir string) (uint64, error) { asked = dir; return snapshotSpaceMargin, nil } // < size+margin
	r := e.do("GET", url, "", nil)
	freeSpaceFn = old
	e.want(r, http.StatusInsufficientStorage, "no space")
	if asked != e.s.St.DataDir || len(integritySlots) != 0 {
		t.Fatal("space check must use the data dir and release the slot", asked, len(integritySlots))
	}
	if left, _ := filepath.Glob(filepath.Join(e.s.St.DataDir, ".verified-download-*")); len(left) != 0 {
		t.Fatal("no temp file may be created", left)
	}
	var count int
	qByName(e.s.St, `SELECT download_count FROM shares WHERE long_id=?`, created.S("long_id")).Scan(&count)
	if count != 0 {
		t.Fatal("refused download consumed a count")
	}
	// Enough room: works again.
	freeSpaceFn = func(string) (uint64, error) { return snapshotSpaceMargin + 3, nil }
	defer func() { freeSpaceFn = old }()
	e.want(e.do("GET", url, "", nil), 200, "enough space")
}

func TestSnapshotSlotCapAndRelease(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{"a": "abc"}, nil)
	files := e.s.shareFiles(e.sid(created))
	var outs []*os.File
	for i := 0; i < cap(integritySlots); i++ {
		out, _, err := e.s.prepareDownload(context.Background(), files)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	if _, _, err := e.s.prepareDownload(ctx, files); err == nil {
		t.Fatal("slot cap not enforced")
	}
	cancel()
	for _, o := range outs {
		o.Close()
		os.Remove(o.Name())
		<-integritySlots
	}
	if len(integritySlots) != 0 {
		t.Fatal("slots not released")
	}
}

func TestSlotHeldAtMostSlotHoldMax(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{"a": "abc"}, nil)
	files := e.s.shareFiles(e.sid(created))
	old := slotHoldMax
	slotHoldMax = 150 * time.Millisecond
	defer func() { slotHoldMax = old }()
	f, _, release, err := e.s.prepareClientDownload(context.Background(), "203.0.113.50", e.sid(created), files)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if _, err := f.Read(make([]byte, 1)); err == nil || err == io.EOF {
		t.Fatal("snapshot must be closed after the hold limit, got", err)
	}
	release()
	if len(integritySlots) != 0 || downloadClients["203.0.113.50"] != 0 || downloadShares[e.sid(created)] != 0 {
		t.Fatal("release must free every slot")
	}
	if left, _ := filepath.Glob(filepath.Join(e.s.St.DataDir, ".verified-download-*")); len(left) != 0 {
		t.Fatal("snapshot leaked", left)
	}
}

func TestPerShareSnapshotCap(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{"a": "abc"}, nil)
	sid := e.sid(created)
	files := e.s.shareFiles(sid)
	var rel []func()
	for i := 0; i < downloadSlotsPerShare; i++ {
		_, _, r, err := e.s.prepareClientDownload(context.Background(), fmt.Sprintf("198.51.100.%d", i+1), sid, files)
		if err != nil {
			t.Fatal(err)
		}
		rel = append(rel, r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	_, _, _, err := e.s.prepareClientDownload(ctx, "198.51.100.99", sid, files)
	cancel()
	if err != errDownloadBusy {
		t.Fatal("per-share cap not enforced:", err)
	}
	if len(integritySlots) != downloadSlotsPerShare || downloadClients["198.51.100.99"] != 0 {
		t.Fatal("a refused request must not hold anything")
	}
	rel[0]()
	_, _, r, err := e.s.prepareClientDownload(context.Background(), "198.51.100.99", sid, files)
	if err != nil {
		t.Fatal("slot not reusable after release:", err)
	}
	r()
	rel[1]()
	if len(integritySlots) != 0 || downloadShares[sid] != 0 {
		t.Fatal("leak")
	}
}

func TestInvalidRangeDoesNotTakeASlot(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{"a.txt": "abc"}, nil)
	for i := 0; i < cap(integritySlots); i++ {
		integritySlots <- struct{}{}
	}
	defer func() {
		for len(integritySlots) > 0 {
			<-integritySlots
		}
	}()
	url := "/api/shares/" + created.S("long_id") + "/download"
	start := time.Now()
	for _, rng := range []string{"bytes=100-", "bytes=5-2", "items=0-1", "bytes=abc"} {
		req, _ := http.NewRequest("GET", e.ts.URL+url, nil)
		req.Header.Set("Range", rng)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusRequestedRangeNotSatisfiable {
			t.Fatalf("range %q: want 416 got %d", rng, res.StatusCode)
		}
		if rng == "bytes=100-" && res.Header.Get("Content-Range") != "bytes */3" {
			t.Fatal("missing Content-Range")
		}
	}
	// 4 plain GETs would each wait for a slot (5 s) and fail with 503.
	if time.Since(start) > 3*time.Second {
		t.Fatal("range rejection waited for a slot")
	}
}

func TestRangeNeverSatisfiable(t *testing.T) {
	for _, c := range []struct {
		rng     string
		size    int64
		invalid bool
	}{
		{"", 10, false}, {"bytes=0-3", 10, false}, {"bytes=9-", 10, false}, {"bytes=10-", 10, true},
		{"bytes=-5", 10, false}, {"bytes=-0", 10, true}, {"bytes=10-20,2-3", 10, false}, {"bytes=4-2", 10, true},
		{"bytes=100-", -1, false}, {"bytes=x-", -1, true}, {"foo=1-2", -1, true},
	} {
		r, _ := http.NewRequest("GET", "/", nil)
		if c.rng != "" {
			r.Header.Set("Range", c.rng)
		}
		if got := rangeNeverSatisfiable(r, c.size); got != c.invalid {
			t.Errorf("%q size %d: got %v want %v", c.rng, c.size, got, c.invalid)
		}
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Range", "bytes=50-")
	r.Header.Set("If-Range", `"etag"`)
	if rangeNeverSatisfiable(r, 3) {
		t.Error("If-Range makes the server ignore the range")
	}
}

// ---------- B: chunk try-lock ----------

func TestChunkBusyReturns409WhileAnotherChunkIsInFlight(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	mk := func(size int) string {
		r := e.do("POST", "/api/uploads", token, map[string]any{"files": []map[string]any{{"name": "f.bin", "size": size}}})
		e.want(r, 201, "create")
		return r.S("id")
	}
	id, other := mk(4), mk(2)
	pr, pw := io.Pipe()
	done := make(chan resp, 1)
	go func() { done <- e.do("PATCH", "/api/uploads/"+id+"/files/0", token, pr, "Upload-Offset", "0") }()
	pw.Write([]byte("ab"))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, busy := chunkBusy.Load(id); busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first chunk never became in flight")
		}
		time.Sleep(10 * time.Millisecond)
	}
	r := e.do("PATCH", "/api/uploads/"+id+"/files/0", token, []byte("cd"), "Upload-Offset", "0")
	e.want(r, 409, "second chunk")
	if r.J()["busy"] != true || r.Hdr.Get("Retry-After") == "" || r.J()["received"] != float64(0) {
		t.Fatal("busy response needs busy flag, Retry-After and offset", string(r.Body))
	}
	// A different session is not blocked, even on the same stripe.
	e.want(e.do("PATCH", "/api/uploads/"+other+"/files/0", token, []byte("zz"), "Upload-Offset", "0"), 200, "other session")
	pw.Write([]byte("cd"))
	pw.Close()
	first := <-done
	e.want(first, 200, "first chunk completes")
	if first.J()["received"] != float64(4) {
		t.Fatal("offset after chunk", string(first.Body))
	}
	if _, busy := chunkBusy.Load(id); busy {
		t.Fatal("busy marker leaked")
	}
	e.want(e.do("POST", "/api/uploads/"+id+"/complete", token, map[string]any{}), 201, "complete")
}

func TestChunkAbortedWhileInFlight(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	r := e.do("POST", "/api/uploads", token, map[string]any{"files": []map[string]any{{"name": "f.bin", "size": 4}}})
	id := r.S("id")
	pr, pw := io.Pipe()
	done := make(chan resp, 1)
	go func() { done <- e.do("PATCH", "/api/uploads/"+id+"/files/0", token, pr, "Upload-Offset", "0") }()
	pw.Write([]byte("ab"))
	for i := 0; i < 500; i++ {
		if _, busy := chunkBusy.Load(id); busy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.want(e.do("DELETE", "/api/uploads/"+id, token, nil), 200, "abort")
	pw.Write([]byte("cd"))
	pw.Close()
	if got := <-done; got.Code != 404 {
		t.Fatalf("chunk of an aborted session must fail, got %d %s", got.Code, got.Body)
	}
	if _, err := os.Stat(e.s.uploadDir(id)); !os.IsNotExist(err) {
		t.Fatal("aborted session left files behind")
	}
}

// ---------- C: file name rules ----------

func TestNewUploadNameRules(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	create := func(name string) resp {
		return e.do("POST", "/api/uploads", token, map[string]any{"files": []map[string]any{{"name": filepath.Base(name), "full_path": name, "size": 1}}})
	}
	for _, bad := range []string{
		"photo\u202egpj.exe", "a\u2066b.txt", "a\u200eb.txt", "a\u2215b.txt", "dir\uff0ffile.txt", "a\uff3cb.txt", "ok/dir\u2215x/y.txt",
		strings.Repeat("a", 201) + ".txt",
		strings.Repeat("d", 100) + "/" + strings.Repeat("e", 201),
		strings.Repeat("x/", 520) + "f",
	} {
		if r := create(bad); r.Code != 400 {
			t.Errorf("%.40q must be refused at create, got %d", bad, r.Code)
		}
	}
	// The longest allowed name must also complete: the disk name adds a prefix.
	long := strings.Repeat("n", 196) + ".txt"
	r := create(long)
	e.want(r, 201, "longest name")
	id := r.S("id")
	e.want(e.do("PATCH", "/api/uploads/"+id+"/files/0", token, []byte("x"), "Upload-Offset", "0"), 200, "chunk")
	e.want(e.do("POST", "/api/uploads/"+id+"/complete", token, map[string]any{}), 201, "complete with the longest name")
	// Legitimate non-ASCII names stay possible.
	e.want(create("Überweisung/résumé 日本語.pdf"), 201, "unicode name")
}

func TestAppendRefusesFileFolderConflicts(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	sh := e.share(token, map[string]string{"a": "1", "d/x": "2"}, nil)
	e.want(sh, 201, "share")
	sid := e.sid(sh)
	for name, files := range map[string][]nf{
		"new folder under an existing file": {{"a/b", "x"}},
		"new file where a folder exists":    {{"d", "x"}},
		"conflict inside the new batch":     {{"n", "x"}, {"n/m", "y"}},
		"case-insensitive":                  {{"D", "x"}},
	} {
		r := e.appendFiles(token, sid, files)
		if r.Code != 409 {
			t.Errorf("%s: want 409 got %d %s", name, r.Code, r.Body)
		}
	}
	if got := len(e.listFiles(token, sid)); got != 2 {
		t.Fatal("a refused append must change nothing, files:", got)
	}
	e.want(e.appendFiles(token, sid, []nf{{"d/y", "ok"}, {"e/f", "ok"}}), 201, "valid append")
}

// ---------- D: share metadata before unlock ----------

func TestShareNameHiddenBeforeUnlockAndAfterExpiry(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	sh := e.share(token, map[string]string{"a.txt": "abc"}, map[string]any{"name": "Secret Salary 2026", "description": "private notes", "password": "longenough-pw1"})
	e.want(sh, 201, "share")
	lid := sh.S("long_id")
	locked := e.do("GET", "/api/shares/"+lid, "", nil)
	e.want(locked, 200, "locked")
	if strings.Contains(string(locked.Body), "Secret") || strings.Contains(string(locked.Body), "private") || locked.J()["password_protected"] != true {
		t.Fatal("locked share leaks metadata:", string(locked.Body))
	}
	unlock := e.do("POST", "/api/shares/"+lid+"/unlock", "", map[string]any{"password": "longenough-pw1"})
	e.want(unlock, 200, "unlock")
	open := e.do("GET", "/api/shares/"+lid, "", nil, "X-Share-Token", unlock.S("token"))
	e.want(open, 200, "unlocked")
	if open.S("name") != "Secret Salary 2026" {
		t.Fatal("unlocked share must show its name")
	}
	e.s.St.DB.Exec(`UPDATE shares SET expires_at=?`, time.Now().Add(-time.Hour))
	gone := e.do("GET", "/api/shares/"+lid, "", nil)
	e.want(gone, 410, "expired")
	if strings.Contains(string(gone.Body), "Secret") || gone.J()["name"] != nil {
		t.Fatal("expired response leaks the name:", string(gone.Body))
	}
}

// ---------- E: defaults for new installations ----------

func TestSecureDefaultsForFreshStoreKeepExistingValues(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"account_password_min_length": "8", "share_password_min_length": "8", "mfa_policy": "optional", "allow_preview": "true", "allow_self_registration": "false"}
	for k, v := range want {
		if got := st.Setting(k); got != v {
			t.Errorf("fresh default %s = %q, want %q", k, got, v)
		}
	}
	// An existing installation keeps what it has stored.
	for k, v := range map[string]string{"account_password_min_length": "12", "share_password_min_length": "10", "mfa_policy": "admins"} {
		if err := st.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	st.DB.Close()
	again, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.DB.Close()
	if again.Setting("account_password_min_length") != "12" || again.Setting("share_password_min_length") != "10" || again.Setting("mfa_policy") != "admins" {
		t.Fatal("upgrade must not change stored settings")
	}
}

func TestFreshInstallDoesNotForceMFA(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	s := New(st, fstest.MapFS{"index.html": {Data: []byte("spa")}}, "test")
	ts := httptest.NewServer(s.Router())
	defer ts.Close()
	e := &env{t: t, s: s, ts: ts}
	r := e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "admin", "password": "Quiet-Ferns9", "email": "a@x.io"})
	e.want(r, 200, "setup with a 12-character password (default minimum is 8; common passwords are refused)")
	me := e.do("GET", "/api/users/me", r.S("access_token"), nil)
	e.want(me, 200, "me")
	u, _ := me.J()["user"].(map[string]any)
	if u["mfa_enroll_required"] == true || u["mfa_required"] == true {
		t.Fatal("MFA must not be forced by default", string(me.Body))
	}
	if u["mfa_enabled"] == true {
		t.Fatal("a new account has no factor yet", string(me.Body))
	}
	// Enrolment stays available for anyone who wants it: the default policy is
	// "optional", not "off" (which would refuse enrolment and make the reminder useless).
	if st.Setting("mfa_policy") != "optional" {
		t.Fatalf("default mfa_policy = %q, want optional", st.Setting("mfa_policy"))
	}
	e.want(e.do("GET", "/api/users/me/mfa", r.S("access_token"), nil), 200, "mfa status reachable")
	_, tok, codes := e.enrollTOTP(r.S("access_token"), "Quiet-Ferns9")
	if len(codes) == 0 {
		t.Fatal("no recovery codes after voluntary enrolment")
	}
	// From now on this account signs in with a second step.
	login := e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "Quiet-Ferns9"})
	e.want(login, 200, "login")
	if login.J()["mfa_required"] != true {
		t.Fatalf("an enrolled factor must be required at sign-in: %s", login.Body)
	}
	_ = tok
}

func TestPreviewOnlyForAllowlistedTypes(t *testing.T) {
	for _, ext := range []string{".svg", ".html", ".htm", ".pdf", ".js", ".xml", ".xhtml", ".txt"} {
		if _, ok := previewTypes[ext]; ok {
			t.Errorf("%s must never be previewable", ext)
		}
	}
}

// ---------- F: startup configuration ----------

func writeSecret(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("super-secret-value-that-is-long-enough"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckSecretFilesRefusesOpenFiles(t *testing.T) {
	for _, name := range []string{"JWT_SECRET_FILE", "SENDORA_SMTP_PASS_FILE", "SENDORA_SMTP_PASSWORD_FILE", "SENDORA_PROVIDER_ENTRA_CLIENT_SECRET_FILE"} {
		for _, mode := range []os.FileMode{0o644, 0o666, 0o620, 0o604} {
			t.Setenv(name, writeSecret(t, mode))
			err := CheckSecretFiles()
			if err == nil || !strings.Contains(err.Error(), name) || strings.Contains(err.Error(), "super-secret") {
				t.Errorf("%s mode %o: want a refusal naming the variable, got %v", name, mode, err)
			}
		}
		for _, mode := range []os.FileMode{0o400, 0o600, 0o440} {
			t.Setenv(name, writeSecret(t, mode))
			if err := CheckSecretFiles(); err != nil {
				t.Errorf("%s mode %o must be accepted: %v", name, mode, err)
			}
		}
		t.Setenv(name, "")
	}
	t.Setenv("JWT_SECRET_FILE", filepath.Join(t.TempDir(), "missing"))
	if CheckSecretFiles() == nil {
		t.Error("a missing file is an error")
	}
}

func TestWarnPlainSecretsNeverLogsTheValue(t *testing.T) {
	buf := logCapture(t)
	t.Setenv("JWT_SECRET", "plain-env-secret-value-0123456789abcdef")
	t.Setenv("SENDORA_SMTP_PASS", "smtp-plain-value")
	t.Setenv("SENDORA_PROVIDER_X_CLIENT_SECRET", "client-plain-value")
	t.Setenv("SENDORA_PROVIDER_Y_CLIENT_SECRET_FILE", writeSecret(t, 0o600))
	WarnPlainSecrets()
	out := buf.String()
	for _, name := range []string{"JWT_SECRET", "SENDORA_SMTP_PASS", "SENDORA_PROVIDER_X_CLIENT_SECRET"} {
		if !strings.Contains(out, "WARNING: "+name+" is set as a plain environment variable") {
			t.Errorf("missing warning for %s:\n%s", name, out)
		}
	}
	if strings.Contains(out, "plain-env-secret") || strings.Contains(out, "smtp-plain") || strings.Contains(out, "client-plain") {
		t.Fatal("a secret value was logged")
	}
	if strings.Contains(out, "PROVIDER_Y") {
		t.Fatal("a secret coming from a file must not warn")
	}
}

func TestWarnSecurityConfig(t *testing.T) {
	e := newEnv(t)
	e.setup()
	buf := logCapture(t)
	t.Setenv("HOST", "0.0.0.0")
	for k, v := range map[string]string{"allow_self_registration": "true", "require_email_verification": "false", "registration_email_domains": "", "smtp_host": "", "mfa_policy": "off", "account_password_min_length": "8", "share_password_min_length": "6", "application_url": ""} {
		e.s.St.SetSetting(k, v)
	}
	e.s.warnSecurityConfig()
	out := buf.String()
	for _, frag := range []string{
		"HOST=0.0.0.0 is not a loopback address but the application URL is empty",
		"self-registration is on without a domain allowlist",
		"self-registration is on without email verification",
		"self-registration is on but no SMTP host",
	} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing warning %q in:\n%s", frag, out)
		}
	}
	// Quiet when everything is fine.
	buf.Reset()
	t.Setenv("HOST", "127.0.0.1")
	for k, v := range map[string]string{"allow_self_registration": "false", "mfa_policy": "admins", "account_password_min_length": "12", "share_password_min_length": "10"} {
		e.s.St.SetSetting(k, v)
	}
	e.s.warnSecurityConfig()
	if buf.Len() != 0 {
		t.Fatal("unexpected warnings:", buf.String())
	}
	// Non-loopback with plain http is flagged, https is not.
	t.Setenv("HOST", "10.0.0.5")
	e.s.St.SetSetting("application_url", "http://files.example.com")
	e.s.warnSecurityConfig()
	if !strings.Contains(buf.String(), "application URL is not https") {
		t.Fatal("http URL must warn:", buf.String())
	}
	buf.Reset()
	e.s.St.SetSetting("application_url", "https://files.example.com")
	e.s.warnSecurityConfig()
	if buf.Len() != 0 {
		t.Fatal("https URL must not warn:", buf.String())
	}
}

func TestForwardedForWarningOnce(t *testing.T) {
	e := newEnv(t)
	buf := logCapture(t)
	warnForwardedOnce = sync.Once{}
	for i := 0; i < 3; i++ {
		e.do("POST", "/api/auth/login", "", map[string]any{"username": "nobody", "password": "x"}, "X-Forwarded-For", "198.51.100.7")
	}
	if n := strings.Count(buf.String(), "X-Forwarded-For received while SENDORA_TRUSTED_PROXIES is empty"); n != 1 {
		t.Fatalf("want exactly one warning, got %d: %s", n, buf.String())
	}
	// A request without the header never warns; with trusted proxies configured neither.
	warnForwardedOnce = sync.Once{}
	buf.Reset()
	e.do("POST", "/api/auth/login", "", map[string]any{"username": "nobody", "password": "x"})
	if strings.Contains(buf.String(), "X-Forwarded-For") {
		t.Fatal("no header, no warning")
	}
}

func TestDisableCoreDumpsIsSafe(t *testing.T) {
	if err := DisableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	if err := DisableCoreDumps(); err != nil { // idempotent
		t.Fatal(err)
	}
}
