// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/ports"
)

func keyJobDone(t *testing.T, e *env, tok string, id float64) map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		r := e.do("GET", "/api/admin/keys", tok, nil)
		e.want(r, 200, "key status")
		for _, j := range r.J()["jobs"].([]any) {
			m := j.(map[string]any)
			if m["id"] == id && (m["status"] == "done" || m["status"] == "failed") {
				return m
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("key job %v did not finish", id)
	return nil
}

func keyPurpose(t *testing.T, r resp, purpose string) map[string]any {
	t.Helper()
	for _, p := range r.J()["purposes"].([]any) {
		if m := p.(map[string]any); m["purpose"] == purpose {
			return m
		}
	}
	t.Fatalf("purpose %s missing in %s", purpose, r.Body)
	return nil
}

func TestTenantKeyRotationAPI(t *testing.T) {
	e := newEncryptedEnv(t)
	tok := e.setup()
	user := e.mkUser(tok, "plain", false)
	ctx := t.Context()
	e.s.RunKeyJobs(ctx)

	// Needs an administrator and a fresh re-authentication.
	e.want(e.do("GET", "/api/admin/keys", user, nil), 403, "status for a non-admin")
	e.want(e.do("POST", "/api/admin/keys/rotate", user, map[string]any{"purpose": "data"}), 403, "rotate by a non-admin")
	e.want(e.do("POST", "/api/admin/keys/retire", user, map[string]any{"purpose": "data", "version": 1}), 403, "retire by a non-admin")
	e.want(e.do("GET", "/api/admin/keys", "", nil), 401, "status without a token")
	stale := staleAdmin(t, e, "admin")
	for _, c := range []struct{ p string }{{"/api/admin/keys/rotate"}, {"/api/admin/keys/retire"}} {
		r := e.do("POST", c.p, stale, map[string]any{"purpose": "data", "version": 1})
		if r.Code != 401 || r.S("code") != stepUpCode {
			t.Fatalf("%s without step-up: %d %s", c.p, r.Code, r.Body)
		}
	}
	if n := countAudit(t, e, "key_rotation_requested"); n != 0 {
		t.Fatalf("a refused request left %d audit records", n)
	}

	// Status: versions, states, fingerprints, never key material.
	r := e.do("GET", "/api/admin/keys", tok, nil)
	e.want(r, 200, "status")
	data := keyPurpose(t, r, "data")
	v1 := data["versions"].([]any)[0].(map[string]any)
	if data["active"] != float64(1) || v1["state"] != "active" || len(fmt.Sprint(v1["fingerprint"])) < 16 || v1["rows"].(float64) == 0 {
		t.Fatalf("data status = %v", data)
	}
	if strings.Contains(string(r.Body), "dek") || strings.Contains(string(r.Body), "wrapped") {
		t.Fatalf("the status looks like it carries key material: %s", r.Body)
	}
	e.want(e.do("POST", "/api/admin/keys/rotate", tok, map[string]any{"purpose": "audit-mac"}), 400, "audit-mac is not rotatable here")
	e.want(e.do("POST", "/api/admin/keys/retire", tok, map[string]any{"purpose": "data", "version": 1}), 409, "the active version cannot be retired")

	// Rotate the data key: accepted, runs in the background, ends with every
	// value on version 2; the audit log's text is under audit-enc, not data.
	r = e.do("POST", "/api/admin/keys/rotate", tok, map[string]any{"purpose": "data"})
	e.want(r, 202, "rotate data")
	job := keyJobDone(t, e, tok, r.J()["job_id"].(float64))
	if job["status"] != "done" || job["version"] != float64(2) {
		t.Fatalf("job = %v", job)
	}
	r = e.do("GET", "/api/admin/keys", tok, nil)
	data = keyPurpose(t, r, "data")
	vs := data["versions"].([]any)
	old, cur := vs[0].(map[string]any), vs[1].(map[string]any)
	if data["active"] != float64(2) || old["state"] != "decrypt_only" || old["rows"] != float64(0) || cur["state"] != "active" || cur["rows"].(float64) == 0 {
		t.Fatalf("after the rotation: %v", data)
	}
	if old["audit_rows"].(float64) != 0 || cur["audit_rows"].(float64) != 0 {
		t.Fatalf("audit rows are counted against audit-enc, not data: %v", data)
	}
	auditEnc := keyPurpose(t, r, "audit-enc")["versions"].([]any)[0].(map[string]any)
	if auditEnc["audit_rows"].(float64) == 0 || auditEnc["rows"].(float64) != 0 {
		t.Fatalf("the audit log should hold audit-enc version 1 values: %v", auditEnc)
	}
	if v, ok := colenc.TextVersion(rawSetting(t, e, "jwt_secret")); !ok || v != 2 {
		t.Fatalf("a setting is on version %d (%v), want 2", v, ok)
	}
	// The audit log records the request and the outcome (written by the new key).
	// Every attempt is recorded before it runs (an "attempted" and a final record).
	if countAudit(t, e, "key_rotation_requested") < 2 || countAudit(t, e, "key_job_started") != 1 || countAudit(t, e, "key_rotation_completed") != 1 {
		t.Fatalf("audit: requested %d, started %d, completed %d", countAudit(t, e, "key_rotation_requested"), countAudit(t, e, "key_job_started"), countAudit(t, e, "key_rotation_completed"))
	}
	// The old data version is retirable although audit records exist.
	r = e.do("POST", "/api/admin/keys/retire", tok, map[string]any{"purpose": "data", "version": 1})
	e.want(r, 202, "retire data v1 while audit rows exist")
	if j := keyJobDone(t, e, tok, r.J()["job_id"].(float64)); j["status"] != "done" {
		t.Fatalf("data retire job = %v", j)
	}
	// An audit-enc version stays needed while audit records use it, also after a rotation.
	r = e.do("POST", "/api/admin/keys/rotate", tok, map[string]any{"purpose": "audit-enc"})
	e.want(r, 202, "rotate audit-enc")
	if j := keyJobDone(t, e, tok, r.J()["job_id"].(float64)); j["status"] != "done" || j["version"] != float64(2) {
		t.Fatalf("audit-enc job = %v", j)
	}
	r = e.do("POST", "/api/admin/keys/retire", tok, map[string]any{"purpose": "audit-enc", "version": 1})
	e.want(r, 409, "retire audit-enc v1 while the audit log uses it")
	if !strings.Contains(r.S("error"), "audit") {
		t.Fatalf("the refusal does not explain itself: %s", r.Body)
	}
	// The application keeps working: the admin still signs in and the lookups work.
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"}), 200, "login after the rotation")

	// The index key: rotate, then retire the old version (no data uses it).
	r = e.do("POST", "/api/admin/keys/rotate", tok, map[string]any{"purpose": "index"})
	e.want(r, 202, "rotate index")
	if j := keyJobDone(t, e, tok, r.J()["job_id"].(float64)); j["status"] != "done" {
		t.Fatalf("index job = %v", j)
	}
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "plain", "password": "password123"}), 200, "login by the rebuilt index")
	r = e.do("POST", "/api/admin/keys/retire", tok, map[string]any{"purpose": "index", "version": 1})
	e.want(r, 202, "retire the old index version")
	if j := keyJobDone(t, e, tok, r.J()["job_id"].(float64)); j["status"] != "done" {
		t.Fatalf("retire job = %v", j)
	}
	idx := keyPurpose(t, e.do("GET", "/api/admin/keys", tok, nil), "index")
	if idx["versions"].([]any)[0].(map[string]any)["state"] != "retired" {
		t.Fatalf("index = %v", idx)
	}
	if countAudit(t, e, "key_retired") != 2 || countAudit(t, e, "key_retire_requested") < 3 {
		t.Fatalf("key_retired records: %d", countAudit(t, e, "key_retired"))
	}
}

func rawSetting(t *testing.T, e *env, key string) string {
	t.Helper()
	var v string
	if err := e.s.St.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestKeyRotationNeedsEncryptedColumns(t *testing.T) {
	e := newEnv(t) // plaintext fixture database: no keys
	tok := e.setup()
	e.want(e.do("GET", "/api/admin/keys", tok, nil), 404, "status")
	e.want(e.do("POST", "/api/admin/keys/rotate", tok, map[string]any{"purpose": "data"}), 404, "rotate")
}

func TestKeyRotationFailureIsAudited(t *testing.T) {
	e := newEncryptedEnv(t)
	tok := e.setup()
	e.s.RunKeyJobs(t.Context())
	// A value that does not open (tampered at rest) stops the re-encryption:
	// it is reported, not rewritten.
	raw := rawSetting(t, e, "application_name")
	flipped := raw[:len(raw)-2] + map[bool]string{true: "AA", false: "BB"}[!strings.HasSuffix(raw, "AA")]
	if _, err := e.s.St.DB.Exec(`UPDATE settings SET value=? WHERE key='application_name'`, flipped); err != nil {
		t.Fatal(err)
	}
	r := e.do("POST", "/api/admin/keys/rotate", tok, map[string]any{"purpose": "data"})
	e.want(r, 202, "rotate data")
	job := keyJobDone(t, e, tok, r.J()["job_id"].(float64))
	if job["status"] != "failed" || !strings.Contains(fmt.Sprint(job["detail"]), "application_name") {
		t.Fatalf("job = %v", job)
	}
	if countAudit(t, e, "key_rotation_failed") != 1 {
		t.Fatalf("key_rotation_failed records: %d", countAudit(t, e, "key_rotation_failed"))
	}
	// The failed job is final; a new request is accepted.
	e.want(e.do("POST", "/api/admin/keys/rotate", tok, map[string]any{"purpose": "secrets"}), 202, "another purpose")
}

// encRefOf returns the files.enc_id value of the file at path in share lid.
func encRefOf(t *testing.T, e *env, lid, path string) (int64, string) {
	t.Helper()
	var shareID int64
	if err := qByName(e.s.St, `SELECT id FROM shares WHERE long_id=?`, lid).Scan(&shareID); err != nil {
		t.Fatal(err)
	}
	list, err := e.s.St.Repos().Shares().Files(t.Context(), shareID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		if f.FullPath == path {
			return f.ID, f.EncID
		}
	}
	t.Fatalf("no file %s in share %s", path, lid)
	return 0, ""
}

// The files key rotates through the admin API: new uploads use the new
// version, old files stay readable meanwhile, the job rewrites them, the old
// version retires and everything still downloads.
func TestFilesKeyRotationAPI(t *testing.T) {
	e := newEncryptedEnv(t)
	tok := e.setup()
	e.s.RunKeyJobs(t.Context())
	oldContent := "OLD-FILE-CONTENT " + randomText(70000)
	oldShare := e.share(tok, map[string]string{"old.txt": oldContent}, nil)
	e.want(oldShare, 201, "share before the rotation")
	oldLID := oldShare.S("long_id")
	if _, ref := encRefOf(t, e, oldLID, "old.txt"); !strings.HasSuffix(ref, ".1") {
		t.Fatalf("enc_id %q: want files version 1", ref)
	}
	files := keyPurpose(t, e.do("GET", "/api/admin/keys", tok, nil), "files")
	if files["rotatable"] != true || files["active"] != float64(1) || files["versions"].([]any)[0].(map[string]any)["files"] != float64(1) {
		t.Fatalf("files status before: %v", files)
	}

	r := e.do("POST", "/api/admin/keys/rotate", tok, map[string]any{"purpose": "files"})
	e.want(r, 202, "rotate files")
	if j := keyJobDone(t, e, tok, r.J()["job_id"].(float64)); j["status"] != "done" || j["version"] != float64(2) {
		t.Fatalf("job = %v", j)
	}
	files = keyPurpose(t, e.do("GET", "/api/admin/keys", tok, nil), "files")
	vs := files["versions"].([]any)
	if files["active"] != float64(2) || vs[0].(map[string]any)["state"] != "decrypt_only" || vs[0].(map[string]any)["files"] != float64(0) || vs[1].(map[string]any)["files"] != float64(1) {
		t.Fatalf("files status after: %v", files)
	}
	// The old file was rewritten under version 2; both old and new download.
	if _, ref := encRefOf(t, e, oldLID, "old.txt"); !strings.HasSuffix(ref, ".2") {
		t.Fatalf("old file enc_id %q after the job", ref)
	}
	newContent := "NEW-FILE-CONTENT " + randomText(5000)
	newShare := e.share(tok, map[string]string{"new.txt": newContent}, nil)
	e.want(newShare, 201, "share after the rotation")
	if _, ref := encRefOf(t, e, newShare.S("long_id"), "new.txt"); !strings.HasSuffix(ref, ".2") {
		t.Fatalf("new file enc_id %q: want files version 2", ref)
	}
	if d := e.do("GET", "/api/shares/"+oldLID+"/download/old.txt", "", nil); d.Code != 200 || string(d.Body) != oldContent {
		t.Fatalf("old file after the rotation: %d", d.Code)
	}
	if d := e.do("GET", "/api/shares/"+newShare.S("long_id")+"/download/new.txt", "", nil); d.Code != 200 || string(d.Body) != newContent {
		t.Fatalf("new file: %d", d.Code)
	}
	// Version 1 retires (no file uses it) and nothing breaks.
	r = e.do("POST", "/api/admin/keys/retire", tok, map[string]any{"purpose": "files", "version": 1})
	e.want(r, 202, "retire files v1")
	if j := keyJobDone(t, e, tok, r.J()["job_id"].(float64)); j["status"] != "done" {
		t.Fatalf("retire job = %v", j)
	}
	if d := e.do("GET", "/api/shares/"+oldLID+"/download/old.txt", "", nil); d.Code != 200 || string(d.Body) != oldContent {
		t.Fatalf("old file after the retirement: %d", d.Code)
	}
	// Version 2 is active: it cannot be retired.
	e.want(e.do("POST", "/api/admin/keys/retire", tok, map[string]any{"purpose": "files", "version": 2}), 409, "retire the active files version")
}

// A file under the old root-derived key is refused, never silently served, and
// the explicit re-encryption job converts it.
func TestLegacyFileRefusedUntilReencrypted(t *testing.T) {
	e := newEncryptedEnv(t)
	tok := e.setup()
	e.s.RunKeyJobs(t.Context())
	content := "LEGACY-CONTENT " + randomText(3000)
	sh := e.share(tok, map[string]string{"legacy.txt": content}, nil)
	e.want(sh, 201, "share")
	lid := sh.S("long_id")
	id, _ := encRefOf(t, e, lid, "legacy.txt")

	// Rewrite the stored file as an earlier build wrote it: under the master
	// derived from the database key, with a bare file id in the row.
	legacy, err := filecrypt.MasterKey(e.dbKey)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, fid, err := filecrypt.Encrypt(&out, strings.NewReader(content), legacy, nil)
	if err != nil {
		t.Fatal(err)
	}
	mf, err := e.s.St.Repos().ObjectStorage().MigrationFile(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(e.s.St.DataDir, "shares", lid, filepath.Base(mf.DiskPath))
	if err := os.WriteFile(disk, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := e.s.St.Repos().ObjectStorage().MoveFile(t.Context(), mf, ports.MovedFile{LocationID: mf.LocationID, DiskPath: mf.DiskPath, Encrypted: true, EncID: fid, SHA256: mf.SHA256}); err != nil || n != 1 {
		t.Fatalf("MoveFile %d %v", n, err)
	}

	d := e.do("GET", "/api/shares/"+lid+"/download/legacy.txt", "", nil)
	if d.Code != 503 || strings.Contains(string(d.Body), "LEGACY-CONTENT") {
		t.Fatalf("legacy file: %d %s", d.Code, d.Body)
	}
	if n := e.do("GET", "/api/admin/keys", tok, nil).J()["legacy_files"]; n != float64(1) {
		t.Fatalf("legacy_files = %v, want 1", n)
	}
	r := e.do("POST", "/api/admin/keys/reencrypt-files", tok, nil)
	e.want(r, 202, "reencrypt files")
	if j := keyJobDone(t, e, tok, r.J()["job_id"].(float64)); j["status"] != "done" {
		t.Fatalf("job = %v", j)
	}
	if d := e.do("GET", "/api/shares/"+lid+"/download/legacy.txt", "", nil); d.Code != 200 || string(d.Body) != content {
		t.Fatalf("after the conversion: %d", d.Code)
	}
	if n := e.do("GET", "/api/admin/keys", tok, nil).J()["legacy_files"]; n != float64(0) {
		t.Fatalf("legacy_files = %v after the job", n)
	}
}
