// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/storage"
	"github.com/sendora-app/sendora/internal/storage/storagetest"
	"github.com/sendora-app/sendora/internal/store"
)

// End-to-end tests of object storage: upload, plain/range/ZIP/verified
// downloads, preview, removal, expiry cleanup, verify-files, remote backups
// and the migration local -> S3 -> Azure -> local.
//
// Without further setup the "S3" and "Azure" locations are in-memory backends
// (storagetest.Memory), so these tests always run. With the emulator variables
// of internal/storage/emulator_test.go (SENDORA_TEST_S3_* for MinIO,
// SENDORA_TEST_AZURE_* for Azurite or a real account) the same flow runs
// against the real services.

type storageFixture struct {
	real bool
	mu   sync.Mutex
	mem  map[string]*storagetest.Memory // by location identity
	s3   map[string]any                 // settings selecting the S3 location
	az   map[string]any                 // settings selecting the Azure location
}

func newStorageFixture(t *testing.T, e *env) *storageFixture {
	t.Helper()
	f := &storageFixture{mem: map[string]*storagetest.Memory{}}
	s3ep, azAcct := os.Getenv("SENDORA_TEST_S3_ENDPOINT"), os.Getenv("SENDORA_TEST_AZURE_ACCOUNT")
	f.real = s3ep != "" && azAcct != ""
	prefix := "e2e-" + randomText(8) + "/"
	if f.real {
		f.s3 = map[string]any{"storage_backend": "s3", "storage_s3_endpoint": s3ep, "storage_s3_region": "us-east-1",
			"storage_s3_bucket": envOr("SENDORA_TEST_S3_BUCKET", "sendora-test"), "storage_s3_prefix": prefix, "storage_s3_path_style": "true",
			"storage_s3_auth": "static", "storage_s3_access_key": os.Getenv("SENDORA_TEST_S3_ACCESS_KEY"), "storage_s3_secret_key": os.Getenv("SENDORA_TEST_S3_SECRET_KEY")}
		f.az = map[string]any{"storage_backend": "azure", "storage_azure_account": azAcct, "storage_azure_endpoint": os.Getenv("SENDORA_TEST_AZURE_ENDPOINT"),
			"storage_azure_container": envOr("SENDORA_TEST_AZURE_CONTAINER", "sendora-test"), "storage_azure_prefix": prefix}
		if k := os.Getenv("SENDORA_TEST_AZURE_KEY"); k != "" {
			f.az["storage_azure_auth"], f.az["storage_azure_account_key"] = "shared_key", k
		} else {
			f.az["storage_azure_auth"], f.az["storage_azure_sas_token"] = "sas", os.Getenv("SENDORA_TEST_AZURE_SAS")
		}
		// Buckets are provisioned by the operator; create them for the emulators.
		for _, set := range []map[string]any{f.s3, f.az} {
			cfg := storage.FromSettings(func(k string) string { v, _ := set[k].(string); return v })
			b, err := storage.Open(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Backend == storage.KindS3 || set["storage_azure_auth"] == "shared_key" {
				if err := storage.CreateBucket(context.Background(), b); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { storage.DeletePrefix(context.Background(), b, "") })
		}
		return f
	}
	f.s3 = map[string]any{"storage_backend": "s3", "storage_s3_endpoint": "https://s3.storage-test.invalid", "storage_s3_region": "us-east-1",
		"storage_s3_bucket": "sendora-test", "storage_s3_prefix": prefix, "storage_s3_auth": "static", "storage_s3_access_key": "AKTEST", "storage_s3_secret_key": "secret-test"}
	f.az = map[string]any{"storage_backend": "azure", "storage_azure_account": "sendoratest", "storage_azure_container": "files",
		"storage_azure_prefix": prefix, "storage_azure_auth": "shared_key", "storage_azure_account_key": "a2V5LWZvci10ZXN0cw=="}
	e.s.St.Backends().OpenFn = func(ctx context.Context, cfg storage.Config) (storage.Backend, error) {
		if cfg.Backend == storage.KindLocal {
			return storage.Open(ctx, cfg)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		m := f.mem[cfg.Identity()]
		if m == nil {
			m = storagetest.NewMemory()
			f.mem[cfg.Identity()] = m
		}
		return m, nil
	}
	return f
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// backend returns the backend of location id (as the server opens it).
func (e *env) backend(id int64) storage.Backend {
	e.t.Helper()
	b, err := e.s.St.Backends().Get(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

type fileLoc struct {
	id, loc  int64
	key      string
	disk     string
	size     int64
	enc      bool
	fullPath string
}

func (e *env) fileLocs(longID string) map[string]fileLoc {
	e.t.Helper()
	// The path is a sealed column: the repository opens it.
	list, err := e.s.St.Repos().Shares().Files(context.Background(), shareIDByLongID(e.t, e.s.St, longID))
	if err != nil {
		e.t.Fatal(err)
	}
	paths := map[int64]string{}
	for _, f := range list {
		paths[f.ID] = f.FullPath
	}
	rows, err := e.s.St.DB.Query(`SELECT f.id,f.full_path,f.storage_id,f.object_key,f.disk_path,f.size,f.enc FROM files f WHERE f.share_id=?`, shareIDByLongID(e.t, e.s.St, longID))
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]fileLoc{}
	for rows.Next() {
		var l fileLoc
		var sealed string
		if err := rows.Scan(&l.id, &sealed, &l.loc, &l.key, &l.disk, &l.size, &l.enc); err != nil {
			e.t.Fatal(err)
		}
		l.fullPath = paths[l.id]
		out[l.fullPath] = l
	}
	return out
}

func objectBytes(t *testing.T, b storage.Backend, key string) []byte {
	t.Helper()
	obj, err := b.Open(context.Background(), key)
	if err != nil {
		t.Fatalf("open %s: %v", key, err)
	}
	defer obj.Close()
	data, err := io.ReadAll(io.NewSectionReader(obj, 0, obj.Size()))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func objectExists(b storage.Backend, key string) bool {
	_, err := b.Stat(context.Background(), key)
	return err == nil
}

// checkDownloads downloads every file whole, with ranges, as a ZIP and (for
// png files) as a preview, and compares with the plaintext.
func (e *env) checkDownloads(lid string, files map[string]string) {
	t := e.t
	t.Helper()
	for name, content := range files {
		d := e.do("GET", "/api/shares/"+lid+"/download/"+name, "", nil)
		e.want(d, 200, "download "+name)
		if string(d.Body) != content {
			t.Fatalf("%s: downloaded bytes differ", name)
		}
		sum := sha256.Sum256([]byte(content))
		if d.Hdr.Get("X-Checksum-Sha256") != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s: verified checksum header %q", name, d.Hdr.Get("X-Checksum-Sha256"))
		}
		if len(content) > 70000 {
			d := e.do("GET", "/api/shares/"+lid+"/download/"+name, "", nil, "Range", "bytes=65530-70009")
			e.want(d, 206, "range "+name)
			if string(d.Body) != content[65530:70010] {
				t.Fatalf("%s: range bytes differ", name)
			}
		}
		if strings.HasSuffix(name, ".png") {
			p := e.do("GET", "/api/shares/"+lid+"/preview/"+name, "", nil, "Range", "bytes=0-99")
			e.want(p, 206, "preview "+name)
			if string(p.Body) != content[:100] {
				t.Fatalf("%s: preview bytes differ", name)
			}
		}
	}
	z := e.do("GET", "/api/shares/"+lid+"/download", "", nil)
	e.want(z, 200, "zip")
	zr, err := zip.NewReader(bytes.NewReader(z.Body), int64(len(z.Body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != len(files) {
		t.Fatalf("zip has %d entries, want %d", len(zr.File), len(files))
	}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if string(b) != files[f.Name] {
			t.Fatalf("zip entry %s differs", f.Name)
		}
	}
}

func (e *env) waitMigration() map[string]any {
	e.t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		st := e.s.migrationStatus()
		if st != nil && st["status"] != "running" {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatal("migration did not finish")
	return nil
}

func pngContent(n int) string {
	return "\x89PNG\r\n\x1a\n" + randomText(n-8)
}

func TestObjectStorageEndToEnd(t *testing.T) {
	e := newEncryptedEnv(t)
	admin := e.setup()
	fx := newStorageFixture(t, e)
	e.s.St.SetSetting("allow_preview", "true")
	oldDelay := migrationDeleteDelay
	migrationDeleteDelay = 0
	t.Cleanup(func() { migrationDeleteDelay = oldDelay })

	big := randomText(3*filecrypt.ChunkSize + 4321)
	localFiles := map[string]string{"local-big.bin": big, "local.txt": "LOCAL-SECRET-MARKER", "legacy-empty.txt": ""}
	r := e.share(admin, localFiles, nil)
	e.want(r, 201, "local share")
	localLID := r.S("long_id")
	for _, l := range e.fileLocs(localLID) {
		if l.loc != store.LocalLocation || l.key != "" {
			t.Fatalf("local upload stored remotely: %+v", l)
		}
	}

	// Switch to "S3": a remote configuration is tested before it is saved.
	e.want(e.do("PUT", "/api/settings", admin, fx.s3), 200, "select s3")
	if !fx.real {
		var n int
		e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='storage_backend_changed'`).Scan(&n)
		if n != 1 {
			t.Fatalf("storage_backend_changed records: %d", n)
		}
	}
	s3Loc, s3b, err := e.s.currentStorage(context.Background())
	if err != nil || s3Loc == store.LocalLocation {
		t.Fatalf("current storage %d %v", s3Loc, err)
	}

	remoteFiles := map[string]string{"remote-big.bin": randomText(4*filecrypt.ChunkSize + 99), "pic.png": pngContent(5000), "empty.txt": "", "dir/note.txt": "REMOTE-SECRET-MARKER-0123456789"}
	r = e.share(admin, remoteFiles, nil)
	e.want(r, 201, "remote share")
	remoteLID, remoteID := r.S("long_id"), r.S("id")
	locs := e.fileLocs(remoteLID)
	for name, content := range remoteFiles {
		l := locs[name]
		if l.loc != s3Loc || !storage.ValidFileKey(l.key) || l.disk != "" || !l.enc {
			t.Fatalf("%s: not stored remotely: %+v", name, l)
		}
		if strings.Contains(l.key, remoteLID) || strings.Contains(l.key, "note") {
			t.Fatalf("%s: object key leaks names: %s", name, l.key)
		}
		raw := objectBytes(t, s3b, l.key)
		if int64(len(raw)) != filecrypt.CipherSize(int64(len(content))) || !bytes.HasPrefix(raw, []byte("SNDF\x02")) {
			t.Fatalf("%s: object is not filecrypt v2 ciphertext (%d bytes)", name, len(raw))
		}
		if len(content) >= 16 && bytes.Contains(raw, []byte(content[:16])) {
			t.Fatalf("%s: plaintext in the object store", name)
		}
	}
	// The local share directory stays empty (it only claims the share ID).
	if ents, _ := os.ReadDir(filepath.Join(e.s.St.DataDir, "shares", remoteLID)); len(ents) != 0 {
		t.Fatalf("remote share wrote %d local files", len(ents))
	}
	e.checkDownloads(remoteLID, remoteFiles)
	e.checkDownloads(localLID, localFiles) // old files stay readable from their old location

	// Appending to a remote share stores the new file remotely too.
	sid, _ := strconv.ParseInt(remoteID, 10, 64)
	e.want(e.appendFiles(admin, sid, []nf{{"added.txt", "appended later"}}), 201, "append")
	remoteFiles["added.txt"] = "appended later"
	if l := e.fileLocs(remoteLID)["added.txt"]; l.loc != s3Loc || !storage.ValidFileKey(l.key) {
		t.Fatalf("appended file: %+v", l)
	}

	// A modified object is refused (GCM authentication), not served.
	if !fx.real {
		key := e.fileLocs(remoteLID)["dir/note.txt"].key
		m := s3b.(*storagetest.Memory)
		m.Corrupt(key, 60)
		e.want(e.do("GET", "/api/shares/"+remoteLID+"/download/dir/note.txt", "", nil), 409, "tampered object")
		m.Corrupt(key, 60)
		e.want(e.do("GET", "/api/shares/"+remoteLID+"/download/dir/note.txt", "", nil), 200, "restored object")
	}

	// verify-files checks remote objects and finds remote orphans.
	verify := func() store.FilesSummary {
		t.Helper()
		sum, err := e.s.St.VerifyStoredFiles(store.VerifyOptions{OpenBackend: e.s.St.Backends().OpenFn})
		if err != nil {
			t.Fatal(err)
		}
		return sum
	}
	if sum := verify(); sum.Failed != 0 || sum.Orphans != 0 || sum.Rows != len(localFiles)+len(remoteFiles) {
		t.Fatalf("verify-files: %+v", sum)
	}
	orphan, _ := storage.NewFileKey()
	s3b.Put(context.Background(), orphan, strings.NewReader("x"), 1)
	if sum := verify(); sum.Orphans != 1 {
		t.Fatalf("verify-files did not find the remote orphan: %+v", sum)
	}
	s3b.Delete(context.Background(), orphan)

	// Removing one file deletes its object.
	removed := e.fileLocs(remoteLID)["added.txt"]
	e.want(e.do("DELETE", "/api/shares/"+remoteID+"/files/"+strconv.FormatInt(removed.id, 10), admin, nil), 200, "remove file")
	delete(remoteFiles, "added.txt")
	e.s.drainDeletes()
	if objectExists(s3b, removed.key) {
		t.Fatal("removed file's object still exists")
	}

	// Migration local -> S3: every file moves, local copies go away.
	if n := store.MigrateRemaining(e.s.St.Repos(), s3Loc); n != int64(len(localFiles)) {
		t.Fatalf("remaining %d", n)
	}
	e.want(e.do("POST", "/api/storage/migrate", admin, nil), 202, "migrate to s3")
	if st := e.waitMigration(); st["status"] != "finished" || st["failed"] != 0 {
		t.Fatalf("migration: %+v", st)
	}
	for name, l := range e.fileLocs(localLID) {
		if l.loc != s3Loc || !storage.ValidFileKey(l.key) || !objectExists(s3b, l.key) {
			t.Fatalf("%s not migrated: %+v", name, l)
		}
	}
	if ents, _ := os.ReadDir(filepath.Join(e.s.St.DataDir, "shares", localLID)); len(ents) != 0 {
		t.Fatalf("%d local files left after migration", len(ents))
	}
	e.checkDownloads(localLID, localFiles)

	// Switch to "Azure" and migrate again: the S3 objects are deleted.
	e.want(e.do("PUT", "/api/settings", admin, fx.az), 200, "select azure")
	azLoc, azb, err := e.s.currentStorage(context.Background())
	if err != nil || azLoc == s3Loc || azLoc == store.LocalLocation {
		t.Fatalf("azure location %d %v", azLoc, err)
	}
	e.checkDownloads(remoteLID, remoteFiles) // still on S3
	oldKeys := []string{}
	for _, l := range e.fileLocs(remoteLID) {
		oldKeys = append(oldKeys, l.key)
	}
	e.want(e.do("POST", "/api/storage/migrate", admin, nil), 202, "migrate to azure")
	if st := e.waitMigration(); st["status"] != "finished" {
		t.Fatalf("migration: %+v", st)
	}
	e.s.drainDeletes()
	for _, k := range oldKeys {
		if objectExists(s3b, k) {
			t.Fatalf("source object %s left on S3", k)
		}
	}
	for _, lid := range []string{localLID, remoteLID} {
		for name, l := range e.fileLocs(lid) {
			if l.loc != azLoc || !objectExists(azb, l.key) {
				t.Fatalf("%s not on azure: %+v", name, l)
			}
		}
	}
	e.checkDownloads(remoteLID, remoteFiles)
	e.checkDownloads(localLID, localFiles)
	if sum := verify(); sum.Failed != 0 || sum.Orphans != 0 {
		t.Fatalf("verify-files after migration: %+v", sum)
	}
	var audits int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action IN ('storage_migration_started','storage_migration_finished')`).Scan(&audits)
	if audits != 4 {
		t.Fatalf("migration audit records: %d, want 4", audits)
	}

	// Remote backup copies honour backup_keep.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"backup_remote_enabled": "true", "backup_keep": "1"}), 200, "remote backups")
	for i := 0; i < 2; i++ {
		if !e.s.autoBackup() {
			t.Fatal("backup failed")
		}
		time.Sleep(1100 * time.Millisecond) // backup names carry the second
	}
	var backups []string
	azb.List(context.Background(), storage.BackupPrefix, func(i storage.Info) error { backups = append(backups, i.Key); return nil })
	if len(backups) != 1 || !strings.HasPrefix(backups[0], "backups/sendora-encrypted-") {
		t.Fatalf("remote backups: %v", backups)
	}
	if raw := objectBytes(t, azb, backups[0]); bytes.HasPrefix(raw, []byte("SQLite format 3")) {
		t.Fatal("remote backup is not encrypted")
	}

	// Expiry cleanup removes the objects of long-expired shares.
	keys := e.fileLocs(remoteLID)
	eByName(e.s.St, `UPDATE shares SET status='expired', expires_at=? WHERE long_id=?`, time.Now().AddDate(0, 0, -30), remoteLID)
	e.s.maintain()
	e.s.drainDeletes()
	for name, l := range keys {
		if objectExists(azb, l.key) {
			t.Fatalf("%s: object of an expired share left behind", name)
		}
	}

	// Back to local: migration writes the classic layout again.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"storage_backend": "local", "backup_remote_enabled": "false"}), 200, "select local")
	e.want(e.do("POST", "/api/storage/migrate", admin, nil), 202, "migrate to local")
	if st := e.waitMigration(); st["status"] != "finished" {
		t.Fatalf("migration: %+v", st)
	}
	for name, l := range e.fileLocs(localLID) {
		if l.loc != store.LocalLocation || l.key != "" || !strings.HasPrefix(l.disk, filepath.Join(e.s.St.DataDir, "shares", localLID)) {
			t.Fatalf("%s not local: %+v", name, l)
		}
	}
	e.checkDownloads(localLID, localFiles)
	e.s.drainDeletes()
	if n := store.PendingDeletes(e.s.St.Repos()); n != 0 {
		t.Fatalf("%d deletions still queued", n)
	}
}

func TestObjectStorageUserDeletionAndFailures(t *testing.T) {
	e := newEncryptedEnv(t)
	admin := e.setup()
	fx := newStorageFixture(t, e)
	if fx.real {
		t.Skip("failure injection needs the in-memory backend")
	}
	e.want(e.do("PUT", "/api/settings", admin, fx.s3), 200, "select s3")
	_, b, _ := e.s.currentStorage(context.Background())
	m := b.(*storagetest.Memory)

	// A failing object store: the upload fails, nothing is left behind, and
	// the upload can be completed once the store works again.
	user := e.mkUser(admin, "alice", false)
	m.FailPut.Store(true)
	files := map[string]string{"a.txt": "alpha", "b.txt": "bravo"}
	meta := []map[string]any{{"name": "a.txt", "full_path": "a.txt", "size": 5}, {"name": "b.txt", "full_path": "b.txt", "size": 5}}
	r := e.do("POST", "/api/uploads", user, map[string]any{"files": meta})
	e.want(r, 201, "upload")
	id := r.S("id")
	for i, n := range []string{"a.txt", "b.txt"} {
		e.want(e.do("PATCH", "/api/uploads/"+id+"/files/"+strconv.Itoa(i), user, []byte(files[n]), "Upload-Offset", "0"), 200, "chunk")
	}
	if r := e.do("POST", "/api/uploads/"+id+"/complete", user, map[string]any{}); r.Code < 500 {
		t.Fatalf("complete with a failing store: %d", r.Code)
	}
	if keys := m.Keys(); len(keys) != 0 {
		t.Fatalf("objects left after a failed upload: %v", keys)
	}
	m.FailPut.Store(false)
	r = e.do("POST", "/api/uploads/"+id+"/complete", user, map[string]any{})
	e.want(r, 201, "retry complete")
	if len(m.Keys()) != 2 {
		t.Fatalf("objects after retry: %v", m.Keys())
	}

	// A connection test reports failures and is audited.
	m.FailOpen.Store(true)
	tr := e.do("POST", "/api/storage/test", admin, map[string]any{})
	e.want(tr, 200, "storage test")
	if tr.J()["ok"] != false {
		t.Fatalf("test passed with a failing store: %s", tr.Body)
	}
	m.FailOpen.Store(false)
	tr = e.do("POST", "/api/storage/test", admin, map[string]any{})
	if tr.J()["ok"] != true {
		t.Fatalf("test failed: %s", tr.Body)
	}
	var tested, failed int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='storage_connection_tested'`).Scan(&tested)
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='storage_connection_test_failed'`).Scan(&failed)
	if tested != 1 || failed != 1 {
		t.Fatalf("test audit records: ok=%d failed=%d", tested, failed)
	}

	// Saving a remote configuration whose connection test fails is refused.
	open := e.s.St.Backends().OpenFn
	broken := storagetest.NewMemory()
	broken.FailPut.Store(true)
	e.s.St.Backends().OpenFn = func(ctx context.Context, cfg storage.Config) (storage.Backend, error) {
		if cfg.S3Bucket == "other-bucket" {
			return broken, nil
		}
		return open(ctx, cfg)
	}
	bad := map[string]any{}
	for k, v := range fx.s3 {
		bad[k] = v
	}
	bad["storage_s3_bucket"] = "other-bucket"
	e.want(e.do("PUT", "/api/settings", admin, bad), 400, "unreachable config")
	if e.s.St.Setting("storage_s3_bucket") != "sendora-test" {
		t.Fatal("refused configuration was stored")
	}

	// Changing where a stored secret is sent requires typing it again.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"storage_s3_endpoint": "https://elsewhere.example"}), 400, "endpoint change without secret")
	// Invalid values are refused.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"storage_s3_bucket": "Bad_Bucket"}), 400, "bad bucket")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"storage_s3_endpoint": "http://s3.example.com", "storage_s3_secret_key": "x"}), 400, "http endpoint")
	// Secrets are write-only.
	gs := e.do("GET", "/api/settings", admin, nil).J()
	if gs["storage_s3_secret_key"] != "" || gs["storage_s3_secret_key_set"] != true {
		t.Fatalf("secret visible: %v %v", gs["storage_s3_secret_key"], gs["storage_s3_secret_key_set"])
	}

	// Deleting the user removes the objects of their shares; GDPR erasure too.
	bob := e.mkUser(admin, "bob", false)
	e.want(e.share(bob, map[string]string{"c.txt": "charlie"}, nil), 201, "bob share")
	before := len(m.Keys())
	var bobID, aliceID int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='bob'`).Scan(&bobID)
	qByName(e.s.St, `SELECT id FROM users WHERE username='alice'`).Scan(&aliceID)
	e.want(e.do("DELETE", "/api/users/"+strconv.FormatInt(bobID, 10), admin, nil), 200, "delete bob")
	e.s.drainDeletes()
	if len(m.Keys()) != before-1 {
		t.Fatalf("objects after user deletion: %d, want %d", len(m.Keys()), before-1)
	}
	e.want(e.do("POST", "/api/users/"+strconv.FormatInt(aliceID, 10)+"/erase", admin, nil), 200, "erase alice")
	e.s.drainDeletes()
	if len(m.Keys()) != 0 {
		t.Fatalf("objects after erasure: %v", m.Keys())
	}
}
