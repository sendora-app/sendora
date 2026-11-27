// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var impKeyA = bytes.Repeat([]byte{0x11}, 32)

// preparedCopy builds a re-keyed, prepared database file in its own dir.
func preparedCopy(t *testing.T, mutate func(*Store)) string {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenEncrypted(dir, impKeyA, true)
	if err != nil {
		t.Fatal(err)
	}
	st.DB.Exec(`INSERT INTO users(username,email,admin) VALUES('importedadmin','ia@x.io',1)`)
	sealRaw(t, st)
	if mutate != nil {
		mutate(st)
		sealRaw(t, st)
	}
	st.Close()
	return filepath.Join(dir, "sendora.db")
}

func TestPrepareImportedCountsAndStaleUploads(t *testing.T) {
	p := preparedCopy(t, func(st *Store) {
		st.DB.Exec(`INSERT INTO users(username,email,admin,is_guest) VALUES('g','g@x.io',1,1)`)
		st.DB.Exec(`INSERT INTO shares(user_id,long_id) VALUES(1,'aaaaaaaaaaaaaaaa')`)
		st.DB.Exec(`INSERT INTO shares(user_id,long_id,status) VALUES(1,'bbbbbbbbbbbbbbbb','deleted')`)
		st.DB.Exec(`INSERT INTO files(share_id,name,full_path,disk_path) VALUES(1,'a','a','/x')`)
		st.DB.Exec(`INSERT INTO files(share_id,name,full_path,disk_path) VALUES(2,'b','b','/y')`)
		st.DB.Exec(`INSERT INTO upload_sessions(id,user_id,quota_owner_id) VALUES('s',1,1)`)
		st.DB.Exec(`INSERT INTO upload_files(session_id,idx,name,full_path,size) VALUES('s',0,'a','a',1)`)
	})
	sum, err := PrepareImported(p, impKeyA, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if *sum != (ImportSummary{Users: 1, Admins: 1, Shares: 1, Files: 1, DroppedUploads: 1}) {
		t.Fatalf("%+v", *sum)
	}
	for _, s := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(p + s); err == nil {
			t.Fatalf("%s left behind", s)
		}
	}
	counts, err := VerifyDatabase(p, impKeyA)
	if err != nil || counts["upload_sessions"] != 0 {
		t.Fatal(counts, err)
	}
	// Idempotent.
	if _, err := PrepareImported(p, impKeyA, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareImportedRejects(t *testing.T) {
	for name, c := range map[string]struct {
		mutate func(*Store)
		msg    string
	}{
		"table":  {func(s *Store) { s.DB.Exec(`CREATE TABLE next_gen(id INTEGER)`) }, "unknown table next_gen"},
		"column": {func(s *Store) { s.DB.Exec(`ALTER TABLE users ADD COLUMN passkey TEXT`) }, "unknown column users.passkey"},
		"admin":  {func(s *Store) { s.DB.Exec(`UPDATE users SET admin=0`) }, "no administrator"},
		"files":  {func(s *Store) { s.DB.Exec(`DROP TABLE files`) }, "required table missing: files"},
	} {
		p := preparedCopy(t, c.mutate)
		_, err := PrepareImported(p, impKeyA, t.TempDir())
		var ie *ImportError
		if err == nil || !errorsAs(err, &ie) || !strings.Contains(ie.Msg, c.msg) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The app's own extra table is allowed.
	p := preparedCopy(t, func(s *Store) {
		s.DB.Exec(`CREATE TABLE verification_attempts (user_id INTEGER PRIMARY KEY, attempts INTEGER NOT NULL, expires_at DATETIME NOT NULL)`)
	})
	if _, err := PrepareImported(p, impKeyA, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareImported(p, bytes.Repeat([]byte{9}, 32), t.TempDir()); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func errorsAs(err error, ie **ImportError) bool {
	e, ok := err.(*ImportError)
	if ok {
		*ie = e
	}
	return ok
}

func liveDir(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenEncrypted(dir, impKeyA, true)
	if err != nil {
		t.Fatal(err)
	}
	st.DB.Exec(`INSERT INTO users(username,email,admin) VALUES('liveuser','l@x.io',1)`)
	sealRaw(t, st)
	st.Close()
	return dir, impKeyA
}

func userNames(t *testing.T, st *Store) string {
	t.Helper()
	list, err := st.Repos().Users().ListLocal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, u := range list {
		names = append(names, u.Username)
	}
	return strings.Join(names, ",")
}

func TestSwapImportedDatabaseFiles(t *testing.T) {
	dir, _ := liveDir(t)
	newDB := preparedCopy(t, nil)
	staged := filepath.Join(dir, "backups", ".import-x.new")
	data, _ := os.ReadFile(newDB)
	os.WriteFile(staged, data, 0o644)
	if _, err := PrepareImported(staged, impKeyA, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "sendora.db")
	oldBytes, _ := os.ReadFile(db)
	// Stale sidecars from the old database must go; uploads are emptied.
	os.WriteFile(db+"-wal", []byte("w"), 0o600)
	os.WriteFile(db+"-shm", []byte("s"), 0o600)
	os.MkdirAll(filepath.Join(dir, "uploads", "sess", "deep"), 0o700)
	os.WriteFile(filepath.Join(dir, "uploads", "sess", "deep", "f"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "uploads", "loose"), []byte("x"), 0o600)
	if err := SwapImportedDatabase(dir, staged); err != nil {
		t.Fatal(err)
	}
	pre, _ := os.ReadFile(db + PreImportSuffix)
	if !bytes.Equal(pre, oldBytes) {
		t.Fatal("old database not kept as .pre-import")
	}
	for _, p := range []string{db + "-wal", db + "-shm", staged} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s should be gone", p)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ImportMarker)); err != nil {
		t.Fatal("marker missing")
	}
	if st, _ := os.Stat(db); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if st, err := os.Stat(filepath.Join(dir, "uploads")); err != nil || !st.IsDir() {
		t.Fatal("uploads dir must remain")
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "uploads")); len(ents) != 0 {
		t.Fatalf("uploads not cleared: %d", len(ents))
	}
	// A leftover .pre-import from an earlier run is replaced, not an obstacle.
	st, err := OpenEncrypted(dir, impKeyA, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := userNames(t, st); got != "importedadmin" {
		t.Fatalf("users: %s", got)
	}
	st.Close()
}

func TestSwapMissingNewFileRollsBack(t *testing.T) {
	dir, _ := liveDir(t)
	if err := SwapImportedDatabase(dir, filepath.Join(dir, "backups", "nope.new")); err == nil {
		t.Fatal("swap of missing file succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, ImportMarker)); err == nil {
		t.Fatal("marker kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "sendora.db"+PreImportSuffix)); err == nil {
		t.Fatal(".pre-import kept")
	}
	st, err := OpenEncrypted(dir, impKeyA, false)
	if err != nil {
		t.Fatal(err)
	}
	if userNames(t, st) != "liveuser" {
		t.Fatal("live data changed")
	}
	st.Close()
}

func TestRecoveryRestoresPreviousDatabaseWhenImportedOneFails(t *testing.T) {
	dir, _ := liveDir(t)
	// "Imported" database is encrypted under another key: the start fails.
	other := t.TempDir()
	o, err := OpenEncrypted(other, bytes.Repeat([]byte{0x22}, 32), true)
	if err != nil {
		t.Fatal(err)
	}
	o.Close()
	staged := filepath.Join(dir, "backups", ".import-bad.new")
	data, _ := os.ReadFile(filepath.Join(other, "sendora.db"))
	os.WriteFile(staged, data, 0o600)
	if err := SwapImportedDatabase(dir, staged); err != nil {
		t.Fatal(err)
	}
	var msgs []string
	logf := func(f string, a ...any) { msgs = append(msgs, f) }
	st, err := OpenEncryptedRecovering(dir, impKeyA, false, logf)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if userNames(t, st) != "liveuser" {
		t.Fatal("previous database not restored")
	}
	for _, p := range []string{ImportMarker, "sendora.db" + PreImportSuffix} {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			t.Fatalf("%s kept", p)
		}
	}
	if len(msgs) == 0 || !strings.Contains(strings.Join(msgs, " "), "restor") {
		t.Fatalf("no restore log: %v", msgs)
	}
}

func TestRecoveryCleansUpAfterSuccessfulImport(t *testing.T) {
	dir, _ := liveDir(t)
	staged := filepath.Join(dir, "backups", ".import-ok.new")
	data, _ := os.ReadFile(preparedCopy(t, nil))
	os.WriteFile(staged, data, 0o600)
	if _, err := PrepareImported(staged, impKeyA, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := SwapImportedDatabase(dir, staged); err != nil {
		t.Fatal(err)
	}
	st, err := OpenEncryptedRecovering(dir, impKeyA, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if userNames(t, st) != "importedadmin" {
		t.Fatal("imported database not used")
	}
	for _, p := range []string{ImportMarker, "sendora.db" + PreImportSuffix} {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			t.Fatalf("%s kept", p)
		}
	}
}

func TestRecoveryWithoutMarkerIsPlainOpen(t *testing.T) {
	dir, _ := liveDir(t)
	// A stray .pre-import without marker is left alone; a missing DB is not recreated.
	os.WriteFile(filepath.Join(dir, "sendora.db"+PreImportSuffix), []byte("x"), 0o600)
	st, err := OpenEncryptedRecovering(dir, impKeyA, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := os.Stat(filepath.Join(dir, "sendora.db"+PreImportSuffix)); err != nil {
		t.Fatal("unmarked .pre-import removed")
	}
	if _, err := OpenEncryptedRecovering(t.TempDir(), impKeyA, false, nil); err == nil {
		t.Fatal("implicit initialization")
	}
}

func TestRecoveryMarkerWithoutPreviousCopyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ImportMarker), []byte("pending\n"), 0o600)
	if _, err := OpenEncryptedRecovering(dir, impKeyA, false, nil); err == nil {
		t.Fatal("opened nothing successfully")
	}
	if _, err := os.Stat(filepath.Join(dir, ImportMarker)); err != nil {
		t.Fatal("marker must stay when nothing could be restored")
	}
}
