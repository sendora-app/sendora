// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/sendora-app/sendora/internal/store"
)

func TestEncryptedBackupAPIAndLegacyRetention(t *testing.T) {
	key := bytes.Repeat([]byte{0x72}, 32)
	st, err := store.OpenEncrypted(t.TempDir(), key, true)
	if err != nil {
		t.Fatal(err)
	}
	legacyTestDefaults(t, st)
	defer st.DB.Close()
	s := New(st, fstest.MapFS{"index.html": {Data: []byte("test")}}, "test")
	s.passwordScreenOff = true
	ts := httptest.NewServer(s.Router())
	defer ts.Close()
	e := &env{t: t, s: s, ts: ts}
	token := e.setup()
	created := e.do("POST", "/api/backups", token, nil)
	e.want(created, 201, "encrypted backup")
	name := created.S("name")
	download := e.do("GET", "/api/backups/"+name, token, nil)
	e.want(download, 200, "download encrypted backup")
	if bytes.HasPrefix(download.Body, []byte("SQLite format 3")) {
		t.Fatal("plaintext response")
	}
	counts, err := store.VerifyDatabase(filepath.Join(st.DataDir, "backups", name), key)
	if err != nil || counts["users"] != 1 {
		t.Fatal(counts, err)
	}
	if _, err := store.VerifyDatabase(filepath.Join(st.DataDir, "backups", name), nil); err == nil {
		t.Fatal("backup readable without key")
	}
	legacy := filepath.Join(st.DataDir, "backups", "sendora-plain-20200101-000000.db")
	if err := os.WriteFile(legacy, []byte("legacy-placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.makeBackup(); err != nil {
		t.Fatal(err)
	}
	st.SetSetting("backup_keep", "1")
	s.pruneBackups()
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("pruned legacy backup", err)
	}
	entries, err := os.ReadDir(filepath.Join(st.DataDir, "backups"))
	if err != nil || len(entries) != 2 {
		t.Fatal("retention", len(entries), err)
	}
}
