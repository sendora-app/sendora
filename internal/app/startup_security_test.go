// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/sendora-app/sendora/internal/store"
)

func TestCrashSnapshotCleanup(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	legacyTestDefaults(t, st)
	defer st.DB.Close()
	stale := filepath.Join(st.DataDir, ".verified-download-stale")
	keep := filepath.Join(st.DataDir, "unrelated-file")
	dir := filepath.Join(st.DataDir, ".verified-download-directory")
	for _, p := range []string{stale, keep} {
		if err := os.WriteFile(p, []byte("private"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	New(st, fstest.MapFS{}, "test")
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale snapshot retained: %v", err)
	}
	for _, p := range []string{keep, dir} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal("unrelated entry removed", err)
		}
	}
}

func TestUploadStorageFailureRollsBack(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	path := filepath.Join(e.s.St.DataDir, "uploads")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	result := e.do("POST", "/api/uploads", token, map[string]any{"files": []map[string]any{{"name": "a.txt", "size": 1}}})
	e.want(result, 503, "storage failure")
	for _, table := range []string{"upload_sessions", "upload_files"} {
		var n int
		if err := e.s.St.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("partial upload metadata %s count %d error %v", table, n, err)
		}
	}
}
