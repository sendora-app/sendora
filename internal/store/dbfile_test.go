// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func wantFiles(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("files %v, want %d", names, len(want))
	}
	for name, body := range want {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(b) != body {
			t.Fatalf("%s = %q, %v; want %q", name, b, err, body)
		}
	}
}

func TestDBPathRenamesLegacyDatabase(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"fileshare.db": "db", "fileshare.db-wal": "wal", "fileshare.db-shm": "shm", "fileshare.db.pre-import": "pre"})
	p, err := DBPath(dir)
	if err != nil || p != filepath.Join(dir, "sendora.db") {
		t.Fatal(p, err)
	}
	wantFiles(t, dir, map[string]string{"sendora.db": "db", "sendora.db-wal": "wal", "sendora.db-shm": "shm", "sendora.db.pre-import": "pre"})
	// Idempotent once migrated.
	if p2, err := DBPath(dir); err != nil || p2 != p {
		t.Fatal(p2, err)
	}
}

func TestDBPathFreshAndCurrent(t *testing.T) {
	dir := t.TempDir()
	if p, err := DBPath(dir); err != nil || p != filepath.Join(dir, "sendora.db") {
		t.Fatal(p, err)
	}
	wantFiles(t, dir, map[string]string{})
}

func TestDBPathRefusesBothNames(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{"fileshare.db": "old", "fileshare.db-wal": "oldwal", "sendora.db": "new"}
	writeFiles(t, dir, files)
	if _, err := DBPath(dir); err == nil {
		t.Fatal("accepted two databases")
	}
	wantFiles(t, dir, files)
}

func TestDBPathResumesInterruptedRename(t *testing.T) {
	dir := t.TempDir()
	// Crash after the sidecars moved, before the main file did.
	writeFiles(t, dir, map[string]string{"fileshare.db": "db", "sendora.db-wal": "wal", "fileshare.db-shm": "shm"})
	if _, err := DBPath(dir); err != nil {
		t.Fatal(err)
	}
	wantFiles(t, dir, map[string]string{"sendora.db": "db", "sendora.db-wal": "wal", "sendora.db-shm": "shm"})
}

func TestDBPathRefusesConflictingSidecar(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{"fileshare.db": "db", "fileshare.db-wal": "wal1", "sendora.db-wal": "wal2"}
	writeFiles(t, dir, files)
	if _, err := DBPath(dir); err == nil {
		t.Fatal("overwrote a write-ahead log")
	}
	wantFiles(t, dir, files)
}

func TestOpenEncryptedMigratesLegacyDatabase(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x61}, 32)
	s, err := OpenEncrypted(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO users(username,email) VALUES('legacy-user','legacy@example.test')`); err != nil {
		t.Fatal(err)
	}
	sealRaw(t, s)
	s.DB.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Rename(filepath.Join(dir, "sendora.db"+suffix), filepath.Join(dir, "fileshare.db"+suffix)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	s, err = OpenEncrypted(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE id=1`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if s.Path != filepath.Join(dir, "sendora.db") {
		t.Fatal(s.Path)
	}
	if _, err := os.Stat(filepath.Join(dir, "fileshare.db")); !os.IsNotExist(err) {
		t.Fatal("legacy file left behind", err)
	}
}
