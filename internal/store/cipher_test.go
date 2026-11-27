// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCipherInitializationAndFailClosed(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x61}, 32)
	if _, err := OpenEncrypted(dir, key, false); err == nil {
		t.Fatal("implicit fresh initialization")
	}
	s, err := OpenEncrypted(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO users(username,disabled_reason,email) VALUES('cipher-user','private-marker','cipher@example.test')`); err != nil {
		t.Fatal(err)
	}
	sealRaw(t, s)
	backup := filepath.Join(dir, "encrypted-backup.db")
	if err := s.ExportEncryptedBackup(backup); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	original, _ := os.ReadFile(filepath.Join(dir, "sendora.db"))
	if bytes.HasPrefix(original, []byte("SQLite format 3")) || bytes.Contains(original, []byte("private-marker")) {
		t.Fatal("plaintext database")
	}
	for _, wrong := range [][]byte{nil, bytes.Repeat([]byte{0x62}, 32)} {
		if _, err := OpenEncrypted(dir, wrong, false); err == nil {
			t.Fatal("accepted missing/wrong key")
		}
		now, _ := os.ReadFile(filepath.Join(dir, "sendora.db"))
		if !bytes.Equal(original, now) {
			t.Fatal("failed open changed database")
		}
	}
	s, err = OpenEncrypted(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var name string
	if err := s.DB.QueryRow(`SELECT disabled_reason FROM users WHERE id=1`).Scan(&name); err != nil || name != "private-marker" {
		t.Fatal(name, err)
	}
	verify, err := openCipherDB(backup, key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer verify.Close()
	if err := verify.QueryRow(`SELECT disabled_reason FROM users WHERE id=1`).Scan(&name); err != nil || name != "private-marker" {
		t.Fatal(name, err)
	}
	if _, err := openCipherDB(backup, bytes.Repeat([]byte{0x63}, 32), true); err == nil {
		t.Fatal("backup accepted wrong key")
	}
	// Every replacement physical connection must receive its key.
	s.DB.SetMaxIdleConns(0)
	for i := 0; i < 3; i++ {
		if err := s.DB.QueryRow(`SELECT disabled_reason FROM users WHERE id=1`).Scan(&name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCipherPlaintextMigrationAndBackup(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO users(username,name) VALUES('legacy','legacy-secret'); PRAGMA user_version=42;`); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x64}, 32)
	if _, err := OpenEncrypted(dir, key, true); err == nil {
		t.Fatal("implicitly migrated plaintext")
	}
	destination := filepath.Join(dir, "encrypted.db")
	// Source has committed WAL data and remains open: export must preserve it.
	if err := ExportDatabase(s.Path, destination, nil, key); err != nil {
		t.Fatal(err)
	}
	rollback := filepath.Join(dir, "rollback.db")
	if err := SnapshotPlaintext(s.Path, rollback); err != nil {
		t.Fatal(err)
	}
	if counts, err := VerifyDatabase(rollback, nil); err != nil || counts["users"] != 1 {
		t.Fatal(counts, err)
	}
	s.DB.Close()
	verify, err := openCipherDB(destination, key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer verify.Close()
	var name string
	var version int
	if err := verify.QueryRow(`SELECT name FROM users WHERE username='legacy'`).Scan(&name); err != nil || name != "legacy-secret" {
		t.Fatal(name, err)
	}
	if err := verify.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 42 {
		t.Fatal(version, err)
	}
	before, _ := os.ReadFile(destination)
	if err := ExportDatabase(filepath.Join(dir, "sendora.db"), destination, nil, key); err == nil {
		t.Fatal("overwrote export")
	}
	after, _ := os.ReadFile(destination)
	if !bytes.Equal(before, after) {
		t.Fatal("existing destination changed")
	}
}

func TestCipherSecretFileValidation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, bytes.Repeat([]byte{0x65}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDatabaseKey(p); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, 0644)
	if _, err := ReadDatabaseKey(p); err == nil {
		t.Fatal("world-readable key")
	}
	os.Chmod(p, 0600)
	os.WriteFile(p, []byte("bad key"), 0600)
	if _, err := ReadDatabaseKey(p); err == nil {
		t.Fatal("short key")
	}
	if _, err := ReadDatabaseKey(""); err == nil {
		t.Fatal("missing key accepted")
	}
}
