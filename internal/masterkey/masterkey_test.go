// SPDX-License-Identifier: AGPL-3.0-or-later

package masterkey

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, p string, b byte) {
	t.Helper()
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	if err := os.WriteFile(p, k, 0o400); err != nil {
		t.Fatal(err)
	}
}

func TestSingleFileIsVersionOne(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	write(t, p, 1)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if vs := s.Versions(); len(vs) != 1 || vs[0] != 1 || s.Highest() != 1 {
		t.Fatalf("versions %v", vs)
	}
	if _, err := s.Key(2); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("version 2: %v", err)
	}
}

func TestDirectoryVersionsAndHotAdd(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "master-1"), 1)
	write(t, filepath.Join(d, "ignored"), 9)
	s, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if s.Has(2) {
		t.Fatal("version 2 before it exists")
	}
	write(t, filepath.Join(d, "master-2"), 2) // mounted later: found by the lookup's reload
	k, err := s.Key(2)
	if err != nil || k[0] != 2 {
		t.Fatalf("version 2: %v %v", k, err)
	}
	clear(k)
	if k2, _ := s.Key(2); k2[0] != 2 {
		t.Fatal("the caller's clear reached the stored key")
	}
	if s.Highest() != 2 {
		t.Fatalf("highest %d", s.Highest())
	}
	os.Remove(filepath.Join(d, "master-1")) // retired and removed
	if err := s.Reload(); err != nil || s.Has(1) {
		t.Fatalf("reload after removal: %v has1=%v", err, s.Has(1))
	}
}

func TestEmptyDirectoryAndBadFile(t *testing.T) {
	d := t.TempDir()
	if _, err := Load(d); err == nil {
		t.Fatal("empty directory accepted")
	}
	if err := os.WriteFile(filepath.Join(d, "master-1"), []byte("short"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(d); err == nil {
		t.Fatal("a short key was accepted")
	}
}
