// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"path/filepath"
	"testing"

	"github.com/sendora-app/sendora/internal/store"
)

func TestLocalJoin(t *testing.T) {
	root := filepath.Join(t.TempDir(), "backgrounds")
	for _, name := range []string{"abc123.png", "logo.svg", "sub/file.txt", "."} {
		p, err := localJoin(root, name)
		if err != nil || p != filepath.Join(root, name) {
			t.Errorf("localJoin(%q) = %q, %v", name, p, err)
		}
	}
	for _, name := range []string{"", "..", "../x", "a/../../x", "a..b", "/etc/passwd", "sub/../x"} {
		if p, err := localJoin(root, name); err == nil {
			t.Errorf("localJoin(%q) accepted: %q", name, p)
		}
	}
}

func TestUploadDirRejectsInvalidIDs(t *testing.T) {
	dataDir := t.TempDir()
	s := &Server{St: &store.Store{DataDir: dataDir}}
	invalid := filepath.Join(dataDir, "uploads", ".invalid-session")
	for _, id := range []string{"", "..", "../x", "ABCDEF0123456789", "0123456789abcdef/../x"} {
		if got := s.uploadDir(id); got != invalid {
			t.Errorf("uploadDir(%q) = %q", id, got)
		}
	}
	if got := s.uploadDir("0123456789abcdef"); got != filepath.Join(dataDir, "uploads", "0123456789abcdef") {
		t.Errorf("uploadDir(valid) = %q", got)
	}
}
