// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"testing"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
)

// TestRemoteStoreSkipsSQLiteStartupMigration: a store opened with OpenRemote
// (Cluster flavour) has no SQLite handle; the startup migration the server
// runs (MigrateVerificationAttempts) must not touch the nil handle (it
// panicked with a nil pointer dereference while a tenant server opened).
func TestRemoteStoreSkipsSQLiteStartupMigration(t *testing.T) {
	root := make([]byte, 32)
	s, err := OpenRemote(sqlite.New(nil), t.TempDir(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Remote() {
		t.Fatal("OpenRemote store does not report Remote")
	}
	if err := s.MigrateVerificationAttempts(); err != nil {
		t.Fatal(err)
	}
}
