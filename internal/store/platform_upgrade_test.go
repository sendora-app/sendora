// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
)

// A platform database left by 0.2 (plaintext setting values, no keys) is
// refused with a hint naming the -platform conversion, and that conversion
// makes it open again with the values intact.
func TestLegacyPlatformDatabaseIsRefusedAndUpgraded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	key := colKey(3)
	s, err := OpenPlatform(dir, key, true, sqlite.PlatformSchema)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.PlatformRepo().PlatformSettings().EnsureDefault(ctx, "smtp_password", "plain smtp secret", "smtp"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.DB.Query(`SELECT key FROM settings WHERE value<>''`)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for rows.Next() {
		var k string
		rows.Scan(&k)
		keys = append(keys, k)
	}
	rows.Close()
	for _, k := range keys {
		v, err := s.PlatformRepo().PlatformSettings().Get(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(`UPDATE settings SET value=? WHERE key=?`, v, k); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{`DROP TABLE control_log`, `DROP TABLE tenant_keyring`} {
		if _, err := s.DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	_, err = OpenPlatform(dir, key, false, sqlite.PlatformSchema)
	if !errors.Is(err, ErrLegacyColumns) || !strings.Contains(err.Error(), "upgrade-encryption -platform -data-dir") {
		t.Fatalf("a legacy platform database: %v", err)
	}
	n, err := UpgradePlatformColumnEncryption(dir, key, sqlite.PlatformSchema)
	if err != nil || n != len(keys) {
		t.Fatalf("upgrade = %d (want %d settings), %v", n, len(keys), err)
	}
	s, err = OpenPlatform(dir, key, false, sqlite.PlatformSchema)
	if err != nil {
		t.Fatalf("open after the upgrade: %v", err)
	}
	defer s.Close()
	if v, err := s.PlatformRepo().PlatformSettings().Get(ctx, "smtp_password"); err != nil || v != "plain smtp secret" {
		t.Fatalf("after the upgrade: %q, %v", v, err)
	}
	var raw string
	s.DB.QueryRow(`SELECT value FROM settings WHERE key='smtp_password'`).Scan(&raw)
	if !strings.HasPrefix(raw, "e1:") {
		t.Fatalf("the table holds %q after the upgrade", raw)
	}
	if n, err := UpgradePlatformColumnEncryption(dir, key, sqlite.PlatformSchema); err != nil || n != 0 {
		t.Fatalf("a second upgrade: %d, %v", n, err)
	}
}
