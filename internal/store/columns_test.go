// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

func colKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// newShare creates a share with a description through the repository layer and
// returns its id.
func newShare(t *testing.T, s *Store, long, desc string) int64 {
	t.Helper()
	ctx := context.Background()
	uid, err := s.Repos().Users().Create(ctx, ports.NewUser{Username: "u-" + long, Name: "u", Email: long + "@example.org", PasswordHash: "h", Language: "en", UILanguage: "en", PasswordChangedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Repos().Shares().Create(ctx, ports.NewShare{UserID: uid, LongID: long, Name: "n", Description: desc, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// plainSettings turns the sealed setting values into plaintext, as a database
// from before column encryption holds them, and returns how many it changed.
func plainSettings(t *testing.T, s *Store) int {
	t.Helper()
	rows, err := s.DB.Query(`SELECT key FROM settings WHERE value<>''`)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	rows.Close()
	for _, k := range keys {
		v, err := s.Repos().Settings().Get(context.Background(), k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(`UPDATE settings SET value=? WHERE key=?`, v, k); err != nil {
			t.Fatal(err)
		}
	}
	return len(keys)
}

func rawDescription(t *testing.T, s *Store, id int64) string {
	t.Helper()
	var v string
	if err := s.DB.QueryRow(`SELECT description FROM shares WHERE id=?`, id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNewDatabaseCreatesKeysAndEncrypts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s, err := OpenEncrypted(dir, colKey(1), true)
	if err != nil {
		t.Fatal(err)
	}
	id := newShare(t, s, "a", "secret description")
	if raw := rawDescription(t, s, id); !strings.HasPrefix(raw, "e1:") || strings.Contains(raw, "secret") {
		t.Fatalf("the table holds %q", raw)
	}
	var events int
	s.DB.QueryRow(`SELECT COUNT(*) FROM control_log`).Scan(&events)
	if events == 0 {
		t.Fatal("a new database has no control log")
	}
	s.Close()

	// Reopening verifies the log and the value still opens.
	s, err = OpenEncrypted(dir, colKey(1), false)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	if got, err := s.Repos().Shares().ByID(context.Background(), id); err != nil || got.Description != "secret description" {
		t.Fatalf("after reopening: %q, %v", got.Description, err)
	}
}

func TestTamperedControlLogRefusesToOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s, err := OpenEncrypted(dir, colKey(1), true)
	if err != nil {
		t.Fatal(err)
	}
	// An attacker with write access to the decrypted database forges a key event.
	if _, err := s.DB.Exec(`UPDATE control_log SET body = body || x'00' WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := OpenEncrypted(dir, colKey(1), false); err == nil || !strings.Contains(err.Error(), "do not verify") {
		t.Fatalf("a tampered control log opened: %v", err)
	}
}

func TestLegacyDatabaseIsRefusedAndUpgraded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s, err := OpenEncrypted(dir, colKey(2), true)
	if err != nil {
		t.Fatal(err)
	}
	id := newShare(t, s, "legacy", "")
	// Turn it into what 0.2 left behind: plaintext in the column, no keys.
	if _, err := s.DB.Exec(`UPDATE shares SET description='plain old description',name='plain old name',long_id='legacy' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE users SET username='u-legacy',name='u',email='legacy@example.org',password_hash='h' WHERE id=(SELECT user_id FROM shares WHERE id=?)`, id); err != nil {
		t.Fatal(err)
	}
	settings := plainSettings(t, s)
	if _, err := s.DB.Exec(`DROP TABLE control_log`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DROP TABLE tenant_keyring`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := OpenEncrypted(dir, colKey(2), false); !errors.Is(err, ErrLegacyColumns) {
		t.Fatalf("a legacy database opened: %v", err)
	}
	n, err := UpgradeColumnEncryption(dir, colKey(2), nil)
	if err != nil || n != 7+settings {
		t.Fatalf("upgrade = %d (want 7 columns of the rows and %d settings), %v", n, settings, err)
	}
	s, err = OpenEncrypted(dir, colKey(2), false)
	if err != nil {
		t.Fatalf("open after the upgrade: %v", err)
	}
	defer s.Close()
	if got, _ := s.Repos().Shares().ByID(context.Background(), id); got.Description != "plain old description" || got.Name != "plain old name" {
		t.Fatalf("after the upgrade: %q", got.Description)
	}
	if raw := rawDescription(t, s, id); !strings.HasPrefix(raw, "e1:") || strings.Contains(raw, "plain old") {
		t.Fatalf("the table holds %q after the upgrade", raw)
	}
	if n, err := UpgradeColumnEncryption(dir, colKey(2), nil); err == nil && n != 0 {
		t.Fatalf("a second upgrade converted %d values", n)
	}
}

// Re-keying a database (import, restore, key change) re-keys the column layer:
// the values survive under the new key, and the copy does not verify under the
// old one.
func TestExportUnderAnotherKeyReKeysTheColumns(t *testing.T) {
	root := t.TempDir()
	srcDir := filepath.Join(root, "src")
	s, err := OpenEncrypted(srcDir, colKey(3), true)
	if err != nil {
		t.Fatal(err)
	}
	id := newShare(t, s, "moved", "survives the re-key")
	src := s.Path
	s.Close()

	dstDir := filepath.Join(root, "dst")
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dst, err := DBPath(dstDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ExportDatabase(src, dst, colKey(3), colKey(4)); err != nil {
		t.Fatalf("export: %v", err)
	}
	d, err := OpenEncrypted(dstDir, colKey(4), false)
	if err != nil {
		t.Fatalf("open the copy: %v", err)
	}
	defer d.Close()
	if got, err := d.Repos().Shares().ByID(context.Background(), id); err != nil || got.Description != "survives the re-key" {
		t.Fatalf("copy: %q, %v", got.Description, err)
	}
	if raw := rawDescription(t, d, id); !strings.HasPrefix(raw, "e1:") || strings.Contains(raw, "survives") {
		t.Fatalf("the copy holds %q", raw)
	}
}
