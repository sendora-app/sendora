// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// The documentation (wiki "Encryption") states the cipher parameters of the
// database. This test pins them against the real engine so the text cannot
// drift from what is actually used.
func TestDatabaseCipherParametersMatchDocumentation(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	st, err := OpenEncrypted(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	pragma := func(name string) string {
		t.Helper()
		var v string
		if err := st.DB.QueryRow("PRAGMA " + name).Scan(&v); err != nil {
			t.Fatalf("PRAGMA %s: %v", name, err)
		}
		return v
	}
	for name, want := range map[string]string{
		"cipher_page_size":      "4096",
		"cipher_hmac_algorithm": "HMAC_SHA512",
		"cipher_kdf_algorithm":  "PBKDF2_HMAC_SHA512",
		"cipher_use_hmac":       "1",
		"cipher_provider":       "openssl",
	} {
		if got := pragma(name); got != want {
			t.Errorf("%s = %q, documented %q", name, got, want)
		}
	}
	if got := pragma("cipher_plaintext_header_size"); got != "0" {
		t.Errorf("plaintext header size = %q: the file must have no readable header", got)
	}
	if v := pragma("cipher_version"); len(v) < 6 || v[:6] != "4.20.0" {
		t.Errorf("cipher_version = %q, documented 4.20.0", v)
	}
	if _, err := st.DB.Exec(`CREATE TABLE IF NOT EXISTS probe(x TEXT); INSERT INTO probe VALUES('PROBE-MARKER-123')`); err != nil {
		t.Fatal(err)
	}
	st.DB.Exec(`PRAGMA wal_checkpoint(FULL)`)
	st.Close()

	b, err := os.ReadFile(filepath.Join(dir, "sendora.db"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b)%4096 != 0 {
		t.Errorf("database size %d is not a multiple of the 4096-byte page size", len(b))
	}
	if bytes.HasPrefix(b, []byte("SQLite format 3\x00")) || bytes.Contains(b, []byte("PROBE-MARKER-123")) {
		t.Error("database is readable without the key")
	}

	// A new database with the same key gets its own random salt (first 16 bytes).
	dir2 := t.TempDir()
	st2, err := OpenEncrypted(dir2, key, true)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()
	b2, _ := os.ReadFile(filepath.Join(dir2, "sendora.db"))
	if bytes.Equal(b[:16], b2[:16]) {
		t.Error("two databases share the same salt")
	}
}

// A wrong key must be reported as a key problem. It used to be reported as a
// missing SQLCipher engine, which sent operators looking in the wrong place.
func TestWrongOrMissingKeyIsReportedAsKeyProblem(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenEncrypted(dir, bytes.Repeat([]byte{1}, 32), true)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	for name, key := range map[string][]byte{"wrong key": bytes.Repeat([]byte{2}, 32), "no key": nil} {
		_, err := OpenEncrypted(dir, key, false)
		if err == nil {
			t.Fatalf("%s: database opened", name)
		}
		if err == errEngineUnavailable {
			t.Fatalf("%s: reported as a missing engine: %v", name, err)
		}
	}
	if _, err := OpenEncrypted(dir, bytes.Repeat([]byte{2}, 32), false); err != errCannotRead {
		t.Fatalf("wrong key error = %v, want %v", err, errCannotRead)
	}
}
