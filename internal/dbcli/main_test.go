// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sendora-app/sendora/internal/filecrypt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

func TestEncryptedBackupCommand(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x75}, 32)
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenEncrypted(filepath.Join(dir, "data"), key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	if _, err := st.DB.Exec(`INSERT INTO users(username) VALUES('backup-test')`); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "backup.db")
	args := []string{"backup", "-source", st.Path, "-destination", destination, "-key-file", keyFile}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	counts, err := store.VerifyDatabase(destination, key)
	if err != nil || counts["users"] != 1 {
		t.Fatal(counts, err)
	}
	if _, err := store.VerifyDatabase(destination, nil); err == nil {
		t.Fatal("unencrypted backup")
	}
	original, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(args); err == nil {
		t.Fatal("overwrote existing backup")
	}
	current, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(original, current) {
		t.Fatal("existing backup changed", err)
	}
}

func TestMFAResetCommand(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x42}, 32)
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenEncrypted(filepath.Join(dir, "data"), key, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users(id,username) VALUES(1,'locked'),(2,'bystander')`,
		`INSERT INTO user_totp(user_id,secret,confirmed) VALUES(1,'S',1),(2,'S',1)`,
		`INSERT INTO user_recovery_codes(user_id,code_hash) VALUES(1,'a'),(2,'b')`,
		`INSERT INTO user_webauthn(user_id,cred_id,public_key,alg) VALUES(1,x'01',x'02',-7)`,
		`INSERT INTO refresh_tokens(hash,user_id,expires_at) VALUES('h1',1,'2099-01-01'),('h2',2,'2099-01-01')`,
		`UPDATE users SET login_failures=5,login_locked_until=4102444800 WHERE id=1`,
	} {
		if _, err := st.DB.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	// Seal the rows written with raw SQL (the legacy upgrade path).
	if _, err := sqlite.New(st.DB).EncryptPlaintextColumns(context.Background(), st.ColumnCodec()); err != nil {
		t.Fatal(err)
	}
	path := st.Path
	st.DB.Close()
	args := []string{"mfa-reset", "-source", path, "-key-file", keyFile, "-user"}
	if err := run(append(args, "nobody")); err == nil {
		t.Fatal("unknown user must fail")
	}
	if err := run(args[:len(args)-1]); err == nil {
		t.Fatal("user is required")
	}
	if err := run(append(args, "locked")); err != nil {
		t.Fatal(err)
	}
	st, err = store.OpenEncrypted(filepath.Join(dir, "data"), key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	count := func(q string) int {
		var n int
		if err := st.DB.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(`SELECT COUNT(*) FROM user_totp WHERE user_id=1`)+count(`SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=1`)+count(`SELECT COUNT(*) FROM user_webauthn WHERE user_id=1`)+count(`SELECT COUNT(*) FROM refresh_tokens WHERE user_id=1`) != 0 {
		t.Fatal("the user's factors and sessions must be gone")
	}
	if count(`SELECT COUNT(*) FROM users WHERE id=1 AND login_failures=0 AND login_locked_until=0 AND mfa_epoch=1`) != 1 {
		t.Fatal("the lock is cleared and the epoch bumped")
	}
	if count(`SELECT COUNT(*) FROM user_totp WHERE user_id=2`)+count(`SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=2`)+count(`SELECT COUNT(*) FROM refresh_tokens WHERE user_id=2`) != 3 {
		t.Fatal("other users must be untouched")
	}
	// Wrong key never modifies anything.
	bad := filepath.Join(dir, "badkey")
	os.WriteFile(bad, bytes.Repeat([]byte{0x43}, 32), 0600)
	if err := run([]string{"mfa-reset", "-source", path, "-key-file", bad, "-user", "bystander"}); err == nil {
		t.Fatal("wrong key must fail")
	}
}

func TestVerifyFilesCommand(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x33}, 32)
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	st, err := store.OpenEncrypted(data, key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	lid := "bbbbbbbbbbbbbbbb"
	seedShare(t, st, lid, "SHARE-NAME-X")
	if err := os.MkdirAll(filepath.Join(data, "shares", lid), 0700); err != nil {
		t.Fatal(err)
	}
	plain := []byte("verify me")
	stored, encID := encryptForTest(t, st, plain)
	disk := filepath.Join(data, "shares", lid, "0_f.txt")
	if err := os.WriteFile(disk, stored, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plain)
	seedFile(t, st, "f.txt", int64(len(plain)), disk, hex.EncodeToString(sum[:]), encID)
	args := []string{"verify-files", "-source", st.Path, "-key-file", keyFile, "-data-dir", data, "-json"}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	// Flip one ciphertext bit: the command must fail in both output modes.
	b := stored
	b[len(b)-1] ^= 1
	if err := os.WriteFile(disk, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(args); err == nil {
		t.Fatal("tampered file did not fail verify-files")
	}
	if err := run([]string{"verify-files", "-source", st.Path, "-key-file", keyFile, "-data-dir", data}); err == nil {
		t.Fatal("text mode must fail as well")
	}
}

// captureVerify runs a command with stdout and stderr captured.
func captureVerify(t *testing.T, terminal bool, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	oldOut, oldErr, oldTerm, oldEvery := stdout, stderr, stderrIsTerminal, progressEvery
	stdout, stderr, stderrIsTerminal, progressEvery = &out, &errOut, func() bool { return terminal }, 2
	defer func() { stdout, stderr, stderrIsTerminal, progressEvery = oldOut, oldErr, oldTerm, oldEvery }()
	err := run(args)
	return out.String(), errOut.String(), err
}

func TestVerifyFilesOutputModes(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x34}, 32)
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	st, err := store.OpenEncrypted(data, key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	lid := "cccccccccccccccc"
	seedShare(t, st, lid, "SHARE-NAME-Y")
	os.MkdirAll(filepath.Join(data, "shares", lid, "nested-dir"), 0700)
	var bad int64
	for i := 0; i < 5; i++ {
		plain := []byte(fmt.Sprintf("content %d", i))
		b, encID := encryptForTest(t, st, plain)
		if i == 3 {
			b[len(b)-1] ^= 1
		}
		disk := filepath.Join(data, "shares", lid, fmt.Sprintf("%d_SECRET-FILE-%d", i, i))
		os.WriteFile(disk, b, 0600)
		sum := sha256.Sum256(plain)
		id := seedFile(t, st, filepath.Base(disk), int64(len(plain)), disk, hex.EncodeToString(sum[:]), encID)
		if i == 3 {
			bad = id
		}
	}
	os.WriteFile(filepath.Join(data, "shares", lid, "SECRET-STRAY"), []byte("x"), 0600)
	base := []string{"verify-files", "-source", st.Path, "-key-file", keyFile, "-data-dir", data}

	// Default: only problems, then the summary. No names, no progress off a terminal.
	out, errOut, err := captureVerify(t, false, base...)
	if err == nil {
		t.Fatal("problems must fail the command")
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], fmt.Sprintf("file id=%d ", bad)) || !strings.Contains(lines[0], "tag-fail@chunk0") ||
		!strings.HasPrefix(lines[1], "orphan path=") || !strings.HasPrefix(lines[2], "summary rows=5 encrypted=5 plain=0 ok=4 plain-legacy=0 legacy-key=0 failed=1 orphans=1") {
		t.Fatalf("default output:\n%s", out)
	}
	if errOut != "" || strings.Contains(out, "SECRET") || strings.Contains(out, "nested-dir") {
		t.Fatalf("leak or unexpected stderr: %q / %q", out, errOut)
	}

	// -all lists every row in id order.
	out, _, _ = captureVerify(t, false, append(base, "-all")...)
	lines = strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 7 {
		t.Fatalf("-all output:\n%s", out)
	}
	for i := 0; i < 5; i++ {
		if !strings.HasPrefix(lines[i], fmt.Sprintf("file id=%d ", i+1)) {
			t.Fatalf("-all line %d: %s", i, lines[i])
		}
	}

	// -json: JSON Lines, one object per reported row and orphan, then the summary.
	out, _, _ = captureVerify(t, false, append(base, "-json", "-all")...)
	lines = strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 7 {
		t.Fatalf("-json output:\n%s", out)
	}
	types := ""
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not a JSON line: %s", l)
		}
		types += m["type"].(string)[:1]
		if m["type"] == "summary" && (m["rows"] != 5.0 || m["failed"] != 1.0 || m["orphans"] != 1.0) {
			t.Fatalf("summary %s", l)
		}
	}
	if types != "fffffos" {
		t.Fatalf("object types %q", types)
	}
	if strings.Contains(out, "SECRET") {
		t.Fatal("json leaks names")
	}
	out, _, _ = captureVerify(t, false, append(base, "-json")...)
	if n := len(strings.Split(strings.TrimSpace(out), "\n")); n != 3 {
		t.Fatalf("-json without -all: %d lines\n%s", n, out)
	}

	// -names adds names; -progress reports on stderr.
	out, errOut, _ = captureVerify(t, false, append(base, "-names", "-progress")...)
	if !strings.Contains(out, "SECRET-FILE-3") || !strings.Contains(out, "SECRET-STRAY") {
		t.Fatalf("-names output:\n%s", out)
	}
	if errOut != "verify-files: 2/5 files checked\nverify-files: 4/5 files checked\nverify-files: 5/5 files checked\n" {
		t.Fatalf("progress %q", errOut)
	}
	// On a terminal progress is shown without -progress, on one line.
	_, errOut, _ = captureVerify(t, true, base...)
	if !strings.HasPrefix(errOut, "\rverify-files: 2/5") || !strings.HasSuffix(errOut, "5/5 files checked\n") {
		t.Fatalf("terminal progress %q", errOut)
	}
}

// seedShare creates an owner and a share of that name through the repository
// (the name is an encrypted column, bound to its row).
func seedShare(t *testing.T, st *store.Store, longID, name string) {
	t.Helper()
	uid, err := st.Repos().Users().Create(context.Background(), ports.NewUser{Username: "owner-" + longID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Repos().Shares().Create(context.Background(), ports.NewShare{UserID: uid, LongID: longID, Name: name, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

// seedFile adds an encrypted file row to share 1 through the repository.
func seedFile(t *testing.T, st *store.Store, name string, size int64, disk, sum, encID string) int64 {
	t.Helper()
	id, err := st.Repos().Shares().AddFile(context.Background(), ports.NewShareFile{ShareID: 1, Name: name, FullPath: name, Size: size,
		DiskPath: disk, SHA256: sum, Integrity: "server_baseline", Encrypted: true, EncID: encID})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// encryptForTest encrypts plain under the store's active files key and
// returns the stored bytes and the files.enc_id value.
func encryptForTest(t *testing.T, st *store.Store, plain []byte) ([]byte, string) {
	t.Helper()
	master, ver, err := st.NewFileKey()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, id, err := filecrypt.Encrypt(&out, bytes.NewReader(plain), master, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), store.EncRef(id, ver)
}
