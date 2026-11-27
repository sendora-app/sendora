// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/ports"
)

const vfLongID = "aaaaaaaaaaaaaaaa"

type vfEnv struct {
	t      *testing.T
	st     *Store
	key    []byte
	master []byte // the active files key (new files)
	ver    int
	legacy []byte // the old root-derived key (v1 and legacy files)
	dir    string
}

// seedShare creates an owner and a share of that name through the repository
// (the name is an encrypted column, bound to its row).
func seedShare(t *testing.T, st *Store, longID, name string) {
	t.Helper()
	uid, err := st.Repos().Users().Create(context.Background(), ports.NewUser{Username: "owner-" + longID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Repos().Shares().Create(context.Background(), ports.NewShare{UserID: uid, LongID: longID, Name: name, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func newVFEnv(t *testing.T) *vfEnv {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	st, err := OpenEncrypted(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	seedShare(t, st, vfLongID, "SECRET-SHARE-NAME")
	master, ver, err := st.NewFileKey()
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := filecrypt.MasterKey(key)
	if err := os.MkdirAll(filepath.Join(dir, "shares", vfLongID), 0o700); err != nil {
		t.Fatal(err)
	}
	return &vfEnv{t: t, st: st, key: key, master: master, ver: ver, legacy: legacy, dir: dir}
}

func (e *vfEnv) disk(base string) string { return filepath.Join(e.dir, "shares", vfLongID, base) }

// add writes a file and its row. kind: v2 | legacy (v2 format, root key) | v1 | plain.
func (e *vfEnv) add(base, kind string, plain []byte) (id int64, stored []byte) {
	e.t.Helper()
	sum := sha256.Sum256(plain)
	encID := ""
	switch kind {
	case "v2":
		var out bytes.Buffer
		_, encID, _ = filecrypt.Encrypt(&out, bytes.NewReader(plain), e.master, nil)
		encID = EncRef(encID, e.ver)
		stored = out.Bytes()
	case "legacy":
		var out bytes.Buffer
		_, encID, _ = filecrypt.Encrypt(&out, bytes.NewReader(plain), e.legacy, nil)
		stored = out.Bytes()
	case "v1":
		stored = sealV1(e.t, e.legacy, plain)
	default:
		stored = plain
	}
	if err := os.WriteFile(e.disk(base), stored, 0o600); err != nil {
		e.t.Fatal(err)
	}
	enc := 0
	if kind != "plain" {
		enc = 1
	}
	id, err := e.st.Repos().Shares().AddFile(context.Background(), ports.NewShareFile{ShareID: 1, Name: base, FullPath: "SECRET-" + base,
		Size: int64(len(plain)), DiskPath: "/old/" + base, SHA256: hex.EncodeToString(sum[:]), Integrity: "server_baseline", Encrypted: enc == 1, EncID: encID})
	if err != nil {
		e.t.Fatal(err)
	}
	return id, stored
}

// sealV1 writes the 0.1.2 - 0.1.4 layout independently of the filecrypt package.
func sealV1(t *testing.T, master, plain []byte) []byte {
	t.Helper()
	salt := make([]byte, 32)
	rand.Read(salt)
	k, _ := hkdf.Key(sha256.New, master, salt, "sendora share file key", 32)
	blk, _ := aes.NewCipher(k)
	aead, _ := cipher.NewGCM(blk)
	out := append([]byte("SNDF\x01"), salt...)
	const cs = filecrypt.ChunkSize
	chunks := (len(plain) + cs - 1) / cs
	if chunks == 0 {
		chunks = 1
	}
	for i := 0; i < chunks; i++ {
		n := make([]byte, 12)
		binary.BigEndian.PutUint64(n[4:], uint64(i))
		last := byte(0)
		if i == chunks-1 {
			last = 1
		}
		out = aead.Seal(out, n, plain[i*cs:min((i+1)*cs, len(plain))], []byte{last})
	}
	return out
}

func statuses(t *testing.T, rep *FilesReport) map[int64]string {
	m := map[int64]string{}
	for _, f := range rep.Files {
		m[f.ID] = f.Status
	}
	return m
}

func TestVerifyFilesStatuses(t *testing.T) {
	e := newVFEnv(t)
	big := make([]byte, filecrypt.ChunkSize+10)
	rand.Read(big)
	okV2, _ := e.add("ok2", "v2", []byte("hello v2"))
	okV1, _ := e.add("ok1", "v1", []byte("hello v1"))
	legacy, _ := e.add("plain", "plain", []byte("legacy plain"))
	empty, _ := e.add("empty", "v2", nil)

	badHdr, _ := e.add("badhdr", "v2", []byte("x"))
	os.WriteFile(e.disk("badhdr"), []byte("not an encrypted file at all, just some text bytes!!"), 0o600)

	sizeMiss, st := e.add("size", "v2", big)
	os.WriteFile(e.disk("size"), st[:len(st)-5], 0o600)

	idMiss, _ := e.add("idA", "v2", []byte("same size AAAA"))
	idB, other := e.add("idB", "v2", []byte("same size BBBB"))
	os.WriteFile(e.disk("idA"), other, 0o600)

	tag, st := e.add("tag", "v2", big)
	st[53+filecrypt.ChunkSize+16+3] ^= 1 // inside chunk 1
	os.WriteFile(e.disk("tag"), st, 0o600)

	shaMiss, _ := e.add("sha", "v2", []byte("sha row"))
	sealed, err := e.st.codec.Seal("files", "sha256", strconv.FormatInt(shaMiss, 10), strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	e.st.DB.Exec(`UPDATE files SET sha256=? WHERE id=?`, sealed, shaMiss)

	missing, _ := e.add("gone", "v2", []byte("gone"))
	os.Remove(e.disk("gone"))

	emptyTag, st := e.add("emptytag", "v2", nil)
	st[len(st)-1] ^= 1
	os.WriteFile(e.disk("emptytag"), st, 0o600)

	os.WriteFile(e.disk("stray"), []byte("orphan"), 0o600)
	// A directory inside a share directory is not a stored file: no orphan.
	os.MkdirAll(e.disk("subdir"), 0o700)
	os.WriteFile(filepath.Join(e.disk("subdir"), "inner"), []byte("x"), 0o600)

	rep, err := VerifyFiles(e.st.Path, e.dir, e.key, false)
	if err != nil {
		t.Fatal(err)
	}
	got := statuses(t, rep)
	want := map[int64]string{
		okV2: "ok", okV1: "legacy-key", idB: "ok", empty: "ok", legacy: "plain-legacy", badHdr: "bad-header",
		sizeMiss: "size-mismatch", idMiss: "id-mismatch", tag: "tag-fail@chunk1", shaMiss: "sha-mismatch",
		missing: "missing", emptyTag: "tag-fail@chunk0",
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("row %d: %q, want %q", id, got[id], w)
		}
	}
	s := rep.Summary
	if s.Rows != len(want) || s.Plain != 1 || s.Encrypted != len(want)-1 || s.OK != 3 || s.LegacyKey != 1 || s.Legacy != 1 || s.Failed != 7 || s.Orphans != 1 {
		t.Errorf("summary %+v", s)
	}
	if rep.Failures() != 8 {
		t.Errorf("failures %d", rep.Failures())
	}

	// Output never contains names, keys or key-derived bytes, and ids/paths are hashed.
	b, _ := json.Marshal(rep)
	for _, secret := range []string{"SECRET", "stray", "ok2", vfLongID, hex.EncodeToString(e.key), hex.EncodeToString(e.master)} {
		if strings.Contains(string(b), secret) {
			t.Errorf("report leaks %q", secret)
		}
	}
	named, _ := VerifyFiles(e.st.Path, e.dir, e.key, true)
	b, _ = json.Marshal(named)
	if !strings.Contains(string(b), "SECRET-SHARE-NAME") || !strings.Contains(string(b), "stray") {
		t.Error("-names did not add names")
	}

	// The report matches the live counters.
	enc, err := e.st.EncryptionStatus()
	if err != nil || enc.Encrypted != int64(s.Encrypted) || enc.Plain != 1 {
		t.Errorf("EncryptionStatus %+v %v", enc, err)
	}
}

func TestVerifyFilesWrongKey(t *testing.T) {
	e := newVFEnv(t)
	if _, err := VerifyFiles(e.st.Path, e.dir, make([]byte, 32), false); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestKeyFingerprint(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	a := KeyFingerprint(k1)
	if len(a) != 16 || a != KeyFingerprint(k1) || a == KeyFingerprint(k2) {
		t.Fatalf("fingerprint %q", a)
	}
	if strings.Contains(a, hex.EncodeToString(k1[:4])) {
		t.Fatal("fingerprint exposes the key")
	}
	e := newVFEnv(t)
	if e.st.KeyFingerprint() != KeyFingerprint(e.key) || !strings.HasPrefix(e.st.CipherVersion(), "4.20.0") {
		t.Fatal("store fingerprint or cipher version")
	}
}

// The streaming form checks rows in parallel but reports them in row id order,
// with the same verdicts as a single worker, and reports progress.
func TestVerifyFilesStreamOrder(t *testing.T) {
	e := newVFEnv(t)
	bad := map[int64]bool{}
	for i := 0; i < 60; i++ {
		plain := make([]byte, 100+i*37)
		rand.Read(plain)
		name := fmt.Sprintf("f%02d", i)
		id, st := e.add(name, "v2", plain)
		if i%7 == 3 {
			st[len(st)-1] ^= 1
			os.WriteFile(e.disk(name), st, 0o600)
			bad[id] = true
		}
	}
	collect := func(workers int) ([]FileCheck, FilesSummary, []int) {
		var got []FileCheck
		var progress []int
		sum, err := VerifyFilesStream(e.st.Path, e.dir, e.key, VerifyOptions{
			Workers:  workers,
			File:     func(c FileCheck) { got = append(got, c) },
			Progress: func(done, total int) { progress = append(progress, done*1000+total) },
		})
		if err != nil {
			t.Fatal(err)
		}
		return got, sum, progress
	}
	one, sum1, _ := collect(1)
	many, sum4, progress := collect(4)
	if len(many) != 60 || sum1 != sum4 || sum4.Failed != len(bad) || sum4.OK != 60-len(bad) {
		t.Fatalf("summary %+v vs %+v (%d rows)", sum4, sum1, len(many))
	}
	for i := range many {
		if i > 0 && many[i].ID <= many[i-1].ID {
			t.Fatalf("rows out of order at %d", i)
		}
		if many[i] != one[i] {
			t.Fatalf("row %d differs between 1 and 4 workers: %+v %+v", i, many[i], one[i])
		}
		if many[i].Problem() != bad[many[i].ID] {
			t.Fatalf("row %d: %s", many[i].ID, many[i].Status)
		}
	}
	if len(progress) != 60 || progress[0] != 1060 || progress[59] != 60060 {
		t.Fatalf("progress %v", progress)
	}
}
