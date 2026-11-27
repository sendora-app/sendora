// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/store"
)

// newEncryptedEnv is newEnv on the production opener: SQLCipher database and
// encrypted share files, exactly as a real installation runs.
func newEncryptedEnv(t *testing.T) *env {
	t.Helper()
	t.Setenv("SENDORA_DISABLE_IP_BANS", "true")
	liftDownloadMailThrottle(t)
	key := make([]byte, 32)
	rand.Read(key)
	st, err := store.OpenEncrypted(t.TempDir(), key, true)
	if err != nil {
		t.Fatal(err)
	}
	legacyTestDefaults(t, st)
	t.Cleanup(func() { st.DB.Close() })
	if k, v, err := st.NewFileKey(); err != nil || k == nil || v != 1 {
		t.Fatalf("encrypted store has no file key: %v v%d %v", k, v, err)
	}
	s := New(st, fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}, "test")
	ctx, cancel := context.WithCancel(context.Background())
	s.RunDownloadMail(ctx)
	t.Cleanup(cancel)
	s.rateWindow = time.Hour
	s.passwordScreenOff = true
	ts := httptest.NewServer(s.Router())
	t.Cleanup(ts.Close)
	return &env{t: t, s: s, ts: ts, dbKey: key}
}

func randomText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

type storedRow struct {
	disk string
	enc  bool
	size int64
	sum  string
}

func (e *env) storedFiles(longID string) map[string]storedRow {
	e.t.Helper()
	// Through the repository: the checksum is an encrypted column.
	var shareID int64
	if err := qByName(e.s.St, `SELECT id FROM shares WHERE long_id=?`, longID).Scan(&shareID); err != nil {
		e.t.Fatal(err)
	}
	list, err := e.s.St.Repos().Shares().Files(context.Background(), shareID)
	if err != nil {
		e.t.Fatal(err)
	}
	out := map[string]storedRow{}
	for _, f := range list {
		out[f.FullPath] = storedRow{
			disk: filepath.Join(e.s.St.DataDir, "shares", longID, filepath.Base(f.DiskPath)),
			enc:  f.Encrypted, size: f.Size, sum: f.SHA256,
		}
	}
	return out
}

func TestEncryptedUploadStoresCiphertextAndDownloadsMatch(t *testing.T) {
	e := newEncryptedEnv(t)
	admin := e.setup()
	big := randomText(3*filecrypt.ChunkSize + 4321)
	files := map[string]string{
		"big.bin":         big,
		"small.txt":       "TOP-SECRET-MARKER small file",
		"empty.txt":       "",
		"exact-chunk.bin": randomText(filecrypt.ChunkSize),
	}
	share := e.share(admin, files, nil)
	e.want(share, 201, "create share")
	lid := share.S("long_id")
	rows := e.storedFiles(lid)
	if len(rows) != len(files) {
		t.Fatalf("stored %d files, want %d", len(rows), len(files))
	}
	for name, content := range files {
		r, ok := rows[name]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if !r.enc {
			t.Fatalf("%s: enc flag not set", name)
		}
		if r.size != int64(len(content)) {
			t.Fatalf("%s: recorded size %d, want plain size %d", name, r.size, len(content))
		}
		sum := sha256.Sum256([]byte(content))
		if r.sum != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s: recorded checksum is not the plaintext SHA-256", name)
		}
		disk, err := os.ReadFile(r.disk)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(disk)) != filecrypt.CipherSize(int64(len(content))) {
			t.Fatalf("%s: stored size %d, want %d", name, len(disk), filecrypt.CipherSize(int64(len(content))))
		}
		if !bytes.HasPrefix(disk, []byte("SNDF\x02")) {
			t.Fatalf("%s: missing SNDF v2 header", name)
		}
		_, encRef := encRefOf(t, e, lid, name)
		if hid, ver := store.ParseEncRef(encRef); ver != 1 || hid != hex.EncodeToString(disk[37:53]) {
			t.Fatalf("%s: enc_id %q does not match the file header or the files key version", name, encRef)
		}
		if len(content) >= 16 && bytes.Contains(disk, []byte(content[:16])) {
			t.Fatalf("%s: plaintext found on disk", name)
		}
		if st, _ := os.Stat(r.disk); st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v, want 0600", name, st.Mode().Perm())
		}
	}

	// Single file download returns the exact plaintext with the plaintext checksum.
	for name, content := range files {
		d := e.do("GET", "/api/shares/"+lid+"/download/"+name, "", nil)
		e.want(d, 200, "download "+name)
		if string(d.Body) != content {
			t.Fatalf("%s: downloaded bytes differ", name)
		}
		sum := sha256.Sum256([]byte(content))
		if d.Hdr.Get("X-Checksum-Sha256") != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s: checksum header %q", name, d.Hdr.Get("X-Checksum-Sha256"))
		}
	}

	// Range requests are served from the middle of an encrypted file.
	for _, c := range []struct {
		rng        string
		start, end int
	}{
		{"bytes=0-9", 0, 10},
		{"bytes=65530-65545", 65530, 65546},
		{"bytes=100000-100999", 100000, 101000},
		{"bytes=-50", len(big) - 50, len(big)},
	} {
		d := e.do("GET", "/api/shares/"+lid+"/download/big.bin", "", nil, "Range", c.rng)
		e.want(d, 206, "range "+c.rng)
		if string(d.Body) != big[c.start:c.end] {
			t.Fatalf("range %s: wrong bytes", c.rng)
		}
	}

	// The whole share as a ZIP.
	z := e.do("GET", "/api/shares/"+lid+"/download", "", nil)
	e.want(z, 200, "zip")
	zr, err := zip.NewReader(bytes.NewReader(z.Body), int64(len(z.Body)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = string(b)
	}
	if len(got) != len(files) {
		t.Fatalf("zip has %d entries, want %d", len(got), len(files))
	}
	for name, content := range files {
		if got[name] != content {
			t.Fatalf("zip entry %s differs", name)
		}
	}

	// No plaintext leftovers: upload parts and download snapshots are gone.
	for _, dir := range []string{filepath.Join(e.s.St.DataDir, "uploads"), e.s.St.DataDir} {
		entries, _ := os.ReadDir(dir)
		for _, en := range entries {
			if strings.HasPrefix(en.Name(), ".verified-download-") {
				t.Fatalf("download snapshot left behind: %s", en.Name())
			}
			if dir != e.s.St.DataDir && en.IsDir() {
				sub, _ := os.ReadDir(filepath.Join(dir, en.Name()))
				for _, f := range sub {
					if strings.HasSuffix(f.Name(), ".part") {
						t.Fatalf("upload part left behind: %s/%s", en.Name(), f.Name())
					}
				}
			}
		}
	}
}

func TestEncryptedPreviewAndAppend(t *testing.T) {
	e := newEncryptedEnv(t)
	admin := e.setup()
	e.s.St.SetSetting("allow_preview", "true")
	share := e.share(admin, map[string]string{"pic.png": pngBytes}, nil)
	e.want(share, 201, "share")
	lid := share.S("long_id")
	p := e.do("GET", "/api/shares/"+lid+"/preview/pic.png", "", nil)
	e.want(p, 200, "preview")
	if string(p.Body) != pngBytes {
		t.Fatal("preview bytes differ")
	}

	// Files appended later are encrypted as well.
	sid := e.sid(share)
	e.want(e.appendFiles(admin, sid, []nf{{"more/note.txt", "APPENDED-MARKER " + randomText(100)}}), 201, "append")
	rows := e.storedFiles(lid)
	r, ok := rows["more/note.txt"]
	if !ok || !r.enc {
		t.Fatalf("appended file not encrypted: %+v", r)
	}
	disk, _ := os.ReadFile(r.disk)
	if bytes.Contains(disk, []byte("APPENDED-MARKER")) || !bytes.HasPrefix(disk, []byte("SNDF")) {
		t.Fatal("appended file is not ciphertext")
	}
	d := e.do("GET", "/api/shares/"+lid+"/download/more/note.txt", "", nil)
	e.want(d, 200, "download appended")
	if !strings.HasPrefix(string(d.Body), "APPENDED-MARKER ") {
		t.Fatal("appended download differs")
	}
}

func TestEncryptedFilesRefuseTamperingAndTruncation(t *testing.T) {
	e := newEncryptedEnv(t)
	admin := e.setup()
	content := "TAMPER-MARKER " + randomText(2*filecrypt.ChunkSize)
	share := e.share(admin, map[string]string{"a.bin": content}, nil)
	e.want(share, 201, "share")
	lid := share.S("long_id")
	r := e.storedFiles(lid)["a.bin"]
	orig, _ := os.ReadFile(r.disk)
	url := "/api/shares/" + lid + "/download/a.bin"
	e.want(e.do("GET", url, "", nil), 200, "intact")

	check := func(what string, mutated []byte) {
		t.Helper()
		if err := os.WriteFile(r.disk, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		d := e.do("GET", url, "", nil)
		if d.Code == 200 || strings.Contains(string(d.Body), "TAMPER-MARKER") {
			t.Fatalf("%s: modified file was served (status %d)", what, d.Code)
		}
		if d.Code != 409 && d.Code != 404 && d.Code != 503 {
			t.Fatalf("%s: unexpected status %d body=%s", what, d.Code, d.Body)
		}
	}
	flipped := bytes.Clone(orig)
	flipped[len(flipped)/2] ^= 0x01
	check("flipped bit", flipped)
	check("truncated", orig[:len(orig)-filecrypt.ChunkSize])
	check("appended garbage", append(bytes.Clone(orig), 1, 2, 3))
	check("header removed", orig[37:])

	// Replacing the encrypted file with plain bytes must not be accepted either.
	check("plain file swapped in", []byte(content))

	// Restored original works again.
	os.WriteFile(r.disk, orig, 0o600)
	d := e.do("GET", url, "", nil)
	e.want(d, 200, "restored")
	if string(d.Body) != content {
		t.Fatal("restored download differs")
	}
}

// Files uploaded before file encryption existed (enc=0) keep working next to new ones.
func TestLegacyPlainFilesStillDownload(t *testing.T) {
	e := newEncryptedEnv(t)
	admin := e.setup()
	content := "LEGACY " + randomText(70000)
	share := e.share(admin, map[string]string{"old.txt": content, "new.txt": "fresh"}, nil)
	e.want(share, 201, "share")
	lid := share.S("long_id")
	r := e.storedFiles(lid)["old.txt"]
	if err := os.WriteFile(r.disk, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.St.DB.Exec(`UPDATE files SET enc=0 WHERE disk_path LIKE ?`, "%old.txt"); err != nil {
		t.Fatal(err)
	}
	d := e.do("GET", "/api/shares/"+lid+"/download/old.txt", "", nil)
	e.want(d, 200, "legacy download")
	if string(d.Body) != content {
		t.Fatal("legacy file differs")
	}
	d = e.do("GET", "/api/shares/"+lid+"/download/new.txt", "", nil, "Range", "bytes=1-3")
	e.want(d, 206, "new file range")
	if string(d.Body) != "res" {
		t.Fatalf("range %q", d.Body)
	}
	z := e.do("GET", "/api/shares/"+lid+"/download", "", nil)
	e.want(z, 200, "mixed zip")
	zr, err := zip.NewReader(bytes.NewReader(z.Body), int64(len(z.Body)))
	if err != nil || len(zr.File) != 2 {
		t.Fatalf("zip: %v entries=%d", err, len(zr.File))
	}
}

// The database file is SQLCipher: no plaintext header, none of the stored text
// is visible in the database file or its write-ahead log.
func TestDatabaseFileIsEncrypted(t *testing.T) {
	e := newEncryptedEnv(t)
	admin := e.setup()
	share := e.share(admin, map[string]string{"SecretFileName-7731.txt": "x"}, map[string]any{"name": "SecretShareName-4412", "description": "SecretDescription-9083"})
	e.want(share, 201, "share")
	e.s.St.DB.Exec(`PRAGMA wal_checkpoint(FULL)`)
	paths := []string{e.s.St.Path, e.s.St.Path + "-wal"}
	for i, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			if i == 1 && os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if bytes.HasPrefix(b, []byte("SQLite format 3\x00")) {
			t.Fatalf("%s has the plain SQLite header", p)
		}
		for _, marker := range []string{"SecretFileName-7731", "SecretShareName-4412", "SecretDescription-9083", "admin@x.io", "password_hash"} {
			if bytes.Contains(b, []byte(marker)) {
				t.Fatalf("%s contains %q in clear", p, marker)
			}
		}
	}
	// Opening the file without a key, or with the wrong key, must fail.
	if st, err := store.OpenEncrypted(filepath.Dir(e.s.St.Path), make([]byte, 32), false); err == nil {
		st.Close()
		t.Fatal("database opened with a wrong key")
	}
	if _, err := store.OpenEncrypted(filepath.Dir(e.s.St.Path), nil, false); err == nil {
		t.Fatal("database opened without a key")
	}
}

// Ciphertext of file A copied over file B (same size, valid under the same key)
// must be refused: the row's file id no longer matches the header.
func TestSwappedCiphertextBetweenRowsRefused(t *testing.T) {
	e := newEncryptedEnv(t)
	admin := e.setup()
	e.s.St.SetSetting("allow_preview", "true")
	a := pngBytes
	b := pngBytes[:len(pngBytes)-1] + "Z"
	share := e.share(admin, map[string]string{"a.png": a, "b.png": b}, nil)
	e.want(share, 201, "share")
	lid := share.S("long_id")
	rows := e.storedFiles(lid)
	ra, rb := rows["a.png"], rows["b.png"]
	if ra.size != rb.size || ra.disk == rb.disk {
		t.Fatal("test needs two distinct files of equal size")
	}
	for _, n := range []string{"a.png", "b.png"} {
		e.want(e.do("GET", "/api/shares/"+lid+"/download/"+n, "", nil), 200, "intact "+n)
	}
	da, _ := os.ReadFile(ra.disk)
	if err := os.WriteFile(rb.disk, da, 0o600); err != nil {
		t.Fatal(err)
	}
	refused := func(what string, d resp) {
		t.Helper()
		if d.Code == 200 || d.Code == 206 || strings.Contains(string(d.Body), "PNG") {
			t.Fatalf("%s: swapped ciphertext was served (status %d)", what, d.Code)
		}
	}
	refused("verified download", e.do("GET", "/api/shares/"+lid+"/download/b.png", "", nil))
	refused("range", e.do("GET", "/api/shares/"+lid+"/download/b.png", "", nil, "Range", "bytes=0-9"))
	refused("preview", e.do("GET", "/api/shares/"+lid+"/preview/b.png", "", nil))
	refused("preview range", e.do("GET", "/api/shares/"+lid+"/preview/b.png", "", nil, "Range", "bytes=0-9"))
	refused("zip", e.do("GET", "/api/shares/"+lid+"/download", "", nil))
	// The untouched file still works.
	e.want(e.do("GET", "/api/shares/"+lid+"/download/a.png", "", nil), 200, "a.png still intact")
}
