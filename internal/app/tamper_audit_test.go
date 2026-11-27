// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/store"
)

func decryptFailedCount(e *env, fileID int64) int {
	e.t.Helper()
	n := 0
	for _, r := range openedAuditRecords(e) {
		if r.Action == "file_decrypt_failed" && r.Target == "file#"+strconv.FormatInt(fileID, 10) && r.Detail == "" {
			n++
		}
	}
	return n
}

// openedAuditRecords reads the audit log through the repository: target and
// detail are encrypted columns, so SQL on the table cannot compare them.
func openedAuditRecords(e *env) []store.AuditRecord {
	e.t.Helper()
	var out []store.AuditRecord
	if err := e.s.St.Repos().AuditChain().All(context.Background(), func(r store.AuditRecord) error { out = append(out, r); return nil }); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func resetDecryptFailureLimit(s *Server) {
	decryptFailures.Lock()
	for k := range decryptFailures.at {
		if k.s == s {
			delete(decryptFailures.at, k)
		}
	}
	decryptFailures.Unlock()
}

// A modified chunk in the middle of an encrypted file is an integrity failure
// (409), never "temporarily unavailable", and leaves one rate-limited audit
// record; the streaming preview notices it too.
func TestTamperedMiddleChunkIsIntegrityFailure(t *testing.T) {
	e := newEncryptedEnv(t)
	admin := e.setup()
	e.s.St.SetSetting("allow_preview", "true")
	content := pngBytes + randomText(2*filecrypt.ChunkSize+100) // three chunks
	share := e.share(admin, map[string]string{"pic.png": content, "other.txt": "intact"}, nil)
	e.want(share, 201, "share")
	lid := share.S("long_id")
	r := e.storedFiles(lid)["pic.png"]
	fileID, _ := encRefOf(t, e, lid, "pic.png")
	disk, err := os.ReadFile(r.disk)
	if err != nil {
		t.Fatal(err)
	}
	disk[53+filecrypt.ChunkSize+16+100] ^= 0x01 // inside chunk 1 of 0..2
	if err := os.WriteFile(r.disk, disk, 0o600); err != nil {
		t.Fatal(err)
	}
	resetDecryptFailureLimit(e.s)

	d := e.do("GET", "/api/shares/"+lid+"/download/pic.png", "", nil)
	e.want(d, 409, "verified download of a modified file")
	if !strings.Contains(string(d.Body), "integrity") {
		t.Fatalf("body %s", d.Body)
	}
	if n := decryptFailedCount(e, fileID); n != 1 {
		t.Fatalf("after verified download: %d file_decrypt_failed records, want 1", n)
	}
	e.want(e.do("GET", "/api/shares/"+lid+"/download/pic.png", "", nil, "Range", "bytes=0-9"), 409, "verified range")
	e.want(e.do("GET", "/api/shares/"+lid+"/download", "", nil), 409, "zip with a modified member")
	if n := decryptFailedCount(e, fileID); n != 1 {
		t.Fatalf("after range and zip: %d records, want still 1 (rate-limited)", n)
	}
	total := 0
	for _, r := range openedAuditRecords(e) {
		if r.Action == "file_decrypt_failed" {
			total++
		}
	}
	if total != 1 {
		t.Fatalf("%d file_decrypt_failed records in total, want 1", total)
	}

	// The preview streams through the decrypting reader: the range from the
	// modified chunk fails (short body) and is recorded once more after the
	// rate-limit interval (simulated by the reset).
	resetDecryptFailureLimit(e.s)
	p := e.do("GET", "/api/shares/"+lid+"/preview/pic.png", "", nil, "Range", "bytes=65536-65600")
	if len(p.Body) == 65 && p.Code == 206 {
		t.Fatalf("modified range served in full (status %d)", p.Code)
	}
	if n := decryptFailedCount(e, fileID); n != 2 {
		t.Fatalf("after preview range: %d records, want 2", n)
	}
	full := e.do("GET", "/api/shares/"+lid+"/preview/pic.png", "", nil)
	if len(full.Body) == len(content) {
		t.Fatal("modified file previewed in full")
	}
	if n := decryptFailedCount(e, fileID); n != 2 {
		t.Fatalf("repeated preview: %d records, want 2 (once per file per interval)", n)
	}
	// After the interval a new failure is recorded again.
	resetDecryptFailureLimit(e.s)
	e.do("GET", "/api/shares/"+lid+"/preview/pic.png", "", nil, "Range", "bytes=65536-65600")
	if n := decryptFailedCount(e, fileID); n != 3 {
		t.Fatalf("after the interval: %d records, want 3", n)
	}
	e.want(e.do("GET", "/api/shares/"+lid+"/download/other.txt", "", nil), 200, "untouched file")
}
