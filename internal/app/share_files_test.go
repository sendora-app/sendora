// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/sendora-app/sendora/internal/store"
)

type nf struct{ path, content string }

func (e *env) sid(r resp) int64 {
	e.t.Helper()
	return int64(r.J()["id"].(float64))
}

// appendReq creates an append session and uploads all chunks, returning the session id.
func (e *env) appendSession(tok string, shareID int64, files []nf) (string, resp) {
	var meta []map[string]any
	for _, f := range files {
		meta = append(meta, map[string]any{"name": filepath.Base(f.path), "full_path": f.path, "size": len(f.content)})
	}
	r := e.do("POST", "/api/uploads", tok, map[string]any{"files": meta, "share_id": shareID})
	if r.Code != 201 {
		return "", r
	}
	id := r.S("id")
	for i, f := range files {
		e.want(e.do("PATCH", fmt.Sprintf("/api/uploads/%s/files/%d", id, i), tok, []byte(f.content), "Upload-Offset", "0"), 200, "chunk")
	}
	return id, r
}

func (e *env) appendFiles(tok string, shareID int64, files []nf) resp {
	id, r := e.appendSession(tok, shareID, files)
	if id == "" {
		return r
	}
	return e.do("POST", "/api/uploads/"+id+"/complete", tok, nil)
}

func (e *env) listFiles(tok string, shareID int64) []shareFileOut {
	e.t.Helper()
	r := e.do("GET", fmt.Sprintf("/api/shares/%d/files", shareID), tok, nil)
	e.want(r, 200, "list files")
	var out []shareFileOut
	if err := json.Unmarshal(r.Body, &out); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func paths(fs []shareFileOut) []string {
	var p []string
	for _, f := range fs {
		p = append(p, f.FullPath)
	}
	return p
}

func TestUniqueSharePath(t *testing.T) {
	ex := map[string]bool{"a.txt": true, "dir/b.tar.gz": true, "dir/b.tar (2).gz": true, ".env": true, "noext": true}
	for _, c := range []struct{ in, want string }{
		{"new.txt", "new.txt"},
		{"A.TXT", "A (2).TXT"},
		{"dir/B.tar.gz", "dir/B.tar (3).gz"},
		{".env", ".env (2)"},
		{"noext", "noext (2)"},
	} {
		got, err := uniqueSharePath(ex, c.in)
		if err != nil || got != c.want {
			t.Fatalf("%s: got %q %v want %q", c.in, got, err, c.want)
		}
	}
	full := map[string]bool{"x": true}
	for i := 2; i <= 10000; i++ {
		full[fmt.Sprintf("x (%d)", i)] = true
	}
	if _, err := uniqueSharePath(full, "x"); err == nil {
		t.Fatal("expected bounded failure")
	}
}

func TestAppendFilesRenamesAndIntegrity(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	first := e.share(tok, map[string]string{"a.txt": "one", "dir/b.txt": "bee"}, map[string]any{"name": "s"})
	e.want(first, 201, "share")
	sid, lid := e.sid(first), first.S("long_id")
	// Make "dir/b.txt" exist as in a folder upload.
	r := e.appendFiles(tok, sid, []nf{{"a.txt", "two"}, {"A.TXT", "three"}, {"dir/B.txt", "four"}, {"c.txt", "five"}, {"c.txt", "six"}})
	e.want(r, 201, "append")
	if r.J()["ok"] != true {
		t.Fatal(string(r.Body))
	}
	var added []shareFileOut
	raw, _ := json.Marshal(r.J()["added"])
	json.Unmarshal(raw, &added)
	want := []string{"a (2).txt", "A (3).TXT", "dir/B (2).txt", "c.txt", "c (2).txt"}
	if fmt.Sprint(paths(added)) != fmt.Sprint(want) {
		t.Fatalf("added %v want %v", paths(added), want)
	}
	if added[0].Name != "a (2).txt" || added[2].Name != "B (2).txt" || added[0].Size != 3 || added[0].ID == 0 {
		t.Fatalf("bad added %+v", added)
	}
	all := e.listFiles(tok, sid)
	if len(all) != 7 {
		t.Fatalf("files %v", paths(all))
	}
	if !sort.SliceIsSorted(all, func(i, j int) bool {
		return all[i].FullPath < all[j].FullPath || (all[i].FullPath == all[j].FullPath && all[i].ID < all[j].ID)
	}) {
		t.Fatalf("not ordered: %v", paths(all))
	}
	// Existing and new files download with verified content.
	for p, c := range map[string]string{"a.txt": "one", "dir/b.txt": "bee", "a (2).txt": "two", "A (3).TXT": "three", "dir/B (2).txt": "four", "c.txt": "five", "c (2).txt": "six"} {
		d := e.do("GET", "/api/shares/"+lid+"/download/"+(&url.URL{Path: p}).EscapedPath(), "", nil)
		e.want(d, 200, "download "+p)
		if string(d.Body) != c {
			t.Fatalf("%s: %q want %q", p, d.Body, c)
		}
	}
	// ZIP holds everything with the renamed paths.
	z := e.do("GET", "/api/shares/"+lid+"/download", "", nil)
	e.want(z, 200, "zip")
	zr, err := zip.NewReader(bytes.NewReader(z.Body), int64(len(z.Body)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	for _, p := range want {
		if !names[p] {
			t.Fatalf("zip lacks %q: %v", p, names)
		}
	}
	// Stored checksum matches the content; share listing counts new files.
	var sum string
	if err := e.s.St.DB.QueryRow(`SELECT sha256 FROM files WHERE id=?`, added[3].ID).Scan(&sum); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("five"))
	if sum != hex.EncodeToString(h[:]) {
		t.Fatal("checksum not recorded")
	}
	pub := e.do("GET", "/api/shares/"+lid, "", nil)
	if pub.J()["file_count"].(float64) != 7 {
		t.Fatal(string(pub.Body))
	}
	// Staging directory is gone and nothing leaked into the share dir.
	entries, _ := os.ReadDir(filepath.Join(e.s.St.DataDir, "shares", lid))
	if len(entries) != 7 {
		t.Fatalf("share dir has %d entries", len(entries))
	}
	var sessions int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM upload_sessions`).Scan(&sessions)
	if sessions != 0 {
		t.Fatal("session not removed")
	}
}

func TestAppendAccessRules(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	alice := e.mkUser(admin, "alice", false)
	bob := e.mkUser(admin, "bob", false)
	sh := e.share(alice, map[string]string{"a.txt": "x"}, nil)
	e.want(sh, 201, "share")
	sid, lid := e.sid(sh), sh.S("long_id")
	one := []map[string]any{{"name": "n", "full_path": "n", "size": 1}}
	e.want(e.do("POST", "/api/uploads", "", map[string]any{"files": one, "share_id": sid}), 401, "anon")
	e.want(e.do("POST", "/api/uploads", bob, map[string]any{"files": one, "share_id": sid}), 404, "other user")
	e.want(e.do("POST", "/api/uploads", admin, map[string]any{"files": one, "share_id": sid}), 404, "admin non-owner")
	e.want(e.do("POST", "/api/uploads", alice, map[string]any{"files": one, "share_id": 99999}), 404, "unknown share")
	// A session created by the owner cannot be completed by someone else.
	id, r := e.appendSession(alice, sid, []nf{{"n.txt", "n"}})
	e.want(r, 201, "owner session")
	e.want(e.do("POST", "/api/uploads/"+id+"/complete", bob, nil), 404, "foreign complete")
	// Empty body or {} both work.
	e.want(e.do("POST", "/api/uploads/"+id+"/complete", alice, map[string]any{}), 201, "complete {}")
	// Listing/removal rules.
	e.want(e.do("GET", fmt.Sprintf("/api/shares/%d/files", sid), bob, nil), 404, "list other")
	e.want(e.do("GET", fmt.Sprintf("/api/shares/%d/files", sid), "", nil), 401, "list anon")
	e.want(e.do("GET", fmt.Sprintf("/api/shares/%d/files", sid), admin, nil), 404, "admin cannot list another user's files")
	if n := len(e.listFiles(alice, sid)); n != 2 {
		t.Fatalf("owner list %d", n)
	}
	// Guest cannot append.
	inv := e.do("POST", "/api/reverse-shares/invite", alice, map[string]any{"name": "g"})
	e.want(inv, 201, "invite")
	acc := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": inv.S("url")[strings.LastIndex(inv.S("url"), "/")+1:]})
	e.want(acc, 200, "accept")
	e.want(e.do("POST", "/api/uploads", acc.S("access_token"), map[string]any{"files": one, "share_id": sid}), 404, "guest")
	// Expired share whose files were cleaned up, and deleted status.
	os.RemoveAll(filepath.Join(e.s.St.DataDir, "shares", lid))
	e.want(e.do("POST", "/api/uploads", alice, map[string]any{"files": one, "share_id": sid}), 409, "cleaned dir")
	os.MkdirAll(filepath.Join(e.s.St.DataDir, "shares", lid), 0o700)
	e.s.St.DB.Exec(`UPDATE shares SET status='deleted' WHERE id=?`, sid)
	e.want(e.do("POST", "/api/uploads", alice, map[string]any{"files": one, "share_id": sid}), 409, "deleted")
}

func TestAppendExpiredWithFilesStillAllowed(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	sh := e.share(tok, map[string]string{"a.txt": "x"}, nil)
	e.want(sh, 201, "share")
	e.want(e.do("POST", fmt.Sprintf("/api/shares/%d/expire", e.sid(sh)), tok, nil), 200, "expire")
	e.want(e.appendFiles(tok, e.sid(sh), []nf{{"b.txt", "y"}}), 201, "append to expired")
}

func TestAppendLimitsAndQuota(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	sh := e.share(tok, map[string]string{"a.bin": strings.Repeat("x", 600*1024)}, nil)
	e.want(sh, 201, "share")
	sid := e.sid(sh)
	big := []map[string]any{{"name": "b", "full_path": "b", "size": 600 * 1024}}
	e.s.St.SetSetting("max_share_size", "1")
	r := e.do("POST", "/api/uploads", tok, map[string]any{"files": big, "share_id": sid})
	e.want(r, 413, "max_share_size includes existing bytes")
	if !strings.Contains(r.S("error"), "limit") {
		t.Fatal(r.S("error"))
	}
	e.s.St.SetSetting("max_share_size", "2048")
	// Snapshot limit.
	t.Setenv("SENDORA_VERIFIED_DOWNLOAD_MAX_BYTES", fmt.Sprint(700*1024))
	r = e.do("POST", "/api/uploads", tok, map[string]any{"files": big, "share_id": sid})
	e.want(r, 413, "snapshot limit")
	if !strings.Contains(r.S("error"), "downloadable") {
		t.Fatal(r.S("error"))
	}
	t.Setenv("SENDORA_VERIFIED_DOWNLOAD_MAX_BYTES", "")
	// Quota admission and reservation.
	uid := quotaUserID(t, e, "admin")
	quotaSet(t, e, uid, 600*1024+10)
	e.want(e.do("POST", "/api/uploads", tok, map[string]any{"files": big, "share_id": sid}), 413, "quota")
	small := []map[string]any{{"name": "s", "full_path": "s", "size": 10}}
	r = e.do("POST", "/api/uploads", tok, map[string]any{"files": small, "share_id": sid})
	e.want(r, 201, "fits quota")
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 600*1024 + 10, StoredBytes: 600 * 1024, ReservedBytes: 10})
	e.want(e.do("PATCH", "/api/uploads/"+r.S("id")+"/files/0", tok, []byte("0123456789"), "Upload-Offset", "0"), 200, "chunk")
	e.want(e.do("POST", "/api/uploads/"+r.S("id")+"/complete", tok, nil), 201, "complete")
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 600*1024 + 10, StoredBytes: 600*1024 + 10})
	// Limit lowered between create and complete is rechecked at completion.
	quotaSet(t, e, uid, 1<<30)
	id, r := e.appendSession(tok, sid, []nf{{"late.txt", strings.Repeat("y", 500*1024)}})
	e.want(r, 201, "session")
	e.s.St.SetSetting("max_share_size", "1")
	e.want(e.do("POST", "/api/uploads/"+id+"/complete", tok, nil), 413, "recheck at completion")
	if n := len(e.listFiles(tok, sid)); n != 2 {
		t.Fatalf("files %d", n)
	}
	entries, _ := os.ReadDir(filepath.Join(e.s.St.DataDir, "shares", sh.S("long_id")))
	if len(entries) != 2 {
		t.Fatalf("staged file leaked: %d entries", len(entries))
	}
}

func TestAppendFailureKeepsExistingFiles(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	sh := e.share(tok, map[string]string{"a.txt": "keep"}, nil)
	e.want(sh, 201, "share")
	sid, lid := e.sid(sh), sh.S("long_id")
	r := e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{
		{"name": "ok.txt", "full_path": "ok.txt", "size": 2},
		{"name": "bad.txt", "full_path": "bad.txt", "size": 2, "sha256": strings.Repeat("0", 64)}}, "share_id": sid})
	e.want(r, 201, "session")
	id := r.S("id")
	e.want(e.do("PATCH", "/api/uploads/"+id+"/files/0", tok, []byte("hi"), "Upload-Offset", "0"), 200, "c0")
	e.want(e.do("PATCH", "/api/uploads/"+id+"/files/1", tok, []byte("yo"), "Upload-Offset", "0"), 200, "c1")
	e.want(e.do("POST", "/api/uploads/"+id+"/complete", tok, nil), 409, "checksum mismatch")
	d := e.do("GET", "/api/shares/"+lid+"/download/a.txt", "", nil)
	e.want(d, 200, "existing file intact")
	if string(d.Body) != "keep" {
		t.Fatal("content changed")
	}
	entries, _ := os.ReadDir(filepath.Join(e.s.St.DataDir, "shares", lid))
	if len(entries) != 1 {
		t.Fatalf("staged files leaked: %d", len(entries))
	}
	if n := len(e.listFiles(tok, sid)); n != 1 {
		t.Fatalf("rows %d", n)
	}
	// Session survives, so abort cleans it.
	e.want(e.do("DELETE", "/api/uploads/"+id, tok, nil), 200, "abort")
}

func TestDeleteShareCleansAppendSessions(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	sh := e.share(tok, map[string]string{"a.txt": "x"}, nil)
	e.want(sh, 201, "share")
	sid := e.sid(sh)
	id, r := e.appendSession(tok, sid, []nf{{"b.txt", "bbb"}})
	e.want(r, 201, "session")
	if _, err := os.Stat(e.s.uploadDir(id)); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("DELETE", fmt.Sprintf("/api/shares/%d", sid), tok, nil), 200, "delete share")
	if _, err := os.Stat(e.s.uploadDir(id)); !os.IsNotExist(err) {
		t.Fatalf("staging dir remains: %v", err)
	}
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM upload_sessions`).Scan(&n)
	var m int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM upload_files`).Scan(&m)
	if n != 0 || m != 0 {
		t.Fatalf("sessions %d files %d", n, m)
	}
	e.want(e.do("GET", "/api/uploads/"+id, tok, nil), 404, "session gone")
}

func TestRemoveShareFile(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	alice := e.mkUser(admin, "alice", false)
	bob := e.mkUser(admin, "bob", false)
	sh := e.share(alice, map[string]string{"a.txt": "AAAA"}, nil)
	e.want(sh, 201, "share")
	sid, lid := e.sid(sh), sh.S("long_id")
	e.want(e.appendFiles(alice, sid, []nf{{"b.txt", "BBBBBB"}, {"c.txt", "C"}}), 201, "append")
	files := e.listFiles(alice, sid)
	byPath := map[string]shareFileOut{}
	for _, f := range files {
		byPath[f.FullPath] = f
	}
	del := func(tok string, fid int64) resp {
		return e.do("DELETE", fmt.Sprintf("/api/shares/%d/files/%d", sid, fid), tok, nil)
	}
	e.want(del("", byPath["b.txt"].ID), 401, "anon")
	e.want(del(bob, byPath["b.txt"].ID), 404, "other user")
	e.want(del(alice, 987654), 404, "unknown file")
	// File of another share is not reachable through this share.
	other := e.share(alice, map[string]string{"o.txt": "o"}, nil)
	ofiles := e.listFiles(alice, e.sid(other))
	e.want(del(alice, ofiles[0].ID), 404, "file from other share")
	// Download history of the file stays (name may be blank).
	e.want(e.do("GET", "/api/shares/"+lid+"/download/b.txt", "", nil), 200, "download before")
	var hist int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM downloads WHERE share_id=?`, sid).Scan(&hist)
	uid := quotaUserID(t, e, "alice")
	var disk string
	e.s.St.DB.QueryRow(`SELECT disk_path FROM files WHERE id=?`, byPath["b.txt"].ID).Scan(&disk)
	r := del(alice, byPath["b.txt"].ID)
	e.want(r, 200, "remove b")
	if r.J()["ok"] != true {
		t.Fatal(string(r.Body))
	}
	if _, err := os.Stat(disk); !os.IsNotExist(err) {
		t.Fatal("disk file remains")
	}
	if _, err := os.Stat(disk + ".removing"); !os.IsNotExist(err) {
		t.Fatal(".removing remains")
	}
	e.want(e.do("GET", "/api/shares/"+lid+"/download/b.txt", "", nil), 404, "b gone")
	var hist2 int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM downloads WHERE share_id=?`, sid).Scan(&hist2)
	if hist2 != hist {
		t.Fatal("download history changed")
	}
	e.want(e.do("GET", fmt.Sprintf("/api/shares/%d/downloads", sid), alice, nil), 200, "history readable")
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 10000000000, QuotaInheritsDefault: true, StoredBytes: 6, AvailableBytes: 10000000000 - 6})
	// Admin may not remove another user's file; the owner may. Last file is refused.
	e.want(del(admin, byPath["c.txt"].ID), 404, "admin remove")
	e.want(del(alice, byPath["c.txt"].ID), 200, "owner remove")
	last := del(alice, byPath["a.txt"].ID)
	e.want(last, 409, "last file")
	if last.S("error") != "a share needs at least one file" {
		t.Fatal(last.S("error"))
	}
	if n := len(e.listFiles(alice, sid)); n != 1 {
		t.Fatalf("files %d", n)
	}
	e.want(e.do("GET", "/api/shares/"+lid+"/download/a.txt", "", nil), 200, "last still there")
}

func TestRemoveShareFileCommitFailureRestores(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	sh := e.share(tok, map[string]string{"a.txt": "AAAA", "b.txt": "BB"}, nil)
	e.want(sh, 201, "share")
	sid, lid := e.sid(sh), sh.S("long_id")
	files := e.listFiles(tok, sid)
	removeFileCommitHook = func() error { return fmt.Errorf("boom") }
	r := e.do("DELETE", fmt.Sprintf("/api/shares/%d/files/%d", sid, files[0].ID), tok, nil)
	removeFileCommitHook = nil
	e.want(r, 500, "forced failure")
	if n := len(e.listFiles(tok, sid)); n != 2 {
		t.Fatalf("rows %d", n)
	}
	d := e.do("GET", "/api/shares/"+lid+"/download/a.txt", "", nil)
	e.want(d, 200, "still downloadable")
	if string(d.Body) != "AAAA" {
		t.Fatal("content")
	}
	entries, _ := os.ReadDir(filepath.Join(e.s.St.DataDir, "shares", lid))
	for _, en := range entries {
		if strings.HasSuffix(en.Name(), ".removing") {
			t.Fatal("rename not undone")
		}
	}
}

func TestParallelAppendsAndRemovals(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	sh := e.share(tok, map[string]string{"base.txt": "base", "z.txt": "zz"}, nil)
	e.want(sh, 201, "share")
	sid, lid := e.sid(sh), sh.S("long_id")
	seed := e.appendFiles(tok, sid, []nf{{"r0.txt", "0"}, {"r1.txt", "1"}, {"r2.txt", "2"}, {"r3.txt", "3"}})
	e.want(seed, 201, "seed")
	var victims []int64
	for _, f := range e.listFiles(tok, sid) {
		if strings.HasPrefix(f.FullPath, "r") {
			victims = append(victims, f.ID)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Same name from every goroutine: renames must stay unique.
			id, r := e.appendSession(tok, sid, []nf{{"same.txt", fmt.Sprint("c", i)}, {"p" + fmt.Sprint(i) + ".txt", "p"}})
			if id == "" {
				errs <- fmt.Sprintf("create %d: %s", r.Code, r.Body)
				return
			}
			if c := e.do("POST", "/api/uploads/"+id+"/complete", tok, nil); c.Code != 201 {
				errs <- fmt.Sprintf("complete %d: %s", c.Code, c.Body)
			}
		}(i)
	}
	for _, v := range victims {
		wg.Add(1)
		go func(v int64) {
			defer wg.Done()
			if c := e.do("DELETE", fmt.Sprintf("/api/shares/%d/files/%d", sid, v), tok, nil); c.Code != 200 {
				errs <- fmt.Sprintf("remove %d: %s", c.Code, c.Body)
			}
		}(v)
	}
	wg.Wait()
	close(errs)
	for m := range errs {
		t.Error(m)
	}
	files := e.listFiles(tok, sid)
	if len(files) != 2+6+6 {
		t.Fatalf("got %d files %v", len(files), paths(files))
	}
	seen := map[string]bool{}
	for _, f := range files {
		k := strings.ToLower(f.FullPath)
		if seen[k] {
			t.Fatalf("duplicate path %s", f.FullPath)
		}
		seen[k] = true
		d := e.do("GET", "/api/shares/"+lid+"/download/"+(&url.URL{Path: f.FullPath}).EscapedPath(), "", nil)
		if d.Code != 200 {
			t.Fatalf("download %s: %d", f.FullPath, d.Code)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(e.s.St.DataDir, "shares", lid))
	if len(entries) != len(files) {
		t.Fatalf("disk %d rows %d", len(entries), len(files))
	}
}
