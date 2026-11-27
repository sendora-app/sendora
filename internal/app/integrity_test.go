// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func sum(s []byte) string { h := sha256.Sum256(s); return hex.EncodeToString(h[:]) }
func TestUploadExpectedChecksumAndTampering(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	create := func(expected string) string {
		r := e.do("POST", "/api/uploads", token, map[string]any{"files": []map[string]any{{"name": "a.txt", "size": 4, "sha256": expected}}})
		e.want(r, 201, "create")
		return r.S("id")
	}
	e.want(e.do("POST", "/api/uploads", token, map[string]any{"files": []map[string]any{{"name": "a", "size": 1, "sha256": "broken"}}}), 400, "bad hash")
	id := create(sum([]byte("good")))
	e.want(e.do("PATCH", "/api/uploads/"+id+"/files/0", token, []byte("evil"), "Upload-Offset", "0"), 200, "chunk")
	e.want(e.do("POST", "/api/uploads/"+id+"/complete", token, map[string]any{}), 409, "mismatch")
	e.want(e.do("GET", "/api/uploads/"+id, token, nil), 200, "retry session preserved")
	if err := os.WriteFile(filepath.Join(e.s.uploadDir(id), "0.part"), []byte("good"), 0600); err != nil {
		t.Fatal(err)
	}
	r := e.do("POST", "/api/uploads/"+id+"/complete", token, map[string]any{})
	e.want(r, 201, "retry complete")
	files := e.s.shareFiles(int64(r.J()["id"].(float64)))
	if files[0].SHA256 != sum([]byte("good")) || files[0].Integrity != "expected_checksum_verified" {
		t.Fatal(files)
	}
	url := "/api/shares/" + r.S("long_id") + "/download"
	good := e.do("GET", url, "", nil)
	e.want(good, 200, "good download")
	assertDigest(t, good)
	if err := os.WriteFile(files[0].diskPath, []byte("evil"), 0600); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("GET", url, "", nil), 409, "tampered download blocked")
	sh, _ := e.s.shareByLongID(r.S("long_id"))
	if sh.DownloadCount != 1 {
		t.Fatal("corruption consumed slot", sh.DownloadCount)
	}
	paths, _ := filepath.Glob(filepath.Join(e.s.St.DataDir, ".verified-download-*"))
	if len(paths) != 0 {
		t.Fatal("snapshot leaked", paths)
	}
}
func assertDigest(t *testing.T, r resp) {
	t.Helper()
	checksum := sum(r.Body)
	if r.Hdr.Get("X-Checksum-SHA256") != checksum {
		t.Fatal("SHA256 header mismatch")
	}
	raw, _ := hex.DecodeString(checksum)
	if r.Hdr.Get("Repr-Digest") != "sha-256=:"+base64.StdEncoding.EncodeToString(raw)+":" {
		t.Fatal("representation digest mismatch")
	}
}
func TestZIPDigestAndLegacyBaseline(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{"folder/a": "alpha", "b": "beta"}, nil)
	e.want(created, 201, "share")
	sid := int64(created.J()["id"].(float64))
	files := e.s.shareFiles(sid)
	if _, err := e.s.St.DB.Exec(`UPDATE files SET sha256='' WHERE share_id=?`, sid); err != nil {
		t.Fatal(err)
	}
	url := "/api/shares/" + created.S("long_id") + "/download"
	r := e.do("GET", url, "", nil)
	e.want(r, 200, "legacy zip")
	assertDigest(t, r)
	zr, err := zip.NewReader(bytes.NewReader(r.Body), int64(len(r.Body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 2 {
		t.Fatal("members missing")
	}
	for _, member := range zr.File {
		in, err := member.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(in)
		in.Close()
		if err != nil {
			t.Fatal(err)
		}
		if member.Name == "b" && string(data) != "beta" {
			t.Fatal("bad member")
		}
	}
	for _, f := range e.s.shareFiles(sid) {
		if !validSHA256(f.SHA256) || f.Integrity != "server_baseline" {
			t.Fatal("missing legacy baseline", f)
		}
	}
	again := e.do("GET", url, "", nil)
	e.want(again, 200, "repeat")
	if !bytes.Equal(r.Body, again.Body) {
		t.Fatal("ZIP not deterministic")
	}
	if err := os.WriteFile(files[0].diskPath, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("GET", url, "", nil), 409, "legacy post-baseline corruption")
}
func TestSnapshotLimitsAndImmutableCopy(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{"a": "abc"}, nil)
	files := e.s.shareFiles(int64(created.J()["id"].(float64)))
	out, checksum, err := e.s.prepareDownload(context.Background(), files)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { out.Close(); os.Remove(out.Name()); <-integritySlots }()
	if err := os.WriteFile(files[0].diskPath, []byte("xyz"), 0600); err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(out)
	if string(data) != "abc" || checksum != sum(data) {
		t.Fatal("mutable snapshot")
	}
	t.Setenv("SENDORA_VERIFIED_DOWNLOAD_MAX_BYTES", "2")
	_, _, err = e.s.prepareDownload(context.Background(), files)
	if err != errSnapshotLimit {
		t.Fatal(fmt.Sprint(err))
	}
}
