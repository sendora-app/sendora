// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPortableUploadPaths(t *testing.T) {
	unsafe := []string{
		`C:\outside\payload.txt`, "C:/outside/payload.txt", "C:payload.txt",
		"dir/file.txt:stream", "dir:stream/file.txt", `\\server\share\file`,
		`\rooted\file`, "//server/share/file", "dir/\x00file", "dir/\nfile", "dir/\u0085file",
		"CON", "con.txt", "dir/AUX.txt", "NUL/file.txt", "PRN.tar.gz",
		"COM1.txt", "com9/file", "LPT1", "lpt9.txt", "COM¹.txt", "LPT².txt", "COM³",
		"CONIN$", "CONOUT$.txt", "NUL .txt", "dir./file", "dir /file", "file.", "file ",
		"dir/fi?le", "dir*/file", "dir/fi<le", "dir/fi>le", `dir/fi"le`, "dir/fi|le",
		"CON/../okay.txt", "bad /../okay.txt", "C:/../okay.txt",
	}
	e := newEnv(t)
	token := e.setup()
	for _, p := range unsafe {
		t.Run(p, func(t *testing.T) {
			if validateUploadPath(p) == nil {
				t.Fatalf("accepted unsafe raw path %q", p)
			}
			for _, field := range []string{"name", "full_path"} {
				file := map[string]any{"name": "safe.txt", "size": 0}
				file[field] = p
				e.want(e.do("POST", "/api/uploads", token, map[string]any{"files": []any{file}}), 400, "unsafe "+field)
			}
		})
	}
	var pending int
	if err := e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM upload_sessions`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("rejected uploads retained metadata: count=%d err=%v", pending, err)
	}
	entries, err := os.ReadDir(filepath.Join(e.s.St.DataDir, "uploads"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected uploads retained directories: %v err=%v", entries, err)
	}
	for _, p := range []string{"folder/file.txt", "資料/été.txt", `folder\child\file.txt`, "COM10.txt", "LPT0/file", ".hidden/file", "dir/../../file.txt", "/folder/file.txt"} {
		if err := validateUploadPath(p); err != nil {
			t.Fatalf("rejected compatible path %q: %v", p, err)
		}
		r := e.do("POST", "/api/uploads", token, map[string]any{"files": []any{map[string]any{"full_path": p, "size": 0}}})
		e.want(r, 201, "compatible path "+p)
		e.want(e.do("DELETE", "/api/uploads/"+r.S("id"), token, nil), 200, "cleanup compatible upload")
	}
}

func TestArchivePathsFailClosed(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{"a.txt": "first", "b.txt": "second"}, nil)
	e.want(created, 201, "create share")
	sh, err := e.s.shareByLongID(created.S("long_id"))
	if err != nil {
		t.Fatal(err)
	}
	files := e.s.shareFiles(sh.ID)
	unsafe := []string{"C:/outside/file", "file:stream", "../file", "dir/../file", "/absolute/file", "//server/file", `dir\file`, "dir/NUL.txt", "dir./file", "dir/file ", "dir/\x00file", "", "dir//file", "dir/file/"}
	for _, p := range unsafe {
		t.Run(p, func(t *testing.T) {
			// Put the unsafe member second, exercising cleanup after one ZIP entry
			// has already been written. Do not normalize persisted legacy names.
			files[1].FullPath = p
			out, checksum, err := e.s.prepareDownload(context.Background(), files)
			if out != nil {
				out.Close()
				os.Remove(out.Name())
				<-integritySlots
				t.Fatal("unsafe archive was prepared")
			}
			if !errors.Is(err, errIntegrity) || checksum != "" {
				t.Fatalf("unexpected preparation result: checksum=%q err=%v", checksum, err)
			}
			if _, err := e.s.St.DB.Exec(`UPDATE files SET full_path=? WHERE id=?`, p, files[1].ID); err != nil {
				t.Fatal(err)
			}
			e.want(e.do("GET", "/api/shares/"+sh.LongID+"/download", "", nil), 409, "unsafe legacy ZIP")
			var persisted string
			if err := e.s.St.DB.QueryRow(`SELECT full_path FROM files WHERE id=?`, files[1].ID).Scan(&persisted); err != nil || persisted != p {
				t.Fatalf("legacy metadata changed: %q err=%v", persisted, err)
			}
			paths, err := filepath.Glob(filepath.Join(e.s.St.DataDir, ".verified-download-*"))
			if err != nil || len(paths) != 0 || len(integritySlots) != 0 {
				t.Fatalf("failed ZIP leaked snapshot or slot: paths=%v slots=%d err=%v", paths, len(integritySlots), err)
			}
		})
	}
	sh, err = e.s.shareByLongID(sh.LongID)
	if err != nil || sh.DownloadCount != 0 {
		t.Fatalf("failed ZIP consumed downloads: share=%v err=%v", sh, err)
	}
	for i, f := range files {
		data, err := os.ReadFile(f.diskPath)
		want := []string{"first", "second"}[i]
		if err != nil || string(data) != want {
			t.Fatalf("source changed: %q err=%v", data, err)
		}
	}
}

func TestPortableDirectoriesInZIP(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{`folder\child\a.txt`: "alpha", "資料/été.txt": "beta"}, nil)
	e.want(created, 201, "create portable share")
	r := e.do("GET", "/api/shares/"+created.S("long_id")+"/download", "", nil)
	e.want(r, 200, "portable ZIP")
	assertDigest(t, r)
	zr, err := zip.NewReader(bytes.NewReader(r.Body), int64(len(r.Body)))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"folder/child/a.txt": true, "資料/été.txt": true}
	for _, member := range zr.File {
		if !want[member.Name] || validateArchivePath(member.Name) != nil {
			t.Fatalf("unexpected archive member %q", member.Name)
		}
		delete(want, member.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing archive members: %v", want)
	}
}
