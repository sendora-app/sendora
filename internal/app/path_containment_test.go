// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Rows in files/shares are untrusted (an imported or tampered database). No
// read, rename or delete may ever leave DATA_DIR/shares/<share id>/.
// victimFile returns the (single) stored file of a share directory.
func victimFile(t *testing.T, data, lid string) string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(data, "shares", lid))
	if err != nil || len(ents) != 1 {
		t.Fatalf("victim share directory damaged: %v %d", err, len(ents))
	}
	return filepath.Join(data, "shares", lid, ents[0].Name())
}

func TestTamperedRecordsNeverEscapeShareDirectory(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	data := e.s.St.DataDir
	secret := filepath.Join(data, "canary.txt")
	os.WriteFile(secret, []byte("do not touch"), 0o600)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	os.WriteFile(outside, []byte("outside secret"), 0o600)

	victim := e.share(admin, map[string]string{"keep.txt": "keep me"}, nil)
	vlid := victim.S("long_id")
	e.want(victim, 201, "victim share")

	a := e.share(admin, map[string]string{"a.txt": "aaa", "b.txt": "bbb"}, nil)
	e.want(a, 201, "share a")
	alid := a.S("long_id")
	var aid, fileID int64
	qByName(e.s.St, `SELECT id FROM shares WHERE long_id=?`, alid).Scan(&aid)
	e.s.St.DB.QueryRow(`SELECT MIN(id) FROM files WHERE share_id=?`, aid).Scan(&fileID)

	// 1) disk_path pointing elsewhere (absolute, traversal) must not be read.
	for _, evil := range []string{"/etc/hosts", outside, "../../canary.txt", "../../sendora.db", ""} {
		if _, err := e.s.St.DB.Exec(`UPDATE files SET disk_path=? WHERE id=?`, evil, fileID); err != nil {
			t.Fatal(err)
		}
		for _, route := range []string{"/download/a.txt", "/download/b.txt", "/preview/a.txt", "/download"} {
			if !strings.Contains(route, "b.txt") && !strings.HasSuffix(route, "/download") && !strings.Contains(route, "a.txt") {
				continue
			}
			r := e.do("GET", "/api/shares/"+alid+route, "", nil)
			body := string(r.Body)
			if strings.Contains(body, "outside secret") || strings.Contains(body, "do not touch") || strings.Contains(body, "localhost") {
				t.Fatalf("disk_path %q leaked through %s: %.80q", evil, route, body)
			}
		}
	}

	// 2) removing a file whose record is tampered must not rename/delete elsewhere.
	if _, err := e.s.St.DB.Exec(`UPDATE files SET disk_path=? WHERE id=?`, secret, fileID); err != nil {
		t.Fatal(err)
	}
	e.do("DELETE", fmt.Sprintf("/api/shares/%d/files/%d", aid, fileID), admin, nil)
	if b, err := os.ReadFile(secret); err != nil || string(b) != "do not touch" {
		t.Fatal("file outside the share directory was touched", err)
	}

	// 3) malformed long IDs must never turn into RemoveAll(DATA_DIR).
	for _, lid := range []string{"..", "../", "../x", ".", ""} {
		bad := e.share(admin, map[string]string{"z.txt": "zzz"}, nil)
		e.want(bad, 201, "share to tamper")
		var bid int64
		qByName(e.s.St, `SELECT id FROM shares WHERE long_id=?`, bad.S("long_id")).Scan(&bid)
		real := filepath.Join(data, "shares", bad.S("long_id"))
		if _, err := rawExec(e.t, e.s.St, `UPDATE shares SET long_id=? WHERE id=?`, lid, bid); err != nil {
			// UNIQUE collisions between empty/odd values are fine to skip
			continue
		}
		e.do("DELETE", fmt.Sprintf("/api/shares/%d", bid), admin, nil)
		os.RemoveAll(real)
		for _, must := range []string{secret, filepath.Join(data, "sendora.db"), victimFile(t, data, vlid)} {
			if _, err := os.Stat(must); err != nil {
				t.Fatalf("long_id %q deletion destroyed %s: %v", lid, must, err)
			}
		}
	}

	// 4) deleting a user whose shares carry malformed long IDs is equally contained.
	other := e.mkUser(admin, "tamper", false)
	o := e.share(other, map[string]string{"o.txt": "ooo"}, nil)
	e.want(o, 201, "other share")
	var uid int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='tamper'`).Scan(&uid)
	rawExec(e.t, e.s.St, `UPDATE shares SET long_id='..' WHERE user_id=?`, uid)
	e.do("DELETE", fmt.Sprintf("/api/users/%d", uid), admin, nil)
	for _, must := range []string{secret, filepath.Join(data, "sendora.db"), victimFile(t, data, vlid)} {
		if _, err := os.Stat(must); err != nil {
			t.Fatalf("user deletion destroyed %s: %v", must, err)
		}
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "outside secret" {
		t.Fatal("file outside DATA_DIR was touched", err)
	}
}
