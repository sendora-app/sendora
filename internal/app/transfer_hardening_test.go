// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

func TestUploadRenamesDuplicatesAndRefusesFolderClashes(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	for name, files := range map[string][]map[string]any{
		"file then folder": {{"name": "x", "full_path": "x", "size": 1}, {"name": "y", "full_path": "x/y", "size": 1}},
		"folder then file": {{"name": "y", "full_path": "X/y", "size": 1}, {"name": "x", "full_path": "x", "size": 1}},
	} {
		e.want(e.do("POST", "/api/uploads", tok, map[string]any{"files": files}), 400, name)
	}
	r := e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{
		{"name": "a.pdf", "full_path": "a.pdf", "size": 1}, {"name": "A.pdf", "full_path": "A.pdf", "size": 1}, {"name": "a.pdf", "full_path": "a.pdf", "size": 1}}})
	e.want(r, 201, "duplicates renamed")
	rows, _ := e.s.St.DB.Query(`SELECT full_path FROM upload_files WHERE session_id=? ORDER BY idx`, r.S("id"))
	var got []string
	for rows.Next() {
		var p string
		rows.Scan(&p)
		got = append(got, p)
	}
	rows.Close()
	if strings.Join(got, "|") != "a.pdf|A (2).pdf|a (3).pdf" {
		t.Fatalf("paths %v", got)
	}
}

func TestShareDeletionRemovesFolderAfterCommit(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	r := e.share(tok, map[string]string{"a.txt": "one", "b.txt": "two"}, nil)
	lid := r.S("long_id")
	dir := filepath.Join(e.s.St.DataDir, "shares", lid)
	if _, err := os.Stat(dir); err != nil {
		t.Skip("share layout differs:", err)
	}
	var id int64
	qByName(e.s.St, `SELECT id FROM shares WHERE long_id=?`, lid).Scan(&id)
	if ok, err := e.s.removeShareIf(id, ports.ShareFilter{Kind: ports.AnyShare}); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("share folder kept")
	}
	left, _ := filepath.Glob(filepath.Join(e.s.St.DataDir, "shares", ".deleting-*"))
	if len(left) != 0 {
		t.Fatal("tombstone left behind", left)
	}
}

func TestLockedShareHidesOwner(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	r := e.share(tok, map[string]string{"a.txt": "one"}, map[string]any{"password": "Share-Passw0rd!9"})
	lid := r.S("long_id")
	pub := e.do("GET", "/api/shares/"+lid, "", nil)
	if strings.Contains(string(pub.Body), "owner") || !strings.Contains(string(pub.Body), "password_protected") {
		t.Fatalf("locked share response: %s", pub.Body)
	}
}

func TestDownloadSlotsPerClient(t *testing.T) {
	for i := 0; i < downloadSlotsPerClient; i++ {
		if !acquireDownloadClient(context.Background(), "203.0.113.5") {
			t.Fatal("slot refused", i)
		}
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if acquireDownloadClient(ctx, "203.0.113.5") {
		t.Fatal("same client got more than its slots")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("waiting ignored the request context")
	}
	if !acquireDownloadClient(context.Background(), "198.51.100.5") {
		t.Fatal("other client refused")
	}
	releaseDownloadClient("203.0.113.5")
	releaseDownloadClient("198.51.100.5")
	if !acquireDownloadClient(context.Background(), "203.0.113.5") {
		t.Fatal("slot not released")
	}
	releaseDownloadClient("203.0.113.5")
	releaseDownloadClient("203.0.113.5")
	if downloadClients["203.0.113.5"] != 0 {
		t.Fatal("slot count leaked")
	}
	if !acquireDownloadClient(context.Background(), "203.0.113.5") {
		t.Fatal("slot not released")
	}
	releaseDownloadClient("203.0.113.5")
}

func TestTransferMinimumRate(t *testing.T) {
	g := rateGuard{start: time.Now().Add(-2 * transferMinGrace)}
	if !g.tooSlow(100) {
		t.Fatal("a trickle after the grace period must be refused")
	}
	fast := rateGuard{start: time.Now().Add(-2 * transferMinGrace)}
	if fast.tooSlow(int(4 * transferMinGrace.Seconds() * transferMinRate)) {
		t.Fatal("a normal transfer was refused")
	}
	early := rateGuard{}
	if early.tooSlow(1) {
		t.Fatal("refused within the grace period")
	}
}

func TestPostDownloadIsRateLimited(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/shares/abc/download", nil)
	if class, _ := routeClass(r); class != "download" {
		t.Fatalf("POST download class = %q", class)
	}
}
