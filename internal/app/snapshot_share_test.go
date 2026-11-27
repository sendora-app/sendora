// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func snapshotsOf(s *Server) int {
	snapshotsMu.Lock()
	defer snapshotsMu.Unlock()
	n := 0
	for k := range snapshots {
		if k.s == s {
			n++
		}
	}
	return n
}

func waitSlotsFree(t *testing.T, e *env, sid int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		downloadSharesMu.Lock()
		busy := downloadShares[sid]
		downloadSharesMu.Unlock()
		if len(integritySlots) == 0 && busy == 0 && snapshotsOf(e.s) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slots not released: global=%d share=%d snapshots=%d", len(integritySlots), busy, snapshotsOf(e.s))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if left, _ := filepath.Glob(filepath.Join(e.s.St.DataDir, ".verified-download-*")); len(left) != 0 {
		t.Fatal("snapshot leaked", left)
	}
}

// Requests of one client for the same files share one snapshot and one set of
// slots; each reader has its own position; the last release frees everything.
func TestSameClientSharesOneSnapshot(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	content := strings.Repeat("0123456789", 1000)
	created := e.share(token, map[string]string{"a.bin": content}, nil)
	sid := e.sid(created)
	files := e.s.shareFiles(sid)
	var readers []*snapshotReader
	var rel []func()
	for i := 0; i < 2*downloadSlotsPerShare+1; i++ {
		rd, sum, r, err := e.s.prepareClientDownload(context.Background(), "203.0.113.70", sid, files)
		if err != nil {
			t.Fatalf("reader %d: %v", i, err)
		}
		if sum != files[0].SHA256 {
			t.Fatal("checksum differs")
		}
		readers = append(readers, rd)
		rel = append(rel, r)
	}
	downloadSharesMu.Lock()
	busy := downloadShares[sid]
	downloadSharesMu.Unlock()
	if len(integritySlots) != 1 || busy != 1 || snapshotsOf(e.s) != 1 {
		t.Fatalf("one snapshot expected: global=%d share=%d snapshots=%d", len(integritySlots), busy, snapshotsOf(e.s))
	}
	// Independent positions.
	readers[1].Seek(5000, io.SeekStart)
	b0 := make([]byte, 10)
	b1 := make([]byte, 10)
	io.ReadFull(readers[0], b0)
	io.ReadFull(readers[1], b1)
	if string(b0) != content[:10] || string(b1) != content[5000:5010] {
		t.Fatalf("readers share a position: %q %q", b0, b1)
	}
	// Another client gets its own snapshot.
	_, _, other, err := e.s.prepareClientDownload(context.Background(), "198.51.100.70", sid, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(integritySlots) != 2 {
		t.Fatalf("other client: %d global slots", len(integritySlots))
	}
	other()
	other() // a second call does nothing
	for _, r := range rel[:len(rel)-1] {
		r()
	}
	if b, err := io.ReadAll(readers[len(readers)-1]); err != nil || string(b) != content {
		t.Fatalf("last reader lost its snapshot: %v", err)
	}
	rel[len(rel)-1]()
	waitSlotsFree(t, e, sid)
	// A released snapshot is not reused: the next request prepares a new one.
	_, _, r, err := e.s.prepareClientDownload(context.Background(), "203.0.113.70", sid, files)
	if err != nil {
		t.Fatal(err)
	}
	r()
	waitSlotsFree(t, e, sid)
}

// After slotHoldMax a snapshot stays open while bytes keep flowing and is
// closed once its readers stop.
func TestSnapshotHoldExtendsWhileReading(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{"a": strings.Repeat("x", 4096)}, nil)
	sid := e.sid(created)
	files := e.s.shareFiles(sid)
	oldHold, oldCheck := slotHoldMax, snapshotProgressCheck
	slotHoldMax, snapshotProgressCheck = 100*time.Millisecond, 100*time.Millisecond
	defer func() { slotHoldMax, snapshotProgressCheck = oldHold, oldCheck }()
	f, _, release, err := e.s.prepareClientDownload(context.Background(), "203.0.113.71", sid, files)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	one := make([]byte, 1)
	for end := time.Now().Add(600 * time.Millisecond); time.Now().Before(end); {
		if _, err := f.Read(one); err != nil {
			t.Fatal("snapshot closed while the reader was making progress:", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond)
	if _, err := f.Read(one); err == nil || err == io.EOF {
		t.Fatal("idle snapshot past the hold limit must be closed, got", err)
	}
	// A closed snapshot is not joined by new requests.
	g, _, r2, err := e.s.prepareClientDownload(context.Background(), "203.0.113.71", sid, files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Read(one); err != nil {
		t.Fatal("new request joined the closed snapshot:", err)
	}
	r2()
	release()
	waitSlotsFree(t, e, sid)
}

// A download manager opening more parallel range connections than the
// per-share cap is served from one snapshot instead of being refused.
func TestParallelRangeRequestsOfOneClient(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	big := make([]byte, 8<<20) // larger than socket buffers: handlers stay busy until bodies are read
	rand.Read(big)
	created := e.share(token, map[string]string{"big.bin": string(big)}, nil)
	sid := e.sid(created)
	url := e.ts.URL + "/api/shares/" + created.S("long_id") + "/download/big.bin"
	var bodies []io.ReadCloser
	defer func() {
		for _, b := range bodies {
			b.Close()
		}
	}()
	const parts = 4
	for i := 0; i < parts; i++ {
		req, _ := http.NewRequest("GET", url, nil)
		start := i * len(big) / parts
		req.Header.Set("Range", "bytes="+strconv.Itoa(start)+"-")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, res.Body)
		if res.StatusCode != http.StatusPartialContent {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("connection %d: status %d %s", i, res.StatusCode, b)
		}
	}
	if n := snapshotsOf(e.s); n != 1 {
		t.Fatalf("%d snapshots for one client, want 1", n)
	}
	// Each connection gets its own bytes.
	for i, b := range bodies {
		buf := make([]byte, 1024)
		if _, err := io.ReadFull(b, buf); err != nil {
			t.Fatal(err)
		}
		start := i * len(big) / parts
		if string(buf) != string(big[start:start+1024]) {
			t.Fatalf("connection %d: wrong bytes", i)
		}
	}
	for _, b := range bodies {
		b.Close()
	}
	bodies = nil
	waitSlotsFree(t, e, sid)
}
