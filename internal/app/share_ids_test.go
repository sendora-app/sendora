// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Encode samples exactly as crypto/rand.Int reads them, including rejected ones.
func shareIDSample(n, choices int) []byte {
	width := (big.NewInt(int64(choices-1)).BitLen() + 7) / 8
	return big.NewInt(int64(n)).FillBytes(make([]byte, width))
}

func shareIDEntropy(word, first, second int) []byte {
	var data []byte
	for i := 0; i < 7; i++ {
		n, choices := word, len(shareIDWords)
		if i == 3 || i == 5 {
			choices, n = shareIDNumberChoices, first
			if i == 5 {
				n = second
			}
		}
		data = append(data, shareIDSample(n, choices)...)
	}
	return data
}

func assertReadableShareID(t *testing.T, id string) {
	t.Helper()
	segments := strings.Split(id, "-")
	if len(segments) != 7 || len(id) > 80 {
		t.Fatalf("invalid share ID shape: %q", id)
	}
	for i, segment := range segments {
		if i == 3 || i == 5 {
			n, err := strconv.Atoi(segment)
			if err != nil || len(segment) != 7 || n < shareIDNumberMin || n >= shareIDNumberMin+shareIDNumberChoices {
				t.Fatalf("invalid numeric segment: %q", segment)
			}
			continue
		}
		found := false
		for _, word := range shareIDWords {
			found = found || word == segment
		}
		if !found {
			t.Fatalf("unknown word: %q", segment)
		}
	}
}

func TestReadableShareIDEntropyAndFormat(t *testing.T) {
	seen := map[string]bool{}
	wordPattern := regexp.MustCompile(`^[a-z]+$`)
	longest := 0
	for _, word := range shareIDWords {
		if seen[word] || !wordPattern.MatchString(word) {
			t.Fatalf("duplicate or unsafe word: %q", word)
		}
		seen[word] = true
		longest = max(longest, len(word))
	}
	bits := 5*math.Log2(float64(len(shareIDWords))) + 2*math.Log2(float64(shareIDNumberChoices))
	if len(seen) < 256 || bits < 86 || 5*longest+14+6 > 80 || shareIDNumberMin != 1000000 || shareIDNumberChoices != 9000000 {
		t.Fatalf("invalid entropy or size parameters: words=%d bits=%f longest=%d", len(seen), bits, longest)
	}
	for _, pair := range [][2]int{{0, shareIDNumberChoices - 1}, {shareIDNumberChoices - 1, 0}, {0, 0}} {
		id, err := generateShareID(bytes.NewReader(shareIDEntropy(len(shareIDWords)-1, pair[0], pair[1])))
		if err != nil {
			t.Fatal(err)
		}
		assertReadableShareID(t, id)
		parts := strings.Split(id, "-")
		if parts[3] != strconv.Itoa(shareIDNumberMin+pair[0]) || parts[5] != strconv.Itoa(shareIDNumberMin+pair[1]) {
			t.Fatal("numeric samples are not independent", id)
		}
		for _, i := range []int{0, 1, 2, 4, 6} {
			if parts[i] != shareIDWords[len(shareIDWords)-1] {
				t.Fatal("last word is not reachable", id)
			}
		}
	}
	for i := 0; i < 200; i++ {
		id, err := newShareID()
		if err != nil {
			t.Fatal(err)
		}
		assertReadableShareID(t, id)
	}
	// Every truncated sample fails closed, never yielding a partial identifier.
	data := shareIDEntropy(0, 0, 0)
	for cut := 0; cut < len(data); cut++ {
		if id, err := generateShareID(bytes.NewReader(data[:cut])); err == nil || id != "" {
			t.Fatalf("entropy truncation %d did not fail closed: %q %v", cut, id, err)
		}
	}
}

func TestReadableShareIDRejectionSampling(t *testing.T) {
	var data []byte
	for i := 0; i < 7; i++ {
		choices := len(shareIDWords)
		if i == 3 || i == 5 {
			choices = shareIDNumberChoices
		}
		// This value must be discarded, not reduced modulo the number of choices.
		data = append(data, shareIDSample(choices, choices)...)
		data = append(data, shareIDSample(0, choices)...)
	}
	id, err := generateShareID(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	want := shareIDWords[0] + "-" + shareIDWords[0] + "-" + shareIDWords[0] + "-1000000-" + shareIDWords[0] + "-1000000-" + shareIDWords[0]
	if id != want {
		t.Fatalf("rejection sampling: got %q want %q", id, want)
	}
}

func TestReadableShareIDClaimCollisions(t *testing.T) {
	e := newEnv(t)
	root := filepath.Join(e.s.St.DataDir, "shares")
	first, _ := generateShareID(bytes.NewReader(shareIDEntropy(0, 0, 0)))
	second, _ := generateShareID(bytes.NewReader(shareIDEntropy(1, 0, 0)))
	third, _ := generateShareID(bytes.NewReader(shareIDEntropy(2, 0, 0)))
	if _, err := rawExec(e.t, e.s.St, `INSERT INTO shares(long_id,name) VALUES(?, 'preserved')`, first); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, second), 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, second, "existing.txt")
	if err := os.WriteFile(marker, []byte("existing data"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	id, dest, err := claimShareDir(e.s.St.Repos().Shares(), root, func() (string, error) {
		candidates := []string{first, second, third}
		calls++
		return candidates[calls-1], nil
	})
	if err != nil || id != third || dest != filepath.Join(root, third) || calls != 3 {
		t.Fatalf("claim: %q %q calls=%d err=%v", id, dest, calls, err)
	}
	if _, err := os.Stat(filepath.Join(root, first)); !os.IsNotExist(err) {
		t.Fatal("DB collision created a directory", err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "existing data" {
		t.Fatal("existing data touched", err)
	}
	var name string
	if err := qByName(e.s.St, `SELECT name FROM shares WHERE long_id=?`, first).Scan(&name); err != nil || name != "preserved" {
		t.Fatal("existing DB row touched", name, err)
	}
	for _, collision := range []string{first, second} {
		calls = 0
		id, dest, err := claimShareDir(e.s.St.Repos().Shares(), root, func() (string, error) { calls++; return collision, nil })
		if err == nil || id != "" || dest != "" || calls != shareIDClaimAttempts {
			t.Fatalf("retry limit: %q %q calls=%d err=%v", id, dest, calls, err)
		}
	}
	// Existing ordinary files are collisions too; never truncate or remove them.
	fileCollision := filepath.Join(root, "occupied")
	if err := os.WriteFile(fileCollision, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := claimShareDir(e.s.St.Repos().Shares(), root, func() (string, error) { return "occupied", nil }); err == nil {
		t.Fatal("existing file accepted")
	}
	if data, err := os.ReadFile(fileCollision); err != nil || string(data) != "keep" {
		t.Fatal("existing file touched", err)
	}
}

func TestReadableShareIDClaimErrorsAndConcurrency(t *testing.T) {
	e := newEnv(t)
	root := filepath.Join(e.s.St.DataDir, "shares")
	entropyError := errors.New("deterministic entropy failure")
	if _, _, err := claimShareDir(e.s.St.Repos().Shares(), root, func() (string, error) { return "", entropyError }); !errors.Is(err, entropyError) {
		t.Fatal("entropy error lost", err)
	}
	if _, _, err := claimShareDir(e.s.St.Repos().Shares(), filepath.Join(root, "missing", "parent"), func() (string, error) { return "candidate", nil }); err == nil {
		t.Fatal("IO error ignored")
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			_, _, err := claimShareDir(e.s.St.Repos().Shares(), root, func() (string, error) { return "concurrent", nil })
			results <- err
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("exclusive claims: successes=%d", successes)
	}
	if err := e.s.St.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := claimShareDir(e.s.St.Repos().Shares(), root, func() (string, error) { return "db-error", nil }); err == nil {
		t.Fatal("database error ignored")
	}
	if _, err := os.Stat(filepath.Join(root, "db-error")); !os.IsNotExist(err) {
		t.Fatal("database failure created directory", err)
	}
}

func TestReadableShareIDCompletionFailureRetainsParts(t *testing.T) {
	for _, mode := range []string{"entropy", "directory-collision", "database-collision", "io", "unique-backstop", "checksum"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			token := e.setup()
			created := e.do("POST", "/api/uploads", token, map[string]any{"files": []map[string]any{{"name": "a.txt", "size": 4, "sha256": sum([]byte("keep"))}}})
			e.want(created, 201, "create")
			id := created.S("id")
			e.want(e.do("PATCH", "/api/uploads/"+id+"/files/0", token, []byte("keep"), "Upload-Offset", "0"), 200, "chunk")
			candidate, _ := generateShareID(bytes.NewReader(shareIDEntropy(0, 0, 0)))
			root := filepath.Join(e.s.St.DataDir, "shares")
			dest := filepath.Join(root, candidate)
			generate := func() (string, error) { return candidate, nil }
			switch mode {
			case "entropy":
				generate = func() (string, error) { return generateShareID(bytes.NewReader(nil)) }
			case "directory-collision":
				if err := os.Mkdir(dest, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dest, "marker"), []byte("untouched"), 0600); err != nil {
					t.Fatal(err)
				}
			case "database-collision":
				if _, err := rawExec(e.t, e.s.St, `INSERT INTO shares(long_id,name) VALUES(?, 'untouched')`, candidate); err != nil {
					t.Fatal(err)
				}
			case "io":
				if err := os.Remove(root); err != nil {
					t.Fatal(err)
				}
			case "unique-backstop":
				if _, err := e.s.St.DB.Exec(`CREATE TRIGGER block_share BEFORE INSERT ON shares BEGIN SELECT RAISE(ABORT, 'private database detail'); END`); err != nil {
					t.Fatal(err)
				}
			case "checksum":
				if err := os.WriteFile(filepath.Join(e.s.uploadDir(id), "0.part"), []byte("evil"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			u, err := e.s.userByID(1)
			if err != nil {
				t.Fatal(err)
			}
			r := withUser(httptest.NewRequest("POST", "/api/uploads/"+id+"/complete", strings.NewReader(`{}`)), u)
			route := chi.NewRouteContext()
			route.URLParams.Add("id", id)
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
			w := httptest.NewRecorder()
			e.s.completeUploadWithShareID(w, r, generate)
			wantStatus := 500
			if mode == "checksum" {
				wantStatus = 409
			}
			if w.Code != wantStatus || strings.Contains(w.Body.String(), "private database detail") {
				t.Fatalf("failure response: %d %s", w.Code, w.Body.String())
			}
			e.want(e.do("GET", "/api/uploads/"+id, token, nil), 200, "reservation retained")
			wantPart := "keep"
			if mode == "checksum" {
				wantPart = "evil"
			}
			if data, err := os.ReadFile(filepath.Join(e.s.uploadDir(id), "0.part")); err != nil || string(data) != wantPart {
				t.Fatal("original parts lost", err)
			}
			if mode == "directory-collision" {
				if data, err := os.ReadFile(filepath.Join(dest, "marker")); err != nil || string(data) != "untouched" {
					t.Fatal("existing directory changed", err)
				}
			} else if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("uncommitted claimed directory leaked", err)
			}
			if mode == "database-collision" {
				var name string
				if err := qByName(e.s.St, `SELECT name FROM shares WHERE long_id=?`, candidate).Scan(&name); err != nil || name != "untouched" {
					t.Fatal("existing row changed", err)
				}
			}
		})
	}
}

func TestReadableShareIDNewAndLegacyDownloads(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	created := e.share(token, map[string]string{"folder/a.txt": "alpha", "b.txt": "beta"}, map[string]any{"password": "secret12"})
	e.want(created, 201, "readable share")
	id := created.S("long_id")
	assertReadableShareID(t, id)
	if !strings.HasSuffix(created.S("url"), "/share/"+id) {
		t.Fatal("wrong public URL")
	}
	e.want(e.do("GET", "/api/shares/"+id, "", nil), 200, "readable lookup")
	e.want(e.do("GET", "/api/shares/"+id+"/download", "", nil), 401, "password required")
	unlock := e.do("POST", "/api/shares/"+id+"/unlock", "", map[string]any{"password": "secret12"})
	e.want(unlock, 200, "unlock")
	download := e.do("GET", "/api/shares/"+id+"/download?token="+unlock.S("token"), "", nil)
	e.want(download, 200, "readable ZIP")
	assertDigest(t, download)
	zr, err := zip.NewReader(bytes.NewReader(download.Body), int64(len(download.Body)))
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{}
	for _, member := range zr.File {
		f, err := member.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		contents[member.Name] = string(data)
	}
	if len(contents) != 2 || contents["folder/a.txt"] != "alpha" || contents["b.txt"] != "beta" {
		t.Fatal("ZIP contents changed", contents)
	}
	legacy := e.share(token, map[string]string{"legacy.txt": "legacy bytes"}, nil)
	e.want(legacy, 201, "legacy fixture")
	files := e.s.shareFiles(int64(legacy.J()["id"].(float64)))
	const oldID = "0123456789abcdef"
	if _, err := rawExec(e.t, e.s.St, `UPDATE shares SET long_id=? WHERE id=?`, oldID, legacy.J()["id"]); err != nil {
		t.Fatal(err)
	}
	// A real legacy share lives in a directory named after its ID.
	if err := os.Rename(filepath.Join(e.s.St.DataDir, "shares", legacy.S("long_id")), filepath.Join(e.s.St.DataDir, "shares", oldID)); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("GET", "/api/shares/"+oldID, "", nil), 200, "legacy lookup")
	oldDownload := e.do("GET", "/api/shares/"+oldID+"/download", "", nil)
	e.want(oldDownload, 200, "legacy download")
	assertDigest(t, oldDownload)
	if string(oldDownload.Body) != "legacy bytes" || filepath.Base(e.s.shareFiles(int64(legacy.J()["id"].(float64)))[0].diskPath) != filepath.Base(files[0].diskPath) {
		t.Fatal("legacy bytes/path changed")
	}
}
