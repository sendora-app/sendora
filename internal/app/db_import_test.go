// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sendora-app/sendora/internal/store"

	"golang.org/x/crypto/bcrypt"
)

var liveKey = bytes.Repeat([]byte{0x31}, 32)
var otherKey = bytes.Repeat([]byte{0x42}, 32)

// newEncEnv is newEnv on an encrypted store (the import needs a key).
func newEncEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.OpenEncrypted(t.TempDir(), liveKey, true)
	if err != nil {
		t.Fatal(err)
	}
	legacyTestDefaults(t, st)
	t.Cleanup(func() { st.DB.Close() })
	s := New(st, fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}, "test")
	// Never exec the test binary or exit the test process.
	s.importExec = func() error { t.Error("unexpected real exec"); return nil }
	s.importExit = func(int) { t.Error("unexpected real exit") }
	s.passwordScreenOff = true
	ctx, cancel := context.WithCancel(context.Background())
	s.RunDownloadMail(ctx)
	t.Cleanup(cancel)
	ts := httptest.NewServer(s.Router())
	t.Cleanup(ts.Close)
	return &env{t: t, s: s, ts: ts}
}

type impPart struct {
	name, filename string
	data           []byte
}

func multipartBody(parts ...impPart) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range parts {
		if p.filename != "" {
			fw, _ := w.CreateFormFile(p.name, p.filename)
			fw.Write(p.data)
		} else {
			w.WriteField(p.name, string(p.data))
		}
	}
	w.Close()
	return &buf, w.FormDataContentType()
}

func (e *env) prepare(token string, parts ...impPart) resp {
	b, ct := multipartBody(parts...)
	return e.do("POST", "/api/backups/import", token, b, "Content-Type", ct)
}

func (e *env) apply(token string, body map[string]any) resp {
	return e.do("POST", "/api/backups/import/apply", token, body)
}

func dbFile(b []byte) impPart { return impPart{"file", "backup.db", b} }

// foreignDB builds an encrypted database (another environment) and returns its bytes.
func foreignDB(t *testing.T, key []byte, mutate func(*store.Store)) []byte {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenEncrypted(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	legacyTestDefaults(t, st)
	h, _ := bcrypt.GenerateFromPassword([]byte("otherpass"), bcrypt.MinCost)
	if _, err := rawExec(t, st, `INSERT INTO users(username,email,password_hash,admin) VALUES('olduser','old@x.io',?,1)`, string(h)); err != nil {
		t.Fatal(err)
	}
	if _, err := rawExec(t, st, `INSERT INTO users(username,email,password_hash,admin) VALUES('plain','plain@x.io',?,0)`, string(h)); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(st)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "sendora.db"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func addShareWithFiles(t *testing.T, st *store.Store, long string, disks ...string) {
	t.Helper()
	res, err := rawExec(t, st, `INSERT INTO shares(user_id,long_id,name) VALUES(1,?,?)`, long, long)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	for i, d := range disks {
		if _, err := st.DB.Exec(`INSERT INTO files(share_id,name,full_path,size,type,disk_path) VALUES(?,?,?,1,'',?)`, id, fmt.Sprint("f", i), fmt.Sprint("f", i), d); err != nil {
			t.Fatal(err)
		}
	}
}

func importLeftovers(t *testing.T, e *env) []string {
	t.Helper()
	var out []string
	ents, _ := os.ReadDir(filepath.Join(e.s.St.DataDir, "backups"))
	for _, x := range ents {
		if strings.HasPrefix(x.Name(), ".import-") {
			out = append(out, x.Name())
		}
	}
	return out
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestImportPrepareSameKeyAndSummary(t *testing.T) {
	e := newEncEnv(t)
	admin := e.setup()
	name := e.do("POST", "/api/backups", admin, nil).S("name")
	raw, err := os.ReadFile(filepath.Join(e.s.St.DataDir, "backups", name))
	if err != nil {
		t.Fatal(err)
	}
	r := e.prepare(admin, dbFile(raw))
	e.want(r, 200, "prepare with live key")
	j := r.J()
	tok, _ := j["token"].(string)
	if len(tok) != 64 || j["expires_in"] != float64(900) {
		t.Fatalf("token/expiry: %v", j)
	}
	sum := j["summary"].(map[string]any)
	if sum["users"] != float64(1) || sum["admins"] != float64(1) || sum["missing_files"] != float64(0) || sum["missing_shares"] != float64(0) {
		t.Fatalf("summary: %v", sum)
	}
	if _, ok := sum["warnings"].([]any); !ok {
		t.Fatalf("warnings: %v", sum)
	}
	left := importLeftovers(t, e)
	if len(left) != 1 || !strings.HasSuffix(left[0], ".new") || !strings.Contains(left[0], tok) {
		t.Fatalf("leftovers: %v", left)
	}
	info, _ := os.Stat(filepath.Join(e.s.St.DataDir, "backups", left[0]))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", info.Mode())
	}
}

func TestImportOtherKeyHexAndKeyFileWithMissingFiles(t *testing.T) {
	e := newEncEnv(t)
	admin := e.setup()
	// Imported disk paths are rebased onto this server's DataDir/shares/<id>/, so a
	// file counts as present only when it exists at that rebased location.
	for _, lid := range []string{"aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"} {
		dir := filepath.Join(e.s.St.DataDir, "shares", lid)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "present.bin"), []byte("x"), 0o600)
	}
	raw := foreignDB(t, otherKey, func(st *store.Store) {
		addShareWithFiles(t, st, "aaaaaaaaaaaaaaaa", "/old/server/present.bin", "/nonexistent/one", "relative/two")
		addShareWithFiles(t, st, "bbbbbbbbbbbbbbbb", "/another/place/present.bin")
		// Stale reservations must not survive.
		st.DB.Exec(`INSERT INTO upload_sessions(id,user_id,quota_owner_id) VALUES('s1',1,1)`)
		st.DB.Exec(`INSERT INTO upload_files(session_id,idx,name,full_path,size) VALUES('s1',0,'a','a',5)`)
	})
	r := e.prepare(admin, impPart{"key_hex", "", []byte(strings.ToUpper(hex.EncodeToString(otherKey)))}, dbFile(raw))
	e.want(r, 200, "other key hex")
	sum := r.J()["summary"].(map[string]any)
	if sum["users"] != float64(2) || sum["admins"] != float64(1) || sum["shares"] != float64(2) || sum["files"] != float64(4) ||
		sum["missing_files"] != float64(2) || sum["missing_shares"] != float64(1) {
		t.Fatalf("summary: %v", sum)
	}
	warn := fmt.Sprint(sum["warnings"])
	if !strings.Contains(warn, "2 file(s) in 1 share(s)") || !strings.Contains(warn, "1 unfinished upload") {
		t.Fatalf("warnings: %v", warn)
	}
	// A second preparation (key file) discards the first.
	first := r.S("token")
	r2 := e.prepare(admin, impPart{"key_file", "key.bin", otherKey}, dbFile(raw))
	e.want(r2, 200, "other key file")
	if len(importLeftovers(t, e)) != 1 {
		t.Fatalf("old preparation kept: %v", importLeftovers(t, e))
	}
	e.want(e.apply(admin, map[string]any{"token": first, "confirm": "IMPORT", "password": "password123"}), 404, "discarded token")
	// The prepared copy is keyed with the live key, not the source key.
	left := importLeftovers(t, e)
	p := filepath.Join(e.s.St.DataDir, "backups", left[0])
	if _, err := store.VerifyDatabase(p, liveKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyDatabase(p, otherKey); err == nil {
		t.Fatal("prepared copy readable with source key")
	}
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	if n != 1 {
		t.Fatal("live database touched")
	}
}

func TestImportRejections(t *testing.T) {
	e := newEncEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	good := foreignDB(t, otherKey, nil)
	secret := hex.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
	plain := append([]byte("SQLite format 3\x00"), make([]byte, 4096)...)
	garbage := make([]byte, 8192)
	rand.Read(garbage)
	futureTable := foreignDB(t, otherKey, func(st *store.Store) { st.DB.Exec(`CREATE TABLE future_things(id INTEGER)`) })
	futureColumn := foreignDB(t, otherKey, func(st *store.Store) { st.DB.Exec(`ALTER TABLE shares ADD COLUMN future_col TEXT`) })
	noAdmin := foreignDB(t, otherKey, func(st *store.Store) { st.DB.Exec(`UPDATE users SET admin=0`) })
	guestAdmin := foreignDB(t, otherKey, func(st *store.Store) { st.DB.Exec(`UPDATE users SET is_guest=1 WHERE admin=1`) })
	notSendora := func() []byte {
		// Valid encrypted SQLite, but not a Sendora schema.
		dir := t.TempDir()
		st, _ := store.OpenEncrypted(dir, otherKey, true)
		st.DB.Exec(`DROP TABLE files`)
		st.Close()
		b, _ := os.ReadFile(filepath.Join(dir, "sendora.db"))
		return b
	}()
	hexOther := impPart{"key_hex", "", []byte(hex.EncodeToString(otherKey))}
	cases := []struct {
		name  string
		token string
		parts []impPart
		want  int
		msg   string
	}{
		{"wrong key", admin, []impPart{{"key_hex", "", []byte(secret)}, dbFile(good)}, 400, "key is wrong"},
		{"missing key for other-key db", admin, []impPart{dbFile(good)}, 400, "key is wrong"},
		{"short hex", admin, []impPart{{"key_hex", "", []byte(secret[:60])}, dbFile(good)}, 400, "64 hexadecimal"},
		{"non-hex", admin, []impPart{{"key_hex", "", []byte(strings.Repeat("zz", 32))}, dbFile(good)}, 400, "64 hexadecimal"},
		{"key file size", admin, []impPart{{"key_file", "k", otherKey[:31]}, dbFile(good)}, 400, "exactly 32 raw bytes"},
		{"key file too long", admin, []impPart{{"key_file", "k", append(append([]byte{}, otherKey...), 1)}, dbFile(good)}, 400, "exactly 32 raw bytes"},
		{"both keys", admin, []impPart{hexOther, {"key_file", "k", otherKey}, dbFile(good)}, 400, "either key_hex or key_file"},
		{"key after file", admin, []impPart{dbFile(good), hexOther}, 400, "before the file"},
		{"unknown field", admin, []impPart{{"x", "", []byte("1")}, dbFile(good)}, 400, "unexpected form field"},
		{"no file", admin, []impPart{hexOther}, 400, "file required"},
		{"empty file", admin, []impPart{dbFile(nil)}, 400, "empty"},
		{"plaintext", admin, []impPart{dbFile(plain)}, 400, "unencrypted"},
		{"garbage", admin, []impPart{hexOther, dbFile(garbage)}, 400, "could not be opened"},
		{"tiny garbage", admin, []impPart{dbFile([]byte("hello"))}, 400, "could not be opened"},
		{"newer table", admin, []impPart{hexOther, dbFile(futureTable)}, 400, "newer Sendora version"},
		{"newer column", admin, []impPart{hexOther, dbFile(futureColumn)}, 400, "newer Sendora version"},
		{"no admin", admin, []impPart{hexOther, dbFile(noAdmin)}, 400, "no administrator"},
		{"only guest admin", admin, []impPart{hexOther, dbFile(guestAdmin)}, 400, "no administrator"},
		{"not sendora", admin, []impPart{hexOther, dbFile(notSendora)}, 400, "not a Sendora database"},
		{"non-admin", bob, []impPart{hexOther, dbFile(good)}, 403, "forbidden"},
		{"anonymous", "", []impPart{hexOther, dbFile(good)}, 401, "unauthorized"},
	}
	logs := &syncBuf{}
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for _, c := range cases {
		r := e.prepare(c.token, c.parts...)
		if r.Code != c.want || !strings.Contains(r.S("error"), c.msg) {
			t.Errorf("%s: got %d %s", c.name, r.Code, r.Body)
		}
		if strings.Contains(string(r.Body), secret) || strings.Contains(string(r.Body), hex.EncodeToString(otherKey)) {
			t.Errorf("%s: key material in response", c.name)
		}
		if left := importLeftovers(t, e); len(left) != 0 {
			t.Errorf("%s: leftovers %v", c.name, left)
		}
	}
	if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), hex.EncodeToString(otherKey)) {
		t.Fatal("key material in logs")
	}
	if r := e.do("POST", "/api/backups/import", admin, []byte("{}"), "Content-Type", "application/json"); r.Code != 400 {
		t.Fatalf("non-multipart: %d", r.Code)
	}
	// All of that left the live database untouched and a good file still works.
	e.want(e.prepare(admin, hexOther, dbFile(good)), 200, "good after failures")
}

func TestImportOversizeStreamed(t *testing.T) {
	e := newEncEnv(t)
	admin := e.setup()
	e.s.importMaxBytes = 2048
	big := make([]byte, 100<<10)
	b, ct := multipartBody(dbFile(big))
	// Unknown length (chunked): the limit must be enforced while streaming.
	r := e.do("POST", "/api/backups/import", admin, io.MultiReader(b), "Content-Type", ct)
	e.want(r, 413, "oversize streamed")
	// Known length is refused up front.
	b, ct = multipartBody(dbFile(big))
	e.want(e.do("POST", "/api/backups/import", admin, b, "Content-Type", ct), 413, "oversize declared")
	// File just over the limit but within framing slack.
	b, ct = multipartBody(dbFile(make([]byte, 3000)))
	e.want(e.do("POST", "/api/backups/import", admin, io.MultiReader(b), "Content-Type", ct), 413, "slightly oversize")
	if left := importLeftovers(t, e); len(left) != 0 {
		t.Fatal(left)
	}
}

func TestImportParallelPrepareAndTokenRules(t *testing.T) {
	e := newEncEnv(t)
	admin := e.setup()
	good := foreignDB(t, otherKey, nil)
	hexOther := impPart{"key_hex", "", []byte(hex.EncodeToString(otherKey))}

	// Slow first upload holds the single preparation slot.
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	done := make(chan resp, 1)
	go func() {
		req, _ := http.NewRequest("POST", e.ts.URL+"/api/backups/import", pr)
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- resp{Code: -1}
			return
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		done <- resp{res.StatusCode, b, res.Header}
	}()
	go func() {
		mw.WriteField("key_hex", hex.EncodeToString(otherKey))
		fw, _ := mw.CreateFormFile("file", "x.db")
		fw.Write(good[:100])
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !e.s.importPreparing.Load() {
		if time.Now().After(deadline) {
			t.Fatal("first prepare never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.want(e.prepare(admin, hexOther, dbFile(good)), 409, "parallel prepare")
	pw.CloseWithError(io.ErrClosedPipe)
	if r := <-done; r.Code == 200 {
		t.Fatal("aborted upload accepted")
	}
	if e.s.importPreparing.Load() {
		for i := 0; i < 100 && e.s.importPreparing.Load(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if e.s.importPreparing.Load() {
			t.Fatal("slot not released")
		}
	}
	if left := importLeftovers(t, e); len(left) != 0 {
		t.Fatalf("interrupted upload leftovers: %v", left)
	}

	// Token rules.
	r := e.prepare(admin, hexOther, dbFile(good))
	e.want(r, 200, "prepare")
	tok := r.S("token")
	body := func(t string) map[string]any {
		return map[string]any{"token": t, "confirm": "IMPORT", "password": "password123"}
	}
	e.want(e.apply(admin, body("")), 404, "empty token")
	e.want(e.apply(admin, body(strings.Repeat("0", 64))), 404, "invalid token")
	e.want(e.apply(admin, body(tok[:63])), 404, "short token")
	e.s.importTTL = 50 * time.Millisecond
	r = e.prepare(admin, hexOther, dbFile(good))
	e.want(r, 200, "prepare ttl")
	if r.J()["expires_in"] != float64(0) { // 50ms truncates to 0 seconds
		t.Fatalf("expires_in: %v", r.J()["expires_in"])
	}
	time.Sleep(120 * time.Millisecond)
	e.want(e.apply(admin, body(r.S("token"))), 404, "expired token")
	if left := importLeftovers(t, e); len(left) != 0 {
		t.Fatalf("expired copy kept: %v", left)
	}
	if e.s.maintenance.Load() || e.s.importApplying.Load() {
		t.Fatal("failed applies must not enter maintenance")
	}
	// maintain() removes stray import files and expired preparations.
	e.s.importTTL = 0
	r = e.prepare(admin, hexOther, dbFile(good))
	e.want(r, 200, "prepare again")
	stray := filepath.Join(e.s.St.DataDir, "backups", ".import-stray.src")
	os.WriteFile(stray, []byte("x"), 0o600)
	e.s.maintain()
	if _, err := os.Stat(stray); err == nil {
		t.Fatal("stray import file kept by maintain")
	}
	if len(importLeftovers(t, e)) != 1 {
		t.Fatal("maintain removed the live preparation")
	}
	e.s.imp.expires = time.Now().Add(-time.Second)
	e.s.maintain()
	if len(importLeftovers(t, e)) != 0 || e.s.imp != nil {
		t.Fatal("expired preparation kept by maintain")
	}
	// Startup cleanup.
	os.WriteFile(stray, []byte("x"), 0o600)
	New(e.s.St, fstest.MapFS{}, "x")
	if _, err := os.Stat(stray); err == nil {
		t.Fatal("stray import file kept at startup")
	}
}

type swapRec struct {
	mu     sync.Mutex
	events []string
	exit   []int
}

func (r *swapRec) add(s string) { r.mu.Lock(); r.events = append(r.events, s); r.mu.Unlock() }

func TestImportApplyFlow(t *testing.T) {
	e := newEncEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	dataDir := e.s.St.DataDir
	logs := &syncBuf{}
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	secret := hex.EncodeToString(otherKey)
	raw := foreignDB(t, otherKey, nil)
	var bodies []string
	r := e.prepare(admin, impPart{"key_hex", "", []byte(secret)}, dbFile(raw))
	e.want(r, 200, "prepare")
	bodies = append(bodies, string(r.Body))
	tok := r.S("token")
	prepared := filepath.Join(dataDir, "backups", ".import-"+tok+".new")

	// Uploads dir has stale staging that must be cleared.
	os.MkdirAll(filepath.Join(dataDir, "uploads", "sess1"), 0o700)
	os.WriteFile(filepath.Join(dataDir, "uploads", "sess1", "0.part"), []byte("p"), 0o600)
	os.WriteFile(filepath.Join(dataDir, "uploads", "loose"), []byte("p"), 0o600)

	rec := &swapRec{}
	release := make(chan struct{})
	e.s.importStop = func() { rec.add("stop"); <-release }
	e.s.importExit = func(c int) { rec.mu.Lock(); rec.exit = append(rec.exit, c); rec.mu.Unlock() }
	e.s.importExec = func() error {
		rec.add("exec")
		db := filepath.Join(dataDir, "sendora.db")
		for _, p := range []string{db + "-wal", db + "-shm"} {
			if _, err := os.Stat(p); err == nil {
				t.Errorf("%s still present at exec", p)
			}
		}
		if _, err := os.Stat(filepath.Join(dataDir, store.ImportMarker)); err != nil {
			t.Error("marker missing at exec")
		}
		if _, err := os.Stat(db + store.PreImportSuffix); err != nil {
			t.Error("pre-import database missing at exec")
		}
		if _, err := os.Stat(prepared); err == nil {
			t.Error("prepared copy still present at exec")
		}
		if ents, _ := os.ReadDir(filepath.Join(dataDir, "uploads")); len(ents) != 0 {
			t.Errorf("uploads not cleared: %d", len(ents))
		}
		if st, err := os.Stat(db); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("new database mode: %v %v", st, err)
		}
		return nil
	}

	good := func(token string) map[string]any {
		return map[string]any{"token": token, "confirm": "IMPORT", "password": "password123"}
	}
	for _, c := range []struct {
		name  string
		token string
		body  map[string]any
		want  int
	}{
		{"anonymous", "", good(tok), 401},
		{"non-admin", bob, good(tok), 403},
		{"no confirm", admin, map[string]any{"token": tok, "password": "password123"}, 400},
		{"wrong confirm", admin, map[string]any{"token": tok, "confirm": "import", "password": "password123"}, 400},
		{"no password", admin, map[string]any{"token": tok, "confirm": "IMPORT"}, 400},
		{"wrong password", admin, map[string]any{"token": tok, "confirm": "IMPORT", "password": "nope"}, 401},
		{"wrong token", admin, good(strings.Repeat("a", 64)), 404},
	} {
		r := e.apply(c.token, c.body)
		if r.Code != c.want {
			t.Fatalf("%s: want %d got %d %s", c.name, c.want, r.Code, r.Body)
		}
		bodies = append(bodies, string(r.Body))
	}
	if e.s.maintenance.Load() {
		t.Fatal("rejected apply entered maintenance")
	}
	if _, err := os.Stat(prepared); err != nil {
		t.Fatal("rejected apply discarded the preparation")
	}
	if ents, _ := os.ReadDir(filepath.Join(dataDir, "backups")); func() bool {
		for _, x := range ents {
			if strings.HasPrefix(x.Name(), "sendora-preimport-") {
				return true
			}
		}
		return false
	}() {
		t.Fatal("pre-import backup made before confirmation")
	}

	r = e.apply(admin, good(tok))
	e.want(r, 202, "apply")
	bodies = append(bodies, string(r.Body))
	name := r.S("backup")
	if !regexp.MustCompile(`^sendora-preimport-\d{8}-\d{6}-[a-f0-9]{12}\.db$`).MatchString(name) || r.J()["ok"] != true || r.J()["restarting"] != true {
		t.Fatalf("apply response: %s", r.Body)
	}
	backupPath := filepath.Join(dataDir, "backups", name)
	counts, err := store.VerifyDatabase(backupPath, liveKey)
	if err != nil || counts["users"] != 2 {
		t.Fatalf("pre-import backup: %v %v", counts, err)
	}

	// Maintenance: 503 + Retry-After, except health and static assets.
	m := e.do("GET", "/api/users/me", admin, nil)
	if m.Code != 503 || m.Hdr.Get("Retry-After") == "" {
		t.Fatalf("maintenance: %d %v", m.Code, m.Hdr)
	}
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"}), 503, "login in maintenance")
	e.want(e.do("GET", "/api/health", "", nil), 200, "health in maintenance")
	e.want(e.do("GET", "/", "", nil), 200, "static in maintenance")
	e.want(e.apply(admin, good(tok)), 409, "concurrent apply")

	// Audit events carry counts and the backup name only.
	// (Through the repository: target and detail are encrypted columns.)
	var applied, importPrepared *store.AuditRecord
	recs := openedAuditRecords(e)
	for i, r := range recs {
		switch {
		case r.Action == "db_import_applied" && r.Outcome == "ok":
			applied = &recs[i]
		case r.Action == "db_import_prepared" && r.Outcome == "ok":
			importPrepared = &recs[i]
		}
	}
	if applied == nil || applied.Target != name || applied.Detail != "users=2 admins=1 shares=0 files=0" {
		t.Fatalf("applied event: %+v", applied)
	}
	if importPrepared == nil || importPrepared.Target != "" || importPrepared.Detail != "users=2 admins=1 shares=0 files=0" {
		t.Fatalf("prepared event: %+v", importPrepared)
	}

	// Pre-import backups are never pruned (regular ones are).
	for i := 0; i < 3; i++ {
		if _, err := e.s.makeBackup(); err != nil {
			t.Fatal(err)
		}
	}
	e.s.St.SetSetting("backup_keep", "1")
	e.s.pruneBackups()
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatal("pre-import backup pruned")
	}
	regular := 0
	ents, _ := os.ReadDir(filepath.Join(dataDir, "backups"))
	for _, x := range ents {
		if strings.HasPrefix(x.Name(), "sendora-encrypted-") {
			regular++
		}
	}
	if regular != 1 {
		t.Fatalf("regular backups after prune: %d", regular)
	}

	// Release the stop hook; the swap runs and exec is invoked exactly once.
	close(release)
	select {
	case <-e.s.importDone:
	case <-time.After(10 * time.Second):
		t.Fatal("swap did not finish")
	}
	rec.mu.Lock()
	if fmt.Sprint(rec.events) != "[stop exec]" || len(rec.exit) != 0 {
		t.Fatalf("sequence: %v exit=%v", rec.events, rec.exit)
	}
	rec.mu.Unlock()

	// Fresh start on the swapped database: imported accounts, backup listing.
	st2, err := store.OpenEncryptedRecovering(dataDir, liveKey, false, log.Printf)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.DB.Close()
	if _, err := os.Stat(filepath.Join(dataDir, store.ImportMarker)); err == nil {
		t.Fatal("marker kept after successful start")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "sendora.db"+store.PreImportSuffix)); err == nil {
		t.Fatal(".pre-import kept after successful start")
	}
	s2 := New(st2, fstest.MapFS{"index.html": {Data: []byte("x")}}, "test")
	ts2 := httptest.NewServer(s2.Router())
	defer ts2.Close()
	e2 := &env{t: t, s: s2, ts: ts2}
	if lr := e2.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"}); lr.Code == 200 {
		t.Fatal("old account survived the import")
	}
	lr := e2.do("POST", "/api/auth/login", "", map[string]any{"username": "olduser", "password": "otherpass"})
	e2.want(lr, 200, "imported account login")
	tok2 := lr.S("access_token")
	list := e2.do("GET", "/api/backups", tok2, nil)
	e2.want(list, 200, "list backups")
	if !strings.Contains(string(list.Body), name) || !strings.Contains(string(list.Body), `"pre_import":true`) {
		t.Fatalf("pre-import backup not listed: %s", list.Body)
	}
	dl := e2.do("GET", "/api/backups/"+name, tok2, nil)
	e2.want(dl, 200, "download pre-import backup")
	if bytes.HasPrefix(dl.Body, []byte("SQLite format 3")) {
		t.Fatal("pre-import backup is plaintext")
	}
	e2.want(e2.do("DELETE", "/api/backups/"+name, tok2, nil), 200, "delete pre-import backup")
	if _, err := os.Stat(backupPath); err == nil {
		t.Fatal("pre-import backup not deleted")
	}

	// No key material, token or file names anywhere observable.
	var evAll string
	rows, _ := st2.DB.Query(`SELECT action||actor_name||target||detail FROM audit_log`)
	for rows != nil && rows.Next() {
		var x string
		rows.Scan(&x)
		evAll += x
	}
	if rows != nil {
		rows.Close()
	}
	for _, leak := range []string{secret, strings.ToUpper(secret), tok, "backup.db"} {
		for _, b := range bodies {
			if strings.Contains(b, leak) && leak != tok {
				t.Fatalf("leak %q in response %s", leak, b)
			}
		}
		if strings.Contains(logs.String(), leak) || strings.Contains(evAll, leak) {
			t.Fatalf("leak %q in logs/events", leak)
		}
	}
	// The token is only ever returned by the prepare response.
	for _, b := range bodies[1:] {
		if strings.Contains(b, tok) {
			t.Fatalf("token echoed: %s", b)
		}
	}
}

func TestImportApplyWithoutLocalPasswordAndBackupFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not apply to root")
	}
	e := newEncEnv(t)
	admin := e.setup()
	raw := foreignDB(t, otherKey, nil)
	hexOther := impPart{"key_hex", "", []byte(hex.EncodeToString(otherKey))}
	tok := e.prepare(admin, hexOther, dbFile(raw)).S("token")
	// Backup failure: nothing changes and the preparation stays usable.
	backups := filepath.Join(e.s.St.DataDir, "backups")
	os.Chmod(backups, 0o500)
	r := e.apply(admin, map[string]any{"token": tok, "confirm": "IMPORT", "password": "password123"})
	os.Chmod(backups, 0o700)
	if r.Code != 500 {
		t.Skipf("cannot make backups directory unwritable here (%d)", r.Code)
	}
	if e.s.maintenance.Load() || e.s.importApplying.Load() {
		t.Fatal("failed backup left maintenance on")
	}
	e.want(e.do("GET", "/api/users/me", admin, nil), 200, "service continues")
	// An administrator without a local password (external login only) cannot
	// apply an import: there is nothing to re-authenticate with.
	var savedHash string
	qByName(e.s.St, `SELECT password_hash FROM users WHERE username='admin'`).Scan(&savedHash)
	if _, err := eByName(e.s.St, `UPDATE users SET password_hash='' WHERE username='admin'`); err != nil {
		t.Fatal(err)
	}
	u, _ := e.s.userByID(1)
	r = e.apply(e.s.accessToken(u), map[string]any{"token": tok, "confirm": "IMPORT"})
	e.want(r, 403, "SSO-only admin cannot apply an import")
	if !strings.Contains(r.S("error"), "local password") {
		t.Fatalf("unclear message: %q", r.S("error"))
	}
	if e.s.maintenance.Load() || e.s.importApplying.Load() {
		t.Fatal("refused import left maintenance on")
	}
	if _, err := eByName(e.s.St, `UPDATE users SET password_hash=? WHERE username='admin'`, savedHash); err != nil {
		t.Fatal(err)
	}
	u, _ = e.s.userByID(1)
	acc := e.s.accessToken(u)
	e.s.importStop = func() {}
	e.s.importExec = func() error { return nil }
	r = e.apply(acc, map[string]any{"token": tok, "confirm": "IMPORT", "password": "password123"})
	e.want(r, 202, "apply with local password")
	select {
	case <-e.s.importDone:
	case <-time.After(10 * time.Second):
		t.Fatal("swap did not finish")
	}
}

func TestImportSwapFailureRestoresAndExits(t *testing.T) {
	e := newEncEnv(t)
	admin := e.setup()
	raw := foreignDB(t, otherKey, nil)
	tok := e.prepare(admin, impPart{"key_hex", "", []byte(hex.EncodeToString(otherKey))}, dbFile(raw)).S("token")
	dataDir := e.s.St.DataDir
	rec := &swapRec{}
	e.s.importStop = func() { rec.add("stop") }
	e.s.importExec = func() error { rec.add("exec"); return nil }
	e.s.importExit = func(c int) { rec.mu.Lock(); rec.exit = append(rec.exit, c); rec.mu.Unlock() }
	// Sabotage: the prepared copy vanishes just before the swap.
	e.s.importStop = func() {
		rec.add("stop")
		os.Remove(filepath.Join(dataDir, "backups", ".import-"+tok+".new"))
	}
	e.want(e.apply(admin, map[string]any{"token": tok, "confirm": "IMPORT", "password": "password123"}), 202, "apply")
	<-e.s.importDone
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if fmt.Sprint(rec.events) != "[stop]" || fmt.Sprint(rec.exit) != "[1]" {
		t.Fatalf("events=%v exit=%v", rec.events, rec.exit)
	}
	if _, err := os.Stat(filepath.Join(dataDir, store.ImportMarker)); err == nil {
		t.Fatal("marker kept after failed swap")
	}
	st, err := store.OpenEncrypted(dataDir, liveKey, false)
	if err != nil {
		t.Fatal("previous database not restored: ", err)
	}
	st.Close()
}

func TestImportRoutesRequireAdminAndPlaintextStoreRefuses(t *testing.T) {
	e := newEnv(t) // plaintext fixture store
	admin := e.setup()
	r := e.prepare(admin, dbFile([]byte("x")))
	e.want(r, 409, "plaintext store")
	e.want(e.apply(admin, map[string]any{"token": "x", "confirm": "IMPORT"}), 409, "plaintext store apply")
}
