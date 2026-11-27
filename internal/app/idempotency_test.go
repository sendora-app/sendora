// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestIdempotencyKeyOnRealRoute(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	body := map[string]any{"username": "idem", "password": "password123", "email": "idem@x.io"}
	first := e.do("POST", "/api/users", tok, body, "Idempotency-Key", "k-1")
	e.want(first, 201, "create with key")
	again := e.do("POST", "/api/users", tok, body, "Idempotency-Key", "k-1")
	e.want(again, 201, "retry with the same key")
	if again.Hdr.Get("Sendora-Idempotency") != "replayed" || !bytes.Equal(again.Body, first.Body) {
		t.Fatalf("retry was not a replay: %q %s vs %s", again.Hdr.Get("Sendora-Idempotency"), again.Body, first.Body)
	}
	if n, _ := e.s.St.Repos().Users().CountByUsernameFold(context.Background(), "idem"); n != 1 {
		t.Fatalf("%d accounts after a retried create", n)
	}
	// The same key for another request is refused.
	other := map[string]any{"username": "idem2", "password": "password123", "email": "idem2@x.io"}
	e.want(e.do("POST", "/api/users", tok, other, "Idempotency-Key", "k-1"), 422, "key reused for another request")
	// JSON key order and spacing do not make a different request.
	e.want(e.do("POST", "/api/users", tok, []byte(`{ "email":"idem@x.io","password":"password123", "username":"idem"}`), "Idempotency-Key", "k-1", "Content-Type", "application/json"), 201, "canonical body replay")
	// Without a key the request runs again (and fails: the name is taken).
	if r := e.do("POST", "/api/users", tok, body); r.Code == 201 {
		t.Fatal("a request without a key was replayed")
	}
	// A failed request releases its key: the retry runs again.
	bad := map[string]any{"username": "", "password": "x"}
	r1 := e.do("POST", "/api/users", tok, bad, "Idempotency-Key", "k-2")
	r2 := e.do("POST", "/api/users", tok, bad, "Idempotency-Key", "k-2")
	if r1.Code < 400 || r2.Code != r1.Code || r2.Hdr.Get("Sendora-Idempotency") == "replayed" {
		t.Fatalf("failed request: %d then %d (%q)", r1.Code, r2.Code, r2.Hdr.Get("Sendora-Idempotency"))
	}
	e.want(e.do("POST", "/api/users", tok, body, "Idempotency-Key", "bad key"), 400, "invalid key")
	// Keys are per user: another account's key never replays this response.
	other2 := e.mkUser(tok, "second", true)
	if r := e.do("POST", "/api/users", other2, body, "Idempotency-Key", "k-1"); r.Hdr.Get("Sendora-Idempotency") == "replayed" {
		t.Fatal("a key of another user replayed")
	}
	// Chunk uploads are exempt.
	up := e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "a", "full_path": "a", "size": 1}}})
	e.want(up, 201, "upload")
	chunk := e.do("PATCH", "/api/uploads/"+up.S("id")+"/files/0", tok, []byte("x"), "Upload-Offset", "0", "Idempotency-Key", "k-3")
	if chunk.Code != 200 || chunk.Hdr.Get("Sendora-Idempotency") != "unsupported" {
		t.Fatalf("chunk: %d %q", chunk.Code, chunk.Hdr.Get("Sendora-Idempotency"))
	}
	// Keys expire after a day (jobs).
	if n, err := e.s.St.Repos().Idempotency().Expire(context.Background(), time.Now().Add(time.Hour)); err != nil || n == 0 {
		t.Fatalf("Expire = %d, %v", n, err)
	}
	e.want(e.do("POST", "/api/users", tok, body, "Idempotency-Key", "k-1"), 400, "expired key runs again (name taken)")
}

func TestIdempotencyConcurrentRetryGetsConflictThenReplay(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	var runs atomic.Int32
	r := chi.NewRouter()
	r.With(e.s.idempotent).Post("/api/x", func(w http.ResponseWriter, r *http.Request) {
		runs.Add(1)
		<-release
		jout(w, 201, map[string]any{"id": 7})
	})
	ts := httptest.NewServer(r)
	defer ts.Close()
	post := func() (*http.Response, string) {
		req, _ := http.NewRequest("POST", ts.URL+"/api/x", strings.NewReader(`{"a":1}`))
		req.Header.Set("Idempotency-Key", "same")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res, string(b)
	}
	done := make(chan string)
	go func() { _, b := post(); done <- b }()
	for runs.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	res, _ := post()
	if res.StatusCode != 409 || res.Header.Get("Retry-After") == "" || res.Header.Get("Sendora-Idempotency") != "in-progress" {
		t.Fatalf("concurrent retry: %d %v", res.StatusCode, res.Header)
	}
	close(release)
	firstBody := <-done
	res, b := post()
	if res.StatusCode != 201 || b != firstBody || runs.Load() != 1 {
		t.Fatalf("after completion: %d %q (first %q), runs=%d", res.StatusCode, b, firstBody, runs.Load())
	}
}

func TestIdempotencyStoredResponseIsEncrypted(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	sealed, err := sealResponse(key, "u:1\x00h", storedResponse{Status: 201, Body: []byte(`{"secret":"token-123"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("token-123")) {
		t.Fatal("response stored in plaintext")
	}
	if _, err := openResponse(key, "u:2\x00h", sealed); err == nil {
		t.Fatal("a stored response opened under another scope")
	}
	r, err := openResponse(key, "u:1\x00h", sealed)
	if err != nil || r.Status != 201 {
		t.Fatalf("open = %+v, %v", r, err)
	}
	if string(canonicalBody([]byte(`{"b":1, "a":[1,2]}`))) != `{"a":[1,2],"b":1}` {
		t.Fatal("canonical JSON")
	}
	for k, ok := range map[string]bool{"550e8400-e29b-41d4-a716-446655440000": true, "": false, "a b": false, strings.Repeat("x", 129): false, "é": false} {
		if validIdempotencyKey(k) != ok {
			t.Errorf("validIdempotencyKey(%q) != %v", k, ok)
		}
	}
}
