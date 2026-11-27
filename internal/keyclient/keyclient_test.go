// SPDX-License-Identifier: AGPL-3.0-or-later

package keyclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

func tokenFile(t *testing.T, tok string) string {
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func caFile(t *testing.T, s *httptest.Server) string {
	f := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0o600)
	return f
}

func TestTLSVerifyFailsWithTheWrongCA(t *testing.T) {
	var hits atomic.Int32
	real := serve(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte(`{}`)) })
	c, err := New(Config{URL: real.URL, CAFile: unrelatedCA(t), TokenFile: tokenFile(t, "t")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Platform(t.Context()); err == nil || hits.Load() != 0 {
		t.Fatalf("untrusted server was contacted (hits %d, err %v)", hits.Load(), err)
	}
	// And the right CA works (a cert is also checked against the host name).
	c, _ = New(Config{URL: real.URL, CAFile: caFile(t, real), TokenFile: tokenFile(t, "t")})
	if _, err := c.Platform(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{URL: "http://x", CAFile: "x", TokenFile: "x"}); err == nil {
		t.Fatal("plain http accepted")
	}
}

func TestRejectsTLS12Server(t *testing.T) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	s.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	s.StartTLS()
	defer s.Close()
	c, _ := New(Config{URL: s.URL, CAFile: caFile(t, s), TokenFile: tokenFile(t, "t")})
	if _, err := c.Platform(t.Context()); err == nil {
		t.Fatal("TLS 1.2 server accepted")
	}
}

func TestBadTokenIsDeniedAndTokenIsReRead(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"db_password":"pw","db_key":"k","root":""}`))
	})
	tf := tokenFile(t, "bad\n")
	c, _ := New(Config{URL: s.URL, CAFile: caFile(t, s), TokenFile: tf})
	if _, err := c.Tenant(t.Context(), "id"); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v, want ErrDenied", err)
	}
	os.WriteFile(tf, []byte("good\n"), 0o600) // rotation
	k, err := c.Tenant(t.Context(), "id")
	if err != nil || k.DBPassword != "pw" {
		t.Fatalf("after rotation: %+v %v", k, err)
	}
}

func TestCacheTTLAndClose(t *testing.T) {
	var hits atomic.Int32
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"db_password":"pw","db_key":"k","root":"r"}`))
	})
	now := time.Now()
	c, _ := New(Config{URL: s.URL, CAFile: caFile(t, s), TokenFile: tokenFile(t, "t"), TTL: time.Minute, Now: func() time.Time { return now }})
	for range 3 {
		if _, err := c.Tenant(t.Context(), "a"); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("cache missed: %d requests", hits.Load())
	}
	c.Tenant(t.Context(), "b")
	if hits.Load() != 2 {
		t.Fatal("tenants must be cached separately")
	}
	now = now.Add(2 * time.Minute)
	c.Tenant(t.Context(), "a")
	if hits.Load() != 3 {
		t.Fatal("expired entry served from the cache")
	}
	var body []byte
	for _, e := range c.cache {
		body = e.body
	}
	c.Close()
	for _, b := range body {
		if b != 0 {
			t.Fatal("cache not wiped on Close")
		}
	}
	if _, err := c.Tenant(t.Context(), "a"); err == nil {
		t.Fatal("closed client served a request")
	}
}

// unrelatedCA writes a self-signed certificate that did not sign the server.
func unrelatedCA(t *testing.T) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "other.crt")
	os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	return f
}

// A controller that reports a lock (423) makes the client drop the cached keys
// of that tenant and return ports.ErrLocked, so a lock is never masked by the cache.
func TestLockedAnswerDropsTheCache(t *testing.T) {
	var locked atomic.Bool
	var hits atomic.Int32
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if locked.Load() {
			w.WriteHeader(http.StatusLocked)
			w.Write([]byte(`{"error":"Locked"}`))
			return
		}
		w.Write([]byte(`{"db_password":"p","db_key":"k","kek":"w"}`))
	})
	now := time.Now()
	c, _ := New(Config{URL: s.URL, CAFile: caFile(t, s), TokenFile: tokenFile(t, "t"), TTL: time.Hour, Now: func() time.Time { return now }})
	if k, err := c.Tenant(t.Context(), "x"); err != nil || k.KEK != "w" {
		t.Fatalf("first: %+v %v", k, err)
	}
	c.Tenant(t.Context(), "x")
	if hits.Load() != 1 {
		t.Fatalf("not cached: %d hits", hits.Load())
	}
	locked.Store(true)
	now = now.Add(2 * time.Hour) // the TTL ends: the next call asks and learns of the lock
	if _, err := c.Tenant(t.Context(), "x"); !errors.Is(err, ports.ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	// The "locked" answer is reused for LockedTTL: a burst of requests for a
	// locked tenant asks the controller once, not once per request.
	before := hits.Load()
	for i := 0; i < 50; i++ {
		if _, err := c.Tenant(t.Context(), "x"); !errors.Is(err, ports.ErrLocked) {
			t.Fatalf("locked (remembered) %d: %v", i, err)
		}
	}
	if hits.Load() != before {
		t.Fatalf("a locked tenant asked the controller %d more times", hits.Load()-before)
	}
	// Unlocked again: after LockedTTL the next call fetches (nothing stale was kept).
	locked.Store(false)
	now = now.Add(2 * time.Second)
	if k, err := c.Tenant(t.Context(), "x"); err != nil || k.KEK != "w" {
		t.Fatalf("after the unlock: %+v %v", k, err)
	}
	// An unlock through this replica (ForgetTenant) takes effect at once.
	locked.Store(true)
	now = now.Add(2 * time.Hour)
	if _, err := c.Tenant(t.Context(), "x"); !errors.Is(err, ports.ErrLocked) {
		t.Fatalf("locked again: %v", err)
	}
	locked.Store(false)
	c.ForgetTenant("x")
	if k, err := c.Tenant(t.Context(), "x"); err != nil || k.KEK != "w" {
		t.Fatalf("after ForgetTenant: %+v %v", k, err)
	}
}
