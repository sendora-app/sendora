// SPDX-License-Identifier: AGPL-3.0-or-later

package keyserver_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sendora-app/sendora/internal/keyclient"
	"github.com/sendora-app/sendora/internal/keyserver"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
)

const allowed = "system:serviceaccount:sendora-cluster:sendora-web"

// fakeReview maps token -> identity.
type fakeReview map[string]ports.Identity

func (f fakeReview) Review(_ context.Context, token, aud string) (ports.Identity, error) {
	if aud != keyserver.Audience {
		return ports.Identity{}, errors.New("audience")
	}
	id, ok := f[token]
	if !ok {
		return ports.Identity{}, errors.New("not authenticated")
	}
	return id, nil
}

type logs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logs) logf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.b, f+"\n", a...)
}
func (l *logs) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type env struct {
	master  []byte
	p       *platform.Platform
	local   *keyserver.Local
	srv     *httptest.Server
	log     *logs
	active  *platform.Tenant
	pending *platform.Tenant
	susp    *platform.Tenant
	deleted string
}

func setup(t *testing.T) *env {
	t.Helper()
	master := make([]byte, 32)
	rand.Read(master)
	p, err := platform.Open(t.TempDir(), master, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	e := &env{master: master, p: p, log: &logs{}}
	if e.active, err = p.CreateTenant("actief", "A", 0, 0); err != nil {
		t.Fatal(err)
	}
	if e.susp, err = p.CreateTenant("schorst", "S", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := p.SetStatus(e.susp.ID, platform.StatusSuspended); err != nil {
		t.Fatal(err)
	}
	if e.pending, err = p.CreatePendingTenant("wacht", "W", 0, 0); err != nil {
		t.Fatal(err)
	}
	gone, _ := p.CreateTenant("weg", "G", 0, 0)
	e.deleted = gone.ID
	if err := p.DeleteTenantRow(gone.ID); err != nil {
		t.Fatal(err)
	}
	e.local = &keyserver.Local{Master: master, P: p}
	h := keyserver.Handler(keyserver.Config{Source: e.local, AllowedUser: allowed, Logf: e.log.logf,
		Review: fakeReview{
			"good":  {User: allowed, Pod: "web-1"},
			"other": {User: "system:serviceaccount:sendora-cluster:sendora-controller", Pod: "evil"},
			"alien": {User: "system:serviceaccount:other-ns:sendora-web", Pod: "alien"},
		},
		Status: func(id string) (string, error) {
			tn, err := p.Tenant(id)
			if err != nil {
				return "", err
			}
			return tn.Status, nil
		}})
	e.srv = httptest.NewUnstartedServer(h)
	e.srv.EnableHTTP2 = false
	e.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) client(t *testing.T, token string) *keyclient.Client {
	t.Helper()
	dir := t.TempDir()
	tf := filepath.Join(dir, "token")
	os.WriteFile(tf, []byte(token+"\n"), 0o600)
	c, err := keyclient.New(keyclient.Config{URL: e.srv.URL, TokenFile: tf, HTTP: e.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWebGetsExactlyTheDerivedKeys(t *testing.T) {
	e := setup(t)
	c := e.client(t, "good")
	ctx := context.Background()
	pk, err := c.Platform(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := e.local.Platform(ctx)
	if pk != want || pk.DBKey == "" || pk.DBPassword == "" || pk.RateKey == "" {
		t.Fatalf("platform keys %+v", pk)
	}
	// The remote provider yields what the controller's own platform derives.
	for _, tn := range []*platform.Tenant{e.active, e.susp} {
		db, root, err := platform.RemoteKeys{Src: c}.TenantKeys(tn.ID)
		if err != nil {
			t.Fatal(err)
		}
		wdb, wroot, _ := e.p.TenantKeys(tn)
		if !bytes.Equal(db, wdb) || !bytes.Equal(root, wroot) {
			t.Fatal("remote tenant keys differ from the controller's")
		}
	}
	for _, v := range []string{pk.DBKey, pk.DBPassword, pk.RateKey} {
		if v == fmt.Sprintf("%x", e.master) {
			t.Fatal("the master key was served")
		}
	}
	if log := e.log.String(); !strings.Contains(log, e.active.ID) || !strings.Contains(log, "web-1") {
		t.Fatalf("audit log lacks tenant and pod: %q", log)
	}
}

func TestRejections(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for _, tok := range []string{"nope", "other", "alien", ""} {
		c := e.client(t, tok)
		if _, err := c.Platform(ctx); !errors.Is(err, keyclient.ErrDenied) {
			t.Fatalf("token %q platform: %v", tok, err)
		}
		if _, err := c.Tenant(ctx, e.active.ID); !errors.Is(err, keyclient.ErrDenied) {
			t.Fatalf("token %q tenant: %v", tok, err)
		}
	}
	c := e.client(t, "good")
	for name, id := range map[string]string{"deleted": e.deleted, "pending": e.pending.ID, "unknown": strings.Repeat("a", 26)} {
		if _, err := c.Tenant(ctx, id); !errors.Is(err, keyclient.ErrDenied) {
			t.Fatalf("%s tenant: %v", name, err)
		}
	}
	if _, err := c.Tenant(ctx, "../x"); err == nil {
		t.Fatal("malformed tenant id accepted")
	}
}

func TestNoStoreAndNoKeyMaterialInLogs(t *testing.T) {
	e := setup(t)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/v1/tenant", strings.NewReader(`{"tenant_id":"`+e.active.ID+`"}`))
	req.Header.Set("Authorization", "Bearer good")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("status %d, cache-control %q, tls %x", resp.StatusCode, resp.Header.Get("Cache-Control"), resp.TLS.Version)
	}
	var k ports.TenantKeys
	json.NewDecoder(resp.Body).Decode(&k)
	log := e.log.String()
	for _, secret := range []string{k.DBKey, k.DBPassword, fmt.Sprintf("%x", e.master), "good"} {
		if secret != "" && strings.Contains(log, secret) {
			t.Fatalf("log leaks %q: %s", secret, log)
		}
	}
	// Errors are no-store too, and GET is refused.
	req, _ = http.NewRequest(http.MethodPost, e.srv.URL+"/v1/tenant", strings.NewReader(`{}`))
	resp2, _ := e.srv.Client().Do(req)
	if resp2.Header.Get("Cache-Control") != "no-store" || resp2.StatusCode != 401 {
		t.Fatalf("unauthenticated: %d %q", resp2.StatusCode, resp2.Header.Get("Cache-Control"))
	}
	resp2.Body.Close()
	resp3, _ := e.srv.Client().Get(e.srv.URL + "/v1/platform")
	if resp3.StatusCode == 200 {
		t.Fatal("GET served keys")
	}
	resp3.Body.Close()
}

func TestTenantRateLimit(t *testing.T) {
	e := setup(t)
	c := e.client(t, "good")
	// A fresh client each time defeats the cache: the controller must throttle.
	limited := false
	for range 200 {
		c2 := e.client(t, "good")
		if _, err := c2.Tenant(context.Background(), e.active.ID); err != nil {
			limited = true
			break
		}
	}
	_ = c
	if !limited {
		t.Fatal("no rate limit on tenant requests")
	}
}
