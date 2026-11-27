// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/keyclient"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// lockableKeys derives a tenant's keys like the master key would, but answers
// ports.ErrLocked while locked (a controller that was restarted).
type lockableKeys struct {
	master []byte
	id     string // the one tenant that can be locked
	locked atomic.Bool
}

func (l *lockableKeys) TenantKeys(id string) (dbKey, root []byte, err error) {
	if l.locked.Load() && id == l.id {
		return nil, nil, ports.ErrLocked
	}
	dbKey, err = store.TenantDBKey(l.master, id)
	return dbKey, nil, err
}

// lockedFixture: a multi-tenant host with a tenant-managed tenant that is open
// and can be locked and unlocked.
func lockedFixture(t *testing.T) (m *mtEnv, e *env, tok string, f *fakeKEK, keys *lockableKeys, tenantID string) {
	t.Helper()
	m = newMTEnv(t)
	e, tok = m.newTenant("acme")
	tn, _ := m.p.TenantBySlug("acme")
	tenantID = tn.ID
	keys = &lockableKeys{master: m.master, id: tenantID}
	m.p.UseKeyProvider(keys)
	f = &fakeKEK{mode: platform.KEKPlatform, unlocked: true}
	m.h.cfg.KEK = f
	kek := newKEKKeyString(t)
	f.mode, f.fp, f.current = platform.KEKTenant, f.fpOf(kek), kek
	if err := m.p.SetKEK(tn.ID, platform.KEKTenant, f.fp); err != nil {
		t.Fatal(err)
	}
	return
}

func lock(m *mtEnv, keys *lockableKeys, f *fakeKEK, id string) {
	keys.locked.Store(true)
	f.mu.Lock()
	f.unlocked = false
	f.mu.Unlock()
	m.h.evict(id, time.Second)
}

func TestLockedTenantAnswers423UntilUnlocked(t *testing.T) {
	m, e, tok, f, keys, id := lockedFixture(t)
	e.want(e.do("GET", "/api/shares", tok, nil), 200, "unlocked tenant serves")

	lock(m, keys, f, id)
	r := e.do("GET", "/api/shares", tok, nil)
	if r.Code != 423 || r.S("code") != "tenant_locked" || r.S("fingerprint") != f.fp {
		t.Fatalf("locked API: %d %s", r.Code, r.Body)
	}
	if r.Hdr.Get("Cache-Control") != "no-store" {
		t.Fatal("a 423 must not be cached")
	}
	page := e.do("GET", "/", "", nil)
	if page.Code != 423 || !strings.Contains(string(page.Body), "/api/unlock") || !strings.Contains(page.Hdr.Get("Content-Security-Policy"), "sha256-") {
		t.Fatalf("locked page: %d %q", page.Code, page.Body)
	}
	if strings.Contains(string(page.Body), f.current) {
		t.Fatal("the locked page shows the key")
	}
	// Other tenants are not affected.
	other, otherTok := m.newTenant("other")
	other.want(other.do("GET", "/api/shares", otherTok, nil), 200, "another tenant")

	// Status is public and shows the fingerprint, nothing else.
	r = e.do("GET", "/api/unlock", "", nil)
	e.want(r, 200, "unlock state")
	if r.J()["locked"] != true || r.J()["fingerprint"] != f.fp {
		t.Fatalf("state: %s", r.Body)
	}

	// Wrong key refused, the tenant stays locked.
	wrong := newKEKKeyString(t)
	r = e.do("POST", "/api/unlock", "", map[string]any{"kek": wrong})
	if r.Code != 403 || strings.Contains(string(r.Body), wrong) {
		t.Fatalf("wrong key: %d %s", r.Code, r.Body)
	}
	e.want(e.do("POST", "/api/unlock", "", map[string]any{"kek": "short"}), 400, "malformed key")
	if e.do("GET", "/api/shares", tok, nil).Code != 423 {
		t.Fatal("a wrong key unlocked the tenant")
	}
	// A form post is not accepted.
	if r := e.do("POST", "/api/unlock", "", []byte("kek=x"), "Content-Type", "application/x-www-form-urlencoded"); r.Code != 415 {
		t.Fatalf("form post: %d", r.Code)
	}

	// The right key unlocks (the controllers answer again), the tenant serves.
	r = e.do("POST", "/api/unlock", "", map[string]any{"kek": f.current})
	e.want(r, 200, "unlock")
	keys.locked.Store(false)
	e.want(e.do("GET", "/api/shares", tok, nil), 200, "serves again after the unlock")

	// Audit: the platform log has every attempt with the fingerprint, never the key.
	recs, err := m.p.AuditPage(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var ok, failed int
	for _, rec := range recs {
		if rec.Action != "tenant_unlock" {
			continue
		}
		blob, _ := json.Marshal(rec)
		if strings.Contains(string(blob), f.current) || strings.Contains(string(blob), wrong) {
			t.Fatalf("a key is in the platform audit log: %s", blob)
		}
		switch rec.Outcome {
		case "ok":
			ok++
			if !strings.Contains(rec.Detail, f.fp) {
				t.Fatalf("the unlock record lacks the fingerprint: %+v", rec)
			}
		case "failed":
			failed++
		}
	}
	if ok != 1 || failed != 1 {
		t.Fatalf("platform audit: %d ok, %d failed", ok, failed)
	}
}

func TestUnlockEndpointIsRateLimited(t *testing.T) {
	m, e, _, f, keys, id := lockedFixture(t)
	lock(m, keys, f, id)
	wrong := newKEKKeyString(t)
	var last int
	for i := 0; i < unlockPerIP+3; i++ {
		last = e.do("POST", "/api/unlock", "", map[string]any{"kek": wrong}).Code
		if i < unlockPerIP && last != 403 {
			t.Fatalf("attempt %d: %d", i+1, last)
		}
	}
	if last != 429 {
		t.Fatalf("after %d attempts: %d, want 429", unlockPerIP+3, last)
	}
	// Even the right key waits: the budget is spent.
	if r := e.do("POST", "/api/unlock", "", map[string]any{"kek": f.current}); r.Code != 429 {
		t.Fatalf("right key during the lockout: %d", r.Code)
	}
}

func TestUnlockOfAPlatformManagedTenantIs404(t *testing.T) {
	m := newMTEnv(t)
	e, _ := m.newTenant("plain")
	m.h.cfg.KEK = &fakeKEK{mode: platform.KEKPlatform}
	e.want(e.do("POST", "/api/unlock", "", map[string]any{"kek": newKEKKeyString(t)}), 404, "unlock without a tenant key")
	e.want(e.do("GET", "/api/unlock", "", nil), 404, "state without a tenant key")
}

func TestUnlockPartialAckIs502(t *testing.T) {
	m, e, _, f, keys, id := lockedFixture(t)
	lock(m, keys, f, id)
	f.err = &keyclient.AckError{Acked: 1, Total: 2, Failed: []string{"x"}}
	r := e.do("POST", "/api/unlock", "", map[string]any{"kek": f.current})
	if r.Code != 502 || r.J()["controllers_total"] != float64(2) {
		t.Fatalf("partial: %d %s", r.Code, r.Body)
	}
}

func TestCloseLockedClosesOpenTenants(t *testing.T) {
	m, e, tok, f, keys, id := lockedFixture(t)
	m.h.cfg.Cluster = &ClusterRuntime{KeyCheck: func(_ context.Context, id string) error {
		_, _, err := keys.TenantKeys(id)
		return err
	}}
	e.want(e.do("GET", "/api/shares", tok, nil), 200, "serves")
	if len(m.h.OpenTenants()) == 0 {
		t.Fatal("tenant not open")
	}
	keys.locked.Store(true) // a controller restarted; the replica still has the tenant open
	f.mu.Lock()
	f.unlocked = false
	f.mu.Unlock()
	m.h.closeLocked()
	deadline := time.Now().Add(5 * time.Second)
	for len(m.h.OpenTenants()) > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(m.h.OpenTenants()) != 0 {
		t.Fatal("a locked tenant is still open in this replica")
	}
	if e.do("GET", "/api/shares", tok, nil).Code != 423 {
		t.Fatal("not 423 after the lock")
	}
	_ = id
}
