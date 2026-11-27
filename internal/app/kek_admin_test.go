// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/sendora-app/sendora/internal/keyclient"
	"github.com/sendora-app/sendora/internal/keyserver"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/store"
)

// fakeKEK stands in for the controllers: it keeps the mode like the platform
// record would and records what it was asked.
type fakeKEK struct {
	mu       sync.Mutex
	mode, fp string
	calls    []string
	err      error // returned by the next mutating call
	current  string
	unlocked bool
}

func (f *fakeKEK) fpOf(kek string) string {
	raw, _ := store.ParseTenantKEK(kek)
	defer clear(raw)
	return store.TenantKEKFingerprint(raw)
}

func (f *fakeKEK) record(call string) { f.calls = append(f.calls, call) }

func (f *fakeKEK) Switch(_ context.Context, tenant, kek, actor string) (keyserver.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("switch:" + tenant + ":" + actor)
	if f.err != nil {
		return keyserver.Response{Steps: []string{"begun: a -> b"}}, f.err
	}
	f.mode, f.fp, f.current = platform.KEKTenant, f.fpOf(kek), kek
	return keyserver.Response{Fingerprint: f.fp, Steps: []string{"begun: a -> b", "wrapped: 6 wraps added", "removed: 6 wraps destroyed"}}, nil
}

func (f *fakeKEK) Replace(_ context.Context, tenant, oldKEK, newKEK, actor string) (keyserver.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("replace:" + tenant + ":" + actor)
	if f.err != nil {
		return keyserver.Response{}, f.err
	}
	if oldKEK != f.current {
		return keyserver.Response{}, keyclient.ErrKEKRefused
	}
	f.fp, f.current = f.fpOf(newKEK), newKEK
	return keyserver.Response{Fingerprint: f.fp, Steps: []string{"begun"}}, nil
}

func (f *fakeKEK) Release(_ context.Context, tenant, kek, actor string) (keyserver.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("release:" + tenant + ":" + actor)
	if f.err != nil {
		return keyserver.Response{}, f.err
	}
	if kek != f.current {
		return keyserver.Response{}, keyclient.ErrKEKRefused
	}
	f.mode, f.fp, f.current = platform.KEKPlatform, "", ""
	return keyserver.Response{Steps: []string{"begun"}}, nil
}

func (f *fakeKEK) Unlock(_ context.Context, tenant, kek string) (keyserver.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("unlock:" + tenant)
	if f.err != nil {
		return keyserver.Response{}, f.err
	}
	if kek != f.current {
		return keyserver.Response{}, keyclient.ErrKEKRefused
	}
	f.unlocked = true
	return keyserver.Response{Fingerprint: f.fp}, nil
}

func (f *fakeKEK) Status(_ context.Context, tenant string) (string, string, int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := 0
	if f.mode != platform.KEKTenant || f.unlocked {
		u = 2
	}
	return f.mode, f.fp, u, 2, nil
}

func newKEKKeyString(t *testing.T) string {
	raw := make([]byte, 32)
	rand.Read(raw)
	return base64.StdEncoding.EncodeToString(raw)
}

func attachFakeKEK(t *testing.T, e *env) *fakeKEK {
	t.Helper()
	f := &fakeKEK{mode: platform.KEKPlatform, unlocked: true}
	e.s.AttachKEK(f, "tenanttenanttenanttenant22", "acme", func() (string, string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.mode, f.fp
	})
	return f
}

func auditBody(t *testing.T, e *env, tok string) string {
	t.Helper()
	return string(e.do("GET", "/api/logs?limit=200", tok, nil).Body)
}

func TestKEKAdminAPI(t *testing.T) {
	e := newEncryptedEnv(t)
	tok := e.setup()
	user := e.mkUser(tok, "plain", false)
	f := attachFakeKEK(t, e)
	kek := newKEKKeyString(t)
	kek2 := newKEKKeyString(t)

	// Administrators only, with a fresh re-authentication.
	for _, c := range []struct{ m, p string }{{"GET", "/api/admin/kek"}, {"POST", "/api/admin/kek/upload"}, {"POST", "/api/admin/kek/replace"}, {"POST", "/api/admin/kek/release"}} {
		e.want(e.do(c.m, c.p, user, map[string]any{"kek": kek}), 403, c.p+" by a non-admin")
		e.want(e.do(c.m, c.p, "", nil), 401, c.p+" without a token")
	}
	stale := staleAdmin(t, e, "admin")
	for _, p := range []string{"/api/admin/kek/upload", "/api/admin/kek/replace", "/api/admin/kek/release"} {
		r := e.do("POST", p, stale, map[string]any{"kek": kek, "confirm": "acme"})
		if r.Code != 401 || r.S("code") != stepUpCode {
			t.Fatalf("%s without step-up: %d %s", p, r.Code, r.Body)
		}
	}
	if n := countAudit(t, e, "kek_upload_requested"); n != 0 || len(f.calls) != 0 {
		t.Fatalf("refused requests left %d audit records and %d controller calls", n, len(f.calls))
	}

	// State before: platform-managed, with the warning.
	r := e.do("GET", "/api/admin/kek", tok, nil)
	e.want(r, 200, "status")
	if r.J()["mode"] != "platform" || r.J()["locked"] != false || r.J()["slug"] != "acme" || !strings.Contains(r.S("warning"), "lose") {
		t.Fatalf("status = %s", r.Body)
	}

	// Input checks: slug confirmation, weak and short keys, not base64.
	e.want(e.do("POST", "/api/admin/kek/upload", tok, map[string]any{"kek": kek}), 400, "no confirmation")
	e.want(e.do("POST", "/api/admin/kek/upload", tok, map[string]any{"kek": kek, "confirm": "other"}), 400, "wrong slug")
	e.want(e.do("POST", "/api/admin/kek/upload", tok, map[string]any{"kek": base64.StdEncoding.EncodeToString(make([]byte, 32)), "confirm": "acme"}), 400, "all-zero key")
	e.want(e.do("POST", "/api/admin/kek/upload", tok, map[string]any{"kek": "c2hvcnQ=", "confirm": "acme"}), 400, "short key")
	e.want(e.do("POST", "/api/admin/kek/upload", tok, map[string]any{"kek": "!!!notbase64", "confirm": "acme"}), 400, "not base64")
	e.want(e.do("POST", "/api/admin/kek/replace", tok, map[string]any{"old_kek": kek, "new_kek": kek2}), 409, "replace while platform-managed")
	e.want(e.do("POST", "/api/admin/kek/release", tok, map[string]any{"kek": kek}), 409, "release while platform-managed")
	if len(f.calls) != 0 {
		t.Fatalf("invalid requests reached the controllers: %v", f.calls)
	}

	// Switch.
	r = e.do("POST", "/api/admin/kek/upload", tok, map[string]any{"kek": kek, "confirm": "acme"})
	e.want(r, 200, "upload")
	fp := f.fpOf(kek)
	if r.J()["mode"] != "tenant" || r.J()["fingerprint"] != fp || !strings.Contains(r.S("warning"), "lose") || strings.Contains(string(r.Body), kek) {
		t.Fatalf("upload answer: %s", r.Body)
	}
	if len(f.calls) != 1 || f.calls[0] != "switch:tenanttenanttenanttenant22:admin" {
		t.Fatalf("controller calls: %v", f.calls)
	}
	e.want(e.do("POST", "/api/admin/kek/upload", tok, map[string]any{"kek": kek, "confirm": "acme"}), 409, "second upload")
	r = e.do("GET", "/api/admin/kek", tok, nil)
	if r.J()["mode"] != "tenant" || r.J()["fingerprint"] != fp || strings.Contains(string(r.Body), kek) {
		t.Fatalf("status after the switch: %s", r.Body)
	}

	// Replace: the old key must match; the new one is checked like any key.
	e.want(e.do("POST", "/api/admin/kek/replace", tok, map[string]any{"old_kek": kek2, "new_kek": kek}), 403, "replace with a wrong old key")
	e.want(e.do("POST", "/api/admin/kek/replace", tok, map[string]any{"old_kek": kek, "new_kek": "short"}), 400, "short new key")
	r = e.do("POST", "/api/admin/kek/replace", tok, map[string]any{"old_kek": kek, "new_kek": kek2})
	e.want(r, 200, "replace")
	if r.J()["fingerprint"] != f.fpOf(kek2) {
		t.Fatalf("replace answer: %s", r.Body)
	}

	// Controllers that did not all take the key: an error that says what to do.
	f.err = &keyclient.AckError{Acked: 1, Total: 2, Failed: []string{"10.0.0.2:8443"}, Cause: errors.New("down")}
	r = e.do("POST", "/api/admin/kek/release", tok, map[string]any{"kek": kek2})
	if r.Code != 502 || r.S("code") != "partial_unlock" {
		t.Fatalf("partial: %d %s", r.Code, r.Body)
	}
	f.err = nil

	// Release.
	e.want(e.do("POST", "/api/admin/kek/release", tok, map[string]any{"kek": kek}), 403, "release with the replaced key")
	r = e.do("POST", "/api/admin/kek/release", tok, map[string]any{"kek": kek2})
	e.want(r, 200, "release")
	if r.J()["mode"] != "platform" {
		t.Fatalf("release answer: %s", r.Body)
	}

	// Audit: fingerprints and steps, never a key; failures recorded.
	logs := auditBody(t, e, tok)
	for _, key := range []string{kek, kek2, strings.TrimRight(kek, "="), strings.TrimRight(kek2, "=")} {
		if strings.Contains(logs, key) {
			t.Fatalf("a key is in the audit log")
		}
	}
	for _, want := range []string{"kek_switched", "kek_replaced", "kek_released", "kek_step", fp, f.fpOf(kek2), "kek_upload_requested", "kek_release_failed"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("audit log lacks %q:\n%s", want, logs)
		}
	}

	// The budget: operations are limited per hour.
	t.Setenv("SENDORA_KEY_OPS_PER_HOUR", "1") // the limit is configurable; the budget is already spent
	for i := 0; i < 3; i++ {
		e.do("POST", "/api/admin/kek/release", tok, map[string]any{"kek": kek})
	}
	r = e.do("POST", "/api/admin/kek/upload", tok, map[string]any{"kek": newKEKKeyString(t), "confirm": "acme"})
	if r.Code != 429 && r.Code != 409 {
		t.Fatalf("rate limit: %d %s", r.Code, r.Body)
	}
}

func TestKEKAdminOutsideTheClusterFlavour(t *testing.T) {
	e := newEncryptedEnv(t)
	tok := e.setup()
	r := e.do("GET", "/api/admin/kek", tok, nil)
	e.want(r, 200, "status")
	if r.J()["supported"] != false || r.J()["mode"] != "platform" {
		t.Fatalf("status = %s", r.Body)
	}
	e.want(e.do("POST", "/api/admin/kek/upload", tok, map[string]any{"kek": newKEKKeyString(t), "confirm": "x"}), 501, "upload")
}

func TestKEKFailureIsAudited(t *testing.T) {
	e := newEncryptedEnv(t)
	tok := e.setup()
	f := attachFakeKEK(t, e)
	f.err = errors.New("boom")
	kek := newKEKKeyString(t)
	r := e.do("POST", "/api/admin/kek/upload", tok, map[string]any{"kek": kek, "confirm": "acme"})
	if r.Code != 502 || strings.Contains(string(r.Body), "boom") {
		t.Fatalf("failure answer: %d %s", r.Code, r.Body)
	}
	if countAudit(t, e, "kek_switch_failed") != 1 || strings.Contains(auditBody(t, e, tok), kek) {
		t.Fatal("the failure is not audited, or the key leaked into the audit log")
	}
}
