// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/store"
)

// Multi-tenant tests: routing, isolation between tenants, the platform console
// and quotas. The single-tenant suite runs unchanged elsewhere.

const mtBase = "example.test"
const mtPassword = "Correct-Horse-Battery-2026!"

var mtStatic = fstest.MapFS{
	"index.html":    {Data: []byte("<html>tenant spa</html>")},
	"platform.html": {Data: []byte("<html>platform console</html>")},
}

type mtEnv struct {
	t      *testing.T
	h      *TenantHost
	p      *platform.Platform
	ts     *httptest.Server
	dir    string
	master []byte
	clock  time.Time
}

func newMTEnv(t *testing.T, proxies ...*net.IPNet) *mtEnv {
	t.Helper()
	t.Setenv("SENDORA_DISABLE_IP_BANS", "true")
	dir := t.TempDir()
	master := make([]byte, 32)
	rand.Read(master)
	p, err := platform.Open(dir, master, true)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewTenantHost(MultiTenantConfig{Platform: p, BaseDomain: mtBase, Static: mtStatic, Version: "test", TrustedProxies: proxies})
	if err != nil {
		t.Fatal(err)
	}
	m := &mtEnv{t: t, h: h, p: p, dir: dir, master: master, clock: time.Now()}
	h.console.clock = func() time.Time { return m.clock }
	m.ts = httptest.NewServer(h)
	t.Cleanup(func() {
		m.ts.Close()
		h.Shutdown(time.Second)
		p.Close()
	})
	return m
}

// tenant returns a request helper for one host.
func (m *mtEnv) host(host string) *env { return &env{t: m.t, ts: m.ts, host: host} }

// newTenant creates a tenant with an administrator whose password is set
// through the one-time link; it returns the host helper and an access token.
func (m *mtEnv) newTenant(slug string) (*env, string) {
	m.t.Helper()
	// Tests store files on the tenant's directory (the platform offers local disk).
	_, link, emailed, err := m.h.CreateTenant("tester", slug, strings.ToUpper(slug), "admin", "admin@"+slug+".test", 0, 0, "local", true)
	if err != nil {
		m.t.Fatal(err)
	}
	if emailed || !strings.HasPrefix(link, "https://"+slug+"."+mtBase+"/reset-password/") {
		m.t.Fatalf("setup link %q emailed=%v", link, emailed)
	}
	e := m.host(slug + "." + mtBase)
	tok := link[strings.LastIndex(link, "/")+1:]
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": tok, "password": mtPassword}), 200, "set first password")
	r := e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": mtPassword})
	e.want(r, 200, "tenant admin login")
	return e, r.S("access_token")
}

func (m *mtEnv) server(slug string) *Server {
	m.t.Helper()
	t, err := m.p.TenantBySlug(slug)
	if err != nil {
		m.t.Fatal(err)
	}
	e, err := m.h.acquire(t.ID)
	if err != nil {
		m.t.Fatal(err)
	}
	m.h.release(e, false)
	return e.srv
}

func TestMTUnknownHostsArePlain404(t *testing.T) {
	m := newMTEnv(t)
	m.newTenant("klant1")
	for _, host := range []string{"unknown.test", mtBase, "klant9." + mtBase, "a.klant1." + mtBase, "127.0.0.1"} {
		r := m.host(host).do("GET", "/", "", nil)
		if r.Code != 404 || strings.Contains(string(r.Body), "spa") || strings.Contains(r.Hdr.Get("Content-Type"), "json") {
			t.Fatalf("%s: %d %q", host, r.Code, r.Body)
		}
		if r := m.host(host).do("GET", "/api/bootstrap", "", nil); r.Code != 404 || strings.Contains(string(r.Body), "setup_needed") {
			t.Fatalf("%s bootstrap: %d %s", host, r.Code, r.Body)
		}
	}
	// Health answers on any host (probes), the tenant SPA only on the tenant.
	m.host("10.1.2.3:8080").want(m.host("10.1.2.3:8080").do("GET", "/api/health", "", nil), 200, "health")
	r := m.host("KLANT1."+mtBase+":443").do("GET", "/", "", nil)
	if r.Code != 200 || !strings.Contains(string(r.Body), "tenant spa") {
		t.Fatalf("tenant spa: %d %s", r.Code, r.Body)
	}
	if r := m.host("klant1."+mtBase).do("GET", "/platform.html", "", nil); strings.Contains(string(r.Body), "platform console") {
		t.Fatal("console entry served on a tenant host")
	}
	if r := m.host("admin."+mtBase).do("GET", "/", "", nil); !strings.Contains(string(r.Body), "platform console") {
		t.Fatalf("console host: %s", r.Body)
	}
}

func TestMTTenantIsolation(t *testing.T) {
	m := newMTEnv(t)
	a, tokA := m.newTenant("klant1")
	b, tokB := m.newTenant("klant2")

	// Same user IDs in both tenants (both admins are user #1), yet a token of
	// one tenant never verifies in the other.
	a.want(a.do("GET", "/api/users/me", tokA, nil), 200, "own token")
	b.want(b.do("GET", "/api/users/me", tokA, nil), 401, "token of A on B")
	a.want(a.do("GET", "/api/users/me", tokB, nil), 401, "token of B on A")
	a.want(a.do("GET", "/api/users", tokB, nil), 401, "admin API of A with B's admin token")

	// Refresh tokens (cookie) of A are unknown to B.
	login := a.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": mtPassword})
	rt := refreshCookie(login)
	if rt == "" {
		t.Fatal("no refresh cookie")
	}
	b.want(b.do("POST", "/api/auth/refresh", "", nil, "Cookie", "refresh="+rt), 401, "refresh of A on B")
	a.want(a.do("POST", "/api/auth/refresh", "", nil, "Cookie", "refresh="+rt), 200, "refresh of A on A")

	// Share links of A are 404 on B.
	sh := a.share(tokA, map[string]string{"secret.txt": "tenant A data"}, nil)
	a.want(sh, 201, "share on A")
	lid := sh.S("long_id")
	a.want(a.do("GET", "/api/shares/"+lid, "", nil), 200, "share on A")
	b.want(b.do("GET", "/api/shares/"+lid, "", nil), 404, "share of A on B")
	b.want(b.do("GET", "/api/shares/"+lid+"/download", "", nil), 404, "download of A on B")
	if r := a.do("GET", "/api/shares/"+lid+"/download", "", nil); r.Code != 200 || string(r.Body) != "tenant A data" {
		t.Fatalf("download on A: %d %q", r.Code, r.Body)
	}

	// Password reset / welcome links of A are invalid on B.
	srvA, srvB := m.server("klant1"), m.server("klant2")
	link, _, err := srvA.ProvisionAdmin("tester", "second", "second@klant1.test")
	if err != nil {
		t.Fatal(err)
	}
	tok := link[strings.LastIndex(link, "/")+1:]
	b.want(b.do("POST", "/api/auth/reset-password", "", map[string]any{"token": tok, "password": mtPassword}), 400, "reset link of A on B")

	// MFA tickets of A are refused by B, although user #1 exists in both.
	uA, _ := srvA.userByID(1)
	b.want(b.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": srvA.mfaToken(uA), "code": "000000"}), 401, "MFA ticket of A on B")

	// Different keys and secrets per tenant: signing secret, file keys, audit chain, WebAuthn RP.
	if bytes.Equal(srvA.Secret, srvB.Secret) || fileKeysEqual(srvA.St, srvB.St) {
		t.Fatal("tenants share secrets or file keys")
	}
	if bytes.Equal(srvA.St.AuditMAC()([]byte("x")), srvB.St.AuditMAC()([]byte("x"))) {
		t.Fatal("tenants share the audit key")
	}
	rpA, okA := srvA.waRP()
	rpB, okB := srvB.waRP()
	if !okA || !okB || rpA.ID != "klant1."+mtBase || rpB.ID != "klant2."+mtBase {
		t.Fatalf("webauthn RP IDs: %+v %+v", rpA, rpB)
	}

	// A stored file of A does not decrypt with B's file key.
	var disk string
	qByName(srvA.St, `SELECT f.disk_path FROM files f JOIN shares s ON s.id=f.share_id WHERE s.long_id=?`, lid).Scan(&disk)
	pA, _ := store.SharePath(srvA.St.DataDir, lid, disk)
	if _, err := os.Stat(pA); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pA, filepath.Join(m.dir, "tenants")) {
		t.Fatal("tenant file outside its directory", pA)
	}

	// Each tenant has its own audit log; B's has none of A's events.
	var n int
	srvB.St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE detail LIKE '%klant1%' OR target LIKE '%second%'`).Scan(&n)
	if n != 0 {
		t.Fatal("tenant B's audit log contains tenant A's events")
	}
}

func TestMTForwardedHostOnlyFromTrustedProxies(t *testing.T) {
	m := newMTEnv(t)
	m.newTenant("klant1")
	e := m.host("unknown.test")
	// Untrusted peer: X-Forwarded-Host is ignored.
	if r := e.do("GET", "/", "", nil, "X-Forwarded-Host", "klant1."+mtBase); r.Code != 404 {
		t.Fatalf("spoofed forwarded host routed: %d", r.Code)
	}
	k := m.host("klant1." + mtBase)
	if r := k.do("GET", "/api/platform/bootstrap", "", nil, "X-Forwarded-Host", "admin."+mtBase); strings.Contains(string(r.Body), "setup_needed") {
		t.Fatal("forwarded host reached the console from an untrusted peer")
	}
	// Trusted proxy: honoured.
	_, loop, _ := net.ParseCIDR("127.0.0.0/8")
	m2 := newMTEnv(t, loop)
	m2.newTenant("klant1")
	if r := m2.host("proxy.internal").do("GET", "/", "", nil, "X-Forwarded-Host", "klant1."+mtBase); r.Code != 200 {
		t.Fatalf("trusted forwarded host not routed: %d", r.Code)
	}
}

func TestMTSuspendedTenantAndConsoleSeparation(t *testing.T) {
	m := newMTEnv(t)
	k, tok := m.newTenant("klant1")
	id := m.server("klant1").tenant.opts.ID
	if err := m.h.SetTenantStatus("tester", id, platform.StatusSuspended); err != nil {
		t.Fatal(err)
	}
	r := k.do("GET", "/", "", nil)
	if r.Code != 503 || !strings.Contains(string(r.Body), "unavailable") {
		t.Fatalf("suspended: %d %s", r.Code, r.Body)
	}
	k.want(k.do("GET", "/api/users/me", tok, nil), 503, "suspended API")
	if err := m.h.SetTenantStatus("tester", id, platform.StatusActive); err != nil {
		t.Fatal(err)
	}
	k.want(k.do("GET", "/api/users/me", tok, nil), 200, "resumed")
	// The tenant's own audit log records the platform's actions.
	var n int
	m.server("klant1").St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action IN ('tenant_created','tenant_suspended','tenant_resumed') AND actor_role='platform_admin'`).Scan(&n)
	if n != 3 {
		t.Fatal("platform actions in the tenant audit log:", n)
	}
	// A tenant administrator cannot reach the console; the console API does not exist on tenant hosts.
	c := m.host("admin." + mtBase)
	c.want(c.do("GET", "/api/platform/tenants", tok, nil), 401, "tenant token on console")
	k.want(k.do("GET", "/api/platform/tenants", "", nil), 404, "console API on tenant host")
}

// consoleLogin performs setup, TOTP enrolment and returns the session cookie.
func (m *mtEnv) consoleLogin() (*env, string, string) {
	m.t.Helper()
	c := m.host("admin." + mtBase)
	r := c.do("POST", "/api/platform/setup", "", map[string]any{"setup_code": "WRONG-CODE", "username": "root", "email": "root@platform.test", "password": "Platform-Admin-2026!"})
	c.want(r, 403, "wrong setup code")
	r = c.do("POST", "/api/platform/setup", "", map[string]any{"setup_code": m.h.console.setupCode, "username": "root", "email": "root@platform.test", "password": "Platform-Admin-2026!"})
	c.want(r, 200, "setup")
	cookie := sessionCookie(m.t, r)
	c.want(c.do("GET", "/api/platform/tenants", "", nil, "Cookie", cookie), 403, "tenants before MFA enrolment")
	r = c.do("POST", "/api/platform/mfa/begin", "", nil, "Cookie", cookie)
	c.want(r, 200, "mfa begin")
	secret := r.S("secret")
	sec, _ := decodeTOTPSecret(secret)
	c.want(c.do("POST", "/api/platform/mfa/confirm", "", map[string]any{"code": totpCode(sec, m.clock)}, "Cookie", cookie), 200, "mfa confirm")
	return c, cookie, secret
}

func sessionCookie(t *testing.T, r resp) string {
	for _, c := range r.Hdr.Values("Set-Cookie") {
		if strings.HasPrefix(c, consoleCookie+"=") {
			if !strings.Contains(c, "HttpOnly") || !strings.Contains(c, "SameSite=Strict") || strings.Contains(strings.ToLower(c), "domain=") {
				t.Fatalf("console cookie attributes: %s", c)
			}
			return strings.SplitN(c, ";", 2)[0]
		}
	}
	t.Fatal("no console session cookie")
	return ""
}

func (m *mtEnv) nextCode(secret string) string {
	m.clock = m.clock.Add(30 * time.Second)
	sec, _ := decodeTOTPSecret(secret)
	return totpCode(sec, m.clock)
}

func TestMTConsoleLifecycle(t *testing.T) {
	m := newMTEnv(t)
	c, cookie, secret := m.consoleLogin()
	r := c.do("POST", "/api/platform/tenants", "", map[string]any{"slug": "klant1", "name": "Klant Een", "admin_email": "boss@klant1.test", "max_users": 5}, "Cookie", cookie)
	c.want(r, 201, "create tenant")
	link, _ := r.J()["setup_link"].(string)
	if !strings.Contains(link, "/reset-password/") {
		t.Fatal("no one-time setup link without SMTP:", r.S("setup_link"))
	}
	c.want(c.do("POST", "/api/platform/tenants", "", map[string]any{"slug": "admin", "admin_email": "x@y.test"}, "Cookie", cookie), 400, "reserved slug")
	c.want(c.do("POST", "/api/platform/tenants", "", map[string]any{"slug": "klant1", "admin_email": "x@y.test"}, "Cookie", cookie), 400, "duplicate slug")
	r = c.do("GET", "/api/platform/tenants?q=een", "", nil, "Cookie", cookie)
	c.want(r, 200, "list")
	var list struct {
		Tenants []map[string]any `json:"tenants"`
	}
	json.Unmarshal(r.Body, &list)
	if len(list.Tenants) != 1 || list.Tenants[0]["slug"] != "klant1" {
		t.Fatalf("list: %s", r.Body)
	}
	id := list.Tenants[0]["id"].(string)
	// The console exposes counts only, never tenant content.
	for _, forbidden := range []string{"password", "shares", "files", "secret"} {
		if strings.Contains(strings.ToLower(string(r.Body)), forbidden) {
			t.Fatalf("tenant list exposes %q: %s", forbidden, r.Body)
		}
	}
	c.want(c.do("PUT", "/api/platform/tenants/"+id+"/quotas", "", map[string]any{"max_users": 1, "max_storage_bytes": 0}, "Cookie", cookie), 200, "quota")
	// Custom domain with DNS TXT verification.
	r = c.do("POST", "/api/platform/tenants/"+id+"/domains", "", map[string]any{"domain": "files.klant1.nl"}, "Cookie", cookie)
	c.want(r, 201, "add domain")
	want := r.S("record_value")
	m.h.console.lookupTXT = func(ctx context.Context, name string) ([]string, error) { return nil, nil }
	c.want(c.do("POST", "/api/platform/tenants/"+id+"/domains/files.klant1.nl/verify", "", nil, "Cookie", cookie), 409, "unverified domain")
	if r := m.host("files.klant1.nl").do("GET", "/", "", nil); r.Code != 404 {
		t.Fatal("unverified custom domain routed", r.Code)
	}
	m.h.console.lookupTXT = func(ctx context.Context, name string) ([]string, error) {
		if name != "_sendora-challenge.files.klant1.nl" {
			return nil, nil
		}
		return []string{want}, nil
	}
	c.want(c.do("POST", "/api/platform/tenants/"+id+"/domains/files.klant1.nl/verify", "", nil, "Cookie", cookie), 200, "verify domain")
	// A non-primary host redirects to the primary one.
	req, _ := http.NewRequest("GET", m.ts.URL+"/x?y=1", nil)
	req.Host = "files.klant1.nl"
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 308 || res.Header.Get("Location") != "https://klant1."+mtBase+"/x?y=1" {
		t.Fatalf("redirect: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	c.want(c.do("PUT", "/api/platform/tenants/"+id+"/storage", "", map[string]any{"offer": "local", "tenant_managed": false}, "Cookie", cookie), 200, "storage decision")
	if sc, _ := m.p.Storage(id); sc.Offer != "local" || sc.TenantManaged {
		t.Fatalf("storage decision not stored: %+v", sc)
	}
	c.want(c.do("PUT", "/api/platform/tenants/"+id+"/storage", "", map[string]any{"offer": "bogus"}, "Cookie", cookie), 400, "invalid offer")
	// Delete needs the confirmation and a fresh TOTP code.
	c.want(c.do("POST", "/api/platform/tenants/"+id+"/delete", "", map[string]any{"confirm": "klant1", "code": "000000"}, "Cookie", cookie), 403, "delete without step-up")
	c.want(c.do("POST", "/api/platform/tenants/"+id+"/delete", "", map[string]any{"confirm": "nope", "code": m.nextCode(secret)}, "Cookie", cookie), 400, "delete without confirmation")
	c.want(c.do("POST", "/api/platform/tenants/"+id+"/delete", "", map[string]any{"confirm": "klant1", "code": m.nextCode(secret)}, "Cookie", cookie), 200, "delete")
	if _, err := os.Stat(filepath.Join(m.dir, "tenants", id)); !os.IsNotExist(err) {
		t.Fatal("tenant directory left behind", err)
	}
	if r := m.host("klant1."+mtBase).do("GET", "/", "", nil); r.Code != 404 {
		t.Fatal("deleted tenant still served", r.Code)
	}
	// The platform audit log holds every action and verifies.
	r = c.do("GET", "/api/platform/audit/status", "", nil, "Cookie", cookie)
	if r.J()["ok"] != true {
		t.Fatalf("platform audit chain: %s", r.Body)
	}
	r = c.do("GET", "/api/platform/audit", "", nil, "Cookie", cookie)
	for _, action := range []string{"platform_setup", "mfa_enrolled", "tenant_created", "tenant_quota_changed", "tenant_domain_verified", "tenant_storage_changed", "tenant_deleted"} {
		if !strings.Contains(string(r.Body), `"`+action+`"`) {
			t.Fatalf("platform audit lacks %s", action)
		}
	}
	// Sign out, sign in again with password + TOTP.
	c.want(c.do("POST", "/api/platform/logout", "", nil, "Cookie", cookie), 200, "logout")
	c.want(c.do("GET", "/api/platform/me", "", nil, "Cookie", cookie), 401, "after logout")
	r = c.do("POST", "/api/platform/login", "", map[string]any{"username": "root", "password": "Platform-Admin-2026!"})
	c.want(r, 200, "login")
	cookie = sessionCookie(t, r)
	c.want(c.do("GET", "/api/platform/tenants", "", nil, "Cookie", cookie), 403, "tenants before TOTP")
	code := m.nextCode(secret)
	c.want(c.do("POST", "/api/platform/login/totp", "", map[string]any{"code": code}, "Cookie", cookie), 200, "totp")
	c.want(c.do("GET", "/api/platform/tenants", "", nil, "Cookie", cookie), 200, "tenants after TOTP")
	// A replayed code is refused.
	r = c.do("POST", "/api/platform/login", "", map[string]any{"username": "root", "password": "Platform-Admin-2026!"})
	cookie2 := sessionCookie(t, r)
	c.want(c.do("POST", "/api/platform/login/totp", "", map[string]any{"code": code}, "Cookie", cookie2), 401, "replayed totp")
	// Cross-origin unsafe requests are refused.
	c.want(c.do("POST", "/api/platform/logout", "", nil, "Cookie", cookie, "Origin", "https://klant1."+mtBase), 403, "cross-origin")
	// The platform session is useless on tenant hosts.
	_, tok := m.newTenant("klant3")
	_ = tok
	k := m.host("klant3." + mtBase)
	k.want(k.do("GET", "/api/users/me", "", nil, "Cookie", cookie), 401, "platform cookie on tenant")
	k.want(k.do("GET", "/api/users", "", nil, "Cookie", cookie), 401, "platform cookie on tenant admin API")
}

func TestMTQuotas(t *testing.T) {
	m := newMTEnv(t)
	k, tok := m.newTenant("klant1")
	id := m.server("klant1").tenant.opts.ID
	if err := m.h.SetTenantQuotas("tester", id, 1, 10); err != nil {
		t.Fatal(err)
	}
	r := k.do("POST", "/api/users", tok, map[string]any{"username": "bob", "password": mtPassword, "email": "bob@klant1.test"})
	k.want(r, 403, "user limit")
	// The trigger enforces it for every path.
	if _, err := m.server("klant1").St.DB.Exec(`INSERT INTO users(username,email) VALUES('direct','d@klant1.test')`); err == nil || !strings.Contains(err.Error(), "tenant user limit") {
		t.Fatal("trigger did not enforce the user limit", err)
	}
	r = k.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "big.bin", "full_path": "big.bin", "size": 100}}})
	k.want(r, 413, "storage quota")
	if err := m.h.SetTenantQuotas("tester", id, 0, 0); err != nil {
		t.Fatal(err)
	}
	k.want(k.do("POST", "/api/users", tok, map[string]any{"username": "bob", "password": mtPassword, "email": "bob@klant1.test"}), 201, "unlimited again")
}

func TestMTLazyOpenLRUAndIdleClose(t *testing.T) {
	m := newMTEnv(t)
	m.newTenant("klant1")
	m.newTenant("klant2")
	m.h.Shutdown(time.Second)
	m.h.mu.Lock()
	m.h.shutdown = false
	m.h.mu.Unlock()
	if open := m.h.OpenTenants(); len(open) != 0 {
		t.Fatal("shutdown left tenants open:", open)
	}
	m.p.PutSettings(map[string]string{"max_open_tenants": "1"}, nil)
	m.host("klant1."+mtBase).do("GET", "/api/bootstrap", "", nil)
	m.host("klant2."+mtBase).do("GET", "/api/bootstrap", "", nil)
	open := m.h.OpenTenants()
	t2, _ := m.p.TenantBySlug("klant2")
	if len(open) != 1 || open[0] != t2.ID {
		t.Fatalf("LRU: open=%v", open)
	}
	// Concurrent first requests open a tenant once.
	done := make(chan int, 8)
	for i := 0; i < 8; i++ {
		go func() {
			r, err := http.NewRequest("GET", m.ts.URL+"/api/bootstrap", nil)
			if err != nil {
				done <- 0
				return
			}
			r.Host = "klant1." + mtBase
			res, err := http.DefaultClient.Do(r)
			if err != nil {
				done <- 0
				return
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			done <- res.StatusCode
		}()
	}
	for i := 0; i < 8; i++ {
		if c := <-done; c != 200 && c != 503 {
			t.Fatal("concurrent open:", c)
		}
	}
	// Idle tenants are closed.
	m.h.now = func() time.Time { return time.Now().Add(time.Hour) }
	m.h.reap()
	if open := m.h.OpenTenants(); len(open) != 0 {
		t.Fatal("idle tenants not closed:", open)
	}
	m.h.now = time.Now
	// Maintenance of idle tenants opens and closes them again; stats are recorded.
	m.p.PutSettings(map[string]string{"max_open_tenants": "5"}, nil)
	m.h.MaintainIdleTenants(context.Background())
	if open := m.h.OpenTenants(); len(open) != 0 {
		t.Fatal("maintenance left tenants open:", open)
	}
	t1, _ := m.p.TenantBySlug("klant1")
	if t1.StatUsers != 1 || t1.StatUpdatedAt == "" {
		t.Fatalf("stats: %+v", t1)
	}
}

// TestMTImportSingleTenant converts an encrypted single-tenant data directory
// (with a stored, encrypted share file) into a tenant and checks that the file
// still decrypts, the audit chain verifies and the original is archived.
func TestMTImportSingleTenant(t *testing.T) {
	t.Setenv("SENDORA_DISABLE_IP_BANS", "true")
	dir := t.TempDir()
	srcKey := make([]byte, 32)
	rand.Read(srcKey)
	st, err := store.OpenEncrypted(dir, srcKey, true)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, mtStatic, "test")
	s.passwordScreenOff = true
	ts := httptest.NewServer(s.Router())
	e := &env{t: t, s: s, ts: ts}
	admin := e.setup()
	sh := e.share(admin, map[string]string{"report.txt": "single tenant data"}, nil)
	e.want(sh, 201, "share")
	lid := sh.S("long_id")
	ts.Close()
	s.GracefulStop(time.Second, nil, nil, nil)
	if _, err := s.makeBackup(); err != nil {
		t.Fatal(err)
	}
	st.Close()

	master := make([]byte, 32)
	rand.Read(master)
	p, err := platform.Open(dir, master, true)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	res, err := p.ImportSingleTenant(platform.ImportOptions{Slug: "legacy", SourceKey: srcKey})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 || res.Backups != 1 {
		t.Fatalf("import result: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, store.DBFile)); !os.IsNotExist(err) {
		t.Fatal("original database not archived")
	}
	if _, err := os.Stat(filepath.Join(res.Archive, store.DBFile)); err != nil {
		t.Fatal("archived original missing", err)
	}
	// The tenant database is re-encrypted: the old key no longer opens it.
	tdb := filepath.Join(dir, "tenants", res.TenantID, store.DBFile)
	if store.DatabaseReadable(tdb, srcKey) {
		t.Fatal("tenant database still readable with the single-tenant key")
	}
	// Re-running finds nothing to convert.
	if _, err := p.ImportSingleTenant(platform.ImportOptions{Slug: "legacy2", SourceKey: srcKey}); err == nil {
		t.Fatal("second conversion should find nothing")
	}
	h, err := NewTenantHost(MultiTenantConfig{Platform: p, BaseDomain: mtBase, Static: mtStatic, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	mts := httptest.NewServer(h)
	defer mts.Close()
	defer h.Shutdown(time.Second)
	k := &env{t: t, ts: mts, host: "legacy." + mtBase}
	r := k.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"})
	k.want(r, 200, "login after import")
	if r := k.do("GET", "/api/shares/"+lid+"/download", "", nil); r.Code != 200 || string(r.Body) != "single tenant data" {
		t.Fatalf("file after import: %d %q", r.Code, r.Body)
	}
	tn, _ := p.Tenant(res.TenantID)
	dbKey, root, _ := p.TenantKeys(tn)
	if root == nil || !bytes.Equal(root, srcKey) {
		t.Fatal("imported tenant must keep the single-tenant key as its file/audit root")
	}
	if st, err := store.VerifyAuditDatabaseRoot(tdb, dbKey, root); err != nil || !st.OK {
		t.Fatal("audit chain after import", st, err)
	}
}

func fileKeysEqual(a, b *store.Store) bool {
	ka, _, _ := a.NewFileKey()
	kb, _, _ := b.NewFileKey()
	return bytes.Equal(ka, kb)
}
