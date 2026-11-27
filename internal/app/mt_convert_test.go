// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// convEnv is a single-tenant installation with a share, ready to schedule a
// conversion through the API.
type convEnv struct {
	*env
	dir, admin, lid string
	key             []byte
	st              *store.Store
}

func newConvEnv(t *testing.T) *convEnv {
	t.Helper()
	t.Setenv("SENDORA_DISABLE_IP_BANS", "true")
	dir := t.TempDir()
	key := make([]byte, 32)
	rand.Read(key)
	st, err := store.OpenEncrypted(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, mtStatic, "test")
	s.passwordScreenOff = true
	ts := httptest.NewServer(s.Router())
	t.Cleanup(ts.Close)
	e := &env{t: t, s: s, ts: ts}
	admin := e.setup()
	sh := e.share(admin, map[string]string{"report.txt": "single tenant data", "notes.txt": "more"}, nil)
	e.want(sh, 201, "share")
	return &convEnv{env: e, dir: dir, admin: admin, lid: sh.S("long_id"), key: key, st: st}
}

func (c *convEnv) schedule(body map[string]any) resp {
	return c.do("POST", "/api/multitenant", c.admin, body)
}

func (c *convEnv) stop() {
	c.ts.Close()
	c.s.GracefulStop(time.Second, nil, nil, nil)
	c.st.Close()
}

var convBody = map[string]any{"base_domain": mtBase, "slug": "acme", "name": "Acme", "admin_username": "platform", "admin_email": "ops@acme.test",
	"admin_password": "Harbor-Lantern-Quiet-7", "mfa_required": false, "custom_domain": "files.acme.test"}

func TestConversionScheduleAndCancel(t *testing.T) {
	c := newConvEnv(t)
	st := c.do("GET", "/api/multitenant", c.admin, nil)
	c.want(st, 200, "status")
	if st.J()["pending"] != nil {
		t.Fatal("nothing should be pending")
	}
	bad := map[string]any{}
	for k, v := range convBody {
		bad[k] = v
	}
	bad["slug"] = "admin"
	c.want(c.schedule(bad), 400, "reserved slug")
	bad["slug"], bad["admin_password"] = "acme", "short"
	c.want(c.schedule(bad), 400, "weak password")
	bad["admin_password"], bad["custom_domain"] = "Harbor-Lantern-Quiet-7", "x."+mtBase
	c.want(c.schedule(bad), 400, "custom domain under the base domain")
	c.want(c.schedule(convBody), 200, "schedule")
	path := filepath.Join(c.dir, ConversionPendingFile)
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("pending file: %v %v", fi, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "Harbor-Lantern-Quiet-7") {
		t.Fatal("password stored in clear")
	}
	var req ConversionRequest
	json.Unmarshal(raw, &req)
	if bcrypt.CompareHashAndPassword([]byte(req.AdminPasswordHash), []byte("Harbor-Lantern-Quiet-7")) != nil || req.RequestedBy != "admin" {
		t.Fatalf("pending request: %+v", req)
	}
	st = c.do("GET", "/api/multitenant", c.admin, nil)
	if p, _ := st.J()["pending"].(map[string]any); p == nil || p["admin_password_hash"] != "" {
		t.Fatalf("status with pending: %s", st.Body)
	}
	c.want(c.do("DELETE", "/api/multitenant", c.admin, nil), 200, "cancel")
	if ConversionPending(c.dir) {
		t.Fatal("pending file left after cancel")
	}
	var n int
	c.s.St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action IN ('multitenant_conversion_scheduled','multitenant_conversion_cancelled')`).Scan(&n)
	if n != 2 {
		t.Fatalf("audit records: %d", n)
	}
	// "Restart now": refused where main registered no restarter, needs a
	// recent sign-in (step-up), is audited and then restarts.
	c.want(c.schedule(convBody), 200, "schedule again")
	if r := c.do("POST", "/api/multitenant/restart", c.admin, nil); r.Code != 409 || !strings.Contains(r.S("error"), "restart the server") {
		t.Fatalf("restart without a restarter: %d %s", r.Code, r.Body)
	}
	restarted := make(chan struct{}, 1)
	c.s.SetRestarter(func() { restarted <- struct{}{} })
	if r := c.do("POST", "/api/multitenant/restart", staleAdmin(t, c.env, "admin"), nil); r.Code != 401 && r.Code != 403 {
		t.Fatalf("restart without re-authentication: %d %s", r.Code, r.Body)
	}
	c.want(c.do("POST", "/api/multitenant/restart", c.admin, nil), 202, "restart")
	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("restarter not called")
	}
	var rn int
	c.s.St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='restart_requested'`).Scan(&rn)
	if rn != 1 {
		t.Fatalf("restart_requested records: %d", rn)
	}
	// Non-administrators cannot schedule.
	user := c.mkUser(c.admin, "bob", false)
	if r := c.do("POST", "/api/multitenant", user, convBody); r.Code != 403 {
		t.Fatalf("non-admin: %d", r.Code)
	}
}

func TestConversionOnStart(t *testing.T) {
	c := newConvEnv(t)
	c.want(c.schedule(convBody), 200, "schedule")
	c.stop()

	base, err := ConvertPending(c.dir, c.key, t.Logf)
	if err != nil || base != mtBase {
		t.Fatalf("conversion: %q %v", base, err)
	}
	if ConversionPending(c.dir) {
		t.Fatal("pending file left")
	}
	if multi, b := ResolveMode("", "", c.dir); !multi || b != mtBase {
		t.Fatalf("persisted mode: %v %q", multi, b)
	}
	if m, _ := filepath.Glob(filepath.Join(c.dir, "pre-multitenant-backup-*.db")); len(m) != 1 {
		t.Fatal("no pre-conversion backup")
	}
	if m, _ := filepath.Glob(filepath.Join(c.dir, "pre-tenant-import-*")); len(m) != 1 {
		t.Fatal("originals not kept in pre-tenant-import-*")
	}
	p, err := platform.Open(c.dir, c.key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	tn, err := p.TenantBySlug("acme")
	if err != nil || tn.Name != "Acme" {
		t.Fatalf("tenant: %+v %v", tn, err)
	}
	if p.MFARequired() {
		t.Fatal("platform_mfa_required not applied")
	}
	a, err := p.AdminByName("platform")
	if err != nil || bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte("Harbor-Lantern-Quiet-7")) != nil {
		t.Fatal("platform administrator not created")
	}
	if sc, _ := p.Storage(tn.ID); sc.Offer != platform.OfferLocal {
		t.Fatalf("converted tenant must keep its local storage: %+v", sc)
	}
	dbKey, root, _ := p.TenantKeys(tn)
	if st, err := store.VerifyAuditDatabaseRoot(filepath.Join(c.dir, "tenants", tn.ID, store.DBFile), dbKey, root); err != nil || !st.OK {
		t.Fatalf("audit chain after conversion: %+v %v", st, err)
	}
	h, err := NewTenantHost(MultiTenantConfig{Platform: p, BaseDomain: base, Static: mtStatic, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()
	defer h.Shutdown(time.Second)
	k := &env{t: t, ts: ts, host: "acme." + mtBase}
	k.want(k.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"}), 200, "tenant login after conversion")
	if r := k.do("GET", "/api/shares/"+c.lid+"/download/report.txt", "", nil); r.Code != 200 || string(r.Body) != "single tenant data" {
		t.Fatalf("share after conversion: %d %q", r.Code, r.Body)
	}
	// The old address is a verified custom domain: old links reach the share.
	req, _ := http.NewRequest("GET", ts.URL+"/s/"+c.lid, nil)
	req.Host = "files.acme.test"
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 308 || res.Header.Get("Location") != "https://acme."+mtBase+"/s/"+c.lid {
		t.Fatalf("old link via custom domain: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	recs, _ := p.AuditPage(0, 50)
	found := false
	for _, r := range recs {
		found = found || r.Action == "multitenant_conversion_completed"
	}
	if !found {
		t.Fatal("conversion not in the platform audit log")
	}
}

// A conversion that fails (here: a share file that no longer decrypts, so the
// import's verification refuses) is undone: the single-tenant installation
// starts as before and the error is shown in the UI.
func TestConversionFailureRollsBack(t *testing.T) {
	c := newConvEnv(t)
	c.want(c.schedule(convBody), 200, "schedule")
	var disk string
	c.s.St.DB.QueryRow(`SELECT disk_path FROM files LIMIT 1`).Scan(&disk)
	c.stop()
	matches, _ := filepath.Glob(filepath.Join(c.dir, "shares", c.lid, "*"))
	if len(matches) == 0 {
		t.Fatal("no share files on disk", disk)
	}
	b, _ := os.ReadFile(matches[0])
	b[len(b)-1] ^= 0xff
	os.WriteFile(matches[0], b, 0o600)

	if _, err := ConvertPending(c.dir, c.key, t.Logf); err == nil {
		t.Fatal("conversion with a corrupt file succeeded")
	}
	if ConversionPending(c.dir) {
		t.Fatal("a failed conversion must not run again at every start")
	}
	if _, err := os.Stat(filepath.Join(c.dir, store.PlatformDBFile)); !os.IsNotExist(err) {
		t.Fatal("platform database left in the data directory")
	}
	if multi, _ := ResolveMode("", "", c.dir); multi {
		t.Fatal("mode persisted after a failed conversion")
	}
	st, err := store.OpenEncrypted(c.dir, c.key, false)
	if err != nil {
		t.Fatalf("single-tenant database after rollback: %v", err)
	}
	defer st.Close()
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM files`).Scan(&n)
	if n != 2 {
		t.Fatalf("files after rollback: %d", n)
	}
	s := New(st, mtStatic, "test")
	ts := httptest.NewServer(s.Router())
	defer ts.Close()
	e := &env{t: t, s: s, ts: ts}
	lr := e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"})
	e.want(lr, 200, "login after rollback")
	stat := e.do("GET", "/api/multitenant", lr.S("access_token"), nil)
	if le, _ := stat.J()["last_error"].(map[string]any); le == nil || le["stage"] != "tenant import" {
		t.Fatalf("error not shown: %s", stat.Body)
	}
	// The untouched file downloads; the one corrupted on purpose stays blocked.
	ok := 0
	for name, want := range map[string]string{"report.txt": "single tenant data", "notes.txt": "more"} {
		if r := e.do("GET", "/api/shares/"+c.lid+"/download/"+name, "", nil); r.Code == 200 && string(r.Body) == want {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("share after rollback: %d of 2 files readable, want 1", ok)
	}
}

func TestResolveModePrecedence(t *testing.T) {
	dir := t.TempDir()
	if multi, _ := ResolveMode("", "", dir); multi {
		t.Fatal("default must be single-tenant")
	}
	writeFile0600(filepath.Join(dir, ModeFile), PersistedMode{Mode: "multi-tenant", BaseDomain: "persisted.example.com"})
	if multi, b := ResolveMode("", "", dir); !multi || b != "persisted.example.com" {
		t.Fatalf("persisted: %v %q", multi, b)
	}
	if multi, b := ResolveMode("false", "", dir); multi || b != "persisted.example.com" {
		t.Fatal("SENDORA_MULTI_TENANT=false must win over the persisted mode")
	}
	if multi, b := ResolveMode("true", "env.example.com", t.TempDir()); !multi || b != "env.example.com" {
		t.Fatal("SENDORA_MULTI_TENANT=true must win")
	}
	if _, b := ResolveMode("", "env.example.com", dir); b != "env.example.com" {
		t.Fatal("SENDORA_BASE_DOMAIN must win over the persisted base domain")
	}
}

// The platform console's restart needs a fresh confirmation and is audited.
func TestConsoleRestart(t *testing.T) {
	m := newMTEnv(t)
	c, cookie, secret := m.consoleLogin()
	c.want(c.do("POST", "/api/platform/restart", "", map[string]any{}, "Cookie", cookie), 409, "no restarter")
	restarted := make(chan struct{}, 1)
	m.h.SetRestarter(func() { restarted <- struct{}{} })
	c.want(c.do("POST", "/api/platform/restart", "", map[string]any{"code": "000000"}, "Cookie", cookie), 403, "restart without re-auth")
	c.want(c.do("POST", "/api/platform/restart", "", map[string]any{"code": m.nextCode(secret)}, "Cookie", cookie), 202, "restart")
	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("restarter not called")
	}
	au := c.do("GET", "/api/platform/audit", "", nil, "Cookie", cookie)
	if !strings.Contains(string(au.Body), `"action":"restart_requested"`) {
		t.Fatal("console restart not audited")
	}
}
