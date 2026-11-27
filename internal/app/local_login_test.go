// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func (e *env) mkProvider(tok, name string, enabled bool) int64 {
	e.t.Helper()
	r := e.do("POST", "/api/auth-providers", tok, map[string]any{"name": name, "type": "github", "client_id": "c-" + name, "client_secret": "s", "enabled": enabled, "allow_registration": true})
	e.want(r, 201, "create provider")
	var id int64
	e.s.St.DB.QueryRow(`SELECT id FROM auth_providers WHERE uuid=?`, r.S("uuid")).Scan(&id)
	return id
}

func (e *env) linkUser(username string, provider int64, sub string) int64 {
	e.t.Helper()
	var uid int64
	if err := qByName(e.s.St, `SELECT id FROM users WHERE username=?`, username).Scan(&uid); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.s.St.DB.Exec(`INSERT INTO user_auth_providers(user_id,provider_id,provider_user_id) VALUES(?,?,?)`, uid, provider, sub); err != nil {
		e.t.Fatal(err)
	}
	return uid
}

func (e *env) wantErr(r resp, code int, msg, what string) {
	e.t.Helper()
	e.want(r, code, what)
	if r.S("error") != msg {
		e.t.Fatalf("%s: error %q want %q", what, r.S("error"), msg)
	}
}

func (e *env) setLocal(tok string, v any) resp {
	return e.do("PUT", "/api/settings", tok, map[string]any{"local_login_enabled": v})
}

func TestLocalLoginDefaultAndBootstrap(t *testing.T) {
	e := newEnv(t)
	if !e.s.St.SettingBool("local_login_enabled") {
		t.Fatal("default must be true")
	}
	b := e.do("GET", "/api/bootstrap", "", nil).J()
	if v, ok := b["local_login_enabled"].(bool); !ok || !v {
		t.Fatal("bootstrap default", b["local_login_enabled"])
	}
}

func TestLocalLoginDisableSafetyChecks(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	// no provider at all
	e.wantErr(e.setLocal(tok, false), 400, msgNeedEnabledProvider, "no provider")
	// invalid value
	e.want(e.setLocal(tok, "maybe"), 400, "invalid string")
	e.want(e.setLocal(tok, nil), 400, "null")
	e.want(e.setLocal(tok, 1), 400, "number")
	// only a disabled provider, admin linked to it
	dis := e.mkProvider(tok, "Off", false)
	e.linkUser("admin", dis, "1")
	e.wantErr(e.setLocal(tok, false), 400, msgNeedEnabledProvider, "provider disabled")
	// enabled provider but admin not linked to it: whole batch rejected
	en := e.mkProvider(tok, "On", true)
	r := e.do("PUT", "/api/settings", tok, map[string]any{"local_login_enabled": false, "application_name": "Changed"})
	e.wantErr(r, 400, msgNeedLinkedAdmin, "admin not linked")
	if e.s.St.Setting("application_name") == "Changed" || !e.s.St.SettingBool("local_login_enabled") {
		t.Fatal("batch must be rejected as a whole")
	}
	// link to the enabled provider: allowed
	e.linkUser("admin", en, "2")
	e.want(e.do("PUT", "/api/settings", tok, map[string]any{"local_login_enabled": false, "application_name": "Changed"}), 200, "disable")
	if e.s.St.SettingBool("local_login_enabled") || e.s.St.Setting("application_name") != "Changed" {
		t.Fatal("not stored")
	}
	if v, _ := e.do("GET", "/api/bootstrap", "", nil).J()["local_login_enabled"].(bool); v {
		t.Fatal("bootstrap must show disabled")
	}
	// re-sending false while already off is not re-checked
	e.s.St.DB.Exec(`DELETE FROM user_auth_providers`)
	e.want(e.setLocal(tok, "false"), 200, "idempotent off")
	// enabling is always allowed
	e.want(e.setLocal(tok, true), 200, "enable")
	if !e.s.St.SettingBool("local_login_enabled") {
		t.Fatal("not re-enabled")
	}
}

func TestLocalLoginDisabledRoutes(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	e.want(e.do("POST", "/api/users", tok, map[string]any{"username": "bob", "password": "password123", "email": "bob@x.io"}), 201, "bob")
	pid := e.mkProvider(tok, "GH", true)
	uid := e.linkUser("admin", pid, "42")
	e.want(e.setLocal(tok, false), 200, "disable")

	for _, c := range []struct {
		path string
		body map[string]any
	}{
		{"/api/auth/login", map[string]any{"username": "bob", "password": "password123"}},
		{"/api/auth/register", map[string]any{"username": "n", "password": "password123", "email": "n@x.io"}},
		{"/api/auth/forgot-password", map[string]any{"email": "bob@x.io"}},
		{"/api/auth/reset-password", map[string]any{"token": "t", "password": "password123"}},
		{"/api/auth/verify-email", map[string]any{"email": "bob@x.io", "code": "000000"}},
		{"/api/auth/resend-verification", map[string]any{"email": "bob@x.io"}},
	} {
		e.wantErr(e.do("POST", c.path, "", c.body), 403, "local login is disabled", c.path)
	}
	// login is refused before any lockout bookkeeping
	for i := 0; i < 8; i++ {
		e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "wrong-password"})
	}
	var fails int
	qByName(e.s.St, `SELECT login_failures FROM users WHERE username='bob'`).Scan(&fails)
	if fails != 0 {
		t.Fatal("disabled login must not touch lockout counters", fails)
	}
	// existing session keeps working, profile update unchanged
	e.want(e.do("GET", "/api/users/me", tok, nil), 200, "existing session")
	e.want(e.do("PUT", "/api/users/me", tok, map[string]any{"name": "Admin Z", "current_password": "password123"}), 200, "updateMe")
	// provider login path still works
	var puuid string
	e.s.St.DB.QueryRow(`SELECT uuid FROM auth_providers WHERE id=?`, pid).Scan(&puuid)
	prov, err := e.s.providerByUUID(puuid)
	if err != nil {
		t.Fatal(err)
	}
	u, msg := e.s.resolveExternalUser(prov, extIdentity{Sub: "42"})
	if u == nil || u.ID != uid {
		t.Fatal("external resolve", msg)
	}
	rec := httptest.NewRecorder()
	if !e.s.issueSession(rec, httptest.NewRequest("GET", "/", nil), u) {
		t.Fatal("issueSession")
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "refresh=") {
		t.Fatal("no refresh cookie")
	}
	e.want(e.do("GET", "/api/users/me", e.s.accessToken(u), nil), 200, "provider session")
	// provider listing / oidc start stay reachable
	e.want(e.do("GET", "/api/auth/providers", "", nil), 200, "public providers")
}

func TestLocalLoginEnvOverride(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	e.want(e.do("POST", "/api/users", tok, map[string]any{"username": "bob", "password": "password123", "email": "bob@x.io"}), 201, "bob")
	pid := e.mkProvider(tok, "GH", true)
	e.linkUser("admin", pid, "42")
	e.want(e.setLocal(tok, false), 200, "disable")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "password123"}), 403, "off")

	e.s.SetForceLocalLogin(true)
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "password123"}), 200, "forced on")
	if v, _ := e.do("GET", "/api/bootstrap", "", nil).J()["local_login_enabled"].(bool); !v {
		t.Fatal("bootstrap must show effective value")
	}
	if e.s.St.SettingBool("local_login_enabled") {
		t.Fatal("override must not write the database")
	}
	// safety guards still use the stored setting
	e.wantErr(e.do("DELETE", fmt.Sprintf("/api/users/me/providers/%d", pid), tok, nil), 400, msgUnlinkLockout, "guard uses stored setting")
	e.s.SetForceLocalLogin(false)
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "password123"}), 403, "off again")
}

func TestLocalLoginSetupOnEmptyDatabase(t *testing.T) {
	e := newEnv(t)
	if err := e.s.St.SetSetting("local_login_enabled", "false"); err != nil {
		t.Fatal(err)
	}
	e.setup()
}

func TestLocalLoginGuardsWhileOff(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	pid := e.mkProvider(tok, "GH", true)
	other := e.mkProvider(tok, "Other", true)
	e.linkUser("admin", pid, "1")
	// a second admin who is only linked externally, plus a plain user
	e.want(e.do("POST", "/api/users", tok, map[string]any{"username": "adm2", "password": "password123", "email": "a2@x.io", "admin": true}), 201, "adm2")
	e.want(e.do("POST", "/api/users", tok, map[string]any{"username": "plain", "password": "password123", "email": "p@x.io"}), 201, "plain")
	adm2 := e.linkUser("adm2", pid, "2")
	plain := e.linkUser("plain", pid, "3")
	// guards are inactive while local login is on
	e.want(e.do("DELETE", fmt.Sprintf("/api/users/me/providers/%d", pid), tok, nil), 200, "unlink while on (admin has password)")
	e.linkUser("admin", pid, "1")
	e.want(e.setLocal(tok, false), 200, "disable")

	// unlink: needs another enabled link
	e.wantErr(e.do("DELETE", fmt.Sprintf("/api/users/me/providers/%d", pid), tok, nil), 400, msgUnlinkLockout, "unlink only link")
	e.linkUser("admin", other, "9")
	// another enabled link remains -> unlinking is allowed
	e.want(e.do("DELETE", fmt.Sprintf("/api/users/me/providers/%d", pid), tok, nil), 200, "unlink with another enabled link")
	// disable provider "other": admin1/adm2 still linked via pid
	upd := func(id int64, enabled bool) resp {
		return e.do("PUT", fmt.Sprintf("/api/auth-providers/%d", id), tok, map[string]any{"name": "x", "type": "github", "client_id": fmt.Sprintf("c-%s", map[int64]string{pid: "GH", other: "Other"}[id]), "enabled": enabled})
	}
	e.want(upd(other, false), 200, "disable other provider keeps access")
	e.want(upd(other, true), 200, "enable other")
	// remove every external admin link except adm2's, leaving adm2 as the only external admin
	e.s.St.DB.Exec(`DELETE FROM user_auth_providers WHERE user_id<>?`, adm2)
	e.s.St.DB.Exec(`INSERT INTO user_auth_providers(user_id,provider_id,provider_user_id) VALUES(?,?,?)`, plain, pid, "3")
	e.wantErr(upd(pid, false), 409, msgLastExternalAdmin, "disable last provider")
	e.wantErr(e.do("DELETE", fmt.Sprintf("/api/auth-providers/%d", pid), tok, nil), 409, msgLastExternalAdmin, "delete last provider")
	e.wantErr(e.do("DELETE", fmt.Sprintf("/api/users/%d", adm2), tok, nil), 409, msgLastExternalAdmin, "delete last admin")
	e.wantErr(e.do("PUT", fmt.Sprintf("/api/users/%d", adm2), tok, map[string]any{"name": "A", "email": "a2@x.io", "admin": false}), 409, msgLastExternalAdmin, "demote last admin")
	// still an admin
	var isAdmin bool
	e.s.St.DB.QueryRow(`SELECT admin FROM users WHERE id=?`, adm2).Scan(&isAdmin)
	if !isAdmin {
		t.Fatal("demotion must not apply")
	}
	// harmless changes remain possible
	e.want(e.do("PUT", fmt.Sprintf("/api/users/%d", adm2), tok, map[string]any{"name": "A", "email": "a2@x.io", "admin": true}), 200, "plain edit")
	e.want(e.do("DELETE", fmt.Sprintf("/api/users/%d", plain), tok, nil), 200, "delete non-admin")
	// a second external admin lifts the restriction
	adm3 := e.linkUser("admin", pid, "7")
	e.want(e.do("PUT", fmt.Sprintf("/api/users/%d", adm2), tok, map[string]any{"name": "A", "email": "a2@x.io", "admin": false}), 200, "demote with another external admin")
	_ = adm3
	// re-enabling local login lifts guards
	e.want(e.setLocal(tok, true), 200, "re-enable")
	e.want(upd(pid, false), 200, "disable provider while local login on")
}
