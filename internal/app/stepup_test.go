// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"testing"
	"time"
)

// staleAdmin returns an access token of the administrator whose sign-in lies
// outside the step-up window.
func staleAdmin(t *testing.T, e *env, name string) string {
	t.Helper()
	var id int64
	if err := qByName(e.s.St, `SELECT id FROM users WHERE username=?`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	u, err := e.s.userByID(id)
	if err != nil {
		t.Fatal(err)
	}
	return e.s.accessTokenAt(u, time.Now().Add(-10*time.Minute))
}

func TestStepUpRequiredForCriticalAdminActions(t *testing.T) {
	e := newEnv(t)
	fresh := e.setup()
	e.mkUser(fresh, "victim", false)
	var vid int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='victim'`).Scan(&vid)
	stale := staleAdmin(t, e, "admin")
	for _, c := range []struct{ m, p string }{
		{"DELETE", fmt.Sprintf("/api/users/%d", vid)},
		{"POST", fmt.Sprintf("/api/users/%d/erase", vid)},
		{"POST", fmt.Sprintf("/api/users/%d/mfa/reset", vid)},
		{"POST", "/api/auth-providers"},
		{"PUT", "/api/auth-providers/1"},
		{"DELETE", "/api/auth-providers/1"},
		{"GET", "/api/backups/x.db"},
		{"DELETE", "/api/backups/x.db"},
		{"POST", "/api/backups/import/apply"},
	} {
		r := e.do(c.m, c.p, stale, map[string]any{})
		if r.Code != 401 || r.S("code") != stepUpCode || r.S("error") != msgStepUpRequired {
			t.Errorf("%s %s without step-up: %d %s", c.m, c.p, r.Code, r.Body)
		}
	}
	// Role change and security settings: checked inside the handler.
	r := e.do("PUT", fmt.Sprintf("/api/users/%d", vid), stale, map[string]any{"admin": true})
	if r.Code != 401 || r.S("code") != stepUpCode {
		t.Fatalf("role change without step-up: %d %s", r.Code, r.Body)
	}
	e.want(e.do("PUT", fmt.Sprintf("/api/users/%d", vid), stale, map[string]any{"name": "Vic"}), 200, "a plain edit needs no step-up")
	r = e.do("PUT", "/api/settings", stale, map[string]any{"mfa_policy": "optional"})
	if r.Code != 401 || r.S("code") != stepUpCode {
		t.Fatalf("security setting without step-up: %d %s", r.Code, r.Body)
	}
	e.want(e.do("PUT", "/api/settings", stale, map[string]any{"application_name": "Files"}), 200, "a general setting needs no step-up")
	e.want(e.do("PUT", "/api/settings", stale, map[string]any{"mfa_policy": e.s.St.Setting("mfa_policy")}), 200, "an unchanged security value needs no step-up")

	// Wrong password: refused and counted; right password: the actions work.
	r = e.do("POST", "/api/auth/step-up", stale, map[string]any{"password": "wrong-one"})
	if r.Code != 400 || r.S("error") != msgStepUpWrong {
		t.Fatalf("wrong password: %d %s", r.Code, r.Body)
	}
	e.want(e.do("POST", "/api/auth/step-up", stale, map[string]any{"password": "password123"}), 200, "step-up")
	e.want(e.do("PUT", fmt.Sprintf("/api/users/%d", vid), stale, map[string]any{"admin": true}), 200, "role change after step-up")
	e.want(e.do("DELETE", fmt.Sprintf("/api/users/%d", vid), stale, nil), 200, "delete after step-up")
	if n := countAudit(t, e, "stepup_ok"); n != 1 {
		t.Fatalf("stepup_ok records: %d", n)
	}
	if n := countAudit(t, e, "stepup_failed"); n != 1 {
		t.Fatalf("stepup_failed records: %d", n)
	}
	// Another session of the same administrator does not inherit the step-up.
	u, _ := e.s.userByID(1)
	other := e.s.accessTokenAt(u, time.Now().Add(-20*time.Minute))
	e.want(e.do("PUT", "/api/settings", other, map[string]any{"mfa_policy": "optional"}), 401, "other session")
	// The window ends.
	e.s.St.SetSetting("admin_stepup_minutes", "1")
	e.s.stepUpMu.Lock()
	for k := range e.s.stepUps {
		e.s.stepUps[k] = time.Now().Add(-2 * time.Minute)
	}
	e.s.stepUpMu.Unlock()
	e.want(e.do("PUT", "/api/settings", stale, map[string]any{"mfa_policy": "optional"}), 401, "expired step-up")
}

func countAudit(t *testing.T, e *env, action string) int {
	t.Helper()
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&n)
	return n
}

func TestStepUpPrefersTheSecondFactor(t *testing.T) {
	e := newEnv(t)
	e.s.St.SetSetting("mfa_policy", "optional")
	tok := e.setup()
	secret, _, _ := e.enrollTOTP(tok, "password123")
	stale := staleAdmin(t, e, "admin")
	r := e.do("DELETE", "/api/users/99", stale, nil)
	if r.Code != 401 || fmt.Sprint(r.J()["methods"]) != "[totp]" {
		t.Fatalf("methods: %d %s", r.Code, r.Body)
	}
	// The password is not accepted once a factor exists.
	e.want(e.do("POST", "/api/auth/step-up", stale, map[string]any{"password": "password123"}), 400, "password refused with a factor")
	e.want(e.do("POST", "/api/auth/step-up", stale, map[string]any{"code": totpCode(secret, time.Now().Add(30*time.Second))}), 200, "totp step-up")
	e.want(e.do("DELETE", "/api/users/99", stale, nil), 404, "past the step-up")
}

func TestStepUpProviderOnlyAdminMustSignInAgain(t *testing.T) {
	e := newEnv(t)
	e.setup()
	eByName(e.s.St, `UPDATE users SET password_hash='' WHERE username='admin'`)
	stale := staleAdmin(t, e, "admin")
	r := e.do("DELETE", "/api/users/99", stale, nil)
	if r.Code != 401 || r.S("code") != stepUpCode || r.J()["reauth"] != true {
		t.Fatalf("provider-only admin: %d %s", r.Code, r.Body)
	}
	r = e.do("POST", "/api/auth/step-up", stale, map[string]any{"password": "anything"})
	if r.Code != 403 || r.S("code") != stepUpCode {
		t.Fatalf("step-up for provider-only admin: %d %s", r.Code, r.Body)
	}
}

func TestStepUpIsAdminOnly(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	user := e.mkUser(admin, "plain", false)
	e.want(e.do("POST", "/api/auth/step-up", user, map[string]any{"password": "password123"}), 403, "non-admin")
}

func TestAdminIdleLogoutIsStricter(t *testing.T) {
	if effectiveIdleMinutes(60, 15, true) != 15 || effectiveIdleMinutes(60, 15, false) != 60 ||
		effectiveIdleMinutes(0, 15, true) != 15 || effectiveIdleMinutes(10, 15, true) != 10 || effectiveIdleMinutes(60, 0, true) != 60 {
		t.Fatal("effective idle minutes")
	}
	e := newEnv(t)
	e.setup()
	// An administrator's refresh token unused for 15+20 minutes is refused; a user's is not.
	login := e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"})
	e.want(login, 200, "login")
	e.s.St.DB.Exec(`UPDATE refresh_tokens SET issued_at=?`, time.Now().Add(-36*time.Minute))
	r := e.do("POST", "/api/auth/refresh", "", nil, "Cookie", "refresh="+refreshCookie(login))
	e.want(r, 401, "admin idle")
	e.s.St.SetSetting("admin_idle_logout_minutes", "0")
	login = e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"})
	e.s.St.DB.Exec(`UPDATE refresh_tokens SET issued_at=?`, time.Now().Add(-36*time.Minute))
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", "refresh="+refreshCookie(login)), 200, "0 = same as everyone (60)")
	b := e.do("GET", "/api/bootstrap", "", nil)
	if b.J()["admin_idle_logout_minutes"] != float64(0) {
		t.Fatalf("bootstrap: %s", b.Body)
	}
	e.want(e.do("PUT", "/api/settings", e.setupTokenAgain(), map[string]any{"admin_stepup_minutes": "61"}), 400, "range")
}
