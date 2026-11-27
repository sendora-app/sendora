// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func idleCookie(t *testing.T, r resp) string {
	t.Helper()
	cookies := (&http.Response{Header: r.Hdr}).Cookies()
	if len(cookies) != 1 || cookies[0].Name != "refresh" {
		t.Fatal("expected one refresh cookie", cookies)
	}
	return cookies[0].Name + "=" + cookies[0].Value
}

func idleLogin(e *env, user string) resp {
	return e.do("POST", "/api/auth/login", "", map[string]any{"username": user, "password": "password123"})
}

func idleAge(t *testing.T, e *env, age time.Duration) {
	t.Helper()
	if _, err := e.s.St.DB.Exec(`UPDATE refresh_tokens SET issued_at=?`, time.Now().Add(-age)); err != nil {
		t.Fatal(err)
	}
}

func TestIdleSettingValidationBootstrapAndRollback(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	boot := func() any { return e.do("GET", "/api/bootstrap", "", nil).J()["idle_logout_minutes"] }
	if boot() != float64(60) {
		t.Fatal("default must be 60 minutes", boot())
	}
	for _, ok := range []any{"0", "1", "90", "10080", 45, float64(120)} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"idle_logout_minutes": ok}), 200, "valid value")
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"idle_logout_minutes": 45}), 200, "set 45")
	if boot() != float64(45) {
		t.Fatal("bootstrap must publish the configured value", boot())
	}
	before := e.s.St.Setting("application_name")
	for _, bad := range []any{"-1", "10081", "1.5", "x", "", " ", nil, true, []int{1}, 99999999999} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"idle_logout_minutes": bad, "application_name": "must-not-change"}), 400, "invalid idle value")
	}
	if e.s.St.Setting("application_name") != before || boot() != float64(45) {
		t.Fatal("a rejected batch changed state")
	}
	e.want(e.do("PUT", "/api/settings", "", map[string]any{"idle_logout_minutes": 5}), 401, "anonymous")
	if err := e.s.St.SetSetting("idle_logout_minutes", "garbage"); err != nil {
		t.Fatal(err)
	}
	if boot() != float64(60) {
		t.Fatal("a corrupt stored value must fall back to the safe default", boot())
	}
}

func TestIdleRefreshWindow(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "idler", false)
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"idle_logout_minutes": 30}), 200, "30 minutes")
	// Start from a clean slate so only the token under test exists.
	if _, err := e.s.St.DB.Exec(`DELETE FROM refresh_tokens`); err != nil {
		t.Fatal(err)
	}

	// Inside the window (30 min + 20 min grace): refresh works and rotates the token.
	login := idleLogin(e, "idler")
	e.want(login, 200, "login")
	cookie := idleCookie(t, login)
	idleAge(t, e, 49*time.Minute)
	first := e.do("POST", "/api/auth/refresh", "", nil, "Cookie", cookie)
	e.want(first, 200, "refresh inside the window")
	next := idleCookie(t, first)
	if next == cookie {
		t.Fatal("refresh must rotate the token")
	}
	var age time.Duration
	var issued time.Time
	if err := e.s.St.DB.QueryRow(`SELECT issued_at FROM refresh_tokens`).Scan(&issued); err != nil {
		t.Fatal(err)
	}
	age = time.Since(issued)
	if age > time.Minute {
		t.Fatal("rotation must reset the idle clock", age)
	}
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", cookie), 401, "old token is single use")

	// Outside the window: refused, and the token is gone for good.
	idleAge(t, e, 71*time.Minute)
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", next), 401, "abandoned session")
	var n int
	if err := e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM refresh_tokens`).Scan(&n); err != nil || n != 0 {
		t.Fatal("an idle-expired token must be deleted", n, err)
	}
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", next), 401, "still refused")

	// Zero disables the rule entirely. (Deleting every refresh token above also
	// ended the administrator's session, so a token without a session is used.)
	adminUser, _ := e.s.userByID(1)
	e.want(e.do("PUT", "/api/settings", e.s.accessToken(adminUser), map[string]any{"idle_logout_minutes": 0}), 200, "never")
	login = idleLogin(e, "idler")
	cookie = idleCookie(t, login)
	idleAge(t, e, 40*24*time.Hour)
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", cookie), 200, "0 disables the idle window")
}

func TestIdleDoesNotAffectGuestsOrLegacyRows(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"idle_logout_minutes": 10}), 200, "10 minutes")
	// A guest session (open invite) is not subject to the inactivity rule.
	inv := e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{})
	e.want(inv, 201, "invite")
	acc := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": filepath.Base(inv.S("url"))})
	e.want(acc, 200, "accept")
	guestCookie := idleCookie(t, acc)
	idleAge(t, e, 5*time.Hour)
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", guestCookie), 200, "guest refresh is unaffected")

	// A legacy row without issued_at (planted or from before the upgrade) is treated as fresh.
	login := idleLogin(e, "admin")
	cookie := idleCookie(t, login)
	if _, err := eByName(e.s.St, `UPDATE refresh_tokens SET issued_at=NULL WHERE user_id=(SELECT id FROM users WHERE username='admin')`); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", cookie), 200, "legacy row")
}

func TestIdleExpiredHelperBoundaries(t *testing.T) {
	e := newEnv(t)
	_ = e
	now := time.Now()
	if idleExpired(60, now.Add(-79*time.Minute), now) || !idleExpired(60, now.Add(-81*time.Minute), now) {
		t.Fatal("window is the setting plus 20 minutes of grace")
	}
	if idleExpired(60, time.Time{}, now) || idleExpired(0, now.Add(-1000*time.Hour), now) {
		t.Fatal("unknown issue time counts as fresh and 0 disables")
	}
}
