// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

func (e *env) countRows(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.s.St.DB.QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) usersPath(id int64, suffix string) string {
	return fmt.Sprintf("/api/users/%d%s", id, suffix)
}

func linkToken(t *testing.T, mailText, route string) string {
	t.Helper()
	m := regexp.MustCompile(`https://files\.example\.com/` + route + `/([0-9a-f]+)`).FindStringSubmatch(mailText)
	if m == nil {
		t.Fatalf("no %s link in mail: %s", route, mailText)
	}
	return m[1]
}

func TestAdminCannotSetAnotherUsersPassword(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "victim", false)
	vid, _ := e.userRow("victim")
	r := e.do("PUT", e.usersPath(vid, ""), admin, map[string]any{"name": "V", "email": "victim@x.io", "password": "attackerchosen1"})
	e.want(r, 400, "admin sets another user's password")
	if !strings.Contains(r.S("error"), "reset link") {
		t.Fatalf("unclear message: %q", r.S("error"))
	}
	e.want(e.login("victim", "password123"), 200, "old password still works")
	if e.login("victim", "attackerchosen1").Code == 200 {
		t.Fatal("admin chosen password works")
	}
	// The administrator's own account is unaffected.
	aid, _ := e.userRow("admin")
	e.want(e.do("PUT", e.usersPath(aid, ""), admin, map[string]any{"password": "adminnewpass1"}), 200, "own password")
}

func TestAdminEmailChangeUnverifiesKillsSessionsAndNotifies(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	sink := newSMTP(t)
	e.useSMTP(sink)
	tok := e.mkUser(admin, "victim", false)
	vid, _ := e.userRow("victim")
	login := e.login("victim", "password123")
	cookie := refreshCookie(login)
	e.want(e.do("PUT", e.usersPath(vid, ""), admin, map[string]any{"email": "attacker@x.io"}), 200, "change email")
	if e.countRows(`SELECT email_verified FROM users WHERE id=?`, vid) != 0 {
		t.Fatal("changed address must be unverified")
	}
	if e.countRows(`SELECT COUNT(*) FROM refresh_tokens WHERE user_id=?`, vid) != 0 {
		t.Fatal("sessions must be revoked")
	}
	e.want(e.do("GET", "/api/users/me", tok, nil), 401, "old access token")
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", "refresh="+cookie), 401, "old refresh token")
	if r := e.login("victim", "password123"); r.Code != 403 || r.J()["needs_verification"] != true {
		t.Fatal("sign-in must require verification of the new address", r.Code, string(r.Body))
	}
	m := sink.wait(t, "changed the email address of your account")
	if !strings.Contains(m, "victim@x.io") || strings.Contains(m, "attacker@x.io") {
		t.Fatal("notice must go to the previous address only", m)
	}
	// The same address again is not a change.
	before := e.countRows(`SELECT COUNT(*) FROM users WHERE email_verified=0`)
	e.want(e.do("PUT", e.usersPath(vid, ""), admin, map[string]any{"name": "Renamed", "email": "attacker@x.io"}), 200, "same email")
	if e.countRows(`SELECT COUNT(*) FROM users WHERE email_verified=0`) != before {
		t.Fatal("unchanged email altered verification")
	}
}

func TestAdminUpdateGuestAndPartialAdminField(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "second", true)
	sid, _ := e.userRow("second")
	e.want(e.do("PUT", e.usersPath(sid, ""), admin, map[string]any{"name": "Second"}), 200, "partial update")
	if e.countRows(`SELECT admin FROM users WHERE id=?`, sid) != 1 {
		t.Fatal("an omitted admin field demoted the user")
	}
	if e.countRows(`SELECT COUNT(*) FROM users WHERE id=? AND email='second@x.io'`, sid) != 1 {
		t.Fatal("an omitted email was cleared")
	}
	e.want(e.do("PUT", e.usersPath(sid, ""), admin, map[string]any{"admin": false}), 200, "explicit demotion")
	if e.countRows(`SELECT admin FROM users WHERE id=?`, sid) != 0 {
		t.Fatal("explicit demotion ignored")
	}
	aid, _ := e.userRow("admin")
	e.want(e.do("PUT", e.usersPath(aid, ""), admin, map[string]any{"admin": false}), 400, "self demotion")

	res, err := rawExec(e.t, e.s.St, `INSERT INTO users(username,is_guest) VALUES('guest1',1)`)
	if err != nil {
		t.Fatal(err)
	}
	gid, _ := res.LastInsertId()
	e.want(e.do("PUT", e.usersPath(gid, ""), admin, map[string]any{"name": "G"}), 404, "update guest")
	e.want(e.do("POST", e.usersPath(gid, "/force-reset-password"), admin, nil), 404, "reset guest")
	e.want(e.do("DELETE", e.usersPath(gid, ""), admin, nil), 404, "delete guest")
	e.want(e.do("POST", e.usersPath(gid, "/mfa/reset"), admin, nil), 404, "mfa reset guest")
	if e.countRows(`SELECT COUNT(*) FROM users WHERE id=?`, gid) != 1 {
		t.Fatal("guest was deleted")
	}
}

func TestForceResetSendsLinkOnlyByEmail(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.BaseURL = "https://files.example.com"
	e.mkUser(admin, "victim", false)
	vid, _ := e.userRow("victim")
	r := e.do("POST", e.usersPath(vid, "/force-reset-password"), admin, nil)
	e.want(r, 200, "force reset")
	if r.S("reset_email") != "sent" {
		t.Fatal(string(r.Body))
	}
	m := sink.wait(t, "/reset-password/")
	tok := linkToken(t, m, "reset-password")
	if !strings.Contains(m, "victim@x.io") {
		t.Fatal("link not sent to the user's address")
	}
	if strings.Contains(string(r.Body), tok) {
		t.Fatal("token leaked to the administrator")
	}
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": tok, "password": "chosenbyuser1"}), 200, "user resets")
	e.want(e.login("victim", "chosenbyuser1"), 200, "new password")

	// No verified address: nothing is mailed, the old behaviour (change at next sign-in) stays.
	e.mkUser(admin, "plain", false)
	pid, _ := e.userRow("plain")
	e.s.St.DB.Exec(`UPDATE users SET email_verified=0 WHERE id=?`, pid)
	r = e.do("POST", e.usersPath(pid, "/force-reset-password"), admin, nil)
	e.want(r, 200, "force reset unverified")
	if r.S("reset_email") != "skipped" || e.countRows(`SELECT COUNT(*) FROM password_resets WHERE user_id=?`, pid) != 0 {
		t.Fatal("link created for an unverified address", string(r.Body))
	}
	// Welcome links also need a verified address (or an unfinished welcome).
	r = e.do("POST", e.usersPath(pid, "/welcome"), admin, nil)
	e.want(r, 409, "welcome to unverified address")
}

func TestMFAResetNeedsUserConfirmation(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.BaseURL = "https://files.example.com"
	e.setting("mfa_policy", "optional")
	tok := e.mkUser(admin, "iris", false)
	_, tok, _ = e.enrollTOTP(tok, "password123")
	iid, _ := e.userRow("iris")
	e.want(e.do("POST", e.usersPath(iid, "/mfa/reset"), tok, nil), 403, "users cannot request")

	r := e.do("POST", e.usersPath(iid, "/mfa/reset"), admin, nil)
	e.want(r, 200, "request")
	mailText := sink.wait(t, "/mfa-reset/")
	token := linkToken(t, mailText, "mfa-reset")
	if !strings.Contains(mailText, "iris") && !strings.Contains(mailText, "iris@x.io") {
		t.Fatal("request not sent to the user", mailText)
	}
	if strings.Contains(string(r.Body), token) {
		t.Fatal("token leaked to the administrator")
	}
	if e.countRows(`SELECT COUNT(*) FROM mfa_reset_requests WHERE hash=?`, token) != 0 || e.countRows(`SELECT COUNT(*) FROM mfa_reset_requests WHERE hash=?`, hashToken(token)) != 1 {
		t.Fatal("only the token hash may be stored")
	}
	// Nothing changed until the user confirms.
	if e.countRows(`SELECT COUNT(*) FROM user_totp WHERE user_id=?`, iid) != 1 {
		t.Fatal("factors removed before confirmation")
	}
	e.want(e.do("GET", "/api/users/me", tok, nil), 200, "session intact before confirmation")
	e.want(e.do("POST", "/api/auth/mfa-reset/confirm", "", map[string]any{"token": "deadbeef"}), 400, "unknown token")
	e.want(e.do("POST", "/api/auth/mfa-reset/confirm", "", map[string]any{}), 400, "missing token")

	e.want(e.do("POST", "/api/auth/mfa-reset/confirm", "", map[string]any{"token": token}), 200, "confirm")
	if e.countRows(`SELECT (SELECT COUNT(*) FROM user_totp)+(SELECT COUNT(*) FROM user_recovery_codes)+(SELECT COUNT(*) FROM user_webauthn)+(SELECT COUNT(*) FROM refresh_tokens WHERE user_id=?)`, iid) != 0 {
		t.Fatal("confirmation must remove factors and sessions")
	}
	e.want(e.do("GET", "/api/users/me", tok, nil), 401, "access token revoked")
	sink.wait(t, "was removed after you confirmed")
	// Single use.
	e.want(e.do("POST", "/api/auth/mfa-reset/confirm", "", map[string]any{"token": token}), 400, "token reuse")
	if l := e.login("iris", "password123"); l.J()["mfa_required"] == true || l.S("access_token") == "" {
		t.Fatal("no second step after the reset")
	}
}

func TestMFAResetTokenExpiryAndRequirements(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.s.BaseURL = "https://files.example.com"
	e.mkUser(admin, "iris", false)
	iid, _ := e.userRow("iris")
	// No SMTP: the user cannot confirm, so the offline tool is named.
	r := e.do("POST", e.usersPath(iid, "/mfa/reset"), admin, nil)
	e.want(r, 409, "no SMTP")
	if !strings.Contains(r.S("error"), "sendora-db mfa-reset") {
		t.Fatal(r.S("error"))
	}
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.St.DB.Exec(`UPDATE users SET email_verified=0 WHERE id=?`, iid)
	r = e.do("POST", e.usersPath(iid, "/mfa/reset"), admin, nil)
	e.want(r, 409, "unverified address")
	if !strings.Contains(r.S("error"), "sendora-db mfa-reset") || e.countRows(`SELECT COUNT(*) FROM mfa_reset_requests`) != 0 {
		t.Fatal("unverified user must be pointed to the offline tool without a request", r.S("error"))
	}
	e.s.St.DB.Exec(`UPDATE users SET email_verified=1 WHERE id=?`, iid)
	e.want(e.do("POST", e.usersPath(iid, "/mfa/reset"), admin, nil), 200, "request")
	token := linkToken(t, sink.wait(t, "/mfa-reset/"), "mfa-reset")
	if _, err := e.s.St.DB.Exec(`UPDATE mfa_reset_requests SET expires_at=?`, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("POST", "/api/auth/mfa-reset/confirm", "", map[string]any{"token": token}), 400, "expired")
	// A changed address invalidates pending requests.
	e.s.St.DB.Exec(`UPDATE mfa_reset_requests SET expires_at=?`, time.Now().Add(time.Hour))
	e.want(e.do("PUT", e.usersPath(iid, ""), admin, map[string]any{"email": "other@x.io"}), 200, "change email")
	e.want(e.do("POST", "/api/auth/mfa-reset/confirm", "", map[string]any{"token": token}), 400, "request dropped on email change")
}

func TestApplicationURLLockedByAppURL(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"application_url": "https://one.example.com"}), 200, "free change")
	e.s.BaseURL = "https://env.example.com"
	r := e.do("PUT", "/api/settings", admin, map[string]any{"application_url": "https://evil.example.com"})
	e.want(r, 400, "locked by APP_URL")
	if e.s.St.Setting("application_url") != "https://one.example.com" {
		t.Fatal("setting changed")
	}
	if got, ok := e.s.emailBaseURL(nil); !ok || got != "https://env.example.com" {
		t.Fatal("email links must use APP_URL", got)
	}
	s := e.do("GET", "/api/settings", admin, nil)
	if !strings.Contains(string(s.Body), `"application_url"]`) && !strings.Contains(fmt.Sprint(s.J()["managed_settings"]), "application_url") {
		t.Fatal("application_url must be listed as managed")
	}
	// Resubmitting the shown value (a whole-form save) is not an error.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"application_url": "https://one.example.com", "application_name": "Files"}), 200, "unchanged value")
}

func TestApplicationURLChangeIsLogged(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("logging_enabled", "true")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"application_url": "https://secret-host.example.com"}), 200, "change")
	logs := e.do("GET", "/api/logs?limit=100", admin, nil)
	if !strings.Contains(string(logs.Body), "application_url_changed") {
		t.Fatal("change not logged", string(logs.Body))
	}
	// The audit trail deliberately records old and new value of this non-secret
	// setting: a changed application URL is how password-reset links could be
	// redirected, so an auditor needs to see where it pointed.
}

func TestSecurityMailTemplatesExistInEveryLanguage(t *testing.T) {
	e := newEnv(t)
	for _, event := range []string{"admin_password_reset", "account_email_changed_notice", "mfa_reset_requested", "mfa_reset_done"} {
		for _, lang := range []string{"en", "nl", "de", "fr", "es", "xx-unknown"} {
			subject, body, _, err := e.s.renderMail(event, lang, map[string]any{"URL": "https://files.example.com/x", "RecipientName": "Ann", "Username": "ann"})
			if err != nil || subject == "" || body == "" {
				t.Fatalf("%s/%s: %v", event, lang, err)
			}
		}
	}
	// A language without text for the event falls back to English.
	e.s.St.SetSetting("subj_mfa_reset_done_nl", "")
	e.s.St.SetSetting("tpl_mfa_reset_done_nl", "")
	_, body, _, err := e.s.renderMail("mfa_reset_done", "nl", map[string]any{"RecipientName": "Ann"})
	if err != nil || !strings.Contains(body, "two-step verification") {
		t.Fatal("no fallback to English", body, err)
	}
}

func TestSSOOnlyAdminCannotApplyImport(t *testing.T) {
	e := newEncEnv(t)
	admin := e.setup()
	raw := foreignDB(t, otherKey, nil)
	tok := e.prepare(admin, impPart{"key_hex", "", []byte(hex.EncodeToString(otherKey))}, dbFile(raw)).S("token")
	eByName(e.s.St, `UPDATE users SET password_hash='' WHERE username='admin'`)
	u, _ := e.s.userByID(1)
	r := e.apply(e.s.accessToken(u), map[string]any{"token": tok, "confirm": "IMPORT"})
	e.want(r, 403, "SSO-only admin")
	if !strings.Contains(r.S("error"), "local password") || e.s.maintenance.Load() || e.s.importApplying.Load() {
		t.Fatal("refusal must explain and leave the service running", string(r.Body))
	}
}
