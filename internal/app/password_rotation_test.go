// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Password maximum age, expiry reminders and password history (password_rotation.go).

func (e *env) setPasswordAge(name string, age time.Duration) {
	e.t.Helper()
	if _, err := eByName(e.s.St, `UPDATE users SET password_changed_at=? WHERE username=?`, time.Now().Add(-age).UTC(), name); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) passwordChangedAt(name string) sql.NullTime {
	e.t.Helper()
	var at sql.NullTime
	if err := qByName(e.s.St, `SELECT password_changed_at FROM users WHERE username=?`, name).Scan(&at); err != nil {
		e.t.Fatal(err)
	}
	return at
}

func (e *env) mustChange(name string) bool {
	e.t.Helper()
	var v bool
	if err := qByName(e.s.St, `SELECT must_change_password FROM users WHERE username=?`, name).Scan(&v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

const day = 24 * time.Hour

func recent(at sql.NullTime) bool { return at.Valid && time.Since(at.Time) < time.Minute }

func TestPasswordRotationSettingsValidationAndStepUp(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	for _, v := range []any{-1, 366, "x", 1.5, nil, true} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"account_password_max_age_days": v}), 400, fmt.Sprintf("max age %v", v))
	}
	for _, v := range []any{-1, 25, "x", nil} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"account_password_history": v}), 400, fmt.Sprintf("history %v", v))
	}
	for _, v := range []any{0, 365, "90"} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"account_password_max_age_days": v}), 200, fmt.Sprintf("max age %v", v))
	}
	for _, v := range []any{0, 24, "5"} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"account_password_history": v}), 200, fmt.Sprintf("history %v", v))
	}
	stale := staleAdmin(t, e, "admin")
	for k, v := range map[string]any{"account_password_max_age_days": 30, "account_password_history": 3} {
		if !securitySettingKey(k) {
			t.Fatalf("%s is not a security setting", k)
		}
		r := e.do("PUT", "/api/settings", stale, map[string]any{k: v})
		if r.Code != 401 || r.S("code") != stepUpCode {
			t.Fatalf("%s without step-up: %d %s", k, r.Code, r.Body)
		}
	}
}

func TestPasswordChangedAtSetOnEveryPath(t *testing.T) {
	e := newEnv(t)
	sink := newSMTP(t)
	e.useSMTP(sink)
	admin := e.setup()
	if !recent(e.passwordChangedAt("admin")) {
		t.Fatal("setup")
	}
	bob := e.mkUser(admin, "bob", false)
	if !recent(e.passwordChangedAt("bob")) {
		t.Fatal("administrator-created user")
	}
	// Own profile.
	e.setPasswordAge("bob", 100*day)
	r := e.do("PUT", "/api/users/me", bob, map[string]any{"name": "", "email": "bob@x.io", "password": "secondpass1", "current_password": "password123"})
	e.want(r, 200, "own change")
	if !recent(e.passwordChangedAt("bob")) || r.J()["user"].(map[string]any)["password_changed_at"] == nil {
		t.Fatal("own profile change")
	}
	// Reset link.
	bid, _ := e.userRow("bob")
	e.setPasswordAge("bob", 100*day)
	e.s.St.DB.Exec(`INSERT INTO password_resets(hash,user_id,expires_at) VALUES(?,?,?)`, hashToken("resettok"), bid, time.Now().Add(time.Hour))
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": "resettok", "password": "thirdpass12"}), 200, "reset")
	if !recent(e.passwordChangedAt("bob")) {
		t.Fatal("reset link")
	}
	if n := countAudit(t, e, "password_reset"); n != 1 {
		t.Fatalf("password_reset records: %d", n)
	}
	// Administrator changing their own password.
	e.setPasswordAge("admin", 100*day)
	e.want(e.do("PUT", "/api/users/1", admin, map[string]any{"password": "adminpass99"}), 200, "admin own change")
	if !recent(e.passwordChangedAt("admin")) {
		t.Fatal("administrator's own change")
	}
	// Self-registration.
	e.s.St.SetSetting("allow_self_registration", "true")
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "carol", "password": "carolpass1", "email": "carol@x.io"}), 201, "register")
	if !recent(e.passwordChangedAt("carol")) {
		t.Fatal("registration")
	}
	// Every password-setting path is audited.
	if countAudit(t, e, "password_changed") != 2 || len(auditRowsWhere(e, `action='user_created' AND target LIKE '%bob%'`)) != 1 {
		t.Fatalf("audit: changed=%d created=%d", countAudit(t, e, "password_changed"), countAudit(t, e, "user_created"))
	}
}

func TestPasswordExpiryForcesChangeAtLogin(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "bob", false)
	e.setPasswordAge("bob", 400*day)

	// Policy 0 never forces.
	r := e.login("bob", "password123")
	e.want(r, 200, "login, policy off")
	if r.J()["user"].(map[string]any)["must_change_password"] != false || e.mustChange("bob") {
		t.Fatal("policy 0 forced a change")
	}

	e.s.St.SetSetting("account_password_max_age_days", "365")
	r = e.login("bob", "password123")
	e.want(r, 200, "login, expired")
	if r.J()["user"].(map[string]any)["must_change_password"] != true || !e.mustChange("bob") {
		t.Fatal("expired password not flagged at sign-in")
	}
	tok := r.S("access_token")
	e.want(e.do("GET", "/api/shares", tok, nil), 403, "only the password change is allowed")
	e.want(e.login("bob", "password123"), 200, "second login")
	rows := auditRowsWhere(e, `action='password_expired'`)
	if len(rows) != 1 || rows[0].Category != catAuth || rows[0].ActorNm != "bob" || rows[0].Detail != "max age 365 days" {
		t.Fatalf("password_expired records: %+v", rows)
	}
	// The forced change works without the current password, clears the flag and restarts the clock.
	r = e.do("PUT", "/api/users/me", tok, map[string]any{"name": "", "email": "bob@x.io", "password": "freshpass12"})
	e.want(r, 200, "forced change")
	if e.mustChange("bob") || !recent(e.passwordChangedAt("bob")) {
		t.Fatal("forced change did not clear the flag")
	}
	e.want(e.do("GET", "/api/shares", r.S("access_token"), nil), 200, "after the change")
}

func TestPasswordExpiryCaughtInExistingSession(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	e.s.St.SetSetting("account_password_max_age_days", "30")
	e.want(e.do("GET", "/api/shares", bob, nil), 200, "valid password")
	e.setPasswordAge("bob", 31*day)
	r := e.do("GET", "/api/shares", bob, nil)
	if r.Code != 401 || r.S("error") != msgPasswordExpired {
		t.Fatalf("expired password in a running session: %d %s", r.Code, r.Body)
	}
	bid, _ := e.userRow("bob")
	if !e.mustChange("bob") || e.countRows(`SELECT COUNT(*) FROM refresh_tokens WHERE user_id=?`, bid) != 0 {
		t.Fatal("sessions not ended")
	}
	e.want(e.do("GET", "/api/shares", bob, nil), 401, "old token")
	if n := countAudit(t, e, "password_expired"); n != 1 {
		t.Fatalf("password_expired records: %d", n)
	}
	r = e.login("bob", "password123")
	e.want(r, 200, "sign in again")
	if r.J()["user"].(map[string]any)["must_change_password"] != true {
		t.Fatal("not forced after signing in again")
	}
	if n := countAudit(t, e, "password_expired"); n != 1 {
		t.Fatalf("password_expired recorded again: %d", n)
	}
}

func TestPasswordExpiryExemptProviderAndGuestAccounts(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "bob", false)
	bid, _ := e.userRow("bob")
	e.s.St.SetSetting("account_password_max_age_days", "30")
	e.setPasswordAge("bob", 60*day)

	e.want(e.do("PUT", e.usersPath(bid, ""), admin, map[string]any{"password_rotation_exempt": true}), 200, "exempt")
	rows := auditRowsWhere(e, `action='password_rotation_exempt_changed'`)
	if len(rows) != 1 || rows[0].Detail != "exempt=true" || rows[0].ActorNm != "admin" || !strings.Contains(rows[0].Target, "bob") {
		t.Fatalf("exempt audit: %+v", rows)
	}
	e.want(e.do("PUT", e.usersPath(bid, ""), admin, map[string]any{"name": "Bob"}), 200, "unrelated edit")
	if n := countAudit(t, e, "password_rotation_exempt_changed"); n != 1 {
		t.Fatalf("exemption recorded without a change: %d", n)
	}
	r := e.login("bob", "password123")
	e.want(r, 200, "exempt login")
	if r.J()["user"].(map[string]any)["must_change_password"] != false || r.J()["user"].(map[string]any)["password_rotation_exempt"] != true {
		t.Fatal("exempt account forced")
	}
	me := e.do("GET", "/api/users/me", r.S("access_token"), nil).J()
	if _, ok := me["password_expires_at"]; ok {
		t.Fatal("expiry shown for an exempt account")
	}

	// Provider-only accounts (no local password) and guests are never affected.
	old := sql.NullTime{Time: time.Now().Add(-90 * day), Valid: true}
	for _, u := range []*User{{ID: bid, Username: "bob", passwordChangedAt: old}, {ID: bid, Username: "bob", IsGuest: true, passwordHash: "x", passwordChangedAt: old}} {
		if _, ok := e.s.passwordExpiry(u); ok || e.s.flagExpiredPassword(u) {
			t.Fatalf("policy applied to %+v", u)
		}
	}
	e.want(e.do("PUT", e.usersPath(bid, ""), admin, map[string]any{"password_rotation_exempt": false}), 200, "not exempt")
	if e.login("bob", "password123").J()["user"].(map[string]any)["must_change_password"] != true {
		t.Fatal("not forced after the exemption ended")
	}
}

func TestPasswordExpiryWarningFields(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	me := e.do("GET", "/api/users/me", bob, nil).J()
	if _, ok := me["password_expires_at"]; ok {
		t.Fatal("fields present with the policy off")
	}
	e.s.St.SetSetting("account_password_max_age_days", "365")
	e.setPasswordAge("bob", 360*day)
	me = e.do("GET", "/api/users/me", bob, nil).J()
	at, err := time.Parse(time.RFC3339, fmt.Sprint(me["password_expires_at"]))
	if err != nil || me["password_expires_in_days"] != float64(5) || at.Sub(time.Now()) > 5*day || at.Sub(time.Now()) < 4*day {
		t.Fatalf("warning fields: %v %v", me["password_expires_at"], me["password_expires_in_days"])
	}
	if me["user"].(map[string]any)["password_changed_at"] == nil {
		t.Fatal("password_changed_at missing")
	}
}

func TestPasswordExpiryMailSentOnce(t *testing.T) {
	e := newEnv(t)
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.BaseURL = "https://files.example.com"
	admin := e.setup()
	e.mkUser(admin, "bob", false)
	e.mkUser(admin, "carl", false)
	e.s.St.SetSetting("account_password_max_age_days", "365")
	e.setPasswordAge("bob", 360*day)  // 5 days left: reminder
	e.setPasswordAge("carl", 350*day) // 15 days left: not yet
	e.s.maintain()
	m := sink.wait(t, "https://files.example.com/profile")
	if !strings.Contains(m, "bob@x.io") || !strings.Contains(m, "expires in 5 days") {
		t.Fatalf("reminder: %s", m)
	}
	e.s.maintain()
	time.Sleep(300 * time.Millisecond)
	sink.mu.Lock()
	n := 0
	for _, msg := range sink.msgs {
		if strings.Contains(msg, "/profile") {
			n++
		}
	}
	sink.mu.Unlock()
	rows := auditRowsWhere(e, `action='password_expiry_warning_sent'`)
	if n != 1 || len(rows) != 1 || rows[0].Category != catAuth || rows[0].Role != "system" || !strings.Contains(rows[0].Target, "bob") {
		t.Fatalf("reminders: %d mails, records %+v", n, rows)
	}
	// A new password starts a new period: its reminder is due again later.
	var warned sql.NullTime
	qByName(e.s.St, `SELECT password_expiry_warned_at FROM users WHERE username='bob'`).Scan(&warned)
	if !warned.Valid {
		t.Fatal("warned_at not recorded")
	}
	tok := e.login("bob", "password123").S("access_token")
	e.want(e.do("PUT", "/api/users/me", tok, map[string]any{"name": "", "email": "bob@x.io", "password": "newpass123", "current_password": "password123"}), 200, "change")
	qByName(e.s.St, `SELECT password_expiry_warned_at FROM users WHERE username='bob'`).Scan(&warned)
	if warned.Valid {
		t.Fatal("warned_at not cleared by the password change")
	}
}

func TestPasswordHistoryRefusesReuse(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	bid, _ := e.userRow("bob")
	e.s.St.SetSetting("account_password_history", "2")
	cur := "password123"
	change := func(next string, code int) {
		t.Helper()
		r := e.do("PUT", "/api/users/me", bob, map[string]any{"name": "", "email": "bob@x.io", "password": next, "current_password": cur})
		if r.Code != code {
			t.Fatalf("change %s -> %s: want %d got %d %s", cur, next, code, r.Code, r.Body)
		}
		if code == 200 {
			bob, cur = r.S("access_token"), next
		} else if r.S("error") != msgPasswordReused {
			t.Fatalf("message: %s", r.Body)
		}
	}
	change("password123", 400) // the current password
	change("secondpass1", 200)
	change("password123", 400) // the previous one
	change("thirdpass12", 200)
	change("fourthpass1", 200)
	if n := e.countRows(`SELECT COUNT(*) FROM password_history WHERE user_id=?`, bid); n != 2 {
		t.Fatalf("history not pruned to 2: %d", n)
	}
	change("secondpass1", 400)
	change("password123", 200) // older than the last two: allowed again

	// The reset link and an administrator's own change refuse reuse too.
	e.s.St.DB.Exec(`INSERT INTO password_resets(hash,user_id,expires_at) VALUES(?,?,?)`, hashToken("tok1"), bid, time.Now().Add(time.Hour))
	r := e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": "tok1", "password": "fourthpass1"})
	if r.Code != 400 || r.S("error") != msgPasswordReused {
		t.Fatalf("reset reuse: %d %s", r.Code, r.Body)
	}
	if e.countRows(`SELECT COUNT(*) FROM password_resets WHERE user_id=?`, bid) != 1 {
		t.Fatal("refused reset consumed the link")
	}
	r = e.do("PUT", "/api/users/1", admin, map[string]any{"password": "password123"})
	if r.Code != 400 || r.S("error") != msgPasswordReused {
		t.Fatalf("admin own reuse: %d %s", r.Code, r.Body)
	}
	// 0 switches the check off and empties the history at the next change.
	e.s.St.SetSetting("account_password_history", "0")
	change("password123", 200)
	if n := e.countRows(`SELECT COUNT(*) FROM password_history WHERE user_id=?`, bid); n != 0 {
		t.Fatalf("history kept with 0: %d", n)
	}
}

func TestPasswordHistoryRemovedOnErasureAndDeletion(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.s.St.SetSetting("account_password_history", "5")
	for _, name := range []string{"bob", "carl"} {
		tok := e.mkUser(admin, name, false)
		e.want(e.do("PUT", "/api/users/me", tok, map[string]any{"name": "", "email": name + "@x.io", "password": "otherpass12", "current_password": "password123"}), 200, "change")
	}
	bid, _ := e.userRow("bob")
	cid, _ := e.userRow("carl")
	if e.countRows(`SELECT COUNT(*) FROM password_history WHERE user_id IN (?,?)`, bid, cid) != 2 {
		t.Fatal("history not recorded")
	}
	e.want(e.do("POST", e.usersPath(bid, "/erase"), admin, nil), 200, "erase")
	if e.countRows(`SELECT COUNT(*) FROM password_history WHERE user_id=?`, bid) != 0 {
		t.Fatal("erasure kept the password history")
	}
	var changed sql.NullTime
	e.s.St.DB.QueryRow(`SELECT password_changed_at FROM users WHERE id=?`, bid).Scan(&changed)
	if changed.Valid {
		t.Fatal("erasure kept password_changed_at")
	}
	e.want(e.do("DELETE", e.usersPath(cid, ""), admin, nil), 200, "delete")
	if e.countRows(`SELECT COUNT(*) FROM password_history WHERE user_id=?`, cid) != 0 {
		t.Fatal("deletion kept the password history")
	}
}

func TestAccessReviewPasswordColumns(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "bob", false)
	bid, _ := e.userRow("bob")
	e.s.St.SetSetting("account_password_max_age_days", "365")
	e.setPasswordAge("bob", 10*day)
	e.want(e.do("PUT", e.usersPath(bid, ""), admin, map[string]any{"password_rotation_exempt": true}), 200, "exempt")
	r := e.do("GET", "/api/access-review", admin, nil)
	e.want(r, 200, "review")
	var bob, adm map[string]any
	for _, u := range r.J()["users"].([]any) {
		m := u.(map[string]any)
		switch m["username"] {
		case "bob":
			bob = m
		case "admin":
			adm = m
		}
	}
	if bob["password_age_days"] != "10" || bob["password_rotation_exempt"] != true || bob["password_expires_at"] != "" {
		t.Fatalf("bob: %v", bob)
	}
	if adm["password_age_days"] != "0" || adm["password_rotation_exempt"] != false || adm["password_expires_at"] == "" {
		t.Fatalf("admin: %v", adm)
	}
	r = e.do("GET", "/api/access-review/export?format=csv", admin, nil)
	e.want(r, 200, "export")
	recs, err := csv.NewReader(strings.NewReader(string(r.Body))).ReadAll()
	if err != nil || strings.Join(recs[0][len(recs[0])-3:], ",") != "password_age_days,password_rotation_exempt,password_expires_at" {
		t.Fatalf("csv header: %v %v", recs, err)
	}
}
