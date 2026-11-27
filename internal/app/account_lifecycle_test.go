// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func (e *env) uid(name string) int64 {
	e.t.Helper()
	var id int64
	if err := qByName(e.s.St, `SELECT id FROM users WHERE username=?`, name).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// ---------- access review ----------

func reviewUsers(t *testing.T, r resp) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	list, _ := r.J()["users"].([]any)
	for _, x := range list {
		m := x.(map[string]any)
		out[m["username"].(string)] = m
	}
	return out
}

func TestAccessReviewReport(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	auditor := e.mkAuditor(admin, "audrey")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_reverse_shares": "true"}), 200, "reverse shares on")
	e.want(e.share(bob, map[string]string{"secret-plan.txt": "12345"}, map[string]any{"name": "Quarterly secret plan"}), 201, "bob share")
	// A guest (reverse-share invitation) never appears in the report.
	inv := e.do("POST", "/api/reverse-shares/invite", bob, map[string]any{"open": true, "max_uploads": 3, "days": 1, "name": "Drop"})
	e.want(inv, 201, "invite")
	u := inv.S("url")
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": u[strings.LastIndex(u, "/")+1:]}), 200, "accept")
	// Role and email changes by the administrator are kept on the account.
	bobID := e.uid("bob")
	e.want(e.do("PUT", fmt.Sprintf("/api/users/%d", bobID), admin, map[string]any{"name": "Bob", "email": "bob2@x.io", "auditor": false, "admin": false}), 200, "email change")
	e.want(e.do("PUT", fmt.Sprintf("/api/users/%d", e.uid("audrey")), admin, map[string]any{"name": "Audrey", "email": "audrey@x.io", "auditor": false}), 200, "role change")
	e.do("PUT", fmt.Sprintf("/api/users/%d", e.uid("audrey")), admin, map[string]any{"name": "Audrey", "email": "audrey@x.io", "auditor": true})
	auditor = e.login("audrey", "password123").S("access_token")
	// (The email change signed bob out and his new address is unverified.)
	eByName(e.s.St, `UPDATE users SET email_verified=1 WHERE username='bob'`)
	bob = e.login("bob", "password123").S("access_token")

	e.want(e.do("GET", "/api/access-review", bob, nil), 403, "ordinary user")
	e.want(e.do("GET", "/api/access-review/export", bob, nil), 403, "ordinary user export")
	for _, tok := range []string{admin, auditor} {
		r := e.do("GET", "/api/access-review", tok, nil)
		e.want(r, 200, "access review")
		if strings.Contains(string(r.Body), "Quarterly secret plan") || strings.Contains(string(r.Body), "secret-plan.txt") {
			t.Fatal("the report must not reveal share names or files")
		}
		users := reviewUsers(t, r)
		if len(users) != 3 {
			t.Fatalf("want admin, bob and audrey only (no guest): %s", r.Body)
		}
		a, b, au := users["admin"], users["bob"], users["audrey"]
		if a["role"] != "admin" || b["role"] != "user" || au["role"] != "auditor" {
			t.Fatalf("roles: %v %v %v", a["role"], b["role"], au["role"])
		}
		if a["created_by"] != "setup" || !strings.Contains(b["created_by"].(string), "(admin)") {
			t.Fatalf("created_by: %v / %v", a["created_by"], b["created_by"])
		}
		if b["source"] != "local" || b["share_count"].(float64) != 1 || b["storage_used_bytes"].(float64) != 5 {
			t.Fatalf("bob: %v", b)
		}
		if b["email_changed_at"] == "" || !strings.Contains(b["email_changed_by"].(string), "admin") || b["role_changed_at"] != "" {
			t.Fatalf("bob changes: %v", b)
		}
		if au["role_changed_at"] == "" || !strings.Contains(au["role_changed_by"].(string), "admin") {
			t.Fatalf("audrey role change: %v", au)
		}
		if b["last_login_at"] == "" || a["last_login_at"] == "" {
			t.Fatalf("last sign-in not recorded: %v %v", a, b)
		}
		for _, k := range []string{"mfa_enrolled", "mfa_factors", "mfa_policy", "mfa_required", "email_verified", "login_locked", "disabled", "disabled_at", "created_at"} {
			if _, ok := b[k]; !ok {
				t.Fatalf("column %s missing: %v", k, b)
			}
		}
	}
	// An account from before this release has no creator: "unknown".
	eByName(e.s.St, `UPDATE users SET created_by='' WHERE username='bob'`)
	if b := reviewUsers(t, e.do("GET", "/api/access-review", admin, nil))["bob"]; b["created_by"] != "unknown" {
		t.Fatalf("legacy creator: %v", b["created_by"])
	}

	// Exports: CSV and JSONL, each recorded (attempted + ok) before it is served.
	c := e.do("GET", "/api/access-review/export?format=csv", auditor, nil)
	e.want(c, 200, "csv export")
	recs, err := csv.NewReader(strings.NewReader(string(c.Body))).ReadAll()
	if err != nil || len(recs) != 4 || strings.Join(recs[0], ",") != strings.Join(accessReviewCSVHeader, ",") {
		t.Fatalf("csv: %v %q", err, c.Body)
	}
	if !strings.Contains(c.Hdr.Get("Content-Disposition"), "sendora-access-review-") {
		t.Fatal(c.Hdr)
	}
	j := e.do("GET", "/api/access-review/export?format=jsonl", admin, nil)
	e.want(j, 200, "jsonl export")
	lines := strings.Split(strings.TrimSpace(string(j.Body)), "\n")
	if len(lines) != 3 {
		t.Fatalf("jsonl lines: %d", len(lines))
	}
	var first map[string]any
	if json.Unmarshal([]byte(lines[0]), &first) != nil || first["username"] == nil {
		t.Fatal(lines[0])
	}
	e.want(e.do("GET", "/api/access-review/export?format=xml", admin, nil), 400, "unknown format")
	byOutcome := map[string]int{}
	for _, r := range auditRowsWhere(e, "action='access_review_exported'") {
		byOutcome[r.Role+"/"+r.Outcome]++
		if r.Category != catSecurity {
			t.Fatalf("category %s", r.Category)
		}
	}
	if byOutcome["auditor/attempted"] != 1 || byOutcome["auditor/ok"] != 1 || byOutcome["admin/attempted"] != 2 || byOutcome["admin/ok"] != 1 {
		t.Fatalf("export records: %v", byOutcome)
	}
	// Without a record there is no export.
	fail := func() error { return errors.New("forced audit failure") }
	e.s.audit.hook.Store(&fail)
	r := e.do("GET", "/api/access-review/export", auditor, nil)
	e.s.audit.hook.Store(nil)
	if r.Code != 503 || strings.Contains(string(r.Body), "username") {
		t.Fatalf("export served without a record: %d %s", r.Code, r.Body)
	}
}

func TestAccessReviewMFAAndLockColumns(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	e.setting("mfa_policy", "optional")
	e.enrollTOTP(bob, "password123")
	eByName(e.s.St, `UPDATE users SET login_locked_until=? WHERE username='bob'`, time.Now().Add(time.Hour).Unix())
	b := reviewUsers(t, e.do("GET", "/api/access-review", admin, nil))["bob"]
	if b["mfa_enrolled"] != true || !strings.Contains(b["mfa_factors"].(string), "totp") || !strings.Contains(b["mfa_factors"].(string), "recovery_codes:") || b["login_locked"] != true {
		t.Fatalf("bob: %v", b)
	}
}

// ---------- deactivation ----------

func TestDisableAccountBlocksEverythingAndEnableRestores(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_reverse_shares": "true"}), 200, "reverse shares on")
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "bob", "password": "password123", "email": "bob@x.io"}), 201, "create bob")
	bl := e.login("bob", "password123")
	e.want(bl, 200, "bob login")
	bob, bobCookie := bl.S("access_token"), refreshCookie(bl)
	bobID := e.uid("bob")
	sh := e.share(bob, map[string]string{"a.txt": "abc"}, nil)
	e.want(sh, 201, "share")
	link := "/api/shares/" + sh.S("long_id")
	e.want(e.do("GET", link, "", nil), 200, "link works")
	// Pending: an unfinished upload, an open invitation and a guest who accepted one.
	up := e.do("POST", "/api/uploads", bob, map[string]any{"files": []map[string]any{{"name": "u.txt", "full_path": "u.txt", "size": 3}}})
	e.want(up, 201, "pending upload")
	inv := e.do("POST", "/api/reverse-shares/invite", bob, map[string]any{"open": true, "max_uploads": 3, "days": 1, "name": "Drop"})
	e.want(inv, 201, "invite")
	invTok := inv.S("url")[strings.LastIndex(inv.S("url"), "/")+1:]
	acc := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": invTok})
	e.want(acc, 200, "guest")
	guest := acc.S("access_token")

	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/disable", e.uid("admin")), admin, nil), 400, "cannot disable yourself")
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/disable", bobID), bob, nil), 403, "not for users")
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/disable", bobID), admin, map[string]any{"reason": strings.Repeat("x", 201)}), 400, "reason too long")
	d := e.do("POST", fmt.Sprintf("/api/users/%d/disable", bobID), admin, map[string]any{"reason": "left the company"})
	e.want(d, 200, "disable")
	if d.J()["uploads_revoked"].(float64) < 1 || d.J()["invites_revoked"].(float64) < 1 {
		t.Fatalf("revocations: %s", d.Body)
	}
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/disable", bobID), admin, nil), 409, "already disabled")

	// Access token refused at once, refresh refused with the reason, sign-in refused.
	if r := e.do("GET", "/api/users/me", bob, nil); r.Code != 401 || r.S("error") != msgAccountDisabled {
		t.Fatalf("access token after disable: %d %s", r.Code, r.Body)
	}
	if r := refreshWith(e, bobCookie); r.Code != 401 {
		t.Fatalf("refresh after disable: %d %s", r.Code, r.Body)
	}
	if r := e.login("bob", "password123"); r.Code != 403 || r.S("error") != msgAccountDisabled {
		t.Fatalf("login while disabled: %d %s", r.Code, r.Body)
	}
	if r := e.login("bob", "wrong-password"); r.Code != 401 {
		t.Fatalf("a wrong password must not reveal the state: %d %s", r.Code, r.Body)
	}
	// Links answer like expired shares, nothing is deleted.
	e.want(e.do("GET", link, "", nil), 410, "link while disabled")
	e.want(e.do("GET", link+"/download", "", nil), 410, "download while disabled")
	var shares, uploads int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM shares WHERE user_id=?`, bobID).Scan(&shares)
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM upload_sessions WHERE user_id=?`, bobID).Scan(&uploads)
	if shares != 1 || uploads != 0 {
		t.Fatalf("shares=%d uploads=%d", shares, uploads)
	}
	// Invitations revoked: the guest session ends and the link cannot be accepted.
	if r := e.do("GET", "/api/users/me", guest, nil); r.Code != 403 && r.Code != 401 {
		t.Fatalf("guest after disable: %d %s", r.Code, r.Body)
	}
	if r := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": invTok}); r.Code < 400 {
		t.Fatalf("revoked invite accepted: %d %s", r.Code, r.Body)
	}
	// The administrator's list shows the state.
	list := e.do("GET", "/api/users", admin, nil)
	if !strings.Contains(string(list.Body), `"disabled":true`) || !strings.Contains(string(list.Body), "left the company") {
		t.Fatalf("user list: %s", list.Body)
	}
	if b := reviewUsers(t, e.do("GET", "/api/access-review", admin, nil))["bob"]; b["disabled"] != true || b["disabled_at"] == "" || !strings.Contains(b["disabled_by"].(string), "admin") || b["disabled_reason"] != "left the company" {
		t.Fatalf("review: %v", b)
	}
	// The administrator's own session is untouched.
	e.want(e.do("GET", "/api/users/me", admin, nil), 200, "admin still signed in")

	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/enable", bobID), admin, nil), 200, "enable")
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/enable", bobID), admin, nil), 409, "not disabled")
	e.want(e.login("bob", "password123"), 200, "login after enable")
	e.want(e.do("GET", link, "", nil), 200, "link after enable")

	acts := strings.Join(auditActions(e, "action IN ('user_disabled','user_enabled') AND outcome='ok'"), ",")
	if acts != "user_disabled,user_enabled" {
		t.Fatalf("audit: %s", acts)
	}
	if r := auditRowsWhere(e, "action='user_disabled' AND outcome='attempted'"); len(r) < 1 {
		t.Fatal("disable not recorded before it ran")
	}
	if r := auditRowsWhere(e, "action='login_failed' AND detail LIKE 'account disabled%'"); len(r) != 1 {
		t.Fatalf("disabled sign-in attempts recorded: %+v", r)
	}
	// Deleting stays a separate, explicit action.
	e.want(e.do("DELETE", fmt.Sprintf("/api/users/%d", bobID), admin, nil), 200, "delete")
}

func TestDisabledAccountRefusedAtSecondFactorAndProvider(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	e.setting("mfa_policy", "optional")
	secret, _, _ := e.enrollTOTP(bob, "password123")
	ch := e.login("bob", "password123")
	e.want(ch, 200, "first step")
	mt := ch.S("mfa_token")
	if mt == "" {
		t.Fatalf("no challenge: %s", ch.Body)
	}
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/disable", e.uid("bob")), admin, nil), 200, "disable between the steps")
	e.s.St.DB.Exec(`UPDATE user_totp SET last_counter=0`) // the enrolment burnt the current step
	if r := e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": totpCode(secret, time.Now())}); r.Code != 403 || r.S("error") != msgAccountDisabled {
		t.Fatalf("second factor of a disabled account: %d %s", r.Code, r.Body)
	}

	// A provider account: no new session and no refresh while disabled.
	e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES('pd','OIDC','oidc',1,'c','s','https://issuer.example',1,1)`)
	p, _ := e.s.providerByUUID("pd")
	u, msg := e.s.resolveExternalUser(p, extIdentity{Sub: "sub-d", Name: "Ext", Username: "ext", Email: "ext@contoso.example", EmailVerified: true})
	if u == nil {
		t.Fatal(msg)
	}
	var createdBy string
	e.s.St.DB.QueryRow(`SELECT created_by FROM users WHERE id=?`, u.ID).Scan(&createdBy)
	if createdBy != "provider OIDC" {
		t.Fatalf("created_by %q", createdBy)
	}
	u.authMethod = authMethodProvider
	rec := httptest.NewRecorder()
	if !e.s.issueSession(rec, httptest.NewRequest("POST", "/", nil), u) {
		t.Fatal("no session")
	}
	cookie := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == "refresh" {
			cookie = c.Value
		}
	}
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/disable", u.ID), admin, nil), 200, "disable provider account")
	e.want(refreshWith(e, cookie), 401, "refresh of a disabled provider account")
	u2, _ := e.s.userByID(u.ID)
	if e.s.issueSession(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), u2) {
		t.Fatal("a session was issued for a disabled account")
	}
}

func TestDisableLastActiveAdministratorRefused(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "admin2", true)
	adminID, admin2ID := e.uid("admin"), e.uid("admin2")
	if n := e.s.activeAdminsExcept(admin2ID); n != 1 {
		t.Fatalf("active admins besides admin2: %d", n)
	}
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/disable", admin2ID), admin, nil), 200, "disable the other admin")
	if n := e.s.activeAdminsExcept(adminID); n != 0 {
		t.Fatalf("a disabled admin must not count as active: %d", n)
	}
	// The caller is always an active administrator, so through the API the self
	// check answers first; the count above is the guard behind it.
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/disable", adminID), admin, nil), 400, "self")
	// A disabled administrator cannot sign in.
	if r := e.login("admin2", "password123"); r.Code != 403 {
		t.Fatalf("disabled admin signed in: %d %s", r.Code, r.Body)
	}
}

// ---------- sessions ----------

func TestSessionListRevokeAndAccessTokenInvalidation(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "bob", false)
	ua := "Mozilla/5.0 ‮" + strings.Repeat("A", 300)
	l1 := e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "password123"}, "User-Agent", ua)
	l2 := e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "password123"}, "User-Agent", "Laptop browser")
	e.want(l1, 200, "login 1")
	e.want(l2, 200, "login 2")
	t1, t2, c1 := l1.S("access_token"), l2.S("access_token"), refreshCookie(l1)
	if claimsOf(t, t1)["sid"] == nil || claimsOf(t, t1)["sid"] == claimsOf(t, t2)["sid"] || claimsOf(t, t1)["amr"] != "password" {
		t.Fatalf("session ids: %v %v", claimsOf(t, t1), claimsOf(t, t2))
	}
	list := e.do("GET", "/api/users/me/sessions", t2, nil)
	e.want(list, 200, "list")
	ss := list.J()["sessions"].([]any)
	if len(ss) != 3 { // mkUser signed in once as well
		t.Fatalf("sessions: %s", list.Body)
	}
	cur, other := ss[0].(map[string]any), ss[1].(map[string]any)
	if cur["current"] != true || other["current"] != false || cur["user_agent"] != "Laptop browser" {
		t.Fatalf("current first: %s", list.Body)
	}
	if got := other["user_agent"].(string); len([]rune(got)) != sessionUserAgentMax || strings.ContainsRune(got, '‮') {
		t.Fatalf("user agent not trimmed: %d %q", len(got), got)
	}
	if cur["ip"] != nil || cur["created_at"] == nil || cur["last_used_at"] == nil {
		t.Fatalf("ip stored although audit_log_ip is off, or times missing: %v", cur)
	}

	// Refresh keeps the session id.
	rr := refreshWith(e, c1)
	e.want(rr, 200, "refresh")
	if claimsOf(t, rr.S("access_token"))["sid"] != claimsOf(t, t1)["sid"] {
		t.Fatal("refresh changed the session id")
	}
	c1 = refreshCookie(rr)

	// Revoking session 1 from session 2 ends its access token and refresh at once.
	e.want(e.do("DELETE", "/api/users/me/sessions/"+other["id"].(string), t2, nil), 200, "revoke other")
	if r := e.do("GET", "/api/users/me", t1, nil); r.Code != 401 {
		t.Fatalf("revoked session's access token still works: %d", r.Code)
	}
	e.want(refreshWith(e, c1), 401, "revoked session's refresh")
	e.want(e.do("GET", "/api/users/me", t2, nil), 200, "own session unaffected")
	e.want(e.do("DELETE", "/api/users/me/sessions/"+other["id"].(string), t2, nil), 404, "already gone")

	// Another user's session id is not found.
	al := e.login("admin", "password123")
	e.want(e.do("DELETE", "/api/users/me/sessions/"+claimsOf(t, al.S("access_token"))["sid"].(string), t2, nil), 404, "someone else's session")
	e.want(e.do("GET", "/api/users/me", al.S("access_token"), nil), 200, "admin session untouched")

	// With IP logging on, the address is stored.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_log_ip": "true"}), 200, "ip logging on")
	l3 := e.login("bob", "password123")
	t3 := l3.S("access_token")
	withIP := e.do("GET", "/api/users/me/sessions", t3, nil).J()["sessions"].([]any)
	if withIP[0].(map[string]any)["ip"] == nil {
		t.Fatalf("ip missing with logging on: %v", withIP)
	}

	// Revoke the others: only the current session remains.
	r := e.do("POST", "/api/users/me/sessions/revoke-others", t3, nil)
	e.want(r, 200, "revoke others")
	if r.J()["revoked"].(float64) != 2 { // mkUser's session and session 2
		t.Fatalf("revoked: %s", r.Body)
	}
	e.want(e.do("GET", "/api/users/me", t2, nil), 401, "other session ended")
	e.want(e.do("GET", "/api/users/me", t3, nil), 200, "current session kept")

	// Administrator: sign out everywhere, recorded before it runs.
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/sessions/revoke", e.uid("bob")), t3, nil), 403, "not for users")
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/sessions/revoke", e.uid("bob")), admin, nil), 200, "sign out everywhere")
	e.want(e.do("GET", "/api/users/me", t3, nil), 401, "every session ended")
	if rows := auditRowsWhere(e, "action='user_signed_out'"); len(rows) != 2 || rows[0].Outcome != "attempted" || rows[1].Outcome != "ok" {
		t.Fatalf("user_signed_out records: %+v", rows)
	}
	if rows := auditRowsWhere(e, "action='session_revoked'"); len(rows) != 2 || rows[0].Category != catAuth {
		t.Fatalf("session_revoked records: %+v", rows)
	}

	// Revoking the current session is a sign-out.
	l4 := e.login("bob", "password123")
	t4 := l4.S("access_token")
	cur4 := claimsOf(t, t4)["sid"].(string)
	d := e.do("DELETE", "/api/users/me/sessions/"+cur4, t4, nil)
	e.want(d, 200, "revoke current")
	if d.J()["current"] != true {
		t.Fatal(string(d.Body))
	}
	e.want(e.do("GET", "/api/users/me", t4, nil), 401, "current session ended")
}

func TestSessionManagementForAuditorsAndProfileChanges(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	aud := e.mkAuditor(admin, "audrey")
	e.want(e.do("GET", "/api/users/me/sessions", aud, nil), 200, "auditor lists own sessions")
	e.want(e.do("POST", "/api/users/me/sessions/revoke-others", aud, nil), 200, "auditor revokes others")
	// A profile change without a new session keeps the returned token bound to the session.
	bob := e.mkUser(admin, "bob", false)
	r := e.do("PUT", "/api/users/me", bob, map[string]any{"name": "Robert", "email": "bob@x.io"})
	e.want(r, 200, "name change")
	if claimsOf(t, r.S("access_token"))["sid"] != claimsOf(t, bob)["sid"] {
		t.Fatal("profile token lost its session")
	}
	// A password change ends the other sessions and gives this one a new id.
	other := e.login("bob", "password123").S("access_token")
	p := e.do("PUT", "/api/users/me", r.S("access_token"), map[string]any{"name": "Robert", "email": "bob@x.io", "current_password": "password123", "password": "NewPassword123"})
	e.want(p, 200, "password change")
	nt := p.S("access_token")
	if claimsOf(t, nt)["sid"] == nil || claimsOf(t, nt)["sid"] == claimsOf(t, bob)["sid"] {
		t.Fatal("password change must start a new session")
	}
	e.want(e.do("GET", "/api/users/me", nt, nil), 200, "new token works")
	e.want(e.do("GET", "/api/users/me", other, nil), 401, "other session ended")
}

// ---------- identity-provider deprovisioning ----------

func TestProviderSessionMaxHours(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	if e.s.St.Setting(settingProviderSessionMaxHours) != "24" || e.s.providerSessionMaxHours() != 24 {
		t.Fatalf("default: %q", e.s.St.Setting(settingProviderSessionMaxHours))
	}
	for _, bad := range []string{"0", "721", "x", "-1"} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{settingProviderSessionMaxHours: bad}), 400, "invalid "+bad)
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{settingProviderSessionMaxHours: "2"}), 200, "valid")

	e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES('pm','OIDC','oidc',1,'c','s','https://issuer.example',1,1)`)
	p, _ := e.s.providerByUUID("pm")
	u, msg := e.s.resolveExternalUser(p, extIdentity{Sub: "sub-m", Name: "Ext", Username: "ext", Email: "ext@contoso.example", EmailVerified: true})
	if u == nil {
		t.Fatal(msg)
	}
	session := func(u *User, method string) string {
		u.authMethod = method
		rec := httptest.NewRecorder()
		if !e.s.issueSession(rec, httptest.NewRequest("POST", "/", nil), u) {
			t.Fatal("no session")
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == "refresh" {
				return c.Value
			}
		}
		return ""
	}
	age := func(cookie string, d time.Duration) {
		e.s.St.DB.Exec(`UPDATE refresh_tokens SET session_started=?,issued_at=? WHERE hash=?`, time.Now().Add(-d), time.Now().Add(-time.Minute), hashToken(cookie))
	}
	// Within the limit the provider session refreshes.
	c := session(u, authMethodProvider)
	age(c, time.Hour)
	r := refreshWith(e, c)
	e.want(r, 200, "within the limit")
	if claimsOf(t, r.S("access_token"))["amr"] != authMethodProvider {
		t.Fatal("method lost on refresh")
	}
	// After it, the user must sign in at the provider again; the reason is clear.
	c = refreshCookie(r)
	age(c, 3*time.Hour)
	r = refreshWith(e, c)
	if r.Code != 401 || r.S("error") != msgProviderSessionExpired {
		t.Fatalf("expired provider session: %d %s", r.Code, r.Body)
	}
	rows := auditRowsWhere(e, "action='session_expired_provider'")
	if len(rows) != 1 || rows[0].Category != catAuth || !strings.Contains(rows[0].Detail, "2 hours") {
		t.Fatalf("audit: %+v", rows)
	}
	// A password session of an account with a local password is not limited by it;
	// a provider sign-in of the same account is.
	e.mkUser(admin, "bob", false)
	bob, _ := e.s.userByID(e.uid("bob"))
	pc := session(bob, authMethodPassword)
	age(pc, 3*time.Hour)
	e.want(refreshWith(e, pc), 200, "password session")
	bob, _ = e.s.userByID(bob.ID)
	prc := session(bob, authMethodProvider)
	age(prc, 3*time.Hour)
	e.want(refreshWith(e, prc), 401, "provider session of a password account")
	// A corrupt stored value falls back to the default.
	e.s.St.DB.Exec(`UPDATE settings SET value='junk' WHERE key=?`, settingProviderSessionMaxHours)
	if e.s.providerSessionMaxHours() != providerSessionMaxHoursDefault {
		t.Fatal("fallback")
	}
}
