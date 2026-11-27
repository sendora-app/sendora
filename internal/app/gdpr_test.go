// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestPersonalDataExport(t *testing.T) {
	e := newEnv(t)
	e.s.St.SetSetting("mfa_policy", "optional")
	admin := e.setup()
	tok := e.mkUser(admin, "quinn", false)
	sh := e.share(tok, map[string]string{"report.txt": "secret contents"}, map[string]any{"name": "Quarterly"})
	e.want(sh, 201, "share")
	_, tok, _ = e.enrollTOTP(tok, "password123")
	r := e.do("GET", "/api/users/me/export", tok, nil)
	e.want(r, 200, "export")
	body := string(r.Body)
	for _, want := range []string{`"username":"quinn"`, `"Quarterly"`, `"report.txt"`, `"authenticator_app":{"created_at"`, `"audit_records"`, `"sessions"`, `"invites"`, `"download_history"`} {
		if !strings.Contains(body, want) {
			t.Errorf("export lacks %s", want)
		}
	}
	var secret string
	qByName(e.s.St, `SELECT secret FROM user_totp WHERE user_id=(SELECT id FROM users WHERE username='quinn')`).Scan(&secret)
	for _, never := range []string{"secret contents", "password_hash\"", "$2a$", secret, "long_id"} {
		if never != "" && strings.Contains(body, never) {
			t.Errorf("export contains %q", never)
		}
	}
	if !strings.Contains(r.Hdr.Get("Content-Disposition"), "attachment") {
		t.Error("not offered as a download")
	}
	if countAudit(t, e, "personal_data_exported") < 1 {
		t.Fatal("export not recorded")
	}
	// Other users' records are not included.
	if strings.Contains(body, `"user_created"`) {
		t.Error("an administrator's record leaked into the export")
	}
}

func TestSelfServiceErasure(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	tok := e.mkUser(admin, "rosa", false)
	sh := e.share(tok, map[string]string{"a.txt": "aaa"}, map[string]any{"name": "Mine"})
	e.want(sh, 201, "share")
	dir := shareDirOf(t, e, sh.S("long_id"))
	e.want(e.do("POST", "/api/reverse-shares/invite", tok, map[string]any{"open": true, "max_uploads": 2, "days": 1, "name": "Drop"}), 201, "invite")
	e.want(e.do("POST", "/api/users/me/erase", tok, map[string]any{"password": "wrong"}), 400, "wrong password")
	e.want(e.do("POST", "/api/users/me/erase", tok, map[string]any{"password": "password123"}), 200, "erase")
	var id int64
	var username, name, email, hash string
	var erased bool
	if err := e.s.St.DB.QueryRow(`SELECT id,username,name,email,password_hash,erased_at IS NOT NULL FROM users WHERE username LIKE 'erased-%'`).Scan(&id, &username, &name, &email, &hash, &erased); err != nil {
		t.Fatal(err)
	}
	if username != fmt.Sprintf("erased-%d", id) || name != "" || email != "" || hash != "" || !erased {
		t.Fatalf("not pseudonymised: %s %q %q %q %v", username, name, email, hash, erased)
	}
	for _, table := range []string{"shares", "reverse_invites", "refresh_tokens", "user_totp", "user_signin_seen"} {
		var n int
		e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE user_id=?`, id).Scan(&n)
		if n != 0 {
			t.Errorf("%s still has %d rows", table, n)
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("share files still on disk: %v", err)
	}
	e.want(e.do("GET", "/api/users/me", tok, nil), 401, "old session ends")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "rosa", "password": "password123"}), 401, "cannot sign in")
	// The audit record keeps the former name (legitimate interest, see gdpr.go).
	var actor string
	e.s.St.DB.QueryRow(`SELECT actor_name FROM audit_log WHERE action='user_erased'`).Scan(&actor)
	if actor != "rosa" {
		t.Fatalf("user_erased actor %q", actor)
	}
	// The last administrator cannot erase itself.
	r := e.do("POST", "/api/users/me/erase", admin, map[string]any{"password": "password123"})
	if r.Code != 409 || r.S("error") != msgEraseLastAdmin {
		t.Fatalf("last admin: %d %s", r.Code, r.Body)
	}
}

func shareDirOf(t *testing.T, e *env, longID string) string {
	t.Helper()
	for _, d := range []string{e.s.St.DataDir + "/shares/" + longID} {
		if _, err := os.Stat(d); err == nil {
			return d
		}
	}
	t.Fatalf("share directory of %s not found", longID)
	return ""
}

func TestAdminErasure(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "sam", false)
	var id int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='sam'`).Scan(&id)
	e.want(e.do("POST", "/api/users/1/erase", admin, nil), 400, "not yourself")
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/erase", id), admin, nil), 200, "erase")
	e.want(e.do("POST", fmt.Sprintf("/api/users/%d/erase", id), admin, nil), 409, "already erased")
	e.want(e.do("PUT", fmt.Sprintf("/api/users/%d", id), admin, map[string]any{"email": "sam@x.io"}), 409, "an erased account cannot be revived")
	var outcome string
	e.s.St.DB.QueryRow(`SELECT outcome FROM audit_log WHERE action='user_erased' ORDER BY seq LIMIT 1`).Scan(&outcome)
	if outcome != "attempted" {
		t.Fatalf("critical attempt record missing: %q", outcome)
	}
	var target string
	e.s.St.DB.QueryRow(`SELECT target FROM audit_log WHERE action='user_erased' AND outcome='ok'`).Scan(&target)
	if !strings.Contains(target, "(sam)") {
		t.Fatalf("target %q", target)
	}
}
