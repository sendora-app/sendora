// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

// Regression: an established account whose new email is not verified yet must
// never be removed by the cleanup of pending self-registrations.
func TestEmailChangeDoesNotDeleteAccount(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	e.want(e.do("PUT", "/api/users/me", bob, map[string]any{"name": "Bob", "email": "bob-new@x.io", "current_password": "password123"}), 200, "change email")
	eByName(e.s.St, `UPDATE users SET created_at='2020-01-01 00:00:00' WHERE username='bob'`)
	e.s.maintain()
	var n int
	qByName(e.s.St, `SELECT COUNT(*) FROM users WHERE username='bob'`).Scan(&n)
	if n != 1 {
		t.Fatal("account with an unverified new email was deleted")
	}
}

func TestPasswordlessAccountsStillTimeOut(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES('pi','OIDC','oidc',1,'c','s','https://issuer.example',0,1)`)
	p, _ := e.s.providerByUUID("pi")
	u, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "sub-i", Username: "idle"})
	rec := httptest.NewRecorder()
	e.s.issueSession(rec, httptest.NewRequest("POST", "/", nil), u)
	cookie := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == "refresh" {
			cookie = c.Value
		}
	}
	e.s.St.DB.Exec(`UPDATE refresh_tokens SET issued_at=? WHERE hash=?`, time.Now().Add(-48*time.Hour), hashToken(cookie))
	e.want(refreshWith(e, cookie), 401, "idle session of a provider-only account")
}

func TestReissuedSessionsKeepTheirStart(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	_ = admin
	// An older token without a start time gives no "recent sign-in".
	r := e.login("bob", "password123")
	c := refreshCookie(r)
	e.s.St.DB.Exec(`UPDATE refresh_tokens SET session_started=NULL WHERE hash=?`, hashToken(c))
	r2 := refreshWith(e, c)
	e.want(r2, 200, "legacy refresh")
	if t0 := e.s.requestAuthTime(httptest.NewRequest("GET", "/", nil)); !t0.IsZero() {
		t.Fatal("sanity")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+r2.S("access_token"))
	if !e.s.requestAuthTime(req).IsZero() {
		t.Fatal("legacy token must not count as a recent sign-in")
	}
	// A profile change re-issues the session with the original start time.
	old := time.Now().Add(-5 * 24 * time.Hour)
	u, _ := e.s.userByID(2)
	tok := e.s.accessTokenAt(u, old)
	upd := e.do("PUT", "/api/users/me", tok, map[string]any{"name": "Bob", "email": "bob2@x.io", "current_password": "password123"})
	e.want(upd, 200, "email change")
	var started time.Time
	e.s.St.DB.QueryRow(`SELECT session_started FROM refresh_tokens WHERE hash=?`, hashToken(refreshCookie(upd))).Scan(&started)
	if started.Sub(old).Abs() > 2*time.Second {
		t.Fatalf("re-issued session restarted: %v vs %v", started, old)
	}
	_ = bob
}

func TestGuestGetsNoShareLinkAndSwitchStopsInvites(t *testing.T) {
	e := newEnv(t)
	owner := e.setup()
	g := quotaGuest(e, owner)
	r := e.do("POST", "/api/uploads", g, map[string]any{"files": []map[string]any{{"name": "a.txt", "full_path": "a.txt", "size": 3}}})
	e.want(r, 201, "guest upload")
	id := r.S("id")
	e.want(e.do("PATCH", "/api/uploads/"+id+"/files/0", g, []byte("abc"), "Upload-Offset", "0"), 200, "chunk")
	done := e.do("POST", "/api/uploads/"+id+"/complete", g, map[string]any{})
	e.want(done, 201, "complete")
	if _, leaked := done.J()["url"]; leaked {
		t.Fatalf("guest received the share link: %s", done.Body)
	}
	if _, leaked := done.J()["long_id"]; leaked {
		t.Fatalf("guest received the share id: %s", done.Body)
	}
	// Switching reverse shares off stops invitations that were already sent.
	_, itok := openInvite(e, owner, 5, 7)
	e.want(e.do("PUT", "/api/settings", owner, map[string]any{"allow_reverse_shares": false}), 200, "switch off")
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 403, "accept after switch-off")
}

func TestOpenLinkSlotsAreReleasedButLimitHolds(t *testing.T) {
	e := newEnv(t)
	owner := e.setup()
	_, itok := openInvite(e, owner, 2, 7)
	accept := func() resp { return e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}) }
	a1, a2 := accept(), accept()
	e.want(a1, 200, "first accept")
	e.want(a2, 200, "second accept")
	e.want(accept(), 410, "slots taken by fresh accepts")
	// Accepts that never start uploading release their slot after an hour.
	e.s.St.DB.Exec(`UPDATE reverse_invites SET created_at='2020-01-01 00:00:00' WHERE parent_id IS NOT NULL`)
	a3 := accept()
	e.want(a3, 200, "slot released by idle accepts")
	// But uploads still cannot exceed the limit: two guests start, the third is refused.
	start := func(tok string) resp {
		return e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "a.txt", "full_path": "a.txt", "size": 1}}})
	}
	e.want(start(a1.S("access_token")), 201, "guest 1 starts")
	e.want(start(a2.S("access_token")), 201, "guest 2 starts")
	e.want(start(a3.S("access_token")), 410, "guest 3 refused at the limit")
}

func TestUsernameInvisibleAndLookalikeCharacters(t *testing.T) {
	for _, bad := range []string{"admin‍", "ad‌min", "xㅤ", "⠀", "victim＠corp.example", "a﹫b"} {
		if validUsername(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestRateLimitKeysGroupIPv6(t *testing.T) {
	a, b := ipBanKey("2001:db8:5:6::1"), ipBanKey("2001:db8:5:6:ffff::2")
	if a != b {
		t.Fatal(fmt.Sprint(a, " != ", b))
	}
}
