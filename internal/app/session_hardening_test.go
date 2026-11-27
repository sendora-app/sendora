// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func refreshWith(e *env, cookie string) resp {
	return e.do("POST", "/api/auth/refresh", "", map[string]any{}, "Cookie", "refresh="+cookie)
}

func TestSessionAbsoluteLifetimeAndReuseDetection(t *testing.T) {
	e := newEnv(t)
	e.setup()
	r := e.login("admin", "password123")
	e.want(r, 200, "login")
	first := refreshCookie(r)

	// Rotation keeps the original sign-in time.
	r2 := refreshWith(e, first)
	e.want(r2, 200, "refresh")
	second := refreshCookie(r2)
	var started, issued time.Time
	e.s.St.DB.QueryRow(`SELECT session_started,issued_at FROM refresh_tokens WHERE hash=?`, hashToken(second)).Scan(&started, &issued)
	if started.IsZero() || started.After(issued) {
		t.Fatalf("rotated token lost its sign-in time: started=%v issued=%v", started, issued)
	}

	// Reuse right after rotation (two tabs, a lost response) is only refused.
	e.want(refreshWith(e, first), 401, "spent token refused within the grace period")
	r2b := refreshWith(e, second)
	e.want(r2b, 200, "the session itself survives a quick reuse")
	third0 := refreshCookie(r2b)
	// Reuse after the grace period means a copy: the whole family is revoked.
	e.s.St.DB.Exec(`UPDATE refresh_spent SET spent_at=?`, time.Now().Add(-2*refreshReuseGrace))
	e.want(refreshWith(e, second), 401, "late reuse refused")
	e.want(refreshWith(e, third0), 401, "family revoked after late reuse")

	// A session older than the absolute limit cannot be refreshed.
	r3 := e.login("admin", "password123")
	third := refreshCookie(r3)
	e.s.St.DB.Exec(`UPDATE refresh_tokens SET session_started=? WHERE hash=?`, time.Now().Add(-sessionMaxAge-time.Hour), hashToken(third))
	e.want(refreshWith(e, third), 401, "session beyond absolute lifetime")
}

func TestProviderOnlySessionsEndWithTheProvider(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES('ps','OIDC','oidc',1,'c','s','https://issuer.example',1,1)`)
	p, _ := e.s.providerByUUID("ps")
	u, msg := e.s.resolveExternalUser(p, extIdentity{Sub: "sub-1", Name: "Ext", Username: "ext", Email: "ext@contoso.example", EmailVerified: true})
	if u == nil {
		t.Fatal(msg)
	}
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
	r := refreshWith(e, cookie)
	e.want(r, 200, "refresh while provider enabled")
	cookie = refreshCookie(r)
	e.s.St.DB.Exec(`UPDATE auth_providers SET enabled=0 WHERE uuid='ps'`)
	e.want(refreshWith(e, cookie), 401, "refresh after provider disabled")

	// A trusted provider email must not let the account set a local password by mail.
	e.do("POST", "/api/auth/forgot-password", "", map[string]any{"email": "ext@contoso.example"})
	time.Sleep(200 * time.Millisecond)
	var resets int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM password_resets WHERE user_id=?`, u.ID).Scan(&resets)
	if resets != 0 {
		t.Fatal("password reset issued for an account without a local password")
	}
}

func TestPasswordlessAccountNeedsRecentSignIn(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES('pr','OIDC','oidc',1,'c','s','https://issuer.example',0,1)`)
	p, _ := e.s.providerByUUID("pr")
	u, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "sub-2", Name: "Ext", Username: "ext2"})
	old := e.s.accessTokenAt(u, time.Now().Add(-time.Hour))
	r := e.do("PUT", "/api/users/me", old, map[string]any{"name": "Ext", "email": "", "password": "Brand-New-Passw0rd"})
	e.want(r, 403, "stale sign-in cannot add a password")
	if !strings.Contains(string(r.Body), "sign in again") {
		t.Fatal(string(r.Body))
	}
	r = e.do("PUT", "/api/users/me", old, map[string]any{"name": "Ext", "email": "attacker@evil.example"})
	e.want(r, 403, "stale sign-in cannot change the email")
	fresh := e.s.accessTokenAt(u, time.Now())
	e.want(e.do("PUT", "/api/users/me", fresh, map[string]any{"name": "Ext", "email": "", "password": "Brand-New-Passw0rd"}), 200, "fresh sign-in may add a password")
}

func TestRegistrationDoesNotRevealEmails(t *testing.T) {
	e, _ := regEnv(t)
	e.want(e.do("POST", "/api/auth/register", "", regBody("first", "taken@x.io")), 201, "first")
	r := e.do("POST", "/api/auth/register", "", regBody("second", "taken@x.io"))
	e.want(r, 201, "taken email answers like success")
	r = e.do("POST", "/api/auth/register", "", regBody("FIRST", "other@x.io"))
	e.want(r, 400, "taken username is reported")
	var n int
	qByName(e.s.St, `SELECT COUNT(*) FROM users WHERE username='second'`).Scan(&n)
	if n != 0 {
		t.Fatal("duplicate email created an account")
	}
}
