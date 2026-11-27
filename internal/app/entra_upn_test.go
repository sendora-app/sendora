// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEntraUserNameBecomesUnverifiedEmail(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	_ = admin
	if _, err := e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES('p1','Entra','entra',1,'c','s','https://issuer.example',1,1)`); err != nil {
		t.Fatal(err)
	}
	p, err := e.s.providerByUUID("p1")
	if err != nil {
		t.Fatal(err)
	}
	u, msg := e.s.resolveExternalUser(p, extIdentity{Sub: "t:o1", Name: "Jan", Email: "claim@evil.example", EmailVerified: true, Username: "Jan@Contoso.Example"})
	if u == nil {
		t.Fatal(msg)
	}
	if u.Email != "jan@contoso.example" {
		t.Fatalf("UPN not stored as email: %q", u.Email)
	}
	var verified bool
	e.s.St.DB.QueryRow(`SELECT email_verified FROM users WHERE id=?`, u.ID).Scan(&verified)
	if verified {
		t.Fatal("UPN email must stay unverified")
	}

	// A user name that is not an email address leaves the email empty.
	u2, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "t:o2", Name: "Plain", Username: "plainuser"})
	if u2 == nil || u2.Email != "" {
		t.Fatalf("non-email user name must not become an email: %+v", u2)
	}
	// An address already used by another account is never taken over.
	e.mkUser(admin, "carol", false)
	u3, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "t:o3", Name: "Dup", Username: "carol@x.io"})
	if u3 == nil || u3.Email != "" {
		t.Fatalf("existing email must not be assigned: %+v", u3)
	}
	// An existing linked account without email is filled once on the next sign-in, never overwritten.
	u2b, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "t:o2", Username: "plain@contoso.example"})
	if u2b == nil || u2b.Email != "plain@contoso.example" {
		t.Fatalf("empty email not filled: %+v", u2b)
	}
	u2c, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "t:o2", Username: "changed@contoso.example"})
	if u2c == nil || u2c.Email != "plain@contoso.example" {
		t.Fatalf("email must not be overwritten: %+v", u2c)
	}
	e.s.St.DB.QueryRow(`SELECT email_verified FROM users WHERE id=?`, u2b.ID).Scan(&verified)
	if verified {
		t.Fatal("backfilled email must stay unverified")
	}
	// Unverified addresses cannot be used for a password reset.
	e.want(e.do("POST", "/api/auth/forgot-password", "", map[string]any{"email": "jan@contoso.example"}), 200, "forgot password answers the same")
	time.Sleep(300 * time.Millisecond)
	var resets int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM password_resets`).Scan(&resets)
	if resets != 0 {
		t.Fatal("password reset issued for an unverified Entra user name")
	}
}

func TestAdminUserListShowsAccountSources(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "local-only", false)
	if _, err := e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES('p9','Entra','entra',1,'c','s','https://issuer.example',1,1)`); err != nil {
		t.Fatal(err)
	}
	p, _ := e.s.providerByUUID("p9")
	if u, msg := e.s.resolveExternalUser(p, extIdentity{Sub: "t:o9", Name: "Ext", Username: "ext@contoso.example"}); u == nil {
		t.Fatal(msg)
	}
	list := e.do("GET", "/api/users", admin, nil)
	e.want(list, 200, "list users")
	var rows []struct {
		Username string   `json:"username"`
		Sources  []string `json:"sources"`
	}
	if err := json.Unmarshal(list.Body, &rows); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.Username] = strings.Join(r.Sources, ",")
	}
	if got["admin"] != "local" || got["local-only"] != "local" || got["extcontoso.example"] != "entra" {
		t.Fatalf("unexpected sources: %v", got)
	}
}
