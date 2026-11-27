// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"net/mail"
	"strings"
	"testing"
	"time"
)

// Regression: the 48-hour cleanup of unverified self-registrations must never
// delete accounts linked to a sign-in provider (their email is unverified on purpose).
func TestCleanupKeepsProviderAccounts(t *testing.T) {
	e := newEnv(t)
	e.setup()
	if _, err := e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES('pc','Entra','entra',1,'c','s','https://issuer.example',1,1)`); err != nil {
		t.Fatal(err)
	}
	p, _ := e.s.providerByUUID("pc")
	ext, msg := e.s.resolveExternalUser(p, extIdentity{Sub: "t:oc", Name: "Ext", Username: "ext@contoso.example"})
	if ext == nil {
		t.Fatal(msg)
	}
	old := time.Now().UTC().Add(-72 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := rawExec(e.t, e.s.St, `INSERT INTO users(username,email,password_hash,email_verified,created_at,pending_registration) VALUES('pending','p@x.io','hash',0,?,1)`, old); err != nil {
		t.Fatal(err)
	}
	e.s.St.DB.Exec(`UPDATE users SET created_at=? WHERE id=?`, old, ext.ID)
	e.s.maintain()
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE id=?`, ext.ID).Scan(&n)
	if n != 1 {
		t.Fatal("provider-linked account with unverified email was deleted")
	}
	qByName(e.s.St, `SELECT COUNT(*) FROM users WHERE username='pending'`).Scan(&n)
	if n != 0 {
		t.Fatal("stale unverified self-registration was kept")
	}
}

func TestEntraGuestUPNIsNotStoredAsEmail(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES('pg','Entra','entra',1,'c','s','https://issuer.example',1,1)`)
	p, _ := e.s.providerByUUID("pg")
	u, msg := e.s.resolveExternalUser(p, extIdentity{Sub: "t:og", Username: "jan_gmail.com#EXT#@tenant.onmicrosoft.com"})
	if u == nil {
		t.Fatal(msg)
	}
	if u.Email != "" {
		t.Fatalf("guest UPN stored as email: %q", u.Email)
	}
}

func TestIPBanPruneAndFairEviction(t *testing.T) {
	e := newEnv(t)
	t.Setenv("SENDORA_DISABLE_IP_BANS", "")
	s := e.s
	now := time.Now()
	s.ipBans.mu.Lock()
	s.ipBans.bans["192.0.2.1"] = ipBan{until: now.Add(-time.Hour), strikes: 1, lastStrike: now.Add(-48 * time.Hour)}
	s.ipBans.bans["192.0.2.2"] = ipBan{until: now.Add(time.Hour), strikes: 1, lastStrike: now}
	s.ipBans.mu.Unlock()
	s.St.DB.Exec(`INSERT INTO ip_bans(ip,banned_until,strikes,last_strike) VALUES('192.0.2.1',?,1,?)`, now.Add(-time.Hour).Unix(), now.Add(-48*time.Hour).Unix())
	s.pruneIPBans()
	if _, ok := s.ipBans.bans["192.0.2.1"]; ok {
		t.Fatal("expired ban kept in memory")
	}
	if _, ok := s.ipBans.bans["192.0.2.2"]; !ok {
		t.Fatal("active ban pruned")
	}
	var n int
	s.St.DB.QueryRow(`SELECT COUNT(*) FROM ip_bans WHERE ip='192.0.2.1'`).Scan(&n)
	if n != 0 {
		t.Fatal("expired ban kept in database")
	}

	// An address one failure below the threshold survives a flood of new addresses.
	victim := "198.51.100.7"
	for i := 0; i < ipBanThreshold-1; i++ {
		s.noteIPFailure(victim)
	}
	for i := 0; i < ipBanMaxKeys+10; i++ {
		s.noteIPFailure(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256))
	}
	s.noteIPFailure(victim)
	if _, banned := s.ipBlocked(victim); !banned {
		t.Fatal("flooding other addresses reset the victim's failure counter")
	}
}

func TestIPBanSkipsI18nAndSignedInRequests(t *testing.T) {
	e := newEnv(t)
	t.Setenv("SENDORA_DISABLE_IP_BANS", "")
	e.setup()
	for i := 0; i < ipBanThreshold; i++ {
		e.do("POST", "/api/users/me/mfa/totp/begin", "expired-or-bogus-token", map[string]any{"password": "x"})
	}
	if len(e.s.activeIPBans()) != 0 {
		t.Fatal("401s on signed-in settings routes must not count as sign-in failures")
	}
	failLogins(e, ipBanThreshold, "x")
	if len(e.s.activeIPBans()) != 1 {
		t.Fatal("expected a ban after failed logins")
	}
	if r := e.do("GET", "/api/i18n/languages", "", nil); r.Code == 429 {
		t.Fatal("translations must stay available to a banned address")
	}
}

func TestReplyToStoredReadably(t *testing.T) {
	for in, want := range map[string]string{
		"Ünïcode Team <support@example.test>": `"Ünïcode Team" <support@example.test>`,
		`"Say \"hi\"" <a@example.test>`:       `"Say \"hi\"" <a@example.test>`,
		"<a@example.test>":                    "a@example.test",
	} {
		v := in
		if _, err := validateReplyToSetting("smtp_reply_to", &v); err != nil {
			t.Fatal(in, err)
		}
		if v != want {
			t.Fatalf("%q stored as %q, want %q", in, v, want)
		}
		a, err := mail.ParseAddress(v)
		if err != nil {
			t.Fatalf("stored value must parse: %v", err)
		}
		hdr := mailMessageReplyTo(&mail.Address{Address: "f@example.test"}, &mail.Address{Address: "t@example.test"}, a, "s", "b")
		if _, err := mail.ReadMessage(strings.NewReader(hdr)); err != nil {
			t.Fatal("message with Reply-To must parse:", err)
		}
	}
}
