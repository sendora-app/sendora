// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"strings"
	"testing"
)

func TestNormalizeRegistrationDomains(t *testing.T) {
	long := strings.Repeat("a", 63)
	ok := map[string]string{
		"":                                  "",
		"  \n ,, ":                          "",
		"Example.COM":                       "example.com",
		"a.com,b.com c.com\r\nd.com\ne.com": "a.com\nb.com\nc.com\nd.com\ne.com",
		"a.com A.COM a.com":                 "a.com",
		"xn--bcher-kva.example":             "xn--bcher-kva.example",
		"sub.a-b.co.uk":                     "sub.a-b.co.uk",
		long + ".com":                       long + ".com",
	}
	for in, want := range ok {
		got, err := normalizeRegistrationDomains(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q err %v want %q", in, got, err, want)
		}
	}
	bad := []string{
		"localhost", "a@b.com", "@b.com", "*.example.com", "*", "https://example.com", "example.com/path",
		"example.com:8080", "-a.com", "a-.com", "a..com", ".com", "a.com.", "exa_mple.com", "bücher.example",
		long + "a.com", strings.Repeat(strings.Repeat("a", 60)+".", 5) + "com", "a.com b@c.com", "a b.com, x",
	}
	for _, in := range bad {
		if got, err := normalizeRegistrationDomains(in); err == nil {
			// "a b.com" splits into valid-looking? "a" has no dot -> must fail anyway.
			t.Errorf("%q accepted as %q", in, got)
		}
	}
	var many []string
	for i := 0; i < 50; i++ {
		many = append(many, "d"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26))+".com")
	}
	if _, err := normalizeRegistrationDomains(strings.Join(many, ",")); err != nil {
		t.Fatalf("50 domains: %v", err)
	}
	if _, err := normalizeRegistrationDomains(strings.Join(many, ",") + ",extra.com"); err == nil {
		t.Fatal("51 domains accepted")
	}
	// Duplicates do not count towards the limit.
	if _, err := normalizeRegistrationDomains(strings.Join(many, ",") + ",EXTRA.com,extra.com"); err == nil {
		t.Fatal("51 unique accepted")
	}
	if _, err := normalizeRegistrationDomains(strings.Join(many, ",") + "," + many[0]); err != nil {
		t.Fatalf("duplicate counted: %v", err)
	}
}

func TestDomainAllowed(t *testing.T) {
	list := "example.com\nfoo.org"
	cases := []struct {
		list, email string
		want        bool
	}{
		{"", "a@anything.io", true},
		{list, "a@example.com", true},
		{list, "a@EXAMPLE.com", true},
		{list, "a@foo.org", true},
		{list, "a@sub.example.com", false},
		{list, "a@notexample.com", false},
		{list, "a@example.com.evil.io", false},
		{list, "a@evil.io", false},
		{list, "noat", false},
		{list, "x@evil.io@example.com", true}, // last '@' decides; canonicalEmail rejects such input earlier
	}
	for _, c := range cases {
		if got := domainAllowed(c.list, c.email); got != c.want {
			t.Errorf("%q %q: got %v", c.list, c.email, got)
		}
	}
}

func regEnv(t *testing.T) (*env, string) {
	e := newEnv(t)
	e.useSMTP(newSMTP(t))
	tok := e.setup()
	e.s.St.SetSetting("allow_self_registration", "true")
	return e, tok
}

func regBody(user, email string) map[string]any {
	return map[string]any{"username": user, "email": email, "password": "password123"}
}

func TestRegistrationDomains(t *testing.T) {
	const denied = "registration is not available for this email domain"
	t.Run("empty list is open", func(t *testing.T) {
		e, _ := regEnv(t)
		e.want(e.do("POST", "/api/auth/register", "", regBody("u1", "u1@anywhere.io")), 201, "open")
	})
	t.Run("allowed and denied", func(t *testing.T) {
		e, tok := regEnv(t)
		e.want(e.do("PUT", "/api/settings", tok, map[string]any{settingRegistrationDomains: "Example.com, foo.org\nbar.net"}), 200, "put")
		if got := e.s.St.Setting(settingRegistrationDomains); got != "example.com\nfoo.org\nbar.net" {
			t.Fatalf("stored %q", got)
		}
		s := e.do("GET", "/api/settings", tok, nil).J()
		if s[settingRegistrationDomains] != "example.com\nfoo.org\nbar.net" {
			t.Fatalf("admin get %v", s[settingRegistrationDomains])
		}
		e.want(e.do("POST", "/api/auth/register", "", regBody("u1", "u1@example.com")), 201, "allowed")
		e.want(e.do("POST", "/api/auth/register", "", regBody("u2", "U2@FOO.ORG")), 201, "case-insensitive")
		e.want(e.do("POST", "/api/auth/register", "", regBody("u3", "u3@bar.net")), 201, "last entry")
		for i, em := range []string{"x@evil.io", "x@sub.example.com", "x@notexample.com", "x@example.com.evil.io"} {
			r := e.do("POST", "/api/auth/register", "", regBody("d"+string(rune('a'+i)), em))
			e.want(r, 400, "denied "+em)
			if r.S("error") != denied {
				t.Fatalf("message %q", r.S("error"))
			}
		}
		var n int
		e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username LIKE 'd_'`).Scan(&n)
		if n != 0 {
			t.Fatal("denied registration created user")
		}
	})
	t.Run("many entries", func(t *testing.T) {
		e, tok := regEnv(t)
		var l []string
		for i := 0; i < 50; i++ {
			l = append(l, "dom"+string(rune('a'+i%26))+string(rune('a'+i/26))+".com")
		}
		e.want(e.do("PUT", "/api/settings", tok, map[string]any{settingRegistrationDomains: strings.Join(l, "\n")}), 200, "put 50")
		e.want(e.do("POST", "/api/auth/register", "", regBody("u1", "u@"+l[49])), 201, "last of 50")
		e.want(e.do("POST", "/api/auth/register", "", regBody("u2", "u@other.com")), 400, "other")
	})
	t.Run("denied before SMTP check", func(t *testing.T) {
		e := newEnv(t)
		tok := e.setup()
		e.s.St.SetSetting("allow_self_registration", "true")
		e.want(e.do("PUT", "/api/settings", tok, map[string]any{settingRegistrationDomains: "example.com"}), 200, "put")
		e.want(e.do("POST", "/api/auth/register", "", regBody("u1", "u@evil.io")), 400, "denied")
		e.want(e.do("POST", "/api/auth/register", "", regBody("u1", "u@example.com")), 503, "smtp still required")
	})
	t.Run("validation rejects whole batch atomically", func(t *testing.T) {
		e, tok := regEnv(t)
		e.want(e.do("PUT", "/api/settings", tok, map[string]any{settingRegistrationDomains: "good.com", "application_name": "Before"}), 200, "seed")
		for _, bad := range []string{"a@b.com", "*.example.com", "https://x.com", "x.com/p", "localhost", "-x.com", "bücher.de", strings.Repeat("a", 64) + ".com"} {
			r := e.do("PUT", "/api/settings", tok, map[string]any{"application_name": "After", settingRegistrationDomains: bad})
			e.want(r, 400, "bad "+bad)
			if r.S("error") == "" {
				t.Fatal("no message")
			}
			if e.s.St.Setting("application_name") != "Before" || e.s.St.Setting(settingRegistrationDomains) != "good.com" {
				t.Fatalf("partial write for %q", bad)
			}
		}
		var many []string
		for i := 0; i < 51; i++ {
			many = append(many, "d"+string(rune('a'+i%26))+string(rune('a'+i/26))+".com")
		}
		e.want(e.do("PUT", "/api/settings", tok, map[string]any{"application_name": "After", settingRegistrationDomains: strings.Join(many, ",")}), 400, "51")
		e.want(e.do("PUT", "/api/settings", tok, map[string]any{"application_name": "After", settingRegistrationDomains: 5}), 400, "number rejected")
	})
	t.Run("clearing reopens", func(t *testing.T) {
		e, tok := regEnv(t)
		e.want(e.do("PUT", "/api/settings", tok, map[string]any{settingRegistrationDomains: "example.com"}), 200, "put")
		e.want(e.do("PUT", "/api/settings", tok, map[string]any{settingRegistrationDomains: " \n,"}), 200, "clear")
		if e.s.St.Setting(settingRegistrationDomains) != "" {
			t.Fatal("not cleared")
		}
		e.want(e.do("POST", "/api/auth/register", "", regBody("u1", "u@anywhere.io")), 201, "open again")
	})
	t.Run("bootstrap flag without list", func(t *testing.T) {
		e, tok := regEnv(t)
		b := e.do("GET", "/api/bootstrap", "", nil)
		e.want(b, 200, "bootstrap")
		if v, ok := b.J()["registration_domain_restricted"]; !ok || v != false {
			t.Fatalf("flag %v", v)
		}
		e.want(e.do("PUT", "/api/settings", tok, map[string]any{settingRegistrationDomains: "secret-corp.example"}), 200, "put")
		b = e.do("GET", "/api/bootstrap", "", nil)
		if b.J()["registration_domain_restricted"] != true {
			t.Fatalf("flag %v", b.J()["registration_domain_restricted"])
		}
		if strings.Contains(string(b.Body), "secret-corp") || strings.Contains(string(b.Body), settingRegistrationDomains) {
			t.Fatal("list leaked in bootstrap")
		}
	})
	t.Run("admin create and provider registration unaffected", func(t *testing.T) {
		e, tok := regEnv(t)
		e.want(e.do("PUT", "/api/settings", tok, map[string]any{settingRegistrationDomains: "example.com"}), 200, "put")
		e.mkUser(tok, "viaadmin", false) // viaadmin@x.io is not on the list
		r := e.do("POST", "/api/auth-providers", tok, map[string]any{"name": "GH", "type": "github", "client_id": "c", "client_secret": "sec", "enabled": true, "allow_registration": true})
		e.want(r, 201, "provider")
		p, _ := e.s.providerByUUID(r.S("uuid"))
		p.AllowRegistration, p.TrustEmail = true, true
		u, _ := e.s.resolveExternalUser(p, extIdentity{Sub: "7", Email: "ext@other.org", EmailVerified: true, Username: "extuser"})
		if u == nil {
			t.Fatal("provider registration blocked by domain list")
		}
	})
	t.Run("corrupt stored value fails closed", func(t *testing.T) {
		e, _ := regEnv(t)
		for _, bad := range []string{"not a domain@x", "*.example.com", "https://a.com"} {
			e.s.St.SetSetting(settingRegistrationDomains, bad)
			r := e.do("POST", "/api/auth/register", "", regBody("u1", "u@example.com"))
			if r.Code != 500 || strings.Contains(string(r.Body), "example") {
				t.Fatalf("corrupt %q: %d %s", bad, r.Code, r.Body)
			}
			if e.do("GET", "/api/bootstrap", "", nil).J()["registration_domain_restricted"] != true {
				t.Fatal("corrupt must report restricted")
			}
		}
		var n int
		qByName(e.s.St, `SELECT COUNT(*) FROM users WHERE username='u1'`).Scan(&n)
		if n != 0 {
			t.Fatal("user created")
		}
	})
}
