// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	uaFirefoxWin = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
	uaChromeMac  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

func TestBrowserFamilyAndAddressClass(t *testing.T) {
	for ua, want := range map[string]string{
		uaFirefoxWin: "Firefox (Windows)",
		uaChromeMac:  "Chrome (macOS)",
		"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/126.0 Safari/537.36 Edg/126.0":                               "Edge (Windows)",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1": "Safari (iOS)",
		"": "Unknown browser",
	} {
		if got := browserFamily(ua); got != want {
			t.Errorf("browserFamily(%q) = %q, want %q", ua, got, want)
		}
	}
	if addressClass("192.0.2.77") != "192.0.0.0/16" || addressClass("2001:db8:aa:bb::1") != "2001:db8:aa::/48" {
		t.Errorf("classes %s %s", addressClass("192.0.2.77"), addressClass("2001:db8:aa:bb::1"))
	}
	if got := approximateTime(time.Date(2026, 3, 4, 10, 17, 59, 0, time.UTC)); got != "2026-03-04 10:15 UTC" {
		t.Errorf("approximate time %q", got)
	}
}

func TestNewSigninNotificationOnlyForUnknownCombination(t *testing.T) {
	e := newEnv(t)
	sink := newSMTP(t)
	e.useSMTP(sink)
	admin := e.setup()
	e.mkUser(admin, "nina", false) // first sign-in: starts the history, no mail
	login := func(ua string) {
		t.Helper()
		e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "nina", "password": "password123"}, "User-Agent", ua), 200, "login")
	}
	count := func() int {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		n := 0
		for _, msg := range sink.msgs {
			if strings.Contains(msg, "New sign-in") {
				n++
			}
		}
		return n
	}
	login(uaFirefoxWin) // new browser family (the fixture signed in with Go's client): mail
	sink.wait(t, "Firefox (Windows)")
	login(uaFirefoxWin) // known now: no mail
	login(uaChromeMac)  // new browser family: mail
	m := sink.wait(t, "Chrome (macOS)")
	if !strings.Contains(m, "New sign-in to your Sendora account") || !strings.Contains(m, "nina@x.io") || strings.Contains(m, "127.0.0.1") {
		t.Fatalf("unexpected mail: %s", m)
	}
	time.Sleep(300 * time.Millisecond)
	if n := count(); n != 2 {
		t.Fatalf("want two new sign-in mails, got %d", n)
	}
	// No raw addresses are stored for this.
	var fp string
	e.s.St.DB.QueryRow(`SELECT fingerprint FROM user_signin_seen LIMIT 1`).Scan(&fp)
	if len(fp) != 32 || strings.Contains(fp, ".") {
		t.Fatalf("fingerprint %q", fp)
	}
	// Switched off: no mail for another new combination.
	e.s.St.SetSetting("notify_new_signin", "false")
	login("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0 OPR/100")
	time.Sleep(500 * time.Millisecond)
	if n := count(); n != 2 {
		t.Fatalf("notification sent while switched off (%d)", n)
	}
}

func TestSecurityNotificationsForPasswordAndFactors(t *testing.T) {
	e := newEnv(t)
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.St.SetSetting("mfa_policy", "optional")
	admin := e.setup()
	tok := e.mkUser(admin, "olga", false)
	r := e.do("PUT", "/api/users/me", tok, map[string]any{"email": "olga@x.io", "current_password": "password123", "password": "Olive-Branch-55"}, "User-Agent", uaFirefoxWin)
	e.want(r, 200, "change password")
	m := sink.wait(t, "The password of your Sendora account was changed")
	if !strings.Contains(m, "Firefox (Windows)") || strings.Contains(m, "Olive-Branch-55") {
		t.Fatalf("password mail: %s", m)
	}
	tok = r.S("access_token")
	_, tok, _ = e.enrollTOTP(tok, "Olive-Branch-55")
	sink.wait(t, "two-step verification of your Sendora account was changed")
	e.want(e.do("POST", "/api/users/me/mfa/recovery/regenerate", tok, map[string]any{"password": "Olive-Branch-55"}), 200, "regenerate")
	sink.wait(t, "New recovery codes were created")
}

func TestSecurityNotificationNeverBlocksWhenMailFails(t *testing.T) {
	e := newEnv(t)
	// SMTP configured but unreachable: the change still succeeds.
	e.s.St.SetSetting("smtp_host", "127.0.0.1")
	e.s.St.SetSetting("smtp_port", "1")
	e.s.St.SetSetting("smtp_tls", "none")
	e.s.St.SetSetting("smtp_from", "files@x.io")
	admin := e.setup()
	tok := e.mkUser(admin, "pia", false)
	e.want(e.do("PUT", "/api/users/me", tok, map[string]any{"email": "pia@x.io", "current_password": "password123", "password": "Pine-Needle-66"}), 200, "change despite mail failure")
}

func TestSigninFingerprintIgnoresHostPart(t *testing.T) {
	e := newEnv(t)
	r1 := httptest.NewRequest("POST", "/api/auth/login", nil)
	r1.RemoteAddr, r1.Header["User-Agent"] = "198.51.100.7:5000", []string{uaFirefoxWin}
	r2 := httptest.NewRequest("POST", "/api/auth/login", nil)
	r2.RemoteAddr, r2.Header["User-Agent"] = "198.51.20.9:6000", []string{uaFirefoxWin}
	r3 := httptest.NewRequest("POST", "/api/auth/login", nil)
	r3.RemoteAddr, r3.Header["User-Agent"] = "203.0.113.9:6000", []string{uaFirefoxWin}
	if e.s.signinFingerprint(1, r1) != e.s.signinFingerprint(1, r2) {
		t.Error("same /16 and browser must give the same fingerprint")
	}
	if e.s.signinFingerprint(1, r1) == e.s.signinFingerprint(1, r3) || e.s.signinFingerprint(1, r1) == e.s.signinFingerprint(2, r1) {
		t.Error("another network or account must differ")
	}
}
