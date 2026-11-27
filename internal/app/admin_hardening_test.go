// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSMTPPasswordMustBeRetypedForAnotherServer(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_host": "mail.example.com", "smtp_port": 587, "smtp_user": "u", "smtp_pass": "real-secret", "smtp_tls": "starttls"}), 200, "initial SMTP")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_host": "mail.example.com", "smtp_port": 587, "smtp_pass": ""}), 200, "unchanged server keeps password")
	for k, v := range map[string]any{"smtp_host": "mx.attacker.example", "smtp_port": 2525, "smtp_user": "other", "smtp_tls": "tls"} {
		r := e.do("PUT", "/api/settings", admin, map[string]any{k: v, "smtp_pass": ""})
		e.want(r, 400, "changing "+k+" without the password")
	}
	if e.s.St.Setting("smtp_host") != "mail.example.com" {
		t.Fatal("server changed although the password was not retyped")
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_host": "mail2.example.com", "smtp_pass": "new-secret"}), 200, "change with password")
}

func TestProviderSecretMustBeRetypedForAnotherIssuer(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	body := map[string]any{"name": "OIDC", "type": "oidc", "issuer_url": "https://issuer.example", "client_id": "c", "client_secret": "s", "enabled": true}
	r := e.do("POST", "/api/auth-providers", admin, body)
	if r.Code != 200 && r.Code != 201 {
		t.Skipf("provider creation needs network discovery here: %d %s", r.Code, r.Body)
	}
	var id int64
	e.s.St.DB.QueryRow(`SELECT id FROM auth_providers WHERE name='OIDC'`).Scan(&id)
	body["issuer_url"] = "https://attacker.example"
	body["client_secret"] = ""
	e.want(e.do("PUT", fmt.Sprintf("/api/auth-providers/%d", id), admin, body), 400, "issuer change without secret")
}

func TestSMTPErrorsAreGeneric(t *testing.T) {
	for raw, want := range map[string]string{
		"dial tcp 10.0.0.5:25: connect: connection refused": "could not connect",
		"535 5.7.8 Username and Password not accepted":      "sign-in failed",
		"tls: failed to verify certificate: x509: unknown":  "secure connection",
		"smtp not configured":                               "smtp not configured",
	} {
		got := smtpErrorCategory(errors.New(raw))
		if !strings.Contains(strings.ToLower(got), want) || strings.Contains(got, "10.0.0.5") {
			t.Fatalf("%q -> %q", raw, got)
		}
	}
}

func TestInstanceWideMailCap(t *testing.T) {
	e := newEnv(t)
	sent := 0
	for user := int64(1); user <= 10; user++ {
		for i := 0; i < mailRecipientsPerHour; i++ {
			if e.s.takeMail(user, 1) {
				sent++
			}
		}
	}
	if sent != mailRecipientsPerHourTotal {
		t.Fatalf("sent %d, want the instance cap %d", sent, mailRecipientsPerHourTotal)
	}
}

func TestUsernameRules(t *testing.T) {
	for _, bad := range []string{"victim@corp.example", "admin ", " admin", "two words", "tab\tname", "zero​width", "rtl‮name", strings.Repeat("a", 65), ""} {
		if validUsername(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, cyr := range []string{"josé", "\u0430dmin", "ad\u043cin"} { // accented and Cyrillic look-alikes
		if validUsername(cyr) {
			t.Fatalf("accepted look-alike %q", cyr)
		}
	}
	for _, good := range []string{"admin", "Jandevriesexample.nl", "jan_de-vries", strings.Repeat("a", 64)} {
		if !validUsername(good) {
			t.Fatalf("rejected %q", good)
		}
	}
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "victim@corp.example", "password": "password123"}), 400, "email-like username")
}

func TestCSVFormulaGuard(t *testing.T) {
	for in, want := range map[string]string{
		"=1+1": "'=1+1", " =1+1": "' =1+1", "\n=HYPERLINK(1)": "'\n=HYPERLINK(1)", "＝1": "'＝1", "|cmd": "'|cmd", "plain": "plain", "": "",
	} {
		if got := csvSafe(in); got != want {
			t.Fatalf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSettingsValidationAndUnknownKeys(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	for k, v := range map[string]any{
		"clean_files_days": -1, "max_share_size": -5, "backup_keep": 0, "smtp_port": 70000, "smtp_tls": "maybe",
		"application_url": "javascript:alert(1)", "application_name": strings.Repeat("x", 81), "default_language": "xx-nope",
		"allow_self_registration": "yes", "smtp_from": "not an address",
	} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{k: v}), 400, fmt.Sprintf("%s=%v", k, v))
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"application_url": "https://files.example.com/", "clean_files_days": 0, "max_share_size": 0, "max_expiry_time": 0}), 200, "valid values")
	if e.s.St.Setting("application_url") != "https://files.example.com" {
		t.Fatal("application URL not normalised:", e.s.St.Setting("application_url"))
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"made_up_key": "x", "smtp_pass_set": true}), 200, "unknown keys ignored")
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='made_up_key'`).Scan(&n)
	if n != 0 {
		t.Fatal("unknown key stored")
	}
}

func TestSetupNeedsTheOneTimeCodeAndVersionIsPrivate(t *testing.T) {
	e := newEnv(t)
	if len(e.s.setupCode) != 14 {
		t.Fatalf("setup code %q", e.s.setupCode)
	}
	body := map[string]any{"username": "admin", "password": "password123"}
	e.want(e.do("POST", "/api/setup", "", body), 403, "missing code")
	body["setup_code"] = "AAAA-BBBB-CCCC"
	e.want(e.do("POST", "/api/setup", "", body), 403, "wrong code")
	body["setup_code"] = strings.ToLower(e.s.setupCode)
	e.want(e.do("POST", "/api/setup", "", body), 200, "right code (case-insensitive)")
	for _, p := range []string{"/api/health", "/api/bootstrap"} {
		if r := e.do("GET", p, "", nil); strings.Contains(string(r.Body), `"version"`) {
			t.Fatalf("%s exposes the version: %s", p, r.Body)
		}
	}
}
