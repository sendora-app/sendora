// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestMigrateAccountSecurity(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	for _, k := range []string{"notify_new_signin", "password_breach_check_online", "admin_stepup_minutes", "admin_idle_logout_minutes", "admin_ip_allowlist", "privacy_url", "terms_url", "terms_acceptance_required", "terms_version"} {
		var n int
		st.DB.QueryRow(`SELECT COUNT(*) FROM settings WHERE key=?`, k).Scan(&n)
		if n != 1 {
			t.Errorf("setting %s missing", k)
		}
	}
	if st.Setting("notify_new_signin") != "true" || st.Setting("password_breach_check_online") != "false" || st.Setting("admin_stepup_minutes") != "5" || st.Setting("admin_idle_logout_minutes") != "15" {
		t.Error("defaults")
	}
	if _, err := st.DB.Exec(`INSERT INTO users(username) VALUES('u')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE users SET terms_accepted_version='1', erased_at=CURRENT_TIMESTAMP`); err != nil {
		t.Fatalf("columns: %v", err)
	}
	// A stored minimum below 8 is raised once, with one log line; existing values stay.
	st.SetSetting("account_password_min_length", "4")
	st.SetSetting("admin_stepup_minutes", "9")
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	for i := 0; i < 2; i++ {
		if err := st.migrateAccountSecurity(); err != nil {
			t.Fatal(err)
		}
		if err := st.migrateAccountSecuritySettings(); err != nil {
			t.Fatal(err)
		}
	}
	log.SetOutput(os.Stderr)
	if st.Setting("account_password_min_length") != "8" || st.Setting("admin_stepup_minutes") != "9" {
		t.Fatalf("after migration: %s %s", st.Setting("account_password_min_length"), st.Setting("admin_stepup_minutes"))
	}
	if strings.Count(buf.String(), "raised to 8") != 1 {
		t.Fatalf("log: %q", buf.String())
	}
	st.SetSetting("account_password_min_length", "12")
	st.migrateAccountSecurity()
	st.migrateAccountSecuritySettings()
	if st.Setting("account_password_min_length") != "12" {
		t.Fatal("a higher minimum was changed")
	}
}

func TestAccountMailDefaultsInEveryLanguage(t *testing.T) {
	for _, event := range []string{"password_changed", "mfa_factor_changed", "recovery_codes_regenerated", "new_signin"} {
		if !IsOptionalMailEvent(event) {
			t.Errorf("%s must be optional so older bundles still import", event)
		}
		found := false
		for _, e := range MailEvents {
			found = found || e == event
		}
		if !found {
			t.Errorf("%s is not a mail event", event)
		}
		for _, lang := range MailLanguages {
			subject, body := MailDefaults(event, lang)
			if subject == "" || !strings.Contains(body, "{{.Time}}") || !strings.Contains(body, "{{.Browser}}") || strings.Contains(body, "{{.URL}}") {
				t.Errorf("%s/%s: %q %q", event, lang, subject, body)
			}
			mailVarSet(t, event+"/"+lang, subject+body)
		}
		if s, _ := MailDefaults(event, "xx"); s == "" {
			t.Errorf("%s: no English fallback", event)
		}
	}
}
