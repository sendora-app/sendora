// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestPasswordPolicyDefaultsFreshInstall(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	if st.Setting(SettingPasswordMaxAgeDays) != "365" || st.Setting(SettingPasswordHistory) != "5" {
		t.Fatalf("fresh defaults: max age %q, history %q", st.Setting(SettingPasswordMaxAgeDays), st.Setting(SettingPasswordHistory))
	}
	// Running the migrations again (next start, with accounts by now) keeps the value.
	st.DB.Exec(`INSERT INTO users(username,password_hash) VALUES('a','x')`)
	if err := st.runMigrations(); err != nil {
		t.Fatal(err)
	}
	if st.Setting(SettingPasswordMaxAgeDays) != "365" {
		t.Fatal("restart changed the maximum age")
	}
}

func TestPasswordPolicyUpgradeWithUsers(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	// Simulate a database from before this feature: accounts, no keys, no columns.
	if _, err := st.DB.Exec(`INSERT INTO users(username,password_hash) VALUES('old','x'),('sso','')`); err != nil {
		t.Fatal(err)
	}
	st.DB.Exec(`DELETE FROM settings WHERE key IN (?,?)`, SettingPasswordMaxAgeDays, SettingPasswordHistory)
	st.DB.Exec(`DROP TABLE password_history`)
	for _, c := range []string{"password_changed_at", "password_rotation_exempt", "password_expiry_warned_at"} {
		if _, err := st.DB.Exec(`ALTER TABLE users DROP COLUMN ` + c); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.runMigrations(); err != nil {
		t.Fatal(err)
	}
	if st.Setting(SettingPasswordMaxAgeDays) != "0" || st.Setting(SettingPasswordHistory) != "5" {
		t.Fatalf("upgrade: max age %q, history %q", st.Setting(SettingPasswordMaxAgeDays), st.Setting(SettingPasswordHistory))
	}
	var changed sql.NullTime
	var exempt bool
	if err := st.DB.QueryRow(`SELECT password_changed_at, password_rotation_exempt FROM users WHERE username='old'`).Scan(&changed, &exempt); err != nil {
		t.Fatal(err)
	}
	if !changed.Valid || time.Since(changed.Time) > time.Minute || exempt {
		t.Fatalf("existing row: %v %v", changed, exempt)
	}
	// The backfill happens only when the column is added.
	st.DB.Exec(`UPDATE users SET password_changed_at=NULL WHERE username='old'`)
	if err := st.runMigrations(); err != nil {
		t.Fatal(err)
	}
	st.DB.QueryRow(`SELECT password_changed_at FROM users WHERE username='old'`).Scan(&changed)
	if changed.Valid {
		t.Fatal("backfill ran again")
	}
	if n := countTable(t, st, "password_history"); n != 0 {
		t.Fatal(n)
	}
}

func countTable(t *testing.T, st *Store, table string) int {
	t.Helper()
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPasswordExpiryMailDefaults(t *testing.T) {
	if !IsOptionalMailEvent("password_expiry_warning") {
		t.Fatal("must be optional so older bundles still import")
	}
	for _, lang := range MailLanguages {
		subject, body := MailDefaults("password_expiry_warning", lang)
		for _, v := range []string{"{{.ExpiresDays}}", "{{.Expires}}", "{{.URL}}", "{{.RecipientName}}", "{{.Username}}"} {
			if !strings.Contains(subject+body, v) {
				t.Errorf("%s: %s missing", lang, v)
			}
		}
		mailVarSet(t, "password_expiry_warning/"+lang, subject+body)
	}
	if s, _ := MailDefaults("password_expiry_warning", "xx"); s == "" {
		t.Fatal("no English fallback")
	}
}
