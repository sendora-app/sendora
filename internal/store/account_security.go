// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// AccountPasswordMinFloor is the lowest allowed account password length.
const AccountPasswordMinFloor = 8

// accountSecurityDefaults are the settings for security notifications, the
// password screening, administrator step-up, the administrator network
// restriction and the privacy/terms links. INSERT OR IGNORE: existing values stay.
var accountSecurityDefaults = []struct{ Key, Val string }{
	{"notify_new_signin", "true"},
	{"password_breach_check_online", "false"},
	{"admin_stepup_minutes", "5"},
	{"admin_idle_logout_minutes", "15"},
	{"admin_ip_allowlist", ""},
	{"privacy_url", ""},
	{"terms_url", ""},
	{"terms_acceptance_required", "false"},
	{"terms_version", ""},
}

// migrateAccountSecurity: see sqlite.MigrateAccountSecurity.
func (s *Store) migrateAccountSecurity() error {
	return sqlite.MigrateAccountSecurity(s.DB)
}

// migrateAccountSecuritySettings: see sqlite.MigrateAccountSecuritySettings.
func (s *Store) migrateAccountSecuritySettings() error {
	return sqlite.MigrateAccountSecuritySettings(s.DB, s.ColumnCodec(), accountSecurityDefaults, AccountPasswordMinFloor)
}
