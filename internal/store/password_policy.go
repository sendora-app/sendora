// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// Password rotation and history settings.
const (
	SettingPasswordMaxAgeDays = "account_password_max_age_days"
	SettingPasswordHistory    = "account_password_history"
	// PasswordMaxAgeDefault is the maximum password age of a NEW installation.
	PasswordMaxAgeDefault = "365"
)

// migratePasswordPolicy: see sqlite.MigratePasswordPolicy.
func (s *Store) migratePasswordPolicy() error {
	return sqlite.MigratePasswordPolicy(s.DB, SettingPasswordMaxAgeDays)
}

// migratePasswordPolicySettings: see sqlite.MigratePasswordPolicySettings.
func (s *Store) migratePasswordPolicySettings() error {
	return sqlite.MigratePasswordPolicySettings(s.DB, s.ColumnCodec(), SettingPasswordMaxAgeDays)
}
