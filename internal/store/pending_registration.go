// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migratePendingRegistration: see sqlite.MigratePendingRegistration.
func (s *Store) migratePendingRegistration() error { return sqlite.MigratePendingRegistration(s.DB) }

// MigrateVerificationAttempts creates the email verification attempt counters.
// The server calls it at startup (outside the migration sequence, as in 0.2);
// see sqlite.MigrateVerificationAttempts. A remote store (OpenRemote) has the
// table in its versioned schema (the controller migrates it): nothing to do.
func (s *Store) MigrateVerificationAttempts() error {
	if s.Remote() {
		return nil
	}
	return sqlite.MigrateVerificationAttempts(s.DB)
}
