// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateSessions: see sqlite.MigrateSessions.
func (s *Store) migrateSessions() error { return sqlite.MigrateSessions(s.DB) }
