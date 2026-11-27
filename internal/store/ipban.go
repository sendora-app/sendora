// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateIPBans creates the table that keeps address bans across restarts. The
// DDL lives with the repository in internal/adapters/sqlite.
func (s *Store) migrateIPBans() error { return sqlite.MigrateIPBans(s.DB) }
