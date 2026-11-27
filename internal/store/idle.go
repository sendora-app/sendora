// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateIdle: see sqlite.MigrateIdle.
func (s *Store) migrateIdle() error { return sqlite.MigrateIdle(s.DB) }
