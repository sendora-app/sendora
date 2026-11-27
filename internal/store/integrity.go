// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateIntegrity: see sqlite.MigrateIntegrity.
func (s *Store) migrateIntegrity() error { return sqlite.MigrateIntegrity(s.DB) }
