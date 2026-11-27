// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateReverseOpen: see sqlite.MigrateReverseOpen.
func (s *Store) migrateReverseOpen() error { return sqlite.MigrateReverseOpen(s.DB) }
