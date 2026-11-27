// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateShareAppend: see sqlite.MigrateShareAppend.
func (s *Store) migrateShareAppend() error { return sqlite.MigrateShareAppend(s.DB) }
