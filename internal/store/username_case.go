// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateUsernameCase: see sqlite.MigrateUsernameCase.
func (s *Store) migrateUsernameCase() error { return sqlite.MigrateUsernameCase(s.DB) }
