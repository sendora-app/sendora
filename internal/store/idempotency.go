// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateIdempotency: see sqlite.MigrateIdempotency.
func (s *Store) migrateIdempotency() error { return sqlite.MigrateIdempotency(s.DB) }
