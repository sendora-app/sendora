// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateLookupIndexes: see sqlite.MigrateLookupIndexes.
func (s *Store) migrateLookupIndexes() error { return sqlite.MigrateLookupIndexes(s.DB) }
