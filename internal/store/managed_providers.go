// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateManagedProviders: see sqlite.MigrateManagedProviders.
func (s *Store) migrateManagedProviders() error { return sqlite.MigrateManagedProviders(s.DB) }
