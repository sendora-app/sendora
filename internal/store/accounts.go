// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateAccounts: see sqlite.MigrateAccounts.
func (s *Store) migrateAccounts() error { return sqlite.MigrateAccounts(s.DB) }

// addColumn adds a column unless the table already has it.
func (s *Store) addColumn(table, column, def string) error {
	return sqlite.AddColumn(s.DB, table, column, def)
}
