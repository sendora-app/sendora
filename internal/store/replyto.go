// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// migrateReplyToFormat: see sqlite.MigrateReplyToFormat.
func (s *Store) migrateReplyToFormat() error {
	return sqlite.MigrateReplyToFormat(s.DB, s.ColumnCodec())
}
