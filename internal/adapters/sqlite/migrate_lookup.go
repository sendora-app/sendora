// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import "database/sql"

// MigrateLookupIndexes adds the blind-index columns of the encrypted lookup
// columns (users.username, users.email, shares.long_id; see blindIndexes) with
// their UNIQUE indexes, and drops the plaintext email guard triggers: the
// UNIQUE index on email_bi enforces the same rule (one address per account,
// compared folded; the empty address has no index). Rows of a database from
// before column encryption have no index until EncryptPlaintextColumns fills
// it. Idempotent.
func MigrateLookupIndexes(db *sql.DB) error {
	for _, c := range []struct{ table, column string }{{"users", "username_bi"}, {"users", "email_bi"}, {"shares", "long_id_bi"}} {
		if err := AddColumn(db, c.table, c.column, "BLOB"); err != nil {
			return err
		}
	}
	for _, q := range []string{
		`DROP TRIGGER IF EXISTS users_email_insert`,
		`DROP TRIGGER IF EXISTS users_email_update`,
		`CREATE UNIQUE INDEX IF NOT EXISTS users_username_bi ON users(username_bi)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS users_email_bi ON users(email_bi)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS shares_long_id_bi ON shares(long_id_bi)`,
	} {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}
