// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "github.com/sendora-app/sendora/internal/adapters/sqlite"

// SnapshotPlaintext creates a restricted, standalone rollback database. The
// source application MUST be stopped; raw copies of a live DB omit WAL commits.
// See sqlite.SnapshotPlaintext.
func SnapshotPlaintext(source, destination string) error {
	return sqlite.SnapshotPlaintext(source, destination)
}

// VerifyDatabase opens without schema migrations and reports non-sensitive row
// counts only after SQLCipher, SQLite and foreign-key integrity checks succeed.
// See sqlite.VerifyDatabase.
func VerifyDatabase(path string, key []byte) (map[string]int64, error) {
	return sqlite.VerifyDatabase(path, key)
}
