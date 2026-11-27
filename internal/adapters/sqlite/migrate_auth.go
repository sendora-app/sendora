// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"database/sql"
	"fmt"
	"log"
)

// The migrations of the account and session domains, moved verbatim from
// internal/store and called from its migration sequence at the same places.

// AddColumn adds a column unless the table already has it.
func AddColumn(db *sql.DB, table, column, def string) error {
	found, err := hasColumn(db, table, column)
	if err != nil || found {
		return err
	}
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, def))
	return err
}

// hasColumn reports whether table has column (PRAGMA table_info).
func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err = rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return false, err
		}
		found = found || name == column
	}
	err = rows.Err()
	rows.Close()
	return found, err
}

// MigrateSessions adds the original sign-in time to refresh tokens (so rotation
// cannot extend a session forever) and a table of spent refresh tokens (so reuse
// of a rotated token can be detected and the session family revoked).
func MigrateSessions(db *sql.DB) error {
	found, err := hasColumn(db, "refresh_tokens", "session_started")
	if err != nil {
		return err
	}
	if !found {
		if _, err := db.Exec(`ALTER TABLE refresh_tokens ADD COLUMN session_started DATETIME`); err != nil {
			return err
		}
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS refresh_spent (
		hash TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		spent_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL)`)
	return err
}

// MigratePendingRegistration marks accounts that were created by public
// registration and have not confirmed their email yet. Only these are removed by
// the 48-hour cleanup: an established account whose new address is not verified
// yet must never be deleted. Existing accounts start unmarked.
func MigratePendingRegistration(db *sql.DB) error {
	found, err := hasColumn(db, "users", "pending_registration")
	if err != nil || found {
		return err
	}
	_, err = db.Exec(`ALTER TABLE users ADD COLUMN pending_registration INTEGER NOT NULL DEFAULT 0`)
	return err
}

// MigrateVerificationAttempts creates the per-account counters of email
// verification attempts. The server runs it at startup, after the migration
// sequence.
func MigrateVerificationAttempts(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS verification_attempts (
		user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		attempts INTEGER NOT NULL, expires_at DATETIME NOT NULL)`)
	return err
}

// MigrateUsernameCase makes usernames unique regardless of ASCII letter case
// ("Admin" and "admin" are the same account). The display case stays as typed.
// If an existing database already holds names that differ only by case, the
// unique index cannot be created: startup continues, a warning gives the number
// of such names (find them with GROUP BY username COLLATE NOCASE), and logins
// prefer the exact-case match.
func MigrateUsernameCase(db *sql.DB) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM (SELECT 1 FROM users GROUP BY username COLLATE NOCASE HAVING COUNT(*)>1)`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		log.Printf("WARNING: %d username(s) exist that differ only by letter case; rename them so case-insensitive uniqueness can be enforced", n)
		return nil
	}
	_, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase ON users(username COLLATE NOCASE)`)
	return err
}

// MigrateAccounts adds the account lifecycle columns used by deactivation and
// the access-review report, and the per-session details of refresh tokens.
// Every step is additive: existing rows keep working with NULL / empty values
// ("unknown" in the report).
func MigrateAccounts(db *sql.DB) error {
	userCols := []struct{ name, def string }{
		{"disabled_at", "DATETIME"},
		{"disabled_by", "TEXT NOT NULL DEFAULT ''"},
		{"disabled_reason", "TEXT NOT NULL DEFAULT ''"},
		{"created_by", "TEXT NOT NULL DEFAULT ''"},
		{"last_login_at", "DATETIME"},
		{"role_changed_at", "DATETIME"},
		{"role_changed_by", "TEXT NOT NULL DEFAULT ''"},
		{"email_changed_at", "DATETIME"},
		{"email_changed_by", "TEXT NOT NULL DEFAULT ''"},
	}
	for _, c := range userCols {
		if err := AddColumn(db, "users", c.name, c.def); err != nil {
			return err
		}
	}
	// A session (refresh-token family) keeps one id across rotations; the
	// access tokens of that session carry it, so revoking the session also ends
	// them before they expire.
	tokenCols := []struct{ name, def string }{
		{"session_id", "TEXT"},
		{"user_agent", "TEXT NOT NULL DEFAULT ''"},
		{"ip", "TEXT NOT NULL DEFAULT ''"},
		{"auth_method", "TEXT NOT NULL DEFAULT ''"},
	}
	for _, c := range tokenCols {
		if err := AddColumn(db, "refresh_tokens", c.name, c.def); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`UPDATE refresh_tokens SET session_id=lower(hex(randomblob(16))) WHERE session_id IS NULL OR session_id=''`); err != nil {
		return err
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS refresh_tokens_session ON refresh_tokens(session_id)`)
	return err
}
