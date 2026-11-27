// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// The migrations of the MFA, account security, password policy and storage
// policy domains, moved verbatim from internal/store and called from its
// migration sequence at the same places. Constants that stay in internal/store
// are passed in.

// MigrateMFA adds multi-factor authentication storage. It is additive and
// idempotent; secrets live inside the (SQLCipher) database like everything else.
//
//	users.mfa_policy  'inherit' | 'required' | 'exempt' (per-user override)
//	users.mfa_epoch   bumped on every factor change/reset; folded into the
//	                  credential version so older access tokens stop working
func MigrateMFA(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, c := range []struct{ name, declaration string }{
		{"mfa_policy", "TEXT NOT NULL DEFAULT 'inherit'"},
		{"mfa_epoch", "INTEGER NOT NULL DEFAULT 0"},
	} {
		rows, err := tx.Query("PRAGMA table_info(users)")
		if err != nil {
			return err
		}
		found := false
		for rows.Next() {
			var cid, notnull, pk int
			var name, typ string
			var def any
			if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
				rows.Close()
				return err
			}
			if name == c.name {
				found = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if !found {
			if _, err := tx.Exec(fmt.Sprintf("ALTER TABLE users ADD COLUMN %s %s", c.name, c.declaration)); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`
CREATE TABLE IF NOT EXISTS user_totp (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret TEXT NOT NULL,
  confirmed INTEGER NOT NULL DEFAULT 0,
  last_counter INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS user_recovery_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at DATETIME,
  UNIQUE(user_id, code_hash));
CREATE TABLE IF NOT EXISTS user_webauthn (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cred_id BLOB NOT NULL UNIQUE,
  public_key BLOB NOT NULL,
  alg INTEGER NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME);
CREATE INDEX IF NOT EXISTS user_webauthn_user ON user_webauthn(user_id);
CREATE TABLE IF NOT EXISTS mfa_reset_requests (
  hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  requested_by INTEGER NOT NULL DEFAULT 0,
  expires_at DATETIME NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS mfa_reset_requests_user ON mfa_reset_requests(user_id);`); err != nil {
		return err
	}
	return tx.Commit()
}

// MigrateAccountSecurity is additive and idempotent:
//   - users.terms_accepted_version / terms_accepted_at: the terms version a user accepted;
//   - users.erased_at: set when an account was erased (pseudonymised) on request;
//   - user_signin_seen: hashed (browser family, address class) fingerprints of
//     recent sign-ins, used for the "new sign-in" notification. No raw addresses.
//
// The settings part is MigrateAccountSecuritySettings.
func MigrateAccountSecurity(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if err = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range []struct{ name, ddl string }{
		{"terms_accepted_version", `ALTER TABLE users ADD COLUMN terms_accepted_version TEXT NOT NULL DEFAULT ''`},
		{"terms_accepted_at", `ALTER TABLE users ADD COLUMN terms_accepted_at DATETIME`},
		{"erased_at", `ALTER TABLE users ADD COLUMN erased_at DATETIME`},
	} {
		if !have[c.name] {
			if _, err := db.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS user_signin_seen (
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		fingerprint TEXT NOT NULL,
		last_seen DATETIME NOT NULL,
		PRIMARY KEY(user_id, fingerprint))`); err != nil {
		return err
	}
	return nil
}

// MigrateAccountSecuritySettings is the settings part of MigrateAccountSecurity
// (it needs the column codec, which exists after the schema migrations):
//   - the settings in defaults (insert if absent: existing values stay);
//   - account_password_min_length below minFloor is raised to minFloor (logged once, when it happens).
func MigrateAccountSecuritySettings(db *sql.DB, codec ports.ColumnCodec, defaults []struct{ Key, Val string }, minFloor int) error {
	ctx := context.Background()
	for _, d := range defaults {
		if err := insertSettingIfAbsent(ctx, db, codec, d.Key, d.Val, "system"); err != nil {
			return err
		}
	}
	raised, err := raiseSettingFloor(ctx, db, codec, "account_password_min_length", minFloor)
	if err != nil {
		return err
	}
	if raised {
		log.Printf("account_password_min_length was below %d and has been raised to %d", minFloor, minFloor)
	}
	return nil
}

// raiseSettingFloor raises an integer setting below floor to floor (a value
// that is not a number counts as 0, as SQLite's CAST does) and reports whether
// it did. The value is sealed, so the comparison is made on the opened value.
func raiseSettingFloor(ctx context.Context, q querier, codec ports.ColumnCodec, key string, floor int) (bool, error) {
	cur, err := readSetting(ctx, q, codec, key)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if castInt(cur) >= int64(floor) {
		return false, nil
	}
	n, err := writeSetting(ctx, q, codec, key, strconv.Itoa(floor))
	return n > 0, err
}

// castInt is CAST(s AS INTEGER): the leading integer of s, 0 when there is none.
func castInt(s string) int64 {
	s = strings.TrimLeft(s, " \t\n\v\f\r")
	end := 0
	if end < len(s) && (s[end] == '+' || s[end] == '-') {
		end++
	}
	digits := end
	for digits < len(s) && s[digits] >= '0' && s[digits] <= '9' {
		digits++
	}
	if digits == end {
		return 0
	}
	n, err := strconv.ParseInt(s[:digits], 10, 64)
	if err != nil { // out of range: SQLite saturates
		if s[0] == '-' {
			return math.MinInt64
		}
		return math.MaxInt64
	}
	return n
}

// MigratePasswordPolicy is additive and idempotent:
//   - users.password_changed_at: when the local password was last set. Rows that
//     exist when the column is added get the migration time, so nobody's password
//     counts as old at the upgrade;
//   - users.password_rotation_exempt: per-account exemption from the maximum age;
//   - users.password_expiry_warned_at: when the "password expires soon" mail was
//     sent for the current password (cleared whenever the password changes);
//   - password_history: bcrypt hashes of earlier passwords (newest N per account);
//   - the setting maxAgeKey: an installation that already has accounts
//     gets 0 (off), so an upgrade never forces anyone to change their password.
//     It runs before seed(), whose defaults list then gives a new installation
//     the default (365) through INSERT OR IGNORE.
func MigratePasswordPolicy(db *sql.DB, maxAgeKey string) error {
	hadChangedAt, err := hasColumnCount(db, "users", "password_changed_at")
	if err != nil {
		return err
	}
	for _, c := range []struct{ name, def string }{
		{"password_changed_at", "DATETIME"},
		{"password_rotation_exempt", "INTEGER NOT NULL DEFAULT 0"},
		{"password_expiry_warned_at", "DATETIME"},
	} {
		if err := AddColumn(db, "users", c.name, c.def); err != nil {
			return err
		}
	}
	if !hadChangedAt {
		if _, err := db.Exec(`UPDATE users SET password_changed_at=? WHERE password_changed_at IS NULL`, time.Now().UTC()); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS password_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		hash TEXT NOT NULL,
		created_at DATETIME NOT NULL)`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS password_history_user ON password_history(user_id, id)`); err != nil {
		return err
	}
	return nil
}

// MigratePasswordPolicySettings is the settings part of MigratePasswordPolicy
// (it needs the column codec): an installation that already has accounts gets
// maxAgeKey = 0 (off), so an upgrade never forces anyone to change their
// password. It runs before the seed, whose defaults then give a new
// installation the default (365).
func MigratePasswordPolicySettings(db *sql.DB, codec ports.ColumnCodec, maxAgeKey string) error {
	var anyUser int
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users)`).Scan(&anyUser); err != nil || anyUser == 0 {
		return err
	}
	return insertSettingIfAbsent(context.Background(), db, codec, maxAgeKey, "0", "system")
}

// hasColumnCount reports whether table has the column (pragma_table_info).
func hasColumnCount(db *sql.DB, table, column string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, table, column).Scan(&n)
	return n > 0, err
}

// MigratePolicy is additive and idempotent. Unattributable legacy reservations
// prevent startup rather than silently releasing their storage commitments.
func MigratePolicy(db *sql.DB, legacyQuota int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, c := range []struct{ table, name, declaration string }{
		{"users", "quota_bytes", "INTEGER NOT NULL DEFAULT 10737418240"},
		{"users", "quota_inherits_default", "INTEGER NOT NULL DEFAULT 1"},
		{"users", "login_failures", "INTEGER NOT NULL DEFAULT 0"},
		{"users", "login_locked_until", "INTEGER NOT NULL DEFAULT 0"},
		{"upload_sessions", "quota_owner_id", "INTEGER REFERENCES users(id) ON DELETE CASCADE"},
		{"password_resets", "kind", "TEXT NOT NULL DEFAULT 'reset'"},
	} {
		rows, err := tx.Query("PRAGMA table_info(" + c.table + ")")
		if err != nil {
			return err
		}
		found := false
		for rows.Next() {
			var cid, notnull, pk int
			var name, typ string
			var def any
			if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
				rows.Close()
				return err
			}
			if name == c.name {
				found = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if !found {
			if _, err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", c.table, c.name, c.declaration)); err != nil {
				return err
			}
			if c.name == "quota_inherits_default" {
				if _, err := tx.Exec(`UPDATE users SET quota_inherits_default=CASE WHEN quota_bytes=? THEN 1 ELSE 0 END`, legacyQuota); err != nil {
					return err
				}
			}
		}
	}
	if _, err := tx.Exec(`UPDATE upload_sessions SET quota_owner_id=user_id
  WHERE quota_owner_id IS NULL AND invite_id IS NULL
  AND EXISTS(SELECT 1 FROM users WHERE id=upload_sessions.user_id AND is_guest=0)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE upload_sessions SET quota_owner_id=(SELECT r.user_id FROM reverse_invites r WHERE r.id=upload_sessions.invite_id)
  WHERE quota_owner_id IS NULL AND EXISTS(SELECT 1 FROM users WHERE id=upload_sessions.user_id AND is_guest=1)
  AND EXISTS(SELECT 1 FROM reverse_invites r JOIN users u ON u.id=r.user_id AND u.is_guest=0
   WHERE r.id=upload_sessions.invite_id AND r.guest_user_id=upload_sessions.user_id)
  AND (SELECT COUNT(*) FROM reverse_invites WHERE guest_user_id=upload_sessions.user_id)=1`); err != nil {
		return err
	}
	var invalid int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM upload_sessions s
  LEFT JOIN users u ON u.id=s.quota_owner_id LEFT JOIN users uploader ON uploader.id=s.user_id
  WHERE s.quota_owner_id IS NULL OR u.id IS NULL OR u.is_guest<>0 OR uploader.id IS NULL`).Scan(&invalid); err != nil {
		return err
	}
	if invalid != 0 {
		return fmt.Errorf("cannot attribute %d upload storage reservations", invalid)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS upload_sessions_quota_owner ON upload_sessions(quota_owner_id);
  CREATE TRIGGER IF NOT EXISTS upload_quota_owner_required BEFORE INSERT ON upload_sessions
  WHEN NEW.quota_owner_id IS NULL BEGIN SELECT RAISE(ABORT,'quota owner required'); END;
  CREATE TRIGGER IF NOT EXISTS upload_quota_owner_immutable BEFORE UPDATE OF quota_owner_id ON upload_sessions
  WHEN NEW.quota_owner_id IS NOT OLD.quota_owner_id BEGIN SELECT RAISE(ABORT,'quota owner is immutable'); END;`); err != nil {
		return err
	}
	return tx.Commit()
}

// MigratePolicySettings adds the default storage quota setting when it is
// missing. It runs after MigratePolicy and before the ordinary settings seed.
func MigratePolicySettings(db *sql.DB, codec ports.ColumnCodec, defaultQuotaKey string, defaultQuota int64) error {
	return insertSettingIfAbsent(context.Background(), db, codec, defaultQuotaKey, strconv.FormatInt(defaultQuota, 10), "uploads")
}
