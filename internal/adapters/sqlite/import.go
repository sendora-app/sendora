// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"database/sql"
	"os"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

// The statements of the database import (internal/store/import.go): an
// uploaded database is untrusted input, inspected and cleaned on its own
// connection before it may replace the live one. Policy decisions and the
// messages shown to the administrator stay in internal/store.

// ScanImportedFiles visits (share id, disk path) of the local files of
// non-deleted shares in the database at path, opened read-only with key, and
// removes the -wal/-shm files the read may leave behind.
func ScanImportedFiles(path string, key []byte, fn func(shareID int64, diskPath string)) error {
	db, err := OpenCipherDB(path, key, true)
	if err != nil {
		return err
	}
	defer func() {
		db.Close()
		for _, suffix := range []string{"-wal", "-shm"} {
			os.Remove(path + suffix)
		}
	}()
	rows, err := db.Query(`SELECT f.share_id,f.disk_path FROM files f JOIN shares s ON s.id=f.share_id WHERE s.status<>'deleted' AND f.storage_id=0`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var p string
		if err := rows.Scan(&id, &p); err != nil {
			return err
		}
		fn(id, p)
	}
	return rows.Err()
}

// ReadSchema returns the tables (without SQLite's internal ones) with their
// column names.
func ReadSchema(db *sql.DB) (map[string]map[string]bool, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{}
	for _, n := range names {
		cols := map[string]bool{}
		rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, n)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				rows.Close()
				return nil, err
			}
			cols[c] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		out[n] = cols
	}
	return out, nil
}

// DistrustSchema stops the connection from running functions defined by the
// file's schema (views, triggers, generated columns) with elevated trust.
func DistrustSchema(db *sql.DB) error {
	_, err := db.Exec(`PRAGMA trusted_schema=OFF`)
	return err
}

// CountGeneratedColumns counts generated (hidden) columns of ordinary tables.
func CountGeneratedColumns(db *sql.DB) (int, error) {
	var generated int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master m, pragma_table_xinfo(m.name) x WHERE m.type='table' AND m.sql NOT LIKE 'CREATE VIRTUAL%' AND x.hidden IN (2,3)`).Scan(&generated)
	return generated, err
}

// CountVirtualTables counts virtual tables.
func CountVirtualTables(db *sql.DB) (int, error) {
	var virtual int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND sql LIKE 'CREATE VIRTUAL TABLE%'`).Scan(&virtual)
	return virtual, err
}

func quoteIdent(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }

// DropSchemaObjects drops every trigger, view and explicit index; InitSchema
// and the migrations then recreate only this binary's own objects.
func DropSchemaObjects(db *sql.DB) error {
	rows, err := db.Query(`SELECT type,name FROM sqlite_master WHERE type IN ('trigger','view','index') AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL`)
	if err != nil {
		return err
	}
	type object struct{ kind, name string }
	var drop []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.kind, &o.name); err != nil {
			rows.Close()
			return err
		}
		drop = append(drop, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, o := range drop {
		var kind string
		switch o.kind {
		case "trigger":
			kind = "TRIGGER"
		case "view":
			kind = "VIEW"
		default:
			kind = "INDEX"
		}
		if _, err := db.Exec("DROP " + kind + " IF EXISTS " + quoteIdent(o.name)); err != nil {
			return err
		}
	}
	return nil
}

// DropUploadReservations removes every upload session and its declared files
// and returns the number of sessions removed.
func DropUploadReservations(db *sql.DB) (int64, error) {
	var n int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM upload_sessions`).Scan(&n); err != nil {
		return 0, err
	}
	if _, err := db.Exec(`DELETE FROM upload_files`); err != nil {
		return n, err
	}
	if _, err := db.Exec(`DELETE FROM upload_sessions`); err != nil {
		return n, err
	}
	return n, nil
}

// ClearImportedSecrets removes everything that grants or proves access:
// sessions, reset and verification codes, revocation lists and the stored
// signing secret. Tables the file does not have are skipped.
func ClearImportedSecrets(db *sql.DB) error {
	for _, table := range []string{"refresh_tokens", "password_resets", "email_verifications", "revoked_access_tokens", "verification_attempts", "ip_bans", "refresh_spent", "mfa_reset_requests"} {
		var present int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&present); err != nil {
			return err
		}
		if present == 1 {
			if _, err := db.Exec("DELETE FROM " + quoteIdent(table)); err != nil {
				return err
			}
		}
	}
	_, err := db.Exec(`DELETE FROM settings WHERE key='jwt_secret'`)
	return err
}

// EnforceImportUniqueness makes share long ids and usernames unique, which an
// imported table definition may lack; an error means duplicates exist. The
// stored values are sealed (randomised), so it is their blind indexes that
// carry the rule.
func EnforceImportUniqueness(db *sql.DB) error {
	for _, q := range []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS import_shares_long_id ON shares(long_id_bi)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS import_users_username ON users(username_bi)`,
	} {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// RebaseLocalFiles calls check for every share long id (stopping at its first
// error) and then rewrites the disk path of every local file to
// rebase(long id, stored disk path) (stopping at its first error, before any
// row is written). Errors of check and rebase are returned unchanged. The long
// ids are opened with codec (nil: plaintext).
func RebaseLocalFiles(db *sql.DB, codec ports.ColumnCodec, check func(longID string) error, rebase func(longID, diskPath string) (string, error)) error {
	rows, err := db.Query(`SELECT id,long_id FROM shares`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var sid int64
		var lid string
		if err := rows.Scan(&sid, &lid); err != nil {
			rows.Close()
			return err
		}
		if lid, err = openCol(codec, "shares", "long_id", sid, lid); err != nil {
			rows.Close()
			return err
		}
		if err := check(lid); err != nil {
			rows.Close()
			return err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = db.Query(`SELECT f.id,s.id,s.long_id,f.disk_path FROM files f JOIN shares s ON s.id=f.share_id WHERE f.storage_id=0`)
	if err != nil {
		return err
	}
	type rewrite struct {
		id   int64
		path string
	}
	var updates []rewrite
	for rows.Next() {
		var id, sid int64
		var lid, disk string
		if err := rows.Scan(&id, &sid, &lid, &disk); err != nil {
			rows.Close()
			return err
		}
		if lid, err = openCol(codec, "shares", "long_id", sid, lid); err != nil {
			rows.Close()
			return err
		}
		safe, perr := rebase(lid, disk)
		if perr != nil {
			rows.Close()
			return perr
		}
		updates = append(updates, rewrite{id, safe})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, u := range updates {
		if _, err := db.Exec(`UPDATE files SET disk_path=? WHERE id=?`, u.path, u.id); err != nil {
			return err
		}
	}
	return nil
}

// CountImportedAccounts counts non-guest accounts and, of those,
// administrators.
func CountImportedAccounts(db *sql.DB) (users, admins int64, err error) {
	if err = db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_guest=0`).Scan(&users); err != nil {
		return
	}
	err = db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_guest=0 AND admin=1`).Scan(&admins)
	return
}

// CountImportedContent counts shares that are not deleted and their files.
func CountImportedContent(db *sql.DB) (shares, files int64, err error) {
	if err = db.QueryRow(`SELECT COUNT(*) FROM shares WHERE status<>'deleted'`).Scan(&shares); err != nil {
		return
	}
	err = db.QueryRow(`SELECT COUNT(*) FROM files WHERE share_id IN (SELECT id FROM shares WHERE status<>'deleted')`).Scan(&files)
	return
}

// CheckpointTruncate folds the WAL into the main file.
func CheckpointTruncate(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA wal_checkpoint(TRUNCATE)`)
	if err != nil {
		return err
	}
	rows.Close()
	return nil
}
