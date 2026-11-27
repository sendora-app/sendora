// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"database/sql"
	"fmt"
	"time"
)

// The migrations of the share, upload, reverse-share and session-idle
// domains, moved verbatim from internal/store and called from its migration
// sequence at the same places.

// MigrateIntegrity adds the checksum and encryption columns of files and
// upload_files. Additive migration preserves existing rows; empty hashes are
// lazily baselined.
func MigrateIntegrity(db *sql.DB) error {
	for _, column := range []struct{ table, name, declaration string }{
		{"upload_files", "sha256", "TEXT NOT NULL DEFAULT ''"},
		{"files", "sha256", "TEXT NOT NULL DEFAULT ''"},
		{"files", "integrity", "TEXT NOT NULL DEFAULT 'server_baseline'"},
		// enc=1: the stored file is chunked AES-256-GCM (internal/filecrypt).
		{"files", "enc", "INTEGER NOT NULL DEFAULT 0"},
		// enc_id: hex of the 16 byte file id (format v2) that binds the ciphertext
		// to this row; empty for plain files and format v1 files (0.1.2 - 0.1.4).
		{"files", "enc_id", "TEXT NOT NULL DEFAULT ''"},
	} {
		rows, err := db.Query("PRAGMA table_info(" + column.table + ")")
		if err != nil {
			return err
		}
		found := false
		for rows.Next() {
			var cid, notnull, pk int
			var name, typ string
			var def any
			if err = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
				rows.Close()
				return err
			}
			if name == column.name {
				found = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if !found {
			if _, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", column.table, column.name, column.declaration)); err != nil {
				return err
			}
		}
	}
	return nil
}

// MigrateReverseOpen adds the columns used by reusable (open) reverse-share
// links. It is additive and idempotent; existing invites keep their meaning
// (reusable=0, no parent).
func MigrateReverseOpen(db *sql.DB) error {
	have := map[string]bool{}
	rows, err := db.Query("PRAGMA table_info(reverse_invites)")
	if err != nil {
		return err
	}
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
	for _, c := range []struct{ name, decl string }{
		{"reusable", "INTEGER NOT NULL DEFAULT 0"},
		{"max_uploads", "INTEGER NOT NULL DEFAULT 0"},
		{"parent_id", "INTEGER"},
	} {
		if have[c.name] {
			continue
		}
		if _, err = db.Exec(fmt.Sprintf("ALTER TABLE reverse_invites ADD COLUMN %s %s", c.name, c.decl)); err != nil {
			return err
		}
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_reverse_invites_parent ON reverse_invites(parent_id)`)
	return err
}

// MigrateShareAppend adds upload_sessions.share_id: an upload session with a
// share_id appends its files to that existing share instead of creating a new
// one. It is additive and idempotent; existing sessions keep share_id NULL.
// Deleting a share cascades to its pending append sessions.
func MigrateShareAppend(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(upload_sessions)")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if err = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "share_id" {
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !found {
		if _, err = db.Exec(`ALTER TABLE upload_sessions ADD COLUMN share_id INTEGER REFERENCES shares(id) ON DELETE CASCADE`); err != nil {
			return err
		}
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_upload_sessions_share ON upload_sessions(share_id)`)
	return err
}

// MigrateIdle adds refresh_tokens.issued_at, the time a refresh token was
// created or rotated. The server uses it to end sessions that were abandoned
// longer than the configured inactivity window. It is additive and idempotent;
// existing rows are backfilled with "now" so an upgrade never signs anyone out.
func MigrateIdle(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(refresh_tokens)")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if err = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "issued_at" {
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !found {
		if _, err = db.Exec(`ALTER TABLE refresh_tokens ADD COLUMN issued_at DATETIME`); err != nil {
			return err
		}
	}
	_, err = db.Exec(`UPDATE refresh_tokens SET issued_at=? WHERE issued_at IS NULL`, time.Now())
	return err
}

// CipherVersion is the SQLCipher version string reported by the engine ("" if
// it cannot be read).
func CipherVersion(db *sql.DB) string {
	var v string
	if db.QueryRow(`PRAGMA cipher_version`).Scan(&v) != nil {
		return ""
	}
	return v
}
