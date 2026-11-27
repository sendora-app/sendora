// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

// BaseSchema is the base schema of a tenant (or single-tenant) database. downloads.ip: see download_ip.go (empty unless
// audit_log_ip is on).
const BaseSchema = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT '',
  admin INTEGER NOT NULL DEFAULT 0,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  is_guest INTEGER NOT NULL DEFAULT 0,
  email_verified INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '',
  grp TEXT NOT NULL DEFAULT 'system'
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS revoked_access_tokens (
 hash TEXT PRIMARY KEY,
 expires_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS password_resets (
  hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS email_verifications (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  expires_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS shares (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  invite_id INTEGER,
  long_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT '',
  public INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',
  download_limit INTEGER,
  download_count INTEGER NOT NULL DEFAULT 0,
  expires_at DATETIME,
  expiry_warned INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  full_path TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  type TEXT NOT NULL DEFAULT '',
  disk_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS downloads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  file_id INTEGER,
  ip TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS upload_sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invite_id INTEGER,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS upload_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES upload_sessions(id) ON DELETE CASCADE,
  idx INTEGER NOT NULL,
  name TEXT NOT NULL,
  full_path TEXT NOT NULL,
  size INTEGER NOT NULL,
  type TEXT NOT NULL DEFAULT '',
  received INTEGER NOT NULL DEFAULT 0,
  UNIQUE(session_id, idx)
);
CREATE TABLE IF NOT EXISTS themes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  category TEXT NOT NULL DEFAULT 'custom',
  bundled INTEGER NOT NULL DEFAULT 0,
  data TEXT NOT NULL DEFAULT '{}',
  active INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS auth_providers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  client_id TEXT NOT NULL DEFAULT '',
  client_secret TEXT NOT NULL DEFAULT '',
  issuer_url TEXT NOT NULL DEFAULT '',
  icon TEXT NOT NULL DEFAULT '',
  trust_email INTEGER NOT NULL DEFAULT 0,
  allow_registration INTEGER NOT NULL DEFAULT 1,
  sort INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS user_auth_providers (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id INTEGER NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
  provider_user_id TEXT NOT NULL,
  PRIMARY KEY(provider_id, provider_user_id)
);
CREATE TABLE IF NOT EXISTS reverse_invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_name TEXT NOT NULL DEFAULT '',
  recipient_email TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT '',
  guest_user_id INTEGER,
  expires_at DATETIME NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  completed_at DATETIME,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`

// InitSchema applies the connection pragmas and the base (idempotent) schema.
func InitSchema(db *sql.DB) error {
	if _, err := db.Exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA temp_store=MEMORY;`); err != nil {
		return err
	}
	_, err := db.Exec(BaseSchema)
	return err
}

// Seed adds the default settings (settings with their groups, then the
// storage settings) and the bundled themes that are missing; stored values,
// custom themes and the selection stay. On a database without themes the
// bundled theme named activeTheme becomes active. Setting values are sealed
// with codec (nil: plaintext). Errors are ignored, as they always were for the
// defaults.
func Seed(db *sql.DB, codec ports.ColumnCodec, settings, storageDefaults []ports.Setting, themes []ports.ThemeRecord, activeTheme string) {
	ctx := context.Background()
	// Carry an earlier "built-in background off" choice over to the new setting,
	// before the default row for it can be inserted.
	if v, err := readSetting(ctx, db, codec, "ui_default_background"); err == nil && v == "false" {
		insertSettingIfAbsent(ctx, db, codec, "ui_builtin_background", "none", "ui")
	}
	for _, d := range settings {
		insertSettingIfAbsent(ctx, db, codec, d.Key, d.Value, d.Group)
	}
	// Storage settings (internal/storage): local stays the default backend.
	for _, d := range storageDefaults {
		insertSettingIfAbsent(ctx, db, codec, d.Key, d.Value, "storage")
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM themes`).Scan(&n)
	for _, theme := range themes {
		active := 0
		if n == 0 && theme.Name == activeTheme {
			active = 1
		}
		// Add new bundles on upgrades without replacing custom data or selection.
		db.Exec(`INSERT OR IGNORE INTO themes(name,category,bundled,data,active) VALUES(?,?,?,?,?)`, theme.Name, "bundled", 1, theme.Data, active)
	}
}

// InitPlatformSchema prepares the platform database of multi-tenant mode:
// connection pragmas, the settings table, the audit chain tables, then the
// statements in extra (the platform's own schema, PlatformSchema).
func InitPlatformSchema(db *sql.DB, extra []string) error {
	stmts := []string{
		`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA temp_store=MEMORY;`,
		`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', grp TEXT NOT NULL DEFAULT 'system')`,
	}
	stmts = append(stmts, AuditSchema...)
	stmts = append(stmts, extra...)
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// MigrateReplyToFormat removes the angle brackets an earlier version stored
// around a bare Reply-To address ("<a@b.c>" becomes "a@b.c"). Values with a
// name are kept.
func MigrateReplyToFormat(db *sql.DB, codec ports.ColumnCodec) error {
	ctx := context.Background()
	v, err := readSetting(ctx, db, codec, "smtp_reply_to")
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(v) >= 3 && strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") && strings.Contains(v[1:len(v)-1], "@") && !strings.Contains(v, " ") {
		_, err = writeSetting(ctx, db, codec, "smtp_reply_to", v[1:len(v)-1])
	}
	return err
}

// Set: see ports.SettingsRepository.
func (r settingsRepo) Set(ctx context.Context, key, value string) error {
	return upsertSetting(ctx, r.q, r.codec, key, value, "system")
}
