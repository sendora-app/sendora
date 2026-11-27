// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sync"
	"sync/atomic"

	sqlite3 "github.com/mattn/go-sqlite3"
	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/storage"
)

type Store struct {
	DB          *sql.DB
	DataDir     string
	Path        string
	cipherKey   []byte
	tenantWrap  []byte // wrapping key of a tenant-supplied KEK (Cluster, D44); nil otherwise
	rootKey     []byte // file and audit keys are derived from this (= cipherKey except for imported tenants)
	settingsGen atomic.Uint64
	auditMu     ctxMutex // serialises appends, purges and carrying the log
	auditOnce   sync.Once
	auditMacFn  func([]byte) []byte
	auditVer    auditVerifyState // incremental verification (audit.go)

	backendsOnce sync.Once
	backends     *Backends // storage backends per location (storage.go)

	reposOnce sync.Once
	repos     ports.Store // repository layer on this database (Repos)

	codec           *keyring.Codec // column encryption of an encrypted database (columns.go)
	columnsUpgraded int            // plaintext values encrypted while opening (UpgradeColumnEncryption)

	closeFn      func() error           // Close of a remote store (OpenRemote)
	settingsHook atomic.Pointer[func()] // SetSettingsHook
}

// Repos returns the repository layer (internal/ports) on this database, backed
// by internal/adapters/sqlite. Domains migrated off direct SQL use it; see
// docs/cluster/REPOSITORY-PATTERN.md.
func (s *Store) Repos() ports.Store {
	s.reposOnce.Do(func() { s.repos = sqlite.New(s.DB) })
	return s.repos
}

// SettingsGen changes whenever SetSetting writes; caches use it to refresh.
func (s *Store) SettingsGen() uint64 { return s.settingsGen.Load() }

// SettingsChanged tells caches that settings were written directly (for example
// by the settings screen's transaction), so SettingsGen moves on.
func (s *Store) SettingsChanged() { s.settingsWritten() }

// The legacy driver name is confined to plaintext migration fixtures/tools.
func init() { sql.Register("sqlite", &sqlite3.SQLiteDriver{}) }

// schema is the base schema (sqlite.BaseSchema).
const schema = sqlite.BaseSchema

// Open is the plaintext legacy/fixture opener. The application entrypoint must
// use OpenEncrypted; this helper never serves as a production encryption fallback.
func Open(dataDir string) (*Store, error) { return openStore(dataDir, nil) }

func openStore(dataDir string, key []byte) (*Store, error) { return openStoreRoot(dataDir, key, nil) }

// openStoreRoot opens the store with key as the SQLCipher key. root (nil = key)
// is the secret the file-encryption master key and the audit chain key are
// derived from; only a tenant imported from a single-tenant installation has a
// root that differs from its database key (see tenant.go).
func openStoreRoot(dataDir string, key, root []byte, opts ...openOpt) (*Store, error) {
	var cfg openCfg
	for _, o := range opts {
		o(&cfg)
	}
	if root == nil {
		root = key
	}
	for _, d := range []string{"", "shares", "uploads", "backups", "branding", "backgrounds"} {
		p := filepath.Join(dataDir, d)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return nil, err
		}
	}
	p, err := DBPath(dataDir)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Chmod(p+suffix, 0o600); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	db, err := openCipherDB(p, key, false)
	if err != nil {
		return nil, err
	}
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{DB: db, DataDir: dataDir, Path: p, cipherKey: append([]byte(nil), key...), rootKey: append([]byte(nil), root...)}
	if err := s.runSchemaMigrations(); err != nil {
		db.Close()
		return nil, err
	}
	if len(key) == 32 {
		// The keys come before the settings steps: setting values are sealed.
		if err := s.enableColumnEncryption(cfg.upgradeColumns); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := s.runSettingsMigrations(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// initSchema applies connection pragmas and the base (idempotent) schema
// (sqlite.InitSchema).
func initSchema(db *sql.DB) error { return sqlite.InitSchema(db) }

// runMigrations is the additive migration sequence shared by openStore and
// PrepareImported: the schema steps, then the settings steps. Order matters:
// seed runs after the policy steps, and after migratePasswordPolicy (which must
// see an existing installation first).
func (s *Store) runMigrations() error {
	if err := s.runSchemaMigrations(); err != nil {
		return err
	}
	return s.runSettingsMigrations()
}

// runSchemaMigrations are the migration steps that change no setting value.
// They run before the database has its column codec (a new database gets its
// keys after them).
func (s *Store) runSchemaMigrations() error {
	for _, step := range []func() error{s.MigratePolicy, s.migrateIntegrity, s.migrateReverseOpen, s.migrateShareAppend, s.migrateMFA, s.migrateIdle, s.migrateUITranslations, s.migrateUsernameCase, s.migrateIPBans, s.migrateSessions, s.migratePendingRegistration, s.migrateManagedProviders, s.migrateAudit, s.migrateAccounts, s.migrateAccountSecurity, s.migratePasswordPolicy, s.migrateStorage, s.migrateIdempotency, s.migrateLookupIndexes} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// runSettingsMigrations are the steps that read or write setting values (the
// seed included). Setting values are encrypted, so they run once the column
// codec is in place.
func (s *Store) runSettingsMigrations() error {
	for _, step := range []func() error{s.migratePolicySettings, s.migrateReplyToFormat, s.migrateAuditSettings, s.migrateDownloadIP, s.migrateAccountSecuritySettings, s.migratePasswordPolicySettings} {
		if err := step(); err != nil {
			return err
		}
	}
	s.seed()
	if err := s.migrateMailLocalization(); err != nil {
		return err
	}
	return s.migrateMailLanguages()
}

// Close releases the database. The caller must have stopped all users of DB.
func (s *Store) Close() error {
	if s.DB == nil {
		clear(s.tenantWrap)
		if s.closeFn != nil {
			return s.closeFn()
		}
		return nil
	}
	if s.codec != nil {
		s.codec.Close()
	}
	return s.DB.Close()
}

// Default settings: key -> {group, value}. seed() uses INSERT OR IGNORE, so these
// only apply to NEW installations; existing ones keep their stored values.
var defaults = []struct{ Key, Grp, Val string }{
	{"application_name", "ui", "Sendora"},
	{"application_url", "system", ""},
	{"default_language", "ui", "en"},
	{"show_language_selector", "ui", "true"},
	{"allow_reverse_shares", "system", "true"},
	{"max_expiry_time", "system", "30"},
	{"default_expiry_time", "system", "7"},
	{"max_share_size", "system", "2048"}, // MB
	{"allow_self_registration", "system", "false"},
	{"registration_email_domains", "system", ""},
	{"require_email_verification", "system", "true"},
	{"clean_files_days", "system", "7"},
	{"expiry_warning_days", "system", "2"},
	{"auto_clean_files", "system", "true"},
	{"backups_enabled", "system", "true"},
	{"backup_keep", "system", "7"},
	{"require_share_password", "system", "false"},
	{"share_password_min_length", "system", "8"},
	{"share_password_require_upper", "system", "false"},
	{"share_password_require_lower", "system", "false"},
	{"share_password_require_digit", "system", "false"},
	{"share_password_require_symbol", "system", "false"},
	{"mfa_policy", "system", "optional"},
	{"mfa_reminder_days", "system", "1"},
	{"idle_logout_minutes", "system", "60"},
	{"provider_session_max_hours", "system", "24"},
	{"ip_ban_enabled", "system", "true"},
	{"ip_ban_allowlist", "system", ""},
	{"mfa_totp_enabled", "system", "true"},
	{"mfa_webauthn_enabled", "system", "true"},
	{"account_password_min_length", "system", "8"},
	{"account_password_require_upper", "system", "false"},
	{"account_password_require_lower", "system", "false"},
	{"account_password_require_digit", "system", "false"},
	{"account_password_require_symbol", "system", "false"},
	// An installation that already has accounts got 0 from migratePasswordPolicy
	// before this list is applied; only a new installation gets 365.
	{SettingPasswordMaxAgeDays, "system", PasswordMaxAgeDefault},
	{SettingPasswordHistory, "system", "5"},
	{"allow_preview", "system", "true"},
	{"local_login_enabled", "system", "true"},
	{"audit_retention_days", "system", "90"},
	{"audit_log_ip", "system", "false"},
	{"audit_forward_stdout", "system", "false"},
	{"audit_forward_syslog", "system", ""},
	{"audit_forward_syslog_tls", "system", "true"},
	{"audit_forward_webhook_url", "system", ""},
	{"smtp_host", "email", ""},
	{"smtp_port", "email", "587"},
	{"smtp_user", "email", ""},
	{"smtp_pass", "email", ""},
	{"smtp_from", "email", ""},
	{"smtp_reply_to", "email", ""},
	{"smtp_tls", "email", "starttls"},
	{"ui_background", "ui", ""},
	{"ui_logo", "ui", ""},
	{"ui_favicon", "ui", ""},
	{"ui_use_unsplash", "ui", "false"},
	{"ui_slideshow_seconds", "ui", "30"},
	{"ui_default_background", "ui", "true"},
	{"ui_builtin_background", "ui", "koenigssee"},
	{"tpl_share_created", "email_templates", "Hi {{.RecipientName}},\n\n{{.SenderName}} shared files with you: {{.URL}}\n\n{{.Message}}\n\nExpires: {{.Expires}}"},
	{"tpl_share_downloaded", "email_templates", "Your share \"{{.ShareName}}\" was downloaded."},
	{"tpl_share_expiring", "email_templates", "Your share \"{{.ShareName}}\" expires on {{.Expires}}: {{.URL}}"},
	{"tpl_password_reset", "email_templates", "Reset your password: {{.URL}}\n\nLink valid for 1 hour."},
	{"tpl_verify_email", "email_templates", "Your verification code is {{.Code}}"},
	{"tpl_reverse_invite", "email_templates", "Hi {{.RecipientName}},\n\n{{.SenderName}} invites you to upload files: {{.URL}}\n\n{{.Message}}"},
}

// Keep insertion order stable, with Light as the fresh-install default.
var builtinThemes = []struct{ Name, Data string }{
	{"Light", `{"primary":"#2563eb","bg":"#f8fafc","surface":"#ffffff","text":"#0f172a","muted":"#64748b","border":"#e2e8f0","danger":"#dc2626"}`},
	{"Dark", `{"primary":"#60a5fa","bg":"#0b1220","surface":"#111a2e","text":"#e5e7eb","muted":"#94a3b8","border":"#1f2a44","danger":"#f87171"}`},
	{"Forest", `{"primary":"#16a34a","bg":"#f0fdf4","surface":"#ffffff","text":"#052e16","muted":"#4d7c5f","border":"#bbf7d0","danger":"#dc2626"}`},
	{"Ocean", `{"primary":"#036985","bg":"#f0f9fc","surface":"#ffffff","text":"#123444","muted":"#465963","border":"#cbdde5","danger":"#b42332"}`},
	{"Midnight", `{"primary":"#93c5fd","bg":"#0b1020","surface":"#151e32","text":"#f1f5f9","muted":"#c1cedd","border":"#334155","danger":"#fda4af"}`},
	{"Violet", `{"primary":"#6d28d9","bg":"#f7f3ff","surface":"#ffffff","text":"#2e164a","muted":"#665477","border":"#e1d5ee","danger":"#b42332"}`},
	{"Sand", `{"primary":"#80521f","bg":"#faf6ef","surface":"#fffdf8","text":"#382b1e","muted":"#6b5c4b","border":"#e2d6c6","danger":"#b42332"}`},
	{"Rose", `{"primary":"#be185d","bg":"#fff1f4","surface":"#ffffff","text":"#4c1830","muted":"#775363","border":"#efd3df","danger":"#b42332"}`},
	{"Slate", `{"primary":"#67e8f9","bg":"#17212b","surface":"#22303d","text":"#f1f5f9","muted":"#cbd5e1","border":"#475569","danger":"#fda4af"}`},
	{"High Contrast", `{"primary":"#ffff00","bg":"#000000","surface":"#000000","text":"#ffffff","muted":"#ffffff","border":"#767676","danger":"#ffb3b3"}`},
	{"Nord", `{"primary":"#88c0d0","bg":"#2e3440","surface":"#3b4252","text":"#eceff4","muted":"#d8dee9","border":"#4c566a","danger":"#ff9aa2"}`},
	{"Solarized Light", `{"primary":"#0b6aa2","bg":"#fdf6e3","surface":"#fffaf0","text":"#073642","muted":"#586e75","border":"#e4dcc4","danger":"#b42318"}`},
	{"Solarized Dark", `{"primary":"#4aa8e0","bg":"#002b36","surface":"#073642","text":"#eee8d5","muted":"#b4c0bf","border":"#2a5560","danger":"#ff8a80"}`},
	{"Mint", `{"primary":"#0f766e","bg":"#f0fdfa","surface":"#ffffff","text":"#042f2e","muted":"#46635f","border":"#c3ece5","danger":"#b42332"}`},
	{"Sunset", `{"primary":"#c2410c","bg":"#fff7ed","surface":"#ffffff","text":"#431407","muted":"#7a5340","border":"#f3d9c3","danger":"#b42332"}`},
	{"Lavender", `{"primary":"#5b4bc4","bg":"#f5f3ff","surface":"#ffffff","text":"#1e1b4b","muted":"#5d5a85","border":"#ddd8f5","danger":"#b42332"}`},
	{"Graphite", `{"primary":"#fbbf24","bg":"#18181b","surface":"#27272a","text":"#fafafa","muted":"#d4d4d8","border":"#52525b","danger":"#fca5a5"}`},
	{"Coffee", `{"primary":"#e0b084","bg":"#1f1612","surface":"#2b201a","text":"#f5ebe0","muted":"#d6c3b0","border":"#4d3a2e","danger":"#ffab91"}`},
	{"Citrus", `{"primary":"#4d7c0f","bg":"#f7fee7","surface":"#ffffff","text":"#1a2e05","muted":"#4f6330","border":"#d9ecb0","danger":"#b42332"}`},
	{"Aqua Night", `{"primary":"#5eead4","bg":"#042f2e","surface":"#0b3f3d","text":"#f0fdfa","muted":"#b5d9d4","border":"#1f5f5a","danger":"#fda4af"}`},
}

// seed applies the default settings and bundled themes (sqlite.Seed): new
// keys and themes are added, stored values and the theme selection stay.
func (s *Store) seed() {
	sqlite.Seed(s.DB, s.ColumnCodec(), defaultSettings(), storageDefaultSettings(), bundledThemes(), activeThemeDefault)
}

// activeThemeDefault is the bundled theme a new installation starts with.
const activeThemeDefault = "Light"

func defaultSettings() []ports.Setting {
	out := make([]ports.Setting, 0, len(defaults))
	for _, d := range defaults {
		out = append(out, ports.Setting{Key: d.Key, Value: d.Val, Group: d.Grp})
	}
	return out
}

func storageDefaultSettings() []ports.Setting {
	out := make([]ports.Setting, 0, len(storage.Settings))
	for _, d := range storage.Settings {
		out = append(out, ports.Setting{Key: d.Key, Value: d.Default, Group: "storage"})
	}
	return out
}

func bundledThemes() []ports.ThemeRecord {
	out := make([]ports.ThemeRecord, 0, len(builtinThemes))
	for _, t := range builtinThemes {
		out = append(out, ports.ThemeRecord{Name: t.Name, Data: t.Data})
	}
	return out
}

func (s *Store) Setting(key string) string {
	v, _ := s.Repos().Settings().Get(context.Background(), key)
	return v
}

func (s *Store) SettingBool(key string) bool {
	return strings.EqualFold(s.Setting(key), "true")
}

func (s *Store) SettingInt(key string, def int) int {
	var n int
	if _, err := fmt.Sscanf(s.Setting(key), "%d", &n); err != nil {
		return def
	}
	return n
}

func (s *Store) SetSetting(key, val string) error {
	err := s.Repos().Settings().Set(context.Background(), key, val)
	s.settingsWritten()
	return err
}
