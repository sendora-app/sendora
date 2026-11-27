// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

var (
	_ ports.PlatformStore = (*PlatformStore)(nil)
	_ ports.PlatformTx    = (*PlatformTx)(nil)
)

// platformRepos hands out the platform repositories bound to one querier.
type platformRepos struct {
	q     querier
	codec ports.ColumnCodec // nil: encrypted columns hold plaintext (see ports.ColumnCodec)
}

func (r platformRepos) Tenants() ports.TenantRepository             { return tenantRepo{q: r.q, codec: r.codec} }
func (r platformRepos) TenantDomains() ports.TenantDomainRepository { return tenantDomainRepo{q: r.q} }
func (r platformRepos) TenantStorage() ports.TenantStorageRepository {
	return tenantStorageRepo{q: r.q}
}
func (r platformRepos) PlatformAdmins() ports.PlatformAdminRepository {
	return platformAdminRepo{q: r.q, codec: r.codec}
}
func (r platformRepos) PlatformSessions() ports.PlatformSessionRepository {
	return platformSessionRepo{q: r.q}
}
func (r platformRepos) PlatformSettings() ports.PlatformSettingsRepository {
	return platformSettingsRepo{q: r.q, codec: r.codec}
}
func (r platformRepos) PlatformAudit() ports.PlatformAuditRepository {
	return platformAuditRepo{q: r.q, codec: r.codec}
}
func (r platformRepos) ControlLog() ports.ControlLogRepository {
	return controlLogRepo{q: r.q}
}
func (r platformRepos) Keyring() ports.KeyringRepository {
	return keyringRepo{q: r.q}
}

// PlatformStore implements ports.PlatformStore on the platform database.
type PlatformStore struct {
	platformRepos
	db *sql.DB
}

// NewPlatform returns the PlatformStore for db (not taking ownership).
func NewPlatform(db *sql.DB) *PlatformStore {
	return &PlatformStore{platformRepos: platformRepos{q: db}, db: db}
}

// SetCodec makes the adapter encrypt and decrypt the encrypted columns of the
// platform database with c (design 6.5, D39). Call it before the store is used.
func (s *PlatformStore) SetCodec(c ports.ColumnCodec) { s.platformRepos.codec = c }

// Begin starts a (deferred) SQLite transaction on the platform database.
func (s *PlatformStore) Begin(ctx context.Context) (ports.PlatformTx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &PlatformTx{platformRepos: platformRepos{q: tx, codec: s.codec}, tx: tx}, nil
}

// PlatformTx implements ports.PlatformTx.
type PlatformTx struct {
	platformRepos
	tx *sql.Tx
}

func (t *PlatformTx) Commit() error   { return commitOutcome(t.tx.Commit()) }
func (t *PlatformTx) Rollback() error { return t.tx.Rollback() }

// ---------- schema ----------

// platformSchemaVersion is stored as platform_schema_version.
const platformSchemaVersion = 1

// PlatformSchema is the platform's own schema (OpenPlatform runs it after the
// settings and audit tables; see InitPlatformSchema).
var PlatformSchema = []string{
	`CREATE TABLE IF NOT EXISTS tenants (
		id TEXT PRIMARY KEY,
		slug TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','importing')),
		created_at TEXT NOT NULL,
		max_users INTEGER NOT NULL DEFAULT 0 CHECK (max_users >= 0),
		max_storage_bytes INTEGER NOT NULL DEFAULT 0 CHECK (max_storage_bytes >= 0),
		key_mode TEXT NOT NULL DEFAULT 'derived' CHECK (key_mode IN ('derived','legacy')),
		legacy_root BLOB,
		primary_domain TEXT NOT NULL DEFAULT '',
		stat_users INTEGER NOT NULL DEFAULT 0,
		stat_storage_bytes INTEGER NOT NULL DEFAULT 0,
		stat_updated_at TEXT NOT NULL DEFAULT '',
		allow_private_targets INTEGER NOT NULL DEFAULT 0,
		kek_mode TEXT NOT NULL DEFAULT 'platform' CHECK (kek_mode IN ('platform','tenant')),
		kek_fingerprint TEXT NOT NULL DEFAULT '',
		master_version INTEGER NOT NULL DEFAULT 1)`,
	`CREATE TABLE IF NOT EXISTS tenant_domains (
		domain TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		kind TEXT NOT NULL DEFAULT 'custom' CHECK (kind IN ('custom')),
		verified INTEGER NOT NULL DEFAULT 0,
		verify_token TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS idx_tenant_domains_tenant ON tenant_domains(tenant_id)`,
	`CREATE TABLE IF NOT EXISTS tenant_storage (
		tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
		mode TEXT NOT NULL DEFAULT 'platform' CHECK (mode IN ('platform','own')),
		prefix TEXT NOT NULL DEFAULT '',
		config TEXT NOT NULL DEFAULT '{}',
		tenant_managed INTEGER NOT NULL DEFAULT 1,
		tenant_managed_explicit INTEGER NOT NULL DEFAULT 0,
		offer TEXT NOT NULL DEFAULT 'none',
		updated_at TEXT NOT NULL DEFAULT '')`,
	`CREATE TABLE IF NOT EXISTS platform_admins (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE COLLATE NOCASE,
		email TEXT NOT NULL DEFAULT '',
		password_hash TEXT NOT NULL,
		totp_secret TEXT NOT NULL DEFAULT '',
		totp_enabled INTEGER NOT NULL DEFAULT 0,
		totp_last_counter INTEGER NOT NULL DEFAULT 0,
		pending_totp_secret TEXT NOT NULL DEFAULT '',
		failures INTEGER NOT NULL DEFAULT 0,
		locked_until INTEGER NOT NULL DEFAULT 0,
		must_change_password INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS platform_sessions (
		hash TEXT PRIMARY KEY,
		admin_id INTEGER NOT NULL REFERENCES platform_admins(id) ON DELETE CASCADE,
		stage TEXT NOT NULL CHECK (stage IN ('mfa','enroll','full')),
		created_at INTEGER NOT NULL,
		last_seen INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		mfa_at INTEGER NOT NULL DEFAULT 0)`,
}

// EnsureSchemaVersion stores the platform schema version marker unless it
// exists. It is not part of PlatformSchema: setting values are sealed, so the
// marker is written once the database has its column keys.
func (s *PlatformStore) EnsureSchemaVersion(ctx context.Context) error {
	return s.PlatformSettings().EnsureDefault(ctx, "platform_schema_version", fmt.Sprint(platformSchemaVersion), "system")
}

// MigratePlatform adds the columns that arrived after the first 0.2.0
// development builds and gives older rows their meaning: tenants stored
// before the storage offer existed keep the platform default, and own storage
// stays allowed unless it was switched off explicitly.
func MigratePlatform(db *sql.DB) error {
	var hadOffer int
	db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('tenant_storage') WHERE name='offer'`).Scan(&hadOffer)
	for _, c := range []struct{ table, name, decl string }{
		{"tenants", "allow_private_targets", "INTEGER NOT NULL DEFAULT 0"},
		{"tenants", "kek_mode", "TEXT NOT NULL DEFAULT 'platform'"},
		{"tenants", "kek_fingerprint", "TEXT NOT NULL DEFAULT ''"},
		{"tenants", "master_version", "INTEGER NOT NULL DEFAULT 1"},
		{"tenant_storage", "tenant_managed", "INTEGER NOT NULL DEFAULT 1"},
		{"tenant_storage", "tenant_managed_explicit", "INTEGER NOT NULL DEFAULT 0"},
		{"tenant_storage", "offer", "TEXT NOT NULL DEFAULT 'none'"},
		{"platform_admins", "must_change_password", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := addColumn(db, c.table, c.name, c.decl); err != nil {
			return err
		}
	}
	// Tenants stored before the storage offer existed keep what they had: the
	// platform default (with their prefix, or their directory while the
	// default is local).
	if hadOffer == 0 {
		if _, err := db.Exec(`UPDATE tenant_storage SET offer='platform' WHERE mode='platform'`); err != nil {
			return err
		}
	}
	// Tenants may configure their own storage unless a platform administrator
	// switched it off for them (an explicit choice); older rows had no choice.
	_, err := db.Exec(`UPDATE tenant_storage SET tenant_managed=1 WHERE tenant_managed_explicit=0 AND tenant_managed=0`)
	return err
}

func addColumn(db *sql.DB, table, name, decl string) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, table, name).Scan(&n); err != nil || n > 0 {
		return err
	}
	_, err := db.Exec("ALTER TABLE " + table + " ADD COLUMN " + name + " " + decl)
	return err
}

// ---------- tenants ----------

type tenantRepo struct {
	q     querier
	codec ports.ColumnCodec
}

const tenantCols = `id,slug,name,status,created_at,max_users,max_storage_bytes,key_mode,legacy_root,primary_domain,stat_users,stat_storage_bytes,stat_updated_at,allow_private_targets,kek_mode,kek_fingerprint,master_version`

func (r tenantRepo) scanTenant(row interface{ Scan(...any) error }) (ports.TenantRecord, error) {
	var t ports.TenantRecord
	err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.CreatedAt, &t.MaxUsers, &t.MaxStorageBytes, &t.KeyMode, &t.LegacyRoot, &t.PrimaryDomain, &t.StatUsers, &t.StatStorageBytes, &t.StatUpdatedAt, &t.AllowPrivateTargets, &t.KEKMode, &t.KEKFingerprint, &t.MasterVersion)
	if err != nil {
		return t, err
	}
	if r.codec != nil && len(t.LegacyRoot) > 0 {
		root, err := openColKey(r.codec, "tenants", "legacy_root", t.ID, string(t.LegacyRoot))
		if err != nil {
			return t, err
		}
		t.LegacyRoot = []byte(root)
	}
	return t, nil
}

func (r tenantRepo) ByID(ctx context.Context, id string) (ports.TenantRecord, error) {
	t, err := r.scanTenant(r.q.QueryRowContext(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id=?`, id))
	return t, notFound(err)
}

func (r tenantRepo) BySlug(ctx context.Context, slug string) (ports.TenantRecord, error) {
	t, err := r.scanTenant(r.q.QueryRowContext(ctx, `SELECT `+tenantCols+` FROM tenants WHERE slug=?`, slug))
	return t, notFound(err)
}

func (r tenantRepo) List(ctx context.Context, search string) ([]ports.TenantRecord, error) {
	query := `SELECT ` + tenantCols + ` FROM tenants`
	var args []any
	if search != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(search) + "%"
		query += ` WHERE lower(slug) LIKE ? ESCAPE '\' OR lower(name) LIKE ? ESCAPE '\' OR id IN (SELECT tenant_id FROM tenant_domains WHERE domain LIKE ? ESCAPE '\')`
		args = append(args, like, like, like)
	}
	query += ` ORDER BY slug`
	rows, err := r.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ports.TenantRecord{}
	for rows.Next() {
		t, err := r.scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r tenantRepo) CountBySlug(ctx context.Context, slug string) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants WHERE slug=?`, slug).Scan(&n)
	return n, err
}

func (r tenantRepo) Insert(ctx context.Context, t ports.TenantRecord) error {
	var root any
	if t.LegacyRoot != nil {
		root = t.LegacyRoot
		if r.codec != nil {
			sealed, err := sealColKey(r.codec, "tenants", "legacy_root", t.ID, string(t.LegacyRoot))
			if err != nil {
				return err
			}
			root = []byte(sealed)
		}
	}
	_, err := r.q.ExecContext(ctx, `INSERT INTO tenants(id,slug,name,status,created_at,max_users,max_storage_bytes,key_mode,legacy_root,primary_domain,master_version) VALUES(?,?,?,?,?,?,?,?,?,'',?)`,
		t.ID, t.Slug, t.Name, t.Status, t.CreatedAt, t.MaxUsers, t.MaxStorageBytes, t.KeyMode, root, max(t.MasterVersion, 1))
	return err
}

func (r tenantRepo) SetStatus(ctx context.Context, id, status string) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE tenants SET status=? WHERE id=? AND status IN ('active','suspended')`, status, id))
}

func (r tenantRepo) Activate(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE tenants SET status='active' WHERE id=? AND status='importing'`, id)
	return err
}

func (r tenantRepo) SetQuotas(ctx context.Context, id string, maxUsers, maxStorageBytes int64) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE tenants SET max_users=?, max_storage_bytes=? WHERE id=?`, maxUsers, maxStorageBytes, id))
}

func (r tenantRepo) SetName(ctx context.Context, id, name string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE tenants SET name=? WHERE id=?`, name, id)
	return err
}

func (r tenantRepo) UpdateStats(ctx context.Context, id string, users, storageBytes int64, at string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE tenants SET stat_users=?, stat_storage_bytes=?, stat_updated_at=? WHERE id=?`, users, storageBytes, at, id)
	return err
}

func (r tenantRepo) SetAllowPrivateTargets(ctx context.Context, id string, allow bool) (int64, error) {
	v := 0
	if allow {
		v = 1
	}
	return changed(r.q.ExecContext(ctx, `UPDATE tenants SET allow_private_targets=? WHERE id=?`, v, id))
}

func (r tenantRepo) SetKEK(ctx context.Context, id, mode, fingerprint string) (int64, error) {
	if mode != "platform" && mode != "tenant" {
		return 0, fmt.Errorf("invalid KEK mode %q", mode)
	}
	return changed(r.q.ExecContext(ctx, `UPDATE tenants SET kek_mode=?, kek_fingerprint=? WHERE id=?`, mode, fingerprint, id))
}

func (r tenantRepo) SetMasterVersion(ctx context.Context, id string, from, to int) (int64, error) {
	if from < 1 || to <= from {
		return 0, fmt.Errorf("invalid master version change %d -> %d", from, to)
	}
	return changed(r.q.ExecContext(ctx, `UPDATE tenants SET master_version=? WHERE id=? AND master_version=?`, to, id, from))
}

func (r tenantRepo) CountByMasterVersion(ctx context.Context) (map[int]int, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT master_version, COUNT(*) FROM tenants WHERE status IN ('active','suspended','importing') GROUP BY master_version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]int{}
	for rows.Next() {
		var v, n int
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		out[v] = n
	}
	return out, rows.Err()
}

func (r tenantRepo) SetPrimaryDomain(ctx context.Context, id, domain string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE tenants SET primary_domain=? WHERE id=?`, domain, id)
	return err
}

func (r tenantRepo) ClearPrimaryDomain(ctx context.Context, id, domain string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE tenants SET primary_domain='' WHERE id=? AND primary_domain=?`, id, domain)
	return err
}

func (r tenantRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM tenants WHERE id=?`, id)
	return err
}

func (r tenantRepo) DeleteImporting(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM tenants WHERE id=? AND status='importing'`, id)
	return err
}

func (r tenantRepo) Routes(ctx context.Context) ([]ports.TenantRoute, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id,slug,status,primary_domain FROM tenants`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.TenantRoute
	for rows.Next() {
		var t ports.TenantRoute
		if err := rows.Scan(&t.ID, &t.Slug, &t.Status, &t.PrimaryDomain); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---------- domains ----------

type tenantDomainRepo struct{ q querier }

func (r tenantDomainRepo) VerifiedCustom(ctx context.Context) (map[string]string, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT d.domain,d.tenant_id FROM tenant_domains d JOIN tenants t ON t.id=d.tenant_id WHERE d.verified=1 AND d.kind='custom'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, id string
		if err := rows.Scan(&k, &id); err != nil {
			return nil, err
		}
		m[k] = id
	}
	return m, rows.Err()
}

func (r tenantDomainRepo) List(ctx context.Context, tenantID string) ([]ports.TenantDomain, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT domain,tenant_id,kind,verified,verify_token,created_at FROM tenant_domains WHERE tenant_id=? ORDER BY domain`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ports.TenantDomain{}
	for rows.Next() {
		var d ports.TenantDomain
		if err := rows.Scan(&d.Domain, &d.TenantID, &d.Kind, &d.Verified, &d.VerifyToken, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r tenantDomainRepo) AddCustom(ctx context.Context, domain, tenantID, verifyToken, createdAt string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO tenant_domains(domain,tenant_id,kind,verified,verify_token,created_at) VALUES(?,?,'custom',0,?,?)`, domain, tenantID, verifyToken, createdAt)
	return err
}

func (r tenantDomainRepo) MarkVerified(ctx context.Context, domain, tenantID string) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE tenant_domains SET verified=1 WHERE domain=? AND tenant_id=? AND kind='custom'`, domain, tenantID))
}

func (r tenantDomainRepo) RemoveCustom(ctx context.Context, domain, tenantID string) (int64, error) {
	return changed(r.q.ExecContext(ctx, `DELETE FROM tenant_domains WHERE domain=? AND tenant_id=? AND kind='custom'`, domain, tenantID))
}

func (r tenantDomainRepo) CountVerified(ctx context.Context, domain, tenantID string) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_domains WHERE domain=? AND tenant_id=? AND verified=1`, domain, tenantID).Scan(&n)
	return n, err
}

// ---------- storage decisions ----------

type tenantStorageRepo struct{ q querier }

func (r tenantStorageRepo) CreateDefault(ctx context.Context, tenantID, prefix, at string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO tenant_storage(tenant_id,mode,prefix,offer,tenant_managed,updated_at) VALUES(?, 'platform', ?, 'none', 1, ?)`, tenantID, prefix, at)
	return err
}

func (r tenantStorageRepo) Get(ctx context.Context, tenantID string) (ports.TenantStorageDecision, error) {
	var d ports.TenantStorageDecision
	var managed int
	err := r.q.QueryRowContext(ctx, `SELECT offer,tenant_managed,updated_at FROM tenant_storage WHERE tenant_id=?`, tenantID).Scan(&d.Offer, &managed, &d.UpdatedAt)
	d.TenantManaged = managed != 0
	return d, notFound(err)
}

func (r tenantStorageRepo) Set(ctx context.Context, tenantID, prefix, offer string, tenantManaged bool, at string) (int64, error) {
	managed := 0
	if tenantManaged {
		managed = 1
	}
	return changed(r.q.ExecContext(ctx, `INSERT INTO tenant_storage(tenant_id,mode,prefix,offer,tenant_managed,tenant_managed_explicit,updated_at) SELECT ?,'platform',?,?,?,1,? WHERE EXISTS (SELECT 1 FROM tenants WHERE id=?)
		ON CONFLICT(tenant_id) DO UPDATE SET offer=excluded.offer,tenant_managed=excluded.tenant_managed,tenant_managed_explicit=1,updated_at=excluded.updated_at`,
		tenantID, prefix, offer, managed, at, tenantID))
}

// ---------- administrators ----------

type platformAdminRepo struct {
	q     querier
	codec ports.ColumnCodec
}

const platformAdminCols = `id,username,email,totp_enabled,created_at,password_hash,totp_secret,pending_totp_secret,totp_last_counter,failures,locked_until,must_change_password`

func (r platformAdminRepo) scanPlatformAdmin(row interface{ Scan(...any) error }) (ports.PlatformAdmin, error) {
	var a ports.PlatformAdmin
	err := row.Scan(&a.ID, &a.Username, &a.Email, &a.TOTPEnabled, &a.CreatedAt, &a.PasswordHash, &a.TOTPSecret, &a.PendingTOTP, &a.LastCounter, &a.Failures, &a.LockedUntil, &a.MustChangePassword)
	if err != nil {
		return a, err
	}
	if a.TOTPSecret, err = openCol(r.codec, "platform_admins", "totp_secret", a.ID, a.TOTPSecret); err != nil {
		return a, err
	}
	a.PendingTOTP, err = openCol(r.codec, "platform_admins", "pending_totp_secret", a.ID, a.PendingTOTP)
	return a, err
}

func (r platformAdminRepo) Count(ctx context.Context) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_admins`).Scan(&n)
	return n, err
}

func (r platformAdminRepo) ByName(ctx context.Context, username string) (ports.PlatformAdmin, error) {
	a, err := r.scanPlatformAdmin(r.q.QueryRowContext(ctx, `SELECT `+platformAdminCols+` FROM platform_admins WHERE username=?`, username))
	return a, notFound(err)
}

func (r platformAdminRepo) ByID(ctx context.Context, id int64) (ports.PlatformAdmin, error) {
	a, err := r.scanPlatformAdmin(r.q.QueryRowContext(ctx, `SELECT `+platformAdminCols+` FROM platform_admins WHERE id=?`, id))
	return a, notFound(err)
}

func (r platformAdminRepo) List(ctx context.Context) ([]ports.PlatformAdmin, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+platformAdminCols+` FROM platform_admins ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ports.PlatformAdmin{}
	for rows.Next() {
		a, err := r.scanPlatformAdmin(rows)
		if err != nil {
			return nil, notFound(err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r platformAdminRepo) Create(ctx context.Context, username, email, passwordHash, createdAt string) (int64, error) {
	res, err := r.q.ExecContext(ctx, `INSERT INTO platform_admins(username,email,password_hash,created_at) VALUES(?,?,?,?)`, username, email, passwordHash, createdAt)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId() // contract of the 0.2 caller: the id error was ignored
	return id, nil
}

func (r platformAdminRepo) CreateFirst(ctx context.Context, username, email, passwordHash, createdAt string) (int64, bool, error) {
	res, err := r.q.ExecContext(ctx, `INSERT INTO platform_admins(username,email,password_hash,created_at) SELECT ?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM platform_admins)`, username, email, passwordHash, createdAt)
	if err != nil {
		return 0, false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, false, nil
	}
	id, _ := res.LastInsertId()
	return id, true, nil
}

func (r platformAdminRepo) DeleteUnlessLast(ctx context.Context, id int64) (int64, error) {
	return changed(r.q.ExecContext(ctx, `DELETE FROM platform_admins WHERE id=? AND (SELECT COUNT(*) FROM platform_admins)>1`, id))
}

func (r platformAdminRepo) SetPassword(ctx context.Context, id int64, hash string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE platform_admins SET password_hash=?, must_change_password=0 WHERE id=?`, hash, id)
	return err
}

func (r platformAdminRepo) SetTemporaryPassword(ctx context.Context, id int64, hash string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE platform_admins SET password_hash=?, must_change_password=1, failures=0, locked_until=0 WHERE id=?`, hash, id)
	return err
}

func (r platformAdminRepo) NoteLoginFailure(ctx context.Context, id int64, limit int, lockUntil int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE platform_admins SET failures=failures+1, locked_until=CASE WHEN failures+1>=? THEN ? ELSE locked_until END WHERE id=?`, limit, lockUntil, id)
	return err
}

func (r platformAdminRepo) ClearLoginFailures(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE platform_admins SET failures=0, locked_until=0 WHERE id=?`, id)
	return err
}

func (r platformAdminRepo) SetPendingTOTP(ctx context.Context, id int64, secret string) error {
	sealed, err := sealCol(r.codec, "platform_admins", "pending_totp_secret", id, secret)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `UPDATE platform_admins SET pending_totp_secret=? WHERE id=?`, sealed, id)
	return err
}

func (r platformAdminRepo) EnableTOTP(ctx context.Context, id, counter int64) error {
	if r.codec == nil {
		_, err := r.q.ExecContext(ctx, `UPDATE platform_admins SET totp_secret=pending_totp_secret, pending_totp_secret='', totp_enabled=1, totp_last_counter=? WHERE id=? AND pending_totp_secret<>''`, counter, id)
		return err
	}
	// The ciphertext is bound to its column: the pending secret is opened and
	// sealed again for totp_secret (the update only applies while the pending
	// value is still the one read).
	var pending string
	if err := r.q.QueryRowContext(ctx, `SELECT pending_totp_secret FROM platform_admins WHERE id=?`, id).Scan(&pending); err != nil || pending == "" {
		if err == nil || errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	plain, err := openCol(r.codec, "platform_admins", "pending_totp_secret", id, pending)
	if err != nil {
		return err
	}
	sealed, err := sealCol(r.codec, "platform_admins", "totp_secret", id, plain)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `UPDATE platform_admins SET totp_secret=?, pending_totp_secret='', totp_enabled=1, totp_last_counter=? WHERE id=? AND pending_totp_secret=?`, sealed, counter, id, pending)
	return err
}

func (r platformAdminRepo) UseTOTPCounter(ctx context.Context, id, counter int64) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE platform_admins SET totp_last_counter=? WHERE id=? AND totp_last_counter<?`, counter, id, counter))
}

func (r platformAdminRepo) ResetTOTP(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE platform_admins SET totp_secret='', pending_totp_secret='', totp_enabled=0, totp_last_counter=0 WHERE id=?`, id)
	return err
}

// ---------- console sessions ----------

type platformSessionRepo struct{ q querier }

func (r platformSessionRepo) Create(ctx context.Context, s ports.PlatformSession) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO platform_sessions(hash,admin_id,stage,created_at,last_seen,expires_at,mfa_at) VALUES(?,?,?,?,?,?,?)`,
		s.Hash, s.AdminID, s.Stage, s.CreatedAt, s.LastSeen, s.ExpiresAt, s.MFAAt)
	return err
}

func (r platformSessionRepo) Get(ctx context.Context, hash string) (ports.PlatformSession, error) {
	s := ports.PlatformSession{Hash: hash}
	err := r.q.QueryRowContext(ctx, `SELECT admin_id,stage,created_at,last_seen,expires_at,mfa_at FROM platform_sessions WHERE hash=?`, hash).Scan(&s.AdminID, &s.Stage, &s.CreatedAt, &s.LastSeen, &s.ExpiresAt, &s.MFAAt)
	return s, notFound(err)
}

func (r platformSessionRepo) Touch(ctx context.Context, hash string, lastSeen int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE platform_sessions SET last_seen=? WHERE hash=?`, lastSeen, hash)
	return err
}

func (r platformSessionRepo) Promote(ctx context.Context, hash string, mfaAt int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE platform_sessions SET stage='full', mfa_at=? WHERE hash=?`, mfaAt, hash)
	return err
}

func (r platformSessionRepo) SetMFAAt(ctx context.Context, hash string, mfaAt int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE platform_sessions SET mfa_at=? WHERE hash=?`, mfaAt, hash)
	return err
}

func (r platformSessionRepo) Delete(ctx context.Context, hash string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM platform_sessions WHERE hash=?`, hash)
	return err
}

func (r platformSessionRepo) DeleteForAdmin(ctx context.Context, adminID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM platform_sessions WHERE admin_id=?`, adminID)
	return err
}

func (r platformSessionRepo) DeleteWithoutTOTP(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM platform_sessions WHERE admin_id IN (SELECT id FROM platform_admins WHERE totp_enabled=0)`)
	return err
}

func (r platformSessionRepo) PruneExpired(ctx context.Context, before int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM platform_sessions WHERE expires_at<?`, before)
	return err
}

// ---------- settings ----------

type platformSettingsRepo struct {
	q     querier
	codec ports.ColumnCodec
}

func (r platformSettingsRepo) Get(ctx context.Context, key string) (string, error) {
	v, err := readSetting(ctx, r.q, r.codec, key)
	return v, notFound(err)
}

func (r platformSettingsRepo) Update(ctx context.Context, key, value string) error {
	_, err := writeSetting(ctx, r.q, r.codec, key, value)
	return err
}

func (r platformSettingsRepo) EnsureDefault(ctx context.Context, key, value, group string) error {
	return insertSettingIfAbsent(ctx, r.q, r.codec, key, value, group)
}

// ---------- audit ----------

type platformAuditRepo struct {
	q     querier
	codec ports.ColumnCodec
}

func (r platformAuditRepo) Page(ctx context.Context, before int64, limit int) ([]ports.AuditRecord, error) {
	q := `SELECT seq,ts,category,actor_id,actor_name,actor_role,action,target,outcome,detail,ip,prev_hash,hash FROM audit_log`
	args := []any{}
	if before > 0 {
		q += ` WHERE seq<?`
		args = append(args, before)
	}
	q += ` ORDER BY seq DESC LIMIT ` + strconv.Itoa(limit)
	rows, err := r.q.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ports.AuditRecord{}
	for rows.Next() {
		var a ports.AuditRecord
		if err := rows.Scan(&a.Seq, &a.TS, &a.Category, &a.ActorID, &a.ActorName, &a.ActorRole, &a.Action, &a.Target, &a.Outcome, &a.Detail, &a.IP, &a.PrevHash, &a.Hash); err != nil {
			return nil, err
		}
		if err := openAudit(r.codec, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
