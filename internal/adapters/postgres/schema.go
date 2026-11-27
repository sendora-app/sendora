// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

// Schema selects which database a migration sequence belongs to.
type Schema int

const (
	// TenantSchema is a tenant's database (or a single organisation's).
	TenantSchema Schema = iota
	// PlatformSchema is the platform database of multi-tenant mode.
	PlatformSchema
)

func (s Schema) String() string {
	if s == PlatformSchema {
		return "platform"
	}
	return "tenant"
}

// Migration is one versioned, transactional schema step. Versions are never
// renumbered or edited once released; a change is a new version.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Migrations returns the ordered migration sequence of s.
func Migrations(s Schema) []Migration {
	if s == PlatformSchema {
		return platformMigrations
	}
	return tenantMigrations
}

// Migrate applies the migrations of s that schema_migrations does not list
// yet, in one transaction, under an advisory lock (concurrent callers wait
// and then find nothing to do). It runs on the schema first on the
// connection's search_path, which must exist. Design 13.2: in Cluster the
// controller runs this as the database owner role; web pods never migrate.
func Migrate(ctx context.Context, db *sql.DB, s Schema) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := pq{raw: tx, tx: true}
	if err := q.lock(ctx, "migrate"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY,
		name text COLLATE "C" NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	applied := map[int]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, m := range Migrations(s) {
		if applied[m.Version] {
			continue
		}
		if _, err := tx.ExecContext(ctx, expandDDL(m.SQL)); err != nil {
			return fmt.Errorf("%s migration %d (%s): %w", s, m.Version, m.Name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,name) VALUES($1,$2)`, m.Version, m.Name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AppliedVersions lists the applied migration versions of the schema on the
// search_path, ascending (empty before the first Migrate).
func AppliedVersions(ctx context.Context, db *sql.DB) ([]int, error) {
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// expandDDL fills the tokens the DDL constants use: CTEXT is text with the
// "C" collation (byte order and ASCII-only case folding, like SQLite's
// default), NOW_S the second-truncated current time that stands in for
// SQLite's CURRENT_TIMESTAMP, LOCKCLASS the advisory lock class.
func expandDDL(ddl string) string {
	return strings.NewReplacer(
		"CTEXT", `text COLLATE "C"`,
		"NOW_S", `date_trunc('second', now())`,
		"LOCKCLASS", strconv.Itoa(lockClass),
	).Replace(ddl)
}

// auditDDL is the audit chain of tenant and platform databases: records,
// checkpoint, change guard and the highest issued sequence number (SQLite
// keeps that in sqlite_sequence; here audit_issued, advanced by a trigger
// like AUTOINCREMENT advances sqlite_sequence on explicit inserts).
const auditDDL = `
CREATE TABLE audit_log (
  seq bigint PRIMARY KEY,
  ts CTEXT NOT NULL,
  category CTEXT NOT NULL,
  actor_id bigint NOT NULL DEFAULT 0,
  actor_name CTEXT NOT NULL DEFAULT '',
  actor_role CTEXT NOT NULL DEFAULT '',
  action CTEXT NOT NULL,
  target CTEXT NOT NULL DEFAULT '',
  outcome CTEXT NOT NULL DEFAULT 'ok',
  detail CTEXT NOT NULL DEFAULT '',
  ip CTEXT NOT NULL DEFAULT '',
  prev_hash CTEXT NOT NULL,
  hash CTEXT NOT NULL);
CREATE INDEX idx_audit_log_ts ON audit_log(ts);
CREATE INDEX idx_audit_log_category ON audit_log(category);
CREATE INDEX idx_audit_log_category_seq ON audit_log(category, seq);
CREATE INDEX idx_audit_log_action_seq ON audit_log(action, seq);
CREATE INDEX idx_audit_log_outcome_seq ON audit_log(outcome, seq);
CREATE INDEX idx_audit_log_actor_id ON audit_log(actor_id, seq);
CREATE TABLE audit_checkpoint (
  id integer PRIMARY KEY CHECK (id=1),
  last_deleted_seq bigint NOT NULL DEFAULT 0,
  last_deleted_hash CTEXT NOT NULL DEFAULT '',
  mac CTEXT NOT NULL DEFAULT '');
INSERT INTO audit_checkpoint(id,last_deleted_seq,last_deleted_hash,mac) VALUES(1,0,'','');
CREATE TABLE audit_guard (
  id integer PRIMARY KEY CHECK (id=1),
  gen bigint NOT NULL DEFAULT 0);
INSERT INTO audit_guard(id,gen) VALUES(1,0);
CREATE TABLE audit_issued (
  id integer PRIMARY KEY CHECK (id=1),
  seq bigint NOT NULL DEFAULT 0);
INSERT INTO audit_issued(id,seq) VALUES(1,0);
CREATE FUNCTION audit_log_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    UPDATE audit_issued SET seq = GREATEST(seq, NEW.seq) WHERE id = 1;
    IF EXISTS (SELECT 1 FROM audit_log WHERE seq > NEW.seq) THEN
      UPDATE audit_guard SET gen = gen + 1 WHERE id = 1;
    END IF;
    RETURN NEW;
  END IF;
  UPDATE audit_guard SET gen = gen + 1 WHERE id = 1;
  RETURN NULL;
END $$;
CREATE TRIGGER audit_log_guard_insert AFTER INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_guard();
CREATE TRIGGER audit_log_guard_update AFTER UPDATE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_guard();
CREATE TRIGGER audit_log_guard_delete AFTER DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_guard();
`

// settingsDDL is the settings table of both databases.
const settingsDDL = `
CREATE TABLE settings (
  key CTEXT PRIMARY KEY,
  value CTEXT NOT NULL DEFAULT '',
  grp CTEXT NOT NULL DEFAULT 'system');
`

// tenantV1 is the tenant schema as the SQLite migration sequence of 0.2.x
// leaves it (BaseSchema plus every Migrate* step), translated: identity
// columns for AUTOINCREMENT, timestamptz for DATETIME, bytea for BLOB,
// integer 0/1 flags, PL/pgSQL triggers for the RAISE triggers. The tenant
// user limit table exists from the start (SQLite creates it in
// TenantLimits.Enable; here the app role has no DDL rights): Enable only
// adds its row.
const tenantV1 = settingsDDL + `
CREATE TABLE users (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  username CTEXT NOT NULL UNIQUE,
  name CTEXT NOT NULL DEFAULT '',
  email CTEXT NOT NULL DEFAULT '',
  password_hash CTEXT NOT NULL DEFAULT '',
  admin integer NOT NULL DEFAULT 0,
  must_change_password integer NOT NULL DEFAULT 0,
  is_guest integer NOT NULL DEFAULT 0,
  email_verified integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT NOW_S,
  quota_bytes bigint NOT NULL DEFAULT 10737418240,
  quota_inherits_default integer NOT NULL DEFAULT 1,
  login_failures bigint NOT NULL DEFAULT 0,
  login_locked_until bigint NOT NULL DEFAULT 0,
  mfa_policy CTEXT NOT NULL DEFAULT 'inherit',
  mfa_epoch bigint NOT NULL DEFAULT 0,
  pending_registration integer NOT NULL DEFAULT 0,
  is_auditor integer NOT NULL DEFAULT 0,
  disabled_at timestamptz,
  disabled_by CTEXT NOT NULL DEFAULT '',
  disabled_reason CTEXT NOT NULL DEFAULT '',
  created_by CTEXT NOT NULL DEFAULT '',
  last_login_at timestamptz,
  role_changed_at timestamptz,
  role_changed_by CTEXT NOT NULL DEFAULT '',
  email_changed_at timestamptz,
  email_changed_by CTEXT NOT NULL DEFAULT '',
  terms_accepted_version CTEXT NOT NULL DEFAULT '',
  terms_accepted_at timestamptz,
  erased_at timestamptz,
  password_changed_at timestamptz,
  password_rotation_exempt integer NOT NULL DEFAULT 0,
  password_expiry_warned_at timestamptz,
  language CTEXT NOT NULL DEFAULT 'en',
  ui_language CTEXT NOT NULL DEFAULT 'en');
CREATE UNIQUE INDEX users_username_nocase ON users(lower(username));
CREATE INDEX users_email_fold ON users(lower(btrim(email)));
CREATE TABLE tenant_limits (
  id integer PRIMARY KEY CHECK (id=1),
  max_users bigint NOT NULL DEFAULT 0,
  max_storage_bytes bigint NOT NULL DEFAULT 0);
-- New identities must not reuse an address (pre-existing duplicates stay).
-- The advisory lock makes the check race-free between concurrent inserts.
CREATE FUNCTION users_email_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF NEW.email = '' OR (TG_OP = 'UPDATE' AND NEW.email = OLD.email) THEN
    RETURN NEW;
  END IF;
  PERFORM pg_advisory_xact_lock(LOCKCLASS, hashtext(current_schema() || ':users'));
  IF EXISTS (SELECT 1 FROM users WHERE lower(btrim(email)) = lower(btrim(NEW.email)) AND (TG_OP = 'INSERT' OR id <> NEW.id)) THEN
    RAISE EXCEPTION 'email already in use' USING ERRCODE = 'SD002';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER users_email_insert BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION users_email_guard();
CREATE TRIGGER users_email_update BEFORE UPDATE OF email ON users FOR EACH ROW EXECUTE FUNCTION users_email_guard();
-- Multi-tenant mode: refuse a non-guest account beyond the platform's limit,
-- whichever way it is added (active once TenantLimits.Enable added the row).
CREATE FUNCTION tenant_user_limit() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE lim bigint;
BEGIN
  SELECT max_users INTO lim FROM tenant_limits WHERE id = 1;
  IF lim IS NULL OR lim <= 0 THEN
    RETURN NEW;
  END IF;
  PERFORM pg_advisory_xact_lock(LOCKCLASS, hashtext(current_schema() || ':users'));
  IF (SELECT count(*) FROM users WHERE is_guest = 0) >= lim THEN
    RAISE EXCEPTION 'tenant user limit reached' USING ERRCODE = 'SD001';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER tenant_user_limit BEFORE INSERT ON users FOR EACH ROW WHEN (NEW.is_guest = 0) EXECUTE FUNCTION tenant_user_limit();

CREATE TABLE refresh_tokens (
  hash CTEXT PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  issued_at timestamptz,
  session_started timestamptz,
  session_id CTEXT,
  user_agent CTEXT NOT NULL DEFAULT '',
  ip CTEXT NOT NULL DEFAULT '',
  auth_method CTEXT NOT NULL DEFAULT '');
CREATE INDEX refresh_tokens_session ON refresh_tokens(session_id);
CREATE INDEX refresh_tokens_user ON refresh_tokens(user_id);
CREATE TABLE revoked_access_tokens (
  hash CTEXT PRIMARY KEY,
  expires_at timestamptz NOT NULL);
CREATE TABLE refresh_spent (
  hash CTEXT PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  spent_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL);
CREATE TABLE password_resets (
  hash CTEXT PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  kind CTEXT NOT NULL DEFAULT 'reset');
CREATE TABLE email_verifications (
  user_id bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  code CTEXT NOT NULL,
  expires_at timestamptz NOT NULL);
CREATE TABLE verification_attempts (
  user_id bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  attempts bigint NOT NULL,
  expires_at timestamptz NOT NULL);
CREATE TABLE user_signin_seen (
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  fingerprint CTEXT NOT NULL,
  last_seen timestamptz NOT NULL,
  PRIMARY KEY(user_id, fingerprint));
CREATE TABLE password_history (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hash CTEXT NOT NULL,
  created_at timestamptz NOT NULL);
CREATE INDEX password_history_user ON password_history(user_id, id);

CREATE TABLE shares (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  user_id bigint REFERENCES users(id) ON DELETE SET NULL,
  invite_id bigint,
  long_id CTEXT NOT NULL UNIQUE,
  name CTEXT NOT NULL DEFAULT '',
  description CTEXT NOT NULL DEFAULT '',
  password_hash CTEXT NOT NULL DEFAULT '',
  public integer NOT NULL DEFAULT 1,
  status CTEXT NOT NULL DEFAULT 'active',
  download_limit bigint,
  download_count bigint NOT NULL DEFAULT 0,
  expires_at timestamptz,
  expiry_warned integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT NOW_S);
CREATE INDEX shares_user ON shares(user_id);
CREATE INDEX shares_invite ON shares(invite_id);
CREATE TABLE files (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  share_id bigint NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  name CTEXT NOT NULL,
  full_path CTEXT NOT NULL,
  size bigint NOT NULL DEFAULT 0,
  type CTEXT NOT NULL DEFAULT '',
  disk_path CTEXT NOT NULL,
  sha256 CTEXT NOT NULL DEFAULT '',
  integrity CTEXT NOT NULL DEFAULT 'server_baseline',
  enc integer NOT NULL DEFAULT 0,
  enc_id CTEXT NOT NULL DEFAULT '',
  storage_id bigint NOT NULL DEFAULT 0,
  object_key CTEXT NOT NULL DEFAULT '');
CREATE INDEX files_share ON files(share_id);
CREATE TABLE downloads (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  share_id bigint NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  file_id bigint,
  ip CTEXT NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT NOW_S);
CREATE INDEX downloads_share_history ON downloads(share_id, created_at DESC, id DESC);
CREATE TABLE upload_sessions (
  id CTEXT PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invite_id bigint,
  created_at timestamptz NOT NULL DEFAULT NOW_S,
  quota_owner_id bigint REFERENCES users(id) ON DELETE CASCADE,
  share_id bigint REFERENCES shares(id) ON DELETE CASCADE);
CREATE INDEX upload_sessions_quota_owner ON upload_sessions(quota_owner_id);
CREATE INDEX idx_upload_sessions_share ON upload_sessions(share_id);
CREATE INDEX upload_sessions_user ON upload_sessions(user_id);
CREATE FUNCTION upload_quota_owner_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.quota_owner_id IS NULL THEN
    RAISE EXCEPTION 'quota owner required';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.quota_owner_id IS DISTINCT FROM OLD.quota_owner_id THEN
    RAISE EXCEPTION 'quota owner is immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER upload_quota_owner_required BEFORE INSERT ON upload_sessions FOR EACH ROW EXECUTE FUNCTION upload_quota_owner_guard();
CREATE TRIGGER upload_quota_owner_immutable BEFORE UPDATE OF quota_owner_id ON upload_sessions FOR EACH ROW EXECUTE FUNCTION upload_quota_owner_guard();
CREATE TABLE upload_files (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  session_id CTEXT NOT NULL REFERENCES upload_sessions(id) ON DELETE CASCADE,
  idx bigint NOT NULL,
  name CTEXT NOT NULL,
  full_path CTEXT NOT NULL,
  size bigint NOT NULL,
  type CTEXT NOT NULL DEFAULT '',
  received bigint NOT NULL DEFAULT 0,
  sha256 CTEXT NOT NULL DEFAULT '',
  UNIQUE(session_id, idx));

CREATE TABLE themes (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  name CTEXT NOT NULL UNIQUE,
  category CTEXT NOT NULL DEFAULT 'custom',
  bundled integer NOT NULL DEFAULT 0,
  data CTEXT NOT NULL DEFAULT '{}',
  active integer NOT NULL DEFAULT 0);
CREATE TABLE auth_providers (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  uuid CTEXT NOT NULL UNIQUE,
  name CTEXT NOT NULL,
  type CTEXT NOT NULL,
  enabled integer NOT NULL DEFAULT 0,
  client_id CTEXT NOT NULL DEFAULT '',
  client_secret CTEXT NOT NULL DEFAULT '',
  issuer_url CTEXT NOT NULL DEFAULT '',
  icon CTEXT NOT NULL DEFAULT '',
  trust_email integer NOT NULL DEFAULT 0,
  allow_registration integer NOT NULL DEFAULT 1,
  sort bigint NOT NULL DEFAULT 0,
  managed integer NOT NULL DEFAULT 0);
CREATE TABLE user_auth_providers (
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id bigint NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
  provider_user_id CTEXT NOT NULL,
  PRIMARY KEY(provider_id, provider_user_id));
CREATE INDEX user_auth_providers_user ON user_auth_providers(user_id);
CREATE TABLE reverse_invites (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  token CTEXT NOT NULL UNIQUE,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_name CTEXT NOT NULL DEFAULT '',
  recipient_email CTEXT NOT NULL DEFAULT '',
  message CTEXT NOT NULL DEFAULT '',
  guest_user_id bigint,
  expires_at timestamptz NOT NULL,
  used integer NOT NULL DEFAULT 0,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT NOW_S,
  reusable integer NOT NULL DEFAULT 0,
  max_uploads bigint NOT NULL DEFAULT 0,
  parent_id bigint);
CREATE INDEX idx_reverse_invites_parent ON reverse_invites(parent_id);
CREATE INDEX reverse_invites_user ON reverse_invites(user_id);
CREATE INDEX reverse_invites_guest ON reverse_invites(guest_user_id);

CREATE TABLE user_totp (
  user_id bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret CTEXT NOT NULL,
  confirmed integer NOT NULL DEFAULT 0,
  last_counter bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT NOW_S);
CREATE TABLE user_recovery_codes (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash CTEXT NOT NULL,
  used_at timestamptz,
  UNIQUE(user_id, code_hash));
CREATE TABLE user_webauthn (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cred_id bytea NOT NULL UNIQUE,
  public_key bytea NOT NULL,
  alg bigint NOT NULL,
  sign_count bigint NOT NULL DEFAULT 0,
  name CTEXT NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT NOW_S,
  last_used_at timestamptz);
CREATE INDEX user_webauthn_user ON user_webauthn(user_id);
CREATE TABLE mfa_reset_requests (
  hash CTEXT PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  requested_by bigint NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  used integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT NOW_S);
CREATE INDEX mfa_reset_requests_user ON mfa_reset_requests(user_id);

CREATE TABLE ui_translations (
  code CTEXT PRIMARY KEY,
  name CTEXT NOT NULL,
  data CTEXT NOT NULL DEFAULT '{}',
  updated_at CTEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'));
CREATE TABLE mail_languages (
  code CTEXT PRIMARY KEY,
  name CTEXT NOT NULL,
  built_in integer NOT NULL DEFAULT 0);
CREATE TABLE ip_bans (
  ip CTEXT PRIMARY KEY,
  banned_until bigint NOT NULL,
  strikes bigint NOT NULL,
  last_strike bigint NOT NULL);

CREATE TABLE storage_locations (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  backend CTEXT NOT NULL,
  identity CTEXT NOT NULL UNIQUE,
  config CTEXT NOT NULL,
  created_at timestamptz NOT NULL DEFAULT NOW_S,
  updated_at timestamptz NOT NULL DEFAULT NOW_S);
CREATE TABLE storage_pending_deletes (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  location_id bigint NOT NULL,
  object_key CTEXT NOT NULL,
  not_before timestamptz NOT NULL DEFAULT NOW_S,
  attempts bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT NOW_S);
CREATE TABLE storage_migrations (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  status CTEXT NOT NULL DEFAULT 'running',
  target_location bigint NOT NULL,
  target CTEXT NOT NULL DEFAULT '',
  total bigint NOT NULL DEFAULT 0,
  done bigint NOT NULL DEFAULT 0,
  failed bigint NOT NULL DEFAULT 0,
  bytes bigint NOT NULL DEFAULT 0,
  started_by CTEXT NOT NULL DEFAULT '',
  started_at timestamptz NOT NULL DEFAULT NOW_S,
  finished_at timestamptz,
  error CTEXT NOT NULL DEFAULT '');
-- Removing a files row (directly or through ON DELETE CASCADE) queues its
-- remote object for deletion in the same transaction.
CREATE FUNCTION files_remote_deleted() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  INSERT INTO storage_pending_deletes(location_id, object_key) VALUES (OLD.storage_id, OLD.object_key);
  RETURN NULL;
END $$;
CREATE TRIGGER files_remote_deleted AFTER DELETE ON files FOR EACH ROW
  WHEN (OLD.storage_id <> 0 AND OLD.object_key <> '') EXECUTE FUNCTION files_remote_deleted();
CREATE TABLE download_mail_outbox (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  share_id bigint NOT NULL,
  status CTEXT NOT NULL DEFAULT 'reserved',
  recipient CTEXT NOT NULL,
  language CTEXT NOT NULL,
  data CTEXT NOT NULL,
  attempts bigint NOT NULL DEFAULT 0,
  next_attempt timestamptz NOT NULL,
  last_error CTEXT NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT NOW_S);
CREATE INDEX download_mail_pending ON download_mail_outbox(status, next_attempt);
` + auditDDL

var tenantMigrations = []Migration{
	{Version: 1, Name: "tenant schema of 0.2.x", SQL: tenantV1},
	{Version: 2, Name: "idempotency keys", SQL: tenantV2},
	{Version: 3, Name: "job fences", SQL: tenantV3},
	{Version: 4, Name: "control log and keyring", SQL: controlLogDDL},
	{Version: 5, Name: "blind indexes of the encrypted lookup columns", SQL: tenantV5},
	{Version: 6, Name: "key jobs of the online key rotation", SQL: tenantV6},
}

// tenantV5 adds the blind-index columns of the encrypted lookup columns
// (users.username, users.email, shares.long_id; sqlite.MigrateLookupIndexes)
// with their UNIQUE indexes, and replaces the plaintext email guard (trigger
// function with advisory lock, folded index) and the folded username index by
// them: a UNIQUE index on email_bi enforces one address per account (compared
// folded; the empty address has no index) without a lock, and the stored
// values themselves are randomised ciphertext. The unique constraints on
// users.username and shares.long_id stay; they only see ciphertext.
const tenantV5 = `
ALTER TABLE users ADD COLUMN username_bi bytea, ADD COLUMN email_bi bytea;
ALTER TABLE shares ADD COLUMN long_id_bi bytea;
DROP TRIGGER users_email_insert ON users;
DROP TRIGGER users_email_update ON users;
DROP FUNCTION users_email_guard();
DROP INDEX users_email_fold;
DROP INDEX users_username_nocase;
CREATE UNIQUE INDEX users_username_bi ON users(username_bi);
CREATE UNIQUE INDEX users_email_bi ON users(email_bi);
CREATE UNIQUE INDEX shares_long_id_bi ON shares(long_id_bi);
`

// tenantV2 adds the idempotency keys of mutating requests (design 4.1, D29;
// sqlite.MigrateIdempotency). Times are Unix seconds.
const tenantV2 = `
CREATE TABLE idempotency_keys (
  scope CTEXT NOT NULL,
  key_hash CTEXT NOT NULL,
  request_hash CTEXT NOT NULL,
  status CTEXT NOT NULL DEFAULT 'pending',
  http_status integer NOT NULL DEFAULT 0,
  response bytea,
  lease_until bigint NOT NULL,
  created_at bigint NOT NULL,
  replayed_at bigint,
  PRIMARY KEY (scope, key_hash));
CREATE INDEX idx_idempotency_keys_created ON idempotency_keys(created_at);
`

// tenantV3 holds the per-tenant fences of leased jobs (design 4.3, M7).
const tenantV3 = `
CREATE TABLE job_fences (
  kind CTEXT PRIMARY KEY,
  fence bigint NOT NULL);
`

// platformV2 holds the Cluster coordination state (design 4.2, 4.3, 4.6):
// work signals, notification versions, lease locks, rate-limit counters
// (UNLOGGED: no WAL, no replication wait; lost on crash or failover, which
// only restarts windows of minutes) and blocks (logged).
const platformV2 = `
CREATE TABLE coord_signals (
  kind CTEXT NOT NULL,
  tenant_id CTEXT NOT NULL,
  signalled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (kind, tenant_id));
CREATE INDEX coord_signals_order ON coord_signals(kind, signalled_at);
CREATE TABLE coord_versions (
  topic CTEXT PRIMARY KEY,
  version bigint NOT NULL);
CREATE TABLE coord_locks (
  name CTEXT PRIMARY KEY,
  holder CTEXT NOT NULL,
  until timestamptz NOT NULL);
CREATE UNLOGGED TABLE rate_buckets (
  scope CTEXT NOT NULL,
  key CTEXT NOT NULL,
  window_ms bigint NOT NULL,
  window_start bigint NOT NULL,
  count bigint NOT NULL,
  PRIMARY KEY (scope, key, window_ms, window_start));
CREATE INDEX rate_buckets_end ON rate_buckets((window_start + window_ms));
CREATE TABLE rate_blocks (
  scope CTEXT NOT NULL,
  key CTEXT NOT NULL,
  until_ms bigint NOT NULL,
  PRIMARY KEY (scope, key));
`

// platformV1 is the platform schema of 0.2.x (settings, audit chain,
// sqlite.PlatformSchema and MigratePlatform), translated as tenantV1.
// Administrator usernames are unique ignoring ASCII case (SQLite: COLLATE
// NOCASE).
const platformV1 = settingsDDL + `
CREATE TABLE tenants (
  id CTEXT PRIMARY KEY,
  slug CTEXT NOT NULL UNIQUE,
  name CTEXT NOT NULL DEFAULT '',
  status CTEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','importing')),
  created_at CTEXT NOT NULL,
  max_users bigint NOT NULL DEFAULT 0 CHECK (max_users >= 0),
  max_storage_bytes bigint NOT NULL DEFAULT 0 CHECK (max_storage_bytes >= 0),
  key_mode CTEXT NOT NULL DEFAULT 'derived' CHECK (key_mode IN ('derived','legacy')),
  legacy_root bytea,
  primary_domain CTEXT NOT NULL DEFAULT '',
  stat_users bigint NOT NULL DEFAULT 0,
  stat_storage_bytes bigint NOT NULL DEFAULT 0,
  stat_updated_at CTEXT NOT NULL DEFAULT '',
  allow_private_targets integer NOT NULL DEFAULT 0);
CREATE TABLE tenant_domains (
  domain CTEXT PRIMARY KEY,
  tenant_id CTEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind CTEXT NOT NULL DEFAULT 'custom' CHECK (kind IN ('custom')),
  verified integer NOT NULL DEFAULT 0,
  verify_token CTEXT NOT NULL DEFAULT '',
  created_at CTEXT NOT NULL);
CREATE INDEX idx_tenant_domains_tenant ON tenant_domains(tenant_id);
CREATE TABLE tenant_storage (
  tenant_id CTEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  mode CTEXT NOT NULL DEFAULT 'platform' CHECK (mode IN ('platform','own')),
  prefix CTEXT NOT NULL DEFAULT '',
  config CTEXT NOT NULL DEFAULT '{}',
  tenant_managed integer NOT NULL DEFAULT 1,
  tenant_managed_explicit integer NOT NULL DEFAULT 0,
  offer CTEXT NOT NULL DEFAULT 'none',
  updated_at CTEXT NOT NULL DEFAULT '');
CREATE TABLE platform_admins (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  username CTEXT NOT NULL,
  email CTEXT NOT NULL DEFAULT '',
  password_hash CTEXT NOT NULL,
  totp_secret CTEXT NOT NULL DEFAULT '',
  totp_enabled integer NOT NULL DEFAULT 0,
  totp_last_counter bigint NOT NULL DEFAULT 0,
  pending_totp_secret CTEXT NOT NULL DEFAULT '',
  failures bigint NOT NULL DEFAULT 0,
  locked_until bigint NOT NULL DEFAULT 0,
  must_change_password integer NOT NULL DEFAULT 0,
  created_at CTEXT NOT NULL);
CREATE UNIQUE INDEX platform_admins_username_nocase ON platform_admins(lower(username));
CREATE TABLE platform_sessions (
  hash CTEXT PRIMARY KEY,
  admin_id bigint NOT NULL REFERENCES platform_admins(id) ON DELETE CASCADE,
  stage CTEXT NOT NULL CHECK (stage IN ('mfa','enroll','full')),
  created_at bigint NOT NULL,
  last_seen bigint NOT NULL,
  expires_at bigint NOT NULL,
  mfa_at bigint NOT NULL DEFAULT 0);
CREATE INDEX platform_sessions_admin ON platform_sessions(admin_id);
` + auditDDL

var platformMigrations = []Migration{
	{Version: 1, Name: "platform schema of 0.2.x", SQL: platformV1},
	{Version: 2, Name: "coordination", SQL: platformV2},
	{Version: 3, Name: "control log and keyring", SQL: controlLogDDL},
	{Version: 4, Name: "tenant-supplied KEK (D44)", SQL: platformV4},
	{Version: 5, Name: "master key version per tenant (D46)", SQL: platformV5},
}

// platformV5 records which version of the master key a tenant's derived
// material (its platform KEK root) comes from; existing tenants are version 1.
const platformV5 = `
ALTER TABLE tenants ADD COLUMN master_version integer NOT NULL DEFAULT 1 CHECK (master_version >= 1);
`

// platformV4 records who holds a tenant's key-encryption key: the platform
// (default) or the tenant itself, with the fingerprint of the tenant's KEK
// (never the KEK).
const platformV4 = `
ALTER TABLE tenants ADD COLUMN kek_mode CTEXT NOT NULL DEFAULT 'platform' CHECK (kek_mode IN ('platform','tenant'));
ALTER TABLE tenants ADD COLUMN kek_fingerprint CTEXT NOT NULL DEFAULT '';
`

// controlLogDDL is the authenticated control log and the keyring (design 6.3),
// in the platform database (for every tenant and for the platform) and in each
// tenant database (for that tenant). Written by the controller as the
// database owner; the app role only reads them (appGrants).
const controlLogDDL = `
CREATE TABLE control_log (
  tenant_id CTEXT NOT NULL,
  seq bigint NOT NULL CHECK (seq >= 1),
  prev_hash bytea NOT NULL,
  kind CTEXT NOT NULL,
  purpose CTEXT,
  version integer,
  body bytea NOT NULL,
  event_hash bytea NOT NULL,
  mac_kek CTEXT NOT NULL,
  mac bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, seq),
  UNIQUE (tenant_id, prev_hash),
  UNIQUE (event_hash));
CREATE UNIQUE INDEX control_log_version_once ON control_log(tenant_id, purpose, version) WHERE kind = 'key_created';
CREATE TABLE tenant_keyring (
  tenant_id CTEXT NOT NULL,
  purpose CTEXT NOT NULL,
  version integer NOT NULL,
  key_id CTEXT NOT NULL,
  wrap_id CTEXT PRIMARY KEY,
  kek_ref CTEXT NOT NULL,
  wrapped bytea NOT NULL,
  fingerprint bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE INDEX tenant_keyring_lookup ON tenant_keyring(tenant_id, purpose, version, created_at);
`
