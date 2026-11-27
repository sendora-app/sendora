// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// controlLogDDL and keyringDDL create the tables on first use: databases that
// never record a key event do not get them (the schema of an existing 0.2
// database stays as it is until column encryption needs them). Same shape as
// the PostgreSQL tables (design 6.3).
const controlLogDDL = `CREATE TABLE IF NOT EXISTS control_log (
  tenant_id TEXT NOT NULL,
  seq INTEGER NOT NULL CHECK (seq >= 1),
  prev_hash BLOB NOT NULL,
  kind TEXT NOT NULL,
  purpose TEXT,
  version INTEGER,
  body BLOB NOT NULL,
  event_hash BLOB NOT NULL,
  mac_kek TEXT NOT NULL,
  mac BLOB NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (tenant_id, seq),
  UNIQUE (tenant_id, prev_hash),
  UNIQUE (event_hash));
CREATE UNIQUE INDEX IF NOT EXISTS control_log_version_once ON control_log(tenant_id, purpose, version) WHERE kind = 'key_created'`

const keyringDDL = `CREATE TABLE IF NOT EXISTS tenant_keyring (
  tenant_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  version INTEGER NOT NULL,
  key_id TEXT NOT NULL,
  wrap_id TEXT PRIMARY KEY,
  kek_ref TEXT NOT NULL,
  wrapped BLOB NOT NULL,
  fingerprint BLOB NOT NULL,
  created_at DATETIME NOT NULL);
CREATE INDEX IF NOT EXISTS tenant_keyring_lookup ON tenant_keyring(tenant_id, purpose, version, created_at)`

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func tableExists(ctx context.Context, q querier, name string) bool {
	var n int
	return q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n) == nil && n > 0
}

const controlLogCols = `tenant_id, seq, prev_hash, kind, purpose, version, body, event_hash, mac_kek, mac, created_at`

type controlLogRepo struct{ q querier }

// Append: see ports.ControlLogRepository (and the PostgreSQL adapter).
func (r controlLogRepo) Append(ctx context.Context, e ports.ControlLogEvent) error {
	if _, err := r.q.ExecContext(ctx, controlLogDDL); err != nil {
		return err
	}
	at := e.CreatedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	res, err := r.q.ExecContext(ctx, `INSERT INTO control_log(`+controlLogCols+`)
		SELECT ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, 0), ?, ?, ?, ?, ?
		WHERE NOT EXISTS (SELECT 1 FROM control_log WHERE tenant_id = ? AND seq = ?)
		  AND (? = 1 OR EXISTS (SELECT 1 FROM control_log WHERE tenant_id = ? AND seq = ? - 1 AND event_hash = ?))`,
		e.TenantID, e.Seq, e.PrevHash, e.Kind, e.Purpose, e.Version, e.Body, e.EventHash, e.MACKEK, e.MAC, at,
		e.TenantID, e.Seq,
		e.Seq, e.TenantID, e.Seq, e.PrevHash)
	if err != nil {
		if isUniqueViolation(err) {
			return ports.ErrControlLogConflict
		}
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ports.ErrControlLogConflict
	}
	return nil
}

func (r controlLogRepo) Latest(ctx context.Context, tenantID string) (ports.ControlLogEvent, error) {
	if !tableExists(ctx, r.q, "control_log") {
		return ports.ControlLogEvent{}, ports.ErrNotFound
	}
	return scanControlLogEvent(r.q.QueryRowContext(ctx, `SELECT `+controlLogCols+` FROM control_log WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1`, tenantID))
}

func (r controlLogRepo) BySeq(ctx context.Context, tenantID string, seq int64) (ports.ControlLogEvent, error) {
	if !tableExists(ctx, r.q, "control_log") {
		return ports.ControlLogEvent{}, ports.ErrNotFound
	}
	return scanControlLogEvent(r.q.QueryRowContext(ctx, `SELECT `+controlLogCols+` FROM control_log WHERE tenant_id = ? AND seq = ?`, tenantID, seq))
}

func (r controlLogRepo) List(ctx context.Context, tenantID string, fromSeq, toSeq int64) ([]ports.ControlLogEvent, error) {
	if !tableExists(ctx, r.q, "control_log") {
		return []ports.ControlLogEvent{}, nil
	}
	query := `SELECT ` + controlLogCols + ` FROM control_log WHERE tenant_id = ? AND seq >= ?`
	args := []any{tenantID, fromSeq}
	if toSeq > 0 {
		query += ` AND seq <= ?`
		args = append(args, toSeq)
	}
	rows, err := r.q.QueryContext(ctx, query+` ORDER BY seq ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ports.ControlLogEvent{}
	for rows.Next() {
		e, err := scanControlLogEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanControlLogEvent(row interface{ Scan(...any) error }) (ports.ControlLogEvent, error) {
	var e ports.ControlLogEvent
	var purpose sql.NullString
	var version sql.NullInt64
	err := row.Scan(&e.TenantID, &e.Seq, &e.PrevHash, &e.Kind, &purpose, &version, &e.Body, &e.EventHash, &e.MACKEK, &e.MAC, &e.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.ControlLogEvent{}, ports.ErrNotFound
	}
	if err != nil {
		return ports.ControlLogEvent{}, err
	}
	e.Purpose = purpose.String
	e.Version = int(version.Int64)
	return e, nil
}

type keyringRepo struct{ q querier }

const keyringCols = `tenant_id, purpose, version, key_id, wrap_id, kek_ref, wrapped, fingerprint, created_at`

// Add: see ports.KeyringRepository.
func (r keyringRepo) Add(ctx context.Context, row ports.KeyringRow) error {
	if _, err := r.q.ExecContext(ctx, keyringDDL); err != nil {
		return err
	}
	at := row.CreatedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_, err := r.q.ExecContext(ctx, `INSERT INTO tenant_keyring(`+keyringCols+`) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.TenantID, row.Purpose, row.Version, row.KeyID, row.WrapID, row.KEKRef, row.Wrapped, row.Fingerprint, at)
	if isUniqueViolation(err) {
		return &classifiedError{kind: ports.ErrDuplicate, err: err}
	}
	return err
}

// Active: see ports.KeyringRepository.
func (r keyringRepo) Active(ctx context.Context, tenantID, purpose string, version int) (ports.KeyringRow, error) {
	var k ports.KeyringRow
	if !tableExists(ctx, r.q, "tenant_keyring") {
		return k, ports.ErrNotFound
	}
	err := r.q.QueryRowContext(ctx, `SELECT `+keyringCols+` FROM tenant_keyring WHERE tenant_id = ? AND purpose = ? AND version = ? ORDER BY created_at DESC, wrap_id DESC LIMIT 1`,
		tenantID, purpose, version).Scan(&k.TenantID, &k.Purpose, &k.Version, &k.KeyID, &k.WrapID, &k.KEKRef, &k.Wrapped, &k.Fingerprint, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return k, ports.ErrNotFound
	}
	return k, err
}

func (r keyringRepo) ListVersions(ctx context.Context, tenantID, purpose string) ([]int, error) {
	if !tableExists(ctx, r.q, "tenant_keyring") {
		return []int{}, nil
	}
	rows, err := r.q.QueryContext(ctx, `SELECT DISTINCT version FROM tenant_keyring WHERE tenant_id = ? AND purpose = ? ORDER BY version ASC`, tenantID, purpose)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Wraps: see ports.KeyringRepository.
func (r keyringRepo) Wraps(ctx context.Context, tenantID, purpose string, version int) ([]ports.KeyringRow, error) {
	out := []ports.KeyringRow{}
	if !tableExists(ctx, r.q, "tenant_keyring") {
		return out, nil
	}
	rows, err := r.q.QueryContext(ctx, `SELECT `+keyringCols+` FROM tenant_keyring WHERE tenant_id = ? AND purpose = ? AND version = ? ORDER BY created_at DESC, wrap_id DESC`, tenantID, purpose, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k ports.KeyringRow
		if err := rows.Scan(&k.TenantID, &k.Purpose, &k.Version, &k.KeyID, &k.WrapID, &k.KEKRef, &k.Wrapped, &k.Fingerprint, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Remove: see ports.KeyringRepository.
func (r keyringRepo) Remove(ctx context.Context, tenantID, wrapID string) (bool, error) {
	if !tableExists(ctx, r.q, "tenant_keyring") {
		return false, nil
	}
	res, err := r.q.ExecContext(ctx, `DELETE FROM tenant_keyring WHERE tenant_id = ? AND wrap_id = ?`, tenantID, wrapID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}
