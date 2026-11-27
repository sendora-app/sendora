// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

const controlLogCols = `tenant_id, seq, prev_hash, kind, purpose, version, body, event_hash, mac_kek, mac, created_at`

type controlLogRepo struct{ q pq }

// Append adds e only when it extends the tenant's chain: its sequence number
// is free and it is either the first event or the successor of the event whose
// hash it names. A key version is created once (unique index). In every other
// case nothing is written and ports.ErrControlLogConflict is returned.
func (r controlLogRepo) Append(ctx context.Context, e ports.ControlLogEvent) error {
	at := e.CreatedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	res, err := r.q.ExecContext(ctx, `INSERT INTO control_log(`+controlLogCols+`)
		SELECT ?::text, ?::bigint, ?::bytea, ?::text, NULLIF(?::text, ''), NULLIF(?::integer, 0), ?::bytea, ?::bytea, ?::text, ?::bytea, ?::timestamptz
		WHERE NOT EXISTS (SELECT 1 FROM control_log WHERE tenant_id = ?::text AND seq = ?::bigint)
		  AND (?::bigint = 1 OR EXISTS (SELECT 1 FROM control_log WHERE tenant_id = ?::text AND seq = ?::bigint - 1 AND event_hash = ?::bytea))`,
		e.TenantID, e.Seq, e.PrevHash, e.Kind, e.Purpose, e.Version, e.Body, e.EventHash, e.MACKEK, e.MAC, at,
		e.TenantID, e.Seq,
		e.Seq, e.TenantID, e.Seq, e.PrevHash)
	if errors.Is(err, ports.ErrDuplicate) {
		return ports.ErrControlLogConflict
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ports.ErrControlLogConflict
	}
	return nil
}

func (r controlLogRepo) Latest(ctx context.Context, tenantID string) (ports.ControlLogEvent, error) {
	return scanControlLogEvent(r.q.QueryRowContext(ctx, `SELECT `+controlLogCols+` FROM control_log WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1`, tenantID))
}

func (r controlLogRepo) BySeq(ctx context.Context, tenantID string, seq int64) (ports.ControlLogEvent, error) {
	return scanControlLogEvent(r.q.QueryRowContext(ctx, `SELECT `+controlLogCols+` FROM control_log WHERE tenant_id = ? AND seq = ?`, tenantID, seq))
}

func (r controlLogRepo) List(ctx context.Context, tenantID string, fromSeq, toSeq int64) ([]ports.ControlLogEvent, error) {
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
	if err = notFound(err); err != nil {
		return ports.ControlLogEvent{}, err
	}
	e.Purpose = purpose.String
	e.Version = int(version.Int64)
	return e, nil
}

type keyringRepo struct{ q pq }

const keyringCols = `tenant_id, purpose, version, key_id, wrap_id, kek_ref, wrapped, fingerprint, created_at`

// Add stores one wrap. Rows are never updated; a repeated wrap_id is
// ports.ErrDuplicate.
func (r keyringRepo) Add(ctx context.Context, row ports.KeyringRow) error {
	at := row.CreatedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_, err := r.q.ExecContext(ctx, `INSERT INTO tenant_keyring(`+keyringCols+`) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.TenantID, row.Purpose, row.Version, row.KeyID, row.WrapID, row.KEKRef, row.Wrapped, row.Fingerprint, at)
	return err
}

// Active is the newest wrap of (tenant, purpose, version).
func (r keyringRepo) Active(ctx context.Context, tenantID, purpose string, version int) (ports.KeyringRow, error) {
	var k ports.KeyringRow
	err := r.q.scan(ctx, `SELECT `+keyringCols+` FROM tenant_keyring WHERE tenant_id = ? AND purpose = ? AND version = ? ORDER BY created_at DESC, wrap_id DESC LIMIT 1`,
		[]any{tenantID, purpose, version},
		&k.TenantID, &k.Purpose, &k.Version, &k.KeyID, &k.WrapID, &k.KEKRef, &k.Wrapped, &k.Fingerprint, &k.CreatedAt)
	return k, err
}

func (r keyringRepo) ListVersions(ctx context.Context, tenantID, purpose string) ([]int, error) {
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

// Wraps is every wrap of (tenant, purpose, version), newest first.
func (r keyringRepo) Wraps(ctx context.Context, tenantID, purpose string, version int) ([]ports.KeyringRow, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+keyringCols+` FROM tenant_keyring WHERE tenant_id = ? AND purpose = ? AND version = ? ORDER BY created_at DESC, wrap_id DESC`, tenantID, purpose, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ports.KeyringRow{}
	for rows.Next() {
		var k ports.KeyringRow
		if err := rows.Scan(&k.TenantID, &k.Purpose, &k.Version, &k.KeyID, &k.WrapID, &k.KEKRef, &k.Wrapped, &k.Fingerprint, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Remove deletes one wrap; only the database owner role may (the app role has
// no DELETE on the keyring).
func (r keyringRepo) Remove(ctx context.Context, tenantID, wrapID string) (bool, error) {
	res, err := r.q.ExecContext(ctx, `DELETE FROM tenant_keyring WHERE tenant_id = ? AND wrap_id = ?`, tenantID, wrapID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}
