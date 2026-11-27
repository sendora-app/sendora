// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// MigrateIdempotency creates the idempotency key table (design 4.1). Called
// from internal/store's migration sequence. Times are Unix seconds.
func MigrateIdempotency(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS idempotency_keys (
		scope TEXT NOT NULL,
		key_hash TEXT NOT NULL,
		request_hash TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		http_status INTEGER NOT NULL DEFAULT 0,
		response BLOB,
		lease_until INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		replayed_at INTEGER,
		PRIMARY KEY (scope, key_hash));
	CREATE INDEX IF NOT EXISTS idx_idempotency_keys_created ON idempotency_keys(created_at)`)
	return err
}

type idempotencyRepo struct{ q querier }

// Claim: see ports.IdempotencyRepository. Inside a Tx the INSERT takes the
// database write lock, so concurrent claims serialise.
func (r idempotencyRepo) Claim(ctx context.Context, scope, keyHash, requestHash string, now, leaseUntil time.Time) (ports.IdempotencyClaim, error) {
	n, err := affected(r.q.ExecContext(ctx, `INSERT OR IGNORE INTO idempotency_keys(scope,key_hash,request_hash,status,lease_until,created_at) VALUES(?,?,?,'pending',?,?)`,
		scope, keyHash, requestHash, leaseUntil.Unix(), now.Unix()))
	if err != nil {
		return ports.IdempotencyClaim{}, err
	}
	if n == 1 {
		return ports.IdempotencyClaim{State: ports.IdempotencyNew}, nil
	}
	var stored, status string
	var httpStatus int
	var response []byte
	var lease int64
	if err := r.q.QueryRowContext(ctx, `SELECT request_hash,status,http_status,response,lease_until FROM idempotency_keys WHERE scope=? AND key_hash=?`, scope, keyHash).
		Scan(&stored, &status, &httpStatus, &response, &lease); err != nil {
		return ports.IdempotencyClaim{}, notFound(err)
	}
	switch {
	case stored != requestHash:
		return ports.IdempotencyClaim{State: ports.IdempotencyMismatch}, nil
	case status == "done":
		return ports.IdempotencyClaim{State: ports.IdempotencyDone, Status: httpStatus, Response: response}, nil
	case lease > now.Unix():
		return ports.IdempotencyClaim{State: ports.IdempotencyInProgress}, nil
	}
	n, err = affected(r.q.ExecContext(ctx, `UPDATE idempotency_keys SET lease_until=? WHERE scope=? AND key_hash=? AND status='pending' AND lease_until<=?`,
		leaseUntil.Unix(), scope, keyHash, now.Unix()))
	if err != nil {
		return ports.IdempotencyClaim{}, err
	}
	if n == 1 {
		return ports.IdempotencyClaim{State: ports.IdempotencyNew}, nil
	}
	return ports.IdempotencyClaim{State: ports.IdempotencyInProgress}, nil
}

func (r idempotencyRepo) Complete(ctx context.Context, scope, keyHash string, status int, response []byte) error {
	_, err := r.q.ExecContext(ctx, `UPDATE idempotency_keys SET status='done',http_status=?,response=? WHERE scope=? AND key_hash=? AND status='pending'`, status, response, scope, keyHash)
	return err
}

func (r idempotencyRepo) Release(ctx context.Context, scope, keyHash string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE scope=? AND key_hash=? AND status='pending'`, scope, keyHash)
	return err
}

func (r idempotencyRepo) MarkReplayed(ctx context.Context, scope, keyHash string, now time.Time) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE idempotency_keys SET replayed_at=? WHERE scope=? AND key_hash=? AND status='done'`, now.Unix(), scope, keyHash))
}

func (r idempotencyRepo) Expire(ctx context.Context, before time.Time) (int64, error) {
	return affected(r.q.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE created_at<?`, before.Unix()))
}
