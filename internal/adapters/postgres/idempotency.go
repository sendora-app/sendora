// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

type idempotencyRepo struct{ q pq }

// Claim: see ports.IdempotencyRepository. A concurrent INSERT of the same
// key waits on the primary key until the first transaction ends, then finds
// its row (READ COMMITTED); the conditional UPDATE decides a takeover race.
func (r idempotencyRepo) Claim(ctx context.Context, scope, keyHash, requestHash string, now, leaseUntil time.Time) (ports.IdempotencyClaim, error) {
	n, err := affected(r.q.ExecContext(ctx, `INSERT INTO idempotency_keys(scope,key_hash,request_hash,status,lease_until,created_at) VALUES(?,?,?,'pending',?,?) ON CONFLICT DO NOTHING`,
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
	if err := r.q.scan(ctx, `SELECT request_hash,status,http_status,response,lease_until FROM idempotency_keys WHERE scope=? AND key_hash=?`, []any{scope, keyHash},
		&stored, &status, &httpStatus, &response, &lease); err != nil {
		return ports.IdempotencyClaim{}, err
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
