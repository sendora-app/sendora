// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"errors"
)

// jobFencesDDL creates the fence table on first use. The Community flavours
// run one process and never fence their jobs, so their databases only get
// this table when something (the conformance suite) actually uses it.
const jobFencesDDL = `CREATE TABLE IF NOT EXISTS job_fences (kind TEXT PRIMARY KEY, fence INTEGER NOT NULL)`

type jobFenceRepo struct{ q querier }

// Advance: see ports.JobFenceRepository.
func (r jobFenceRepo) Advance(ctx context.Context, kind string, fence int64) (bool, error) {
	if _, err := r.q.ExecContext(ctx, jobFencesDDL); err != nil {
		return false, err
	}
	n, err := affected(r.q.ExecContext(ctx, `INSERT INTO job_fences(kind,fence) VALUES(?,?) ON CONFLICT(kind) DO UPDATE SET fence=excluded.fence WHERE job_fences.fence <= excluded.fence`, kind, fence))
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Current: see ports.JobFenceRepository.
func (r jobFenceRepo) Current(ctx context.Context, kind string) (int64, error) {
	var exists int
	if err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='job_fences'`).Scan(&exists); err != nil || exists == 0 {
		return 0, err
	}
	var f int64
	err := r.q.QueryRowContext(ctx, `SELECT fence FROM job_fences WHERE kind=?`, kind).Scan(&f)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return f, err
}
