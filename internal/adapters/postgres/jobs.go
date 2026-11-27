// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"errors"

	"github.com/sendora-app/sendora/internal/ports"
)

type jobFenceRepo struct{ q pq }

// Advance: see ports.JobFenceRepository. The upsert's conflict path locks
// the kind's row, so concurrent advances serialise.
func (r jobFenceRepo) Advance(ctx context.Context, kind string, fence int64) (bool, error) {
	n, err := affected(r.q.ExecContext(ctx, `INSERT INTO job_fences(kind,fence) VALUES(?,?) ON CONFLICT (kind) DO UPDATE SET fence = EXCLUDED.fence WHERE job_fences.fence <= EXCLUDED.fence`, kind, fence))
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Current: see ports.JobFenceRepository.
func (r jobFenceRepo) Current(ctx context.Context, kind string) (int64, error) {
	var f int64
	err := r.q.scan(ctx, `SELECT fence FROM job_fences WHERE kind=?`, []any{kind}, &f)
	if errors.Is(err, ports.ErrNotFound) {
		return 0, nil
	}
	return f, err
}
