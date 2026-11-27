// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import "context"

// JobFenceRepository keeps one fence per job kind in the tenant's own
// database (design 4.3, review M7). A fence on a platform row cannot guard
// writes in a tenant database, so a job that mutates tenant state advances
// the tenant's fence to its leadership epoch (Coordinator.Epoch) in the same
// transaction as its effects: a former leader still running with an older
// epoch then fails to advance and must roll back.
type JobFenceRepository interface {
	// Advance raises the fence of kind to fence and reports true when fence
	// is not lower than the stored one (equal fences pass: one leader runs
	// many transactions with the same epoch); it reports false and changes
	// nothing for a lower fence. A kind never advanced has fence 0.
	Advance(ctx context.Context, kind string, fence int64) (bool, error)
	// Current returns the fence of kind (0 when never advanced).
	Current(ctx context.Context, kind string) (int64, error)
}
