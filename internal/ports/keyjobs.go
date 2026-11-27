// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"time"
)

// Operations and states of a key job (a tenant administrator's request to
// rotate or retire one of the tenant's data keys, DESIGN 6.4, D43).
const (
	KeyJobRotate = "rotate"
	KeyJobRetire = "retire"
	// KeyJobRekeyFiles rewrites the stored files that are not under the active
	// files key (the conversion of legacy root-derived files, D45).
	KeyJobRekeyFiles = "rekey-files"

	KeyJobPending = "pending"
	KeyJobRunning = "running"
	KeyJobDone    = "done"
	KeyJobFailed  = "failed"
)

// KeyJob is one request. The web tier only creates it; the process that may
// write the control log (the SQLite process itself, the Cluster controller)
// executes it, so the request lives in the tenant's own database.
type KeyJob struct {
	ID          int64
	Op          string // KeyJobRotate or KeyJobRetire
	Purpose     string
	Version     int // rotate: the version the job created (0 until then); retire: the version to retire
	Status      string
	Detail      string
	Actor       string
	RequestedAt time.Time
	UpdatedAt   time.Time
}

// ColumnVersions counts the encrypted values by the key version that sealed
// them.
type ColumnVersions struct {
	// Columns counts the values the re-encryption job rewrites.
	Columns map[int]int64
	// Audit counts the audit log's encrypted fields: the log is append-only
	// and hash-chained, so the job never rewrites them and an old data key
	// version stays needed until retention purges those records.
	Audit map[int]int64
}

// ResealCursor is the position of a re-encryption pass: the zero value starts
// a pass; After is the last primary key handled in (Table, Column).
type ResealCursor struct {
	Table, Column, After string
}

// ColumnKeyRepository holds the key jobs and the maintenance operations of
// online key rotation. Run its methods on a transaction (Store.Begin) when
// they must be atomic; ResealBatch and ReindexBlind are written for that.
type ColumnKeyRepository interface {
	// CreateKeyJob stores a pending job and returns its id.
	CreateKeyJob(ctx context.Context, j KeyJob) (int64, error)
	// KeyJobs lists the newest jobs first (at most limit).
	KeyJobs(ctx context.Context, limit int) ([]KeyJob, error)
	// NextKeyJob returns the oldest job that is pending or running
	// (ErrNotFound when there is none).
	NextKeyJob(ctx context.Context) (KeyJob, error)
	// UpdateKeyJob sets the status, version and detail of job id (a job that
	// is done or failed is final).
	UpdateKeyJob(ctx context.Context, id int64, status string, version int, detail string) error

	// ColumnVersions counts the encrypted values per key version.
	ColumnVersions(ctx context.Context) (ColumnVersions, error)
	// ResealBatch re-seals up to limit encrypted values after cur whose key
	// version is lower than newest: each is opened with c, sealed again with
	// c (under its active key) and written only if the stored value is still
	// the one that was read (compare-and-swap; a concurrent change is not
	// overwritten). It returns the cursor to continue from, how many values it
	// rewrote and whether the pass reached its end.
	ResealBatch(ctx context.Context, c ColumnCodec, newest int, cur ResealCursor, limit int) (next ResealCursor, resealed int, done bool, err error)
	// ReindexBlind recomputes every blind-index column from the stored values
	// with c, in the caller's transaction. On PostgreSQL it first locks the
	// tables against writes for the length of the transaction.
	ReindexBlind(ctx context.Context, c ColumnCodec) error
}
