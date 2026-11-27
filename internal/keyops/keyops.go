// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keyops runs the online rotation of a tenant's data keys (DESIGN 6.4,
// D43): it creates the next key version through the keyring, re-encrypts the
// values still sealed under older versions in small compare-and-swap batches,
// rebuilds the blind indexes when the index key rotates, and retires versions
// no data uses any more. It works on the ports only (no SQL). The process that
// owns the control log (the SQLite process, the Cluster controller) executes
// jobs; any process can read the status.
package keyops

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/ports"
)

// Purposes a tenant administrator can rotate. audit-mac stays out: the audit
// chain is MACed with its key for the life of the records (D45). Every
// encrypted column except the audit log's text fields is sealed with the data
// key, the audit log's actor/target/detail with the audit-enc key (new records
// use the active version; the log is append-only and never rewritten, so
// rotating audit-enc only creates the next version and old versions stay in
// use for as long as their records exist), the blind indexes use the index
// key and stored files the files key (a rotation of it rewrites the files,
// see Files); secrets is versioned and rotatable, but nothing is sealed under
// it yet, so rotating it only creates the next version.
var Purposes = []string{keyring.PurposeData, keyring.PurposeFiles, keyring.PurposeSecrets, keyring.PurposeAuditEnc, keyring.PurposeIndex}

// ErrAuditMACFixed is why the audit-mac key is refused.
var ErrAuditMACFixed = errors.New("the audit-mac key cannot be rotated: audit records stay MACed under the key they were written with (D45)")

// FileRewriter rewrites stored files under the active files key (the store
// implements it; the process that runs the job needs access to the files).
type FileRewriter interface {
	// RewriteFiles re-encrypts every encrypted file not under the active key
	// version, pausing between batches, and returns the counts.
	RewriteFiles(ctx context.Context, pause time.Duration) (rewritten, failed int, err error)
	// FileKeyCounts counts the encrypted files per key version (0 = legacy).
	FileKeyCounts(ctx context.Context) (map[int]int64, error)
}

// Rotatable reports whether purpose can be rotated by the tenant.
func Rotatable(purpose string) bool { return slices.Contains(Purposes, purpose) }

// Engine rotates the keys of one database.
type Engine struct {
	KeyID string           // control-log identity of the database's keys
	Svc   *keyring.Service // must be able to write the control log to run jobs
	Codec *keyring.Codec
	Store ports.Store
	Files FileRewriter // nil: the files key cannot be rotated here
	Actor string       // control-log actor when a job names none

	Batch   int           // values per re-encryption transaction (default 200)
	Pause   time.Duration // pause between batches (default none)
	Settle  time.Duration // wait after an index activation before the repair pass
	Changed func()        // called after the keyring changed (tell the other replicas)
}

func (e *Engine) batch() int {
	if e.Batch > 0 {
		return e.Batch
	}
	return 200
}

func (e *Engine) changed() {
	if e.Changed != nil {
		e.Changed()
	}
}

// Status is what the administrator sees: never key material.
type Status struct {
	// LegacyFiles counts files still under the old root-derived key (they are
	// not served until the files re-encryption has run).
	LegacyFiles int64
	Purposes    []PurposeStatus
	Jobs        []ports.KeyJob
}

// PurposeStatus describes the versions of one purpose.
type PurposeStatus struct {
	Purpose   string
	Rotatable bool
	Active    int
	Staged    int
	Versions  []VersionStatus
}

// VersionStatus describes one key version.
type VersionStatus struct {
	Version     int
	State       string
	Fingerprint string // hex of the key fingerprint, not the key
	CreatedAt   time.Time
	// Rows counts the encrypted values still sealed under this version
	// (data purpose only); AuditRows those of the audit log (audit-enc
	// purpose only), which the re-encryption job never rewrites.
	Rows      int64
	AuditRows int64
	// Files counts the stored files under this version (files purpose only;
	// -1 when this process cannot count them).
	Files int64
}

// Status reads the verified keyring, the counts per version and the jobs.
func (e *Engine) Status(ctx context.Context) (Status, error) {
	st, err := e.Svc.Verify(ctx, e.KeyID)
	if err != nil {
		return Status{}, err
	}
	counts, err := e.Store.ColumnKeys().ColumnVersions(ctx)
	if err != nil {
		return Status{}, err
	}
	var fileCounts map[int]int64
	if e.Files != nil {
		if fileCounts, err = e.Files.FileKeyCounts(ctx); err != nil {
			return Status{}, err
		}
	}
	out := Status{}
	if fileCounts[0] > 0 {
		out.LegacyFiles = fileCounts[0]
	}
	purposes := make([]string, 0, len(st.Versions))
	for p := range st.Versions {
		purposes = append(purposes, p)
	}
	sort.Strings(purposes)
	for _, p := range purposes {
		ps := PurposeStatus{Purpose: p, Rotatable: Rotatable(p), Active: st.Active[p], Staged: st.Staged(p)}
		for _, v := range st.Versions[p] {
			vs := VersionStatus{Version: v, State: st.States[p][v]}
			if row, err := e.Svc.Ring.Active(ctx, e.KeyID, p, v); err == nil {
				vs.Fingerprint = hex.EncodeToString(row.Fingerprint)
				vs.CreatedAt = row.CreatedAt
			}
			switch p {
			case keyring.PurposeData:
				vs.Rows = counts.Columns[v]
			case keyring.PurposeAuditEnc:
				vs.AuditRows = counts.Audit[v]
			}
			if p == keyring.PurposeFiles {
				vs.Files = -1
				if fileCounts != nil {
					vs.Files = fileCounts[v]
				}
			}
			ps.Versions = append(ps.Versions, vs)
		}
		out.Purposes = append(out.Purposes, ps)
	}
	if out.Jobs, err = e.Store.ColumnKeys().KeyJobs(ctx, 20); err != nil {
		return Status{}, err
	}
	return out, nil
}

// CheckRetire reports why version of purpose cannot be retired (nil when it
// can): it must be decrypt-only and, for the data key, no encrypted column
// value may still be sealed under it; for audit-enc no audit record may be
// (the audit log is never rewritten, so such a version stays until retention
// has purged its records).
func (e *Engine) CheckRetire(ctx context.Context, purpose string, version int) error {
	if purpose == keyring.PurposeAuditMAC {
		return ErrAuditMACFixed
	}
	if !Rotatable(purpose) {
		return fmt.Errorf("the %s key cannot be retired by the tenant", purpose)
	}
	st, err := e.Svc.Verify(ctx, e.KeyID)
	if err != nil {
		return err
	}
	switch st.States[purpose][version] {
	case keyring.StateDecryptOnly:
	case keyring.StateRetired:
		return fmt.Errorf("%s version %d is already retired", purpose, version)
	case "":
		return fmt.Errorf("%s version %d does not exist", purpose, version)
	default:
		return fmt.Errorf("%s version %d is %s; only a decrypt-only version can be retired", purpose, version, st.States[purpose][version])
	}
	if purpose == keyring.PurposeData {
		counts, err := e.Store.ColumnKeys().ColumnVersions(ctx)
		if err != nil {
			return err
		}
		if n := counts.Columns[version]; n > 0 {
			return fmt.Errorf("%d encrypted values are still sealed under data version %d", n, version)
		}
	}
	if purpose == keyring.PurposeAuditEnc {
		counts, err := e.Store.ColumnKeys().ColumnVersions(ctx)
		if err != nil {
			return err
		}
		if a := counts.Audit[version]; a > 0 {
			return fmt.Errorf("%d audit-log values are still sealed under audit-enc version %d (the audit log is never rewritten)", a, version)
		}
	}
	if purpose == keyring.PurposeFiles {
		if e.Files == nil {
			return errors.New("the stored files cannot be counted in this process")
		}
		counts, err := e.Files.FileKeyCounts(ctx)
		if err != nil {
			return err
		}
		if n := counts[version]; n > 0 {
			return fmt.Errorf("%d stored files are still encrypted under files version %d", n, version)
		}
	}
	return nil
}

// Result is what a finished job did.
type Result struct {
	Version int
	Detail  string
}

// Execute runs job to completion and records the outcome on the job row (a job
// with ID 0, as the offline CLI builds, has none). It can be called again for a
// job that was interrupted: it continues where the job's version says it was.
func (e *Engine) Execute(ctx context.Context, job ports.KeyJob) (Result, error) {
	if job.Actor == "" {
		job.Actor = e.Actor
	}
	e.update(ctx, job, ports.KeyJobRunning, "")
	var res Result
	var err error
	switch job.Op {
	case ports.KeyJobRotate:
		res, err = e.rotate(ctx, &job)
	case ports.KeyJobRetire:
		res, err = e.retire(ctx, job)
	case ports.KeyJobRekeyFiles:
		res, err = e.rekeyFiles(ctx, job)
	default:
		err = fmt.Errorf("unknown key job %q", job.Op)
	}
	if err != nil {
		e.update(ctx, withVersion(job, res.Version), ports.KeyJobFailed, err.Error())
		return res, err
	}
	e.update(ctx, withVersion(job, res.Version), ports.KeyJobDone, res.Detail)
	return res, nil
}

func withVersion(j ports.KeyJob, v int) ports.KeyJob {
	if v != 0 {
		j.Version = v
	}
	return j
}

func (e *Engine) update(ctx context.Context, j ports.KeyJob, status, detail string) {
	if j.ID == 0 {
		return
	}
	// The job row must be written even when ctx has ended (shutdown).
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	e.Store.ColumnKeys().UpdateKeyJob(wctx, j.ID, status, j.Version, detail)
}

func (e *Engine) rotate(ctx context.Context, job *ports.KeyJob) (Result, error) {
	switch job.Purpose {
	case keyring.PurposeData:
		return e.rotateData(ctx, job)
	case keyring.PurposeIndex:
		return e.rotateIndex(ctx, job)
	case keyring.PurposeFiles:
		return e.rotateFiles(ctx, job)
	case keyring.PurposeAuditMAC:
		return Result{}, ErrAuditMACFixed
	case keyring.PurposeSecrets, keyring.PurposeAuditEnc:
		v := job.Version
		if v == 0 {
			var err error
			if v, err = e.Svc.Rotate(ctx, e.KeyID, job.Purpose, job.Actor); err != nil {
				return Result{}, err
			}
			e.changed()
		}
		if job.Purpose == keyring.PurposeAuditEnc {
			// New audit records are sealed under the new version from now on.
			if _, err := e.Codec.Refresh(ctx); err != nil {
				return Result{Version: v}, err
			}
		}
		return Result{v, fmt.Sprintf("%s key version %d active", job.Purpose, v)}, nil
	}
	return Result{}, fmt.Errorf("the %s key cannot be rotated by the tenant", job.Purpose)
}

// begin records the version a rotate job created, so a restarted job does not
// create another one.
func (e *Engine) begin(ctx context.Context, job *ports.KeyJob, version int) {
	job.Version = version
	e.update(ctx, *job, ports.KeyJobRunning, "")
}

func (e *Engine) rotateData(ctx context.Context, job *ports.KeyJob) (Result, error) {
	if job.Version == 0 {
		v, err := e.Svc.Rotate(ctx, e.KeyID, keyring.PurposeData, job.Actor)
		if err != nil {
			return Result{}, err
		}
		e.begin(ctx, job, v)
		if _, err := e.Codec.Refresh(ctx); err != nil {
			return Result{Version: v}, err
		}
		e.changed()
	}
	n, left, err := e.ResealAll(ctx, job.Version)
	res := Result{Version: job.Version}
	if err != nil {
		return res, err
	}
	res.Detail = fmt.Sprintf("data key version %d is active; %d values re-encrypted, %d still on older versions", job.Version, n, left)
	return res, nil
}

func (e *Engine) rotateFiles(ctx context.Context, job *ports.KeyJob) (Result, error) {
	if e.Files == nil {
		return Result{}, errors.New("this process cannot rewrite the stored files, so it cannot rotate the files key")
	}
	if job.Version == 0 {
		v, err := e.Svc.Rotate(ctx, e.KeyID, keyring.PurposeFiles, job.Actor)
		if err != nil {
			return Result{}, err
		}
		e.begin(ctx, job, v)
		if _, err := e.Codec.Refresh(ctx); err != nil {
			return Result{Version: v}, err
		}
		e.changed()
	}
	n, left, err := e.rewriteFiles(ctx, job.Version)
	res := Result{Version: job.Version}
	if err != nil {
		return res, err
	}
	res.Detail = fmt.Sprintf("files key version %d is active; %d files re-encrypted, %d still on older versions", job.Version, n, left)
	return res, nil
}

// rekeyFiles is the job that converts the files still under the legacy key (or
// any older version) to the active version without rotating.
func (e *Engine) rekeyFiles(ctx context.Context, job ports.KeyJob) (Result, error) {
	if e.Files == nil {
		return Result{}, errors.New("this process cannot rewrite the stored files")
	}
	if _, err := e.Codec.Refresh(ctx); err != nil {
		return Result{}, err
	}
	active := e.Codec.FilesActive()
	n, left, err := e.rewriteFiles(ctx, active)
	res := Result{Version: active}
	if err != nil {
		return res, err
	}
	res.Detail = fmt.Sprintf("%d files re-encrypted under files key version %d, %d still on older keys", n, active, left)
	if left > 0 {
		return res, errors.New(res.Detail)
	}
	return res, nil
}

// rewriteFiles repeats the file rewrite (up to five passes: files uploaded
// meanwhile by a replica that had not yet followed the rotation are picked up
// by the next one) until no file is left under a version older than newest.
func (e *Engine) rewriteFiles(ctx context.Context, newest int) (rewritten int, left int64, err error) {
	for pass := 0; pass < 5; pass++ {
		n, _, err := e.Files.RewriteFiles(ctx, e.Pause)
		rewritten += n
		if err != nil {
			return rewritten, 0, err
		}
		counts, err := e.Files.FileKeyCounts(ctx)
		if err != nil {
			return rewritten, 0, err
		}
		left = 0
		for v, c := range counts {
			if v < newest {
				left += c
			}
		}
		if left == 0 {
			return rewritten, 0, nil
		}
		if n == 0 {
			break // no progress: what is left failed (see the log), do not repeat
		}
	}
	return rewritten, left, nil
}

// ResealAll re-encrypts every value sealed under a version lower than newest
// (the audit log excepted) and returns how many it rewrote and how many are
// still on older versions afterwards (values changed concurrently, or sealed
// by a replica that has not yet followed the rotation, are picked up by a
// repeat pass; a few passes run before it gives up).
func (e *Engine) ResealAll(ctx context.Context, newest int) (rewritten int, left int64, err error) {
	if data, _ := e.Codec.Versions(); data < newest {
		if _, err := e.Codec.Refresh(ctx); err != nil {
			return 0, 0, err
		}
		if data, _ = e.Codec.Versions(); data < newest {
			return 0, 0, fmt.Errorf("the codec encrypts with version %d, not the new version %d", data, newest)
		}
	}
	for pass := 0; pass < 5; pass++ {
		var cur ports.ResealCursor
		for {
			if err := ctx.Err(); err != nil {
				return rewritten, 0, err
			}
			next, n, done, err := e.resealBatch(ctx, newest, cur)
			if err != nil {
				return rewritten, 0, err
			}
			rewritten += n
			if done {
				break
			}
			cur = next
			if e.Pause > 0 {
				select {
				case <-ctx.Done():
					return rewritten, 0, ctx.Err()
				case <-time.After(e.Pause):
				}
			}
		}
		counts, err := e.Store.ColumnKeys().ColumnVersions(ctx)
		if err != nil {
			return rewritten, 0, err
		}
		left = 0
		for v, c := range counts.Columns {
			if v < newest {
				left += c
			}
		}
		if left == 0 {
			return rewritten, 0, nil
		}
	}
	return rewritten, left, nil
}

func (e *Engine) resealBatch(ctx context.Context, newest int, cur ports.ResealCursor) (ports.ResealCursor, int, bool, error) {
	tx, err := e.Store.Begin(ctx)
	if err != nil {
		return cur, 0, false, err
	}
	defer tx.Rollback()
	next, n, done, err := tx.ColumnKeys().ResealBatch(ctx, e.Codec, newest, cur, e.batch())
	if err != nil {
		return cur, 0, false, err
	}
	return next, n, done, tx.Commit()
}

// reindex rebuilds every blind index with c in one transaction.
func (e *Engine) reindex(ctx context.Context, c ports.ColumnCodec) error {
	tx, err := e.Store.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.ColumnKeys().ReindexBlind(ctx, c); err != nil {
		return err
	}
	return tx.Commit()
}

func (e *Engine) rotateIndex(ctx context.Context, job *ports.KeyJob) (Result, error) {
	st, err := e.Svc.Verify(ctx, e.KeyID)
	if err != nil {
		return Result{}, err
	}
	v := job.Version
	if v == 0 {
		if v = st.Staged(keyring.PurposeIndex); v == 0 {
			if v, err = e.Svc.Stage(ctx, e.KeyID, keyring.PurposeIndex, job.Actor); err != nil {
				return Result{}, err
			}
		}
		e.begin(ctx, job, v)
	}
	res := Result{Version: v}
	if st.Active[keyring.PurposeIndex] < v {
		// The new index key is built first, into the live columns, in one
		// transaction; it is activated only once that has committed.
		view, release, err := e.Codec.IndexView(ctx, v)
		if err != nil {
			return res, err
		}
		err = e.reindex(ctx, view)
		release()
		if err != nil {
			return res, fmt.Errorf("rebuilding the blind indexes: %w", err)
		}
		if err := e.Svc.Activate(ctx, e.KeyID, keyring.PurposeIndex, v, job.Actor); err != nil {
			return res, err
		}
	}
	if _, err := e.Codec.Refresh(ctx); err != nil {
		return res, err
	}
	e.changed()
	// Replicas that have not yet followed may have written a row with the old
	// index key: repair pass once they have.
	if e.Settle > 0 {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(e.Settle):
		}
	}
	if err := e.reindex(ctx, e.Codec); err != nil {
		return res, fmt.Errorf("repairing the blind indexes: %w", err)
	}
	res.Detail = fmt.Sprintf("index key version %d is active; the blind indexes were rebuilt", v)
	return res, nil
}

func (e *Engine) retire(ctx context.Context, job ports.KeyJob) (Result, error) {
	res := Result{Version: job.Version}
	if err := e.CheckRetire(ctx, job.Purpose, job.Version); err != nil {
		return res, err
	}
	if err := e.Svc.Retire(ctx, e.KeyID, job.Purpose, job.Version, job.Actor); err != nil {
		return res, err
	}
	e.changed()
	res.Detail = fmt.Sprintf("%s key version %d retired", job.Purpose, job.Version)
	return res, nil
}

// OpenJob reports whether an unfinished job for purpose exists.
func OpenJob(jobs []ports.KeyJob, purpose string) bool {
	for _, j := range jobs {
		if j.Purpose == purpose && (j.Status == ports.KeyJobPending || j.Status == ports.KeyJobRunning) {
			return true
		}
	}
	return false
}

// ErrNotEnabled is returned when the database does not encrypt its columns.
var ErrNotEnabled = errors.New("column encryption is not enabled")

// Describe renders a job for the audit log.
func Describe(j ports.KeyJob) string {
	return strings.TrimSpace(fmt.Sprintf("%s %s version=%d %s", j.Op, j.Purpose, j.Version, j.Detail))
}

// Overview is the short, cheap view the platform operator gets of a tenant's
// keys: never key material, no row counts (D46: the operator's key management
// screen lists every tenant and must not scan their data).
type Overview struct {
	// Active is the active version per purpose.
	Active map[string]int
	// Behind counts the key versions that are only kept for decryption (not
	// yet retired) over all purposes: rotations whose old version is still
	// needed.
	Behind int
	// LastRotation is the newest creation time of an active version above
	// v1 (zero when no purpose was ever rotated).
	LastRotation time.Time
	// Running names the purposes with an unfinished job.
	Running []string
	// LastFinished is the update time of the newest finished job (zero when
	// none); LastFailed is its error text when that job failed.
	LastFinished time.Time
	LastFailed   string
}

// Overview reads the verified keyring and the recent jobs.
func (e *Engine) Overview(ctx context.Context) (Overview, error) {
	st, err := e.Svc.Verify(ctx, e.KeyID)
	if err != nil {
		return Overview{}, err
	}
	out := Overview{Active: map[string]int{}}
	for p, vs := range st.Versions {
		out.Active[p] = st.Active[p]
		for _, v := range vs {
			if st.States[p][v] == keyring.StateDecryptOnly {
				out.Behind++
			}
			if v == st.Active[p] && v > 1 {
				if row, err := e.Svc.Ring.Active(ctx, e.KeyID, p, v); err == nil && row.CreatedAt.After(out.LastRotation) {
					out.LastRotation = row.CreatedAt
				}
			}
		}
	}
	jobs, err := e.Store.ColumnKeys().KeyJobs(ctx, 20)
	if err != nil {
		return Overview{}, err
	}
	seen := false // jobs come newest first: the first finished one is the last operation
	for _, j := range jobs {
		switch j.Status {
		case ports.KeyJobPending, ports.KeyJobRunning:
			if !slices.Contains(out.Running, j.Purpose) {
				out.Running = append(out.Running, j.Purpose)
			}
		case ports.KeyJobDone, ports.KeyJobFailed:
			if !seen {
				seen = true
				out.LastFinished = j.UpdatedAt
				if j.Status == ports.KeyJobFailed {
					out.LastFailed = j.Detail
				}
			}
		}
	}
	sort.Strings(out.Running)
	return out, nil
}
