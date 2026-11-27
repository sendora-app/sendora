// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/keyops"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// Tenant key rotation (docs/cluster/DESIGN.md 6.4, D43). A tenant administrator
// asks for a rotation or a retirement; the request is a row in the tenant's own
// database (ports.KeyJob). The process that may write the control log runs it:
// the SQLite process itself, or the Cluster controller leader (web replicas
// only create the row and signal the controller). The re-encryption runs in
// small batches in the background and the tenant keeps working meanwhile.

// WorkKeyJob is the work signal a web replica sends the controller for a new
// key job; TopicKeys announces that a tenant's keyring changed.
const WorkKeyJob = "key_job"

func topicKeys(tenant string) string { return "keys:" + tenant }

const (
	keyJobPoll    = time.Minute // finds jobs whose signal was lost or whose process restarted
	keyBatchPause = 20 * time.Millisecond
	keyJobLimit   = 20
)

// keysEnabled reports whether this tenant's database encrypts its columns (a
// plaintext fixture database has no keys to rotate).
func (s *Server) keysEnabled() bool { return s.St.ColumnKeyring() != nil }

// runsKeyJobs reports whether this process executes key jobs.
func (s *Server) runsKeyJobs() bool {
	return s.keysEnabled() && (s.cl == nil || s.cl.rt.RunJobs)
}

// keyEngine builds the engine over this tenant's store. A writing engine needs
// the keyring service that may write the control log: the store's own on
// SQLite, the controller's owner-role service on the Cluster flavour.
func (s *Server) keyEngine(ctx context.Context, write bool) (*keyops.Engine, func(), error) {
	if !s.keysEnabled() {
		return nil, nil, keyops.ErrNotEnabled
	}
	release := func() {}
	var svc *keyring.Service
	var err error
	if write && s.cl != nil {
		if s.cl.rt.KeyWriter == nil {
			return nil, nil, errors.New("this replica cannot write the tenant's keys; the controller does")
		}
		svc, release, err = s.cl.rt.KeyWriter(ctx, s.cl.tenantID)
	} else {
		svc, err = s.St.KeyringService()
	}
	if err != nil {
		return nil, nil, err
	}
	e := &keyops.Engine{KeyID: store.ColumnKeyID, Svc: svc, Codec: s.St.ColumnKeyring(), Store: s.St.Repos(), Files: s.St, Actor: "key rotation",
		Batch: 200, Pause: keyBatchPause, Settle: s.keySettle, Changed: s.keysChanged}
	return e, release, nil
}

// keysChanged tells the other replicas that this tenant's keyring changed so
// their codecs switch to the new versions.
func (s *Server) keysChanged() {
	if s.cl == nil {
		return
	}
	if err := s.cl.rt.Coordinator.Notify(context.Background(), topicKeys(s.cl.tenantID)); err != nil {
		s.cl.warn("key notification", err)
	}
}

// refreshKeys makes this replica's codec follow the keyring.
func (s *Server) refreshKeys() {
	if c := s.St.ColumnKeyring(); c != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := c.Refresh(ctx); err != nil {
			log.Printf("keys: following the keyring: %v", err)
		}
	}
}

// WakeKeyJobs wakes the tenant's key-job worker.
func (s *Server) WakeKeyJobs() {
	select {
	case s.keyJobWake <- struct{}{}:
	default:
	}
}

// WakeKeyJobs opens tenant id (when needed) and wakes its key-job worker (the
// controller's work-signal consumer).
func (h *TenantHost) WakeKeyJobs(id string) error {
	return h.withTenant(id, func(s *Server) error {
		s.WakeKeyJobs()
		return nil
	})
}

// RunKeyJobs starts the worker that executes the tenant's key jobs, one at a
// time, until ctx ends. It continues a job a restart interrupted.
func (s *Server) RunKeyJobs(ctx context.Context) {
	if !s.runsKeyJobs() {
		return
	}
	s.keyJobsOnce.Do(func() {
		go func() {
			t := time.NewTicker(keyJobPoll)
			defer t.Stop()
			for {
				for s.runNextKeyJob(ctx) {
				}
				select {
				case <-ctx.Done():
					return
				case <-s.keyJobWake:
				case <-t.C:
				}
			}
		}()
	})
}

// keyJobSlots bounds how many key jobs run at the same time in this process
// (SENDORA_KEY_JOB_CONCURRENCY, default 3): a forced rotation of every tenant
// (platform console) would otherwise start one job per tenant at once, every
// one re-encrypting rows through the database pooler.
var (
	keyJobSlotsOnce sync.Once
	keyJobSlots     chan struct{}
)

func acquireKeyJobSlot(ctx context.Context) (release func(), ok bool) {
	keyJobSlotsOnce.Do(func() {
		n := 3
		if v, err := strconv.Atoi(os.Getenv("SENDORA_KEY_JOB_CONCURRENCY")); err == nil && v >= 1 && v <= 64 {
			n = v
		}
		keyJobSlots = make(chan struct{}, n)
	})
	select {
	case keyJobSlots <- struct{}{}:
		return func() { <-keyJobSlots }, true
	case <-ctx.Done():
		return nil, false
	}
}

// runNextKeyJob executes the oldest open job and reports whether there was one.
func (s *Server) runNextKeyJob(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	if _, err := s.St.Repos().ColumnKeys().NextKeyJob(ctx); err != nil {
		return false // nothing to do: do not queue for a slot
	}
	slotDone, ok := acquireKeyJobSlot(ctx)
	if !ok {
		return false
	}
	defer slotDone()
	job, err := s.St.Repos().ColumnKeys().NextKeyJob(ctx)
	if err != nil {
		return false
	}
	// Cluster: only the leader runs jobs; a former leader (epoch 0 or stale)
	// must not start one. The writes of a job are idempotent and serialised by
	// the control log's linked sequence, so a stale leader cannot corrupt it.
	if s.cl != nil && s.cl.rt.Coordinator.Epoch() <= 0 {
		return false
	}
	e, release, err := s.keyEngine(ctx, true)
	if err != nil {
		log.Printf("keys: tenant job %d: %v", job.ID, err)
		return false
	}
	defer release()
	if job.Status == ports.KeyJobPending {
		s.logEvent(0, "system", "key_job_started", "keys:"+job.Purpose, keyops.Describe(job)+" requested by "+job.Actor)
	}
	res, err := e.Execute(ctx, job)
	if ctx.Err() != nil && err != nil {
		return false // shutting down: the job stays running and resumes at the next start
	}
	done := job
	done.Version, done.Detail = max(res.Version, job.Version), res.Detail
	switch {
	case err != nil && job.Op == ports.KeyJobRetire:
		s.logEvent(0, "system", "key_retire_failed", "keys:"+job.Purpose, fmt.Sprintf("version %d: %v (requested by %s)", job.Version, err, job.Actor))
	case err != nil:
		s.logEvent(0, "system", "key_rotation_failed", "keys:"+job.Purpose, fmt.Sprintf("%v (requested by %s)", err, job.Actor))
		log.Printf("keys: %s rotation of tenant failed: %v", job.Purpose, err)
	case job.Op == ports.KeyJobRetire:
		s.logEvent(0, "system", "key_retired", "keys:"+job.Purpose, fmt.Sprintf("%s (requested by %s)", res.Detail, job.Actor))
	default:
		s.logEvent(0, "system", "key_rotation_completed", "keys:"+job.Purpose, fmt.Sprintf("%s (requested by %s)", res.Detail, job.Actor))
	}
	return true
}

// wakeKeyWorker makes the process that runs key jobs look for new work.
func (s *Server) wakeKeyWorker() {
	if s.runsKeyJobs() {
		s.WakeKeyJobs()
		return
	}
	s.signalWork(WorkKeyJob)
}

// ---------- API (tenant administrators, step-up) ----------

type keyVersionJSON struct {
	Version     int    `json:"version"`
	State       string `json:"state"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at,omitempty"`
	Rows        int64  `json:"rows"`
	AuditRows   int64  `json:"audit_rows"`
	Files       int64  `json:"files"` // stored files under this version (files key; -1 unknown)
}

type keyPurposeJSON struct {
	Purpose   string           `json:"purpose"`
	Rotatable bool             `json:"rotatable"`
	Active    int              `json:"active"`
	Staged    int              `json:"staged,omitempty"`
	Versions  []keyVersionJSON `json:"versions"`
}

type keyJobJSON struct {
	ID          int64  `json:"id"`
	Op          string `json:"op"`
	Purpose     string `json:"purpose"`
	Version     int    `json:"version"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	RequestedBy string `json:"requested_by"`
	RequestedAt string `json:"requested_at"`
	UpdatedAt   string `json:"updated_at"`
}

// keysStatus: GET /api/admin/keys. Versions, states, fingerprints, the number
// of encrypted values still on each version and the recent jobs; never key
// material.
func (s *Server) keysStatus(w http.ResponseWriter, r *http.Request) {
	e, release, err := s.keyEngine(r.Context(), false)
	if err != nil {
		jerr(w, http.StatusNotFound, "column encryption is not enabled")
		return
	}
	defer release()
	st, err := e.Status(r.Context())
	if err != nil {
		log.Printf("keys: status: %v", err)
		jerr(w, http.StatusInternalServerError, "the key status could not be read")
		return
	}
	out := struct {
		Purposes    []keyPurposeJSON `json:"purposes"`
		Jobs        []keyJobJSON     `json:"jobs"`
		LegacyFiles int64            `json:"legacy_files"` // files under the old root-derived key: not served until re-encrypted
	}{Purposes: []keyPurposeJSON{}, Jobs: []keyJobJSON{}, LegacyFiles: st.LegacyFiles}
	for _, p := range st.Purposes {
		pj := keyPurposeJSON{Purpose: p.Purpose, Rotatable: p.Rotatable, Active: p.Active, Staged: p.Staged, Versions: []keyVersionJSON{}}
		for _, v := range p.Versions {
			vj := keyVersionJSON{Version: v.Version, State: v.State, Fingerprint: v.Fingerprint, Rows: v.Rows, AuditRows: v.AuditRows, Files: v.Files}
			if !v.CreatedAt.IsZero() {
				vj.CreatedAt = v.CreatedAt.UTC().Format(time.RFC3339)
			}
			pj.Versions = append(pj.Versions, vj)
		}
		out.Purposes = append(out.Purposes, pj)
	}
	for _, j := range st.Jobs {
		out.Jobs = append(out.Jobs, keyJobJSON{ID: j.ID, Op: j.Op, Purpose: j.Purpose, Version: j.Version, Status: j.Status, Detail: j.Detail,
			RequestedBy: j.Actor, RequestedAt: j.RequestedAt.UTC().Format(time.RFC3339), UpdatedAt: j.UpdatedAt.UTC().Format(time.RFC3339)})
	}
	jout(w, http.StatusOK, out)
}

// keysRotate: POST /api/admin/keys/rotate {purpose} (administrators, step-up).
func (s *Server) keysRotate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Purpose string `json:"purpose"`
	}
	if decode(r, &b) != nil || !keyops.Rotatable(strings.TrimSpace(b.Purpose)) {
		jerr(w, http.StatusBadRequest, "purpose must be one of: "+strings.Join(keyops.Purposes, ", "))
		return
	}
	s.keysEnqueue(w, r, ports.KeyJob{Op: ports.KeyJobRotate, Purpose: strings.TrimSpace(b.Purpose)})
}

// keysRekeyFiles: POST /api/admin/keys/reencrypt-files (administrators,
// step-up). Rewrites the stored files that are not under the active files key
// (files from before the files key was kept in the keyring included).
func (s *Server) keysRekeyFiles(w http.ResponseWriter, r *http.Request) {
	s.keysEnqueue(w, r, ports.KeyJob{Op: ports.KeyJobRekeyFiles, Purpose: keyring.PurposeFiles})
}

// keysRetire: POST /api/admin/keys/retire {purpose, version} (administrators,
// step-up). Only a decrypt-only version that no value uses any more.
func (s *Server) keysRetire(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Purpose string `json:"purpose"`
		Version int    `json:"version"`
	}
	if decode(r, &b) != nil || !keyops.Rotatable(strings.TrimSpace(b.Purpose)) || b.Version < 1 {
		jerr(w, http.StatusBadRequest, "purpose and version required")
		return
	}
	e, release, err := s.keyEngine(r.Context(), false)
	if err != nil {
		jerr(w, http.StatusNotFound, "column encryption is not enabled")
		return
	}
	defer release()
	if err := e.CheckRetire(r.Context(), strings.TrimSpace(b.Purpose), b.Version); err != nil {
		jerr(w, http.StatusConflict, err.Error())
		return
	}
	s.keysEnqueue(w, r, ports.KeyJob{Op: ports.KeyJobRetire, Purpose: strings.TrimSpace(b.Purpose), Version: b.Version})
}

// keyOpsPerHour is the budget of key operations a tenant may start per hour:
// SENDORA_KEY_OPS_PER_HOUR (default 10). It limits what a stolen administrator
// session can do; raise it for testing.
func keyOpsPerHour() int {
	if n, err := strconv.Atoi(os.Getenv("SENDORA_KEY_OPS_PER_HOUR")); err == nil && n >= 1 && n <= 10000 {
		return n
	}
	return 10
}

func (s *Server) keysEnqueue(w http.ResponseWriter, r *http.Request, job ports.KeyJob) {
	if !s.keysEnabled() {
		jerr(w, http.StatusNotFound, "column encryption is not enabled")
		return
	}
	if !s.allowRequest("keyjob", keyOpsPerHour(), time.Hour) {
		jerr(w, http.StatusTooManyRequests, "too many key operations; try again later")
		return
	}
	jobs, err := s.St.Repos().ColumnKeys().KeyJobs(r.Context(), keyJobLimit)
	if err != nil {
		jerr(w, http.StatusInternalServerError, "the key jobs could not be read")
		return
	}
	if keyops.OpenJob(jobs, job.Purpose) {
		jerr(w, http.StatusConflict, "a key operation for this purpose is still running")
		return
	}
	me := s.ctxUser(r)
	job.Actor = me.Username
	id, err := s.St.Repos().ColumnKeys().CreateKeyJob(r.Context(), job)
	if err != nil {
		jerr(w, http.StatusInternalServerError, "the request could not be stored")
		return
	}
	s.wakeKeyWorker()
	jout(w, http.StatusAccepted, map[string]any{"ok": true, "job_id": id, "status": ports.KeyJobPending})
}
