// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sendora-app/sendora/internal/barrier"
)

// Readiness (GET /api/health/ready) and Prometheus metrics (GET /api/metrics).
// /api/health stays the liveness probe: it only says the process serves HTTP.

const metricsTokenEnv = "SENDORA_METRICS_TOKEN_FILE"

// Variables so tests can change them.
var (
	// readyMinFreeBytes is the free space the data directory needs to be ready.
	readyMinFreeBytes uint64 = 256 << 20
	readyCheckTimeout        = 2 * time.Second
	// readyBackupGrace: right after a start no automatic backup exists yet (the
	// first one runs ten minutes in); a stale backup is tolerated this long.
	readyBackupGrace = time.Hour
)

// opsState holds counters for /api/metrics and readiness state.
type opsState struct {
	loginOK, loginFailed, mfaFailed, decryptFailed, ipBans, downloadsStarted, uploadsCompleted atomic.Int64
	lastAutoBackup                                                                             atomic.Int64 // unix seconds of the last successful automatic backup
	chainBroken                                                                                atomic.Bool  // last known result of the chain verification
	chainChecking                                                                              atomic.Bool  // a readiness verification is running
}

// countAction counts the audit actions that have a metric. It runs before the
// record is written, so a failing audit log does not hide them.
func (o *opsState) countAction(action string) {
	switch action {
	case "login_ok", "mfa_login_ok":
		o.loginOK.Add(1)
	case "login_failed":
		o.loginFailed.Add(1)
	case "mfa_failed":
		o.mfaFailed.Add(1)
	case "file_decrypt_failed":
		o.decryptFailed.Add(1)
	case "ip_banned":
		o.ipBans.Add(1)
	case "download_started":
		o.downloadsStarted.Add(1)
	case "share_created", "share_files_added":
		o.uploadsCompleted.Add(1)
	}
}

// ready: GET /api/health/ready (no authentication). 200 when every check
// passes, 503 otherwise; the body names each check as "ok" or "fail" and
// nothing more.
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readyCheckTimeout)
	defer cancel()
	checks := map[string]string{}
	all := true
	set := func(name string, ok bool) {
		checks[name] = "ok"
		if !ok {
			checks[name] = "fail"
			all = false
		}
	}
	pong, pingErr := s.St.Repos().System().Ping(ctx)
	dbOK := pingErr == nil && pong
	set("database", dbOK)
	// Cheap and without writing a record: the last append succeeded and the
	// connection is not read-only.
	set("audit_log", dbOK && !s.audit.lastFailed.Load() && s.writable(ctx))
	free, err := freeSpaceFn(s.St.DataDir)
	set("disk", errors.Is(err, errNoDiskSpaceInfo) || (err == nil && free >= readyMinFreeBytes)) // unknown platform: not a failure
	if s.St.SettingBool("backups_enabled") {
		set("backup", s.backupFresh())
	}
	set("audit_chain", s.chainReady(ctx))
	status, code := "ok", http.StatusOK
	if !all {
		status, code = "fail", http.StatusServiceUnavailable
	}
	w.Header().Set("Cache-Control", "no-store")
	jout(w, code, map[string]any{"status": status, "checks": checks})
}

// backupFresh: the newest backup (automatic, or one an administrator made) is
// at most two backup intervals old, or the process started less than
// readyBackupGrace ago.
func (s *Server) backupFresh() bool {
	newest := time.Time{}
	if t := s.ops.lastAutoBackup.Load(); t > 0 {
		newest = time.Unix(t, 0)
	}
	ents, _ := os.ReadDir(filepath.Join(s.St.DataDir, "backups"))
	for _, e := range ents {
		if !backupRe.MatchString(e.Name()) || strings.HasPrefix(e.Name(), "sendora-preimport-") || e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return time.Since(newest) <= 2*autoBackupInterval || time.Since(s.Started) < readyBackupGrace
}

// chainReady verifies the new part of the audit chain (incremental, so cheap
// once the start-up verification is done). When that does not finish within
// the readiness timeout the last known result is used.
func (s *Server) chainReady(ctx context.Context) bool {
	// The verification waits for a lock another verification may hold for long
	// (the start-up walk of a large log), so it runs aside and at most once at a
	// time; the probe returns the last known result when it does not finish.
	if s.ops.chainChecking.CompareAndSwap(false, true) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer s.ops.chainChecking.Store(false)
			vctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if st, err := s.St.AuditVerifyIncremental(vctx); err == nil {
				s.ops.chainBroken.Store(!st.OK)
			}
		}()
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
	return !s.ops.chainBroken.Load()
}

// metrics: GET /api/metrics in the Prometheus text format. Off (404) unless
// SENDORA_METRICS_TOKEN_FILE names a token file; the request must carry that
// token as a bearer token.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	p := os.Getenv(metricsTokenEnv)
	if p == "" {
		jerr(w, 404, "not found")
		return
	}
	want, err := readSecretToken(metricsTokenEnv, p)
	if err != nil {
		log.Printf("metrics: %v", err)
		jerr(w, 503, "metrics unavailable")
		return
	}
	h := r.Header.Get("Authorization")
	got, ok := strings.CutPrefix(h, "Bearer ")
	a, b := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(want))
	if !ok || subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		jerr(w, 401, "unauthorized")
		return
	}
	sessions, _ := s.St.Repos().Uploads().CountAll(r.Context())

	var out strings.Builder
	metric := func(name, typ, help string, samples ...string) {
		fmt.Fprintf(&out, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		for _, smp := range samples {
			out.WriteString(name + smp + "\n")
		}
	}
	v := func(labels string, n int64) string { return fmt.Sprintf("%s %d", labels, n) }
	o := &s.ops
	metric("sendora_logins_total", "counter", "Sign-ins by result (password and second-factor completions).",
		v(`{result="ok"}`, o.loginOK.Load()), v(`{result="failed"}`, o.loginFailed.Load()))
	metric("sendora_mfa_failures_total", "counter", "Failed second-factor checks.", v("", o.mfaFailed.Load()))
	metric("sendora_audit_write_failures_total", "counter", "Audit records that could not be written.", v("", s.audit.fails.Load()))
	var dropped, failed, queue []string
	s.fwd.sinks(s)
	for _, kind := range forwardSinkKinds {
		s.fwd.mu.Lock()
		st := s.fwd.statsFor(kind)
		s.fwd.mu.Unlock()
		l := `{sink="` + kind + `"}`
		dropped = append(dropped, v(l, st.dropped.Load()))
		failed = append(failed, v(l, st.failed.Load()))
		queue = append(queue, v(l, s.fwd.queued(kind)))
	}
	metric("sendora_audit_forward_dropped_total", "counter", "Audit records dropped because a forwarding queue was full.", dropped...)
	metric("sendora_audit_forward_failed_total", "counter", "Failed audit forwarding attempts (retried).", failed...)
	metric("sendora_decrypt_failures_total", "counter", "Stored files that could not be decrypted.", v("", o.decryptFailed.Load()))
	metric("sendora_ip_bans_total", "counter", "Addresses blocked after repeated failures.", v("", o.ipBans.Load()))
	metric("sendora_downloads_started_total", "counter", "Share downloads started.", v("", o.downloadsStarted.Load()))
	metric("sendora_uploads_completed_total", "counter", "Completed uploads (new shares and files added to shares).", v("", o.uploadsCompleted.Load()))
	metric("sendora_upload_sessions_active", "gauge", "Upload sessions in progress.", v("", sessions))
	metric("sendora_verified_download_slots_in_use", "gauge", "Verified-download slots in use.", v("", int64(len(integritySlots))))
	metric("sendora_audit_forward_queue_length", "gauge", "Audit records waiting to be forwarded.", queue...)
	metric("sendora_commit_outcome_unknown_total", "counter", "Commits whose outcome is unknown (design 4.1); each is logged as a reconciliation record.", v("", barrier.UnknownTotal()))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(out.String()))
}

// writable reports whether the database connection accepts writes.
func (s *Server) writable(ctx context.Context) bool {
	ro, err := s.St.Repos().System().ReadOnly(ctx)
	return err == nil && !ro
}
