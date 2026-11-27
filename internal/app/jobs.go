// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// jobsStopWait bounds how long GracefulStop waits for the maintenance loop.
const jobsStopWait = 5 * time.Second

// RunJobs starts periodic maintenance until ctx is cancelled. The stop itself is
// recorded by GracefulStop, after the loop has ended.
func (s *Server) RunJobs(ctx context.Context) {
	s.RunDownloadMail(ctx)
	s.RunKeyJobs(ctx)
	s.auditStartup()
	s.fwd.startHeartbeat(s, ctx)
	// Verify the whole chain once in the background (in chunks that free the
	// database connection in between); status requests then only check new records.
	go func() {
		st, err := s.St.AuditVerifyIncremental(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			log.Printf("audit log verification at start-up: %v", err)
		case err == nil && !st.OK:
			log.Printf("WARNING: the audit log does not verify: first broken record %d (%s)", st.FirstBroken, st.Reason)
		}
	}()
	s.maintain()
	t := time.NewTicker(10 * time.Minute)
	lastBackup := s.initialLastBackup()
	done := make(chan struct{})
	s.jobsDone.Store(&done)
	go func() {
		defer close(done)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				s.maintain()
				if s.St.SettingBool("backups_enabled") && now.Sub(lastBackup) > autoBackupInterval {
					if s.autoBackup() {
						lastBackup = now
					}
				}
			}
		}
	}()
}

// GracefulStop stops serving and records the stop: it cancels the background
// jobs, shuts the HTTP server down (shutdown waits for requests in flight; when
// it fails or timeout passes, closeNow drops the remaining connections), waits
// (bounded) for the maintenance loop, and then writes system_stop
// synchronously, so the caller may close the store when it returns. Only the
// first call does the work; concurrent calls wait for it.
func (s *Server) GracefulStop(timeout time.Duration, stopJobs func(), shutdown func(context.Context) error, closeNow func() error) {
	s.stopOnce.Do(func() {
		if stopJobs != nil {
			stopJobs()
		}
		s.stopMigration()
		if shutdown != nil {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			if err := shutdown(ctx); err != nil {
				log.Printf("HTTP shutdown: %v; closing the remaining connections", err)
				if closeNow != nil {
					closeNow()
				}
			}
			cancel()
		}
		if done := s.jobsDone.Load(); done != nil {
			select {
			case <-*done:
			case <-time.After(jobsStopWait):
				log.Printf("background jobs did not stop within %s", jobsStopWait)
			}
		}
		s.recordStop()
	})
}

// recordStop writes system_stop once per process, then forwards the final
// chain head and drains the forwarding queues (bounded).
func (s *Server) recordStop() {
	s.stopRecorded.Do(func() {
		s.auditShutdown()
		s.fwd.stop(s, forwardStopWait)
	})
}

// autoBackupInterval is the period of the automatic backup.
const autoBackupInterval = 24 * time.Hour

// autoBackup makes the periodic backup and prunes old ones, recording both in
// the audit log as system actions. It reports whether the backup succeeded.
func (s *Server) autoBackup() bool {
	name, err := s.makeBackup()
	if err != nil {
		log.Println("backup failed:", err)
		// The error text may contain paths; it stays in the server log.
		s.logEvent(0, "system", "backup_failed_auto", "", "automatic backup failed; details are in the server log")
		return false
	}
	s.ops.lastAutoBackup.Store(time.Now().Unix())
	s.logEvent(0, "system", "backup_created_auto", name, "")
	for _, n := range s.pruneBackups() {
		s.logEvent(0, "system", "backup_pruned", n, "backup_keep="+strconv.Itoa(s.St.SettingInt("backup_keep", 7)))
	}
	// The backup is already SQLCipher-encrypted: the object store gets ciphertext.
	s.copyBackupRemote(name)
	return true
}

func (s *Server) maintain() {
	now := time.Now()
	s.cleanImportFiles()
	// mark expired
	if n, err := s.St.Repos().Maintenance().ExpireShares(context.Background(), now); err == nil {
		if n > 0 {
			s.logEvent(0, "system", "shares_expired", "", strconv.FormatInt(n, 10)+" shares")
		}
	}

	// expiry warnings
	if days := s.St.SettingInt("expiry_warning_days", 2); days > 0 {
		ws, _ := s.St.Repos().Maintenance().SharesToWarn(context.Background(), now.AddDate(0, 0, days))
		// Same rules as every other email link: a configured public https URL
		// (or a loopback address); otherwise no expiry mail with a broken link.
		base, baseOK := s.emailBaseURL(&http.Request{Host: "invalid.invalid"})
		if !baseOK {
			ws = nil
		}
		for _, x := range ws {
			s.St.Repos().Maintenance().MarkExpiryWarned(context.Background(), x.ID)
			s.queueMail(x.OwnerEmail, "Share expiring soon", "tpl_share_expiring", map[string]any{
				"ShareName": x.Name, "URL": base + "/share/" + x.LongID, "Expires": x.ExpiresAt.Format("2006-01-02")})
		}
	}

	// passwords that reach their maximum age within a week (password_rotation.go)
	s.warnExpiringPasswords(now)

	// delete files of long-expired shares
	if s.St.SettingBool("auto_clean_files") {
		keep := s.St.SettingInt("clean_files_days", 7)
		ids, _ := s.St.Repos().Maintenance().RetiredShareIDs(context.Background(), now.AddDate(0, 0, -keep))
		removed, failed := 0, 0
		for _, id := range ids {
			ok, err := s.removeShareIf(id, ports.ShareFilter{Kind: ports.ShareRetiredBefore, At: now.AddDate(0, 0, -keep)})
			switch {
			case err != nil:
				failed++
				log.Printf("expired share cleanup: %v", err)
			case ok:
				removed++
			}
		}
		if removed > 0 || failed > 0 {
			s.logEvent(0, "system", "share_files_purged", "", fmt.Sprintf("%d shares removed, %d failed (expired more than %d days ago)", removed, failed, keep))
		}
	}

	// stale upload sessions (> 24h)
	// Creation times may be stored as UTC text or with an offset; the
	// repository compares them in UTC.
	staleBefore := now.UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	stale, _ := s.St.Repos().Maintenance().StaleUploadIDs(context.Background(), staleBefore)
	for _, id := range stale {
		unlock := s.stripe(&s.uploadLocks, id)
		// The discovery query is only a snapshot. Completion/abort may already
		// have removed this session while cleanup waited for its stripe.
		if exists, err := s.St.Repos().Maintenance().CountStaleUpload(context.Background(), id, staleBefore); err == nil && exists == 1 {
			if err := s.removeUploadSession(id); err != nil {
				log.Printf("stale upload cleanup: %v", err)
			}
		}
		unlock()
	}
	s.St.Repos().Maintenance().PruneExpiredCredentials(context.Background(), now)
	if _, err := s.St.Repos().Idempotency().Expire(context.Background(), now.Add(-idempotencyTTL)); err != nil {
		log.Printf("idempotency key clean-up: %v", err)
	}
	s.St.Repos().Maintenance().PruneDownloads(context.Background(), now.UTC().AddDate(0, 0, -90).Format("2006-01-02 15:04:05"))
	// Recipient addresses are kept only while audit_log_ip is on; switching it
	// off empties the stored ones at the next run.
	if err := s.St.BlankDownloadIPs(); err != nil {
		log.Printf("download address clean-up: %v", err)
	}
	// Self-registrations that never proved their email (they cannot sign in) are
	// squatting on usernames and addresses: remove them after 48 hours. Only
	// accounts still marked as a pending registration qualify, never an
	// established account whose changed address is not verified yet, nor one
	// linked to a sign-in provider (whose email may be unverified on purpose).
	if gone := removedLabels(s.St.Repos().Maintenance().RemoveUnverifiedRegistrations(context.Background(), now.UTC().Add(-48*time.Hour).Format("2006-01-02 15:04:05"))); len(gone) > 0 {
		log.Printf("removed %d unverified account(s) older than 48 hours", len(gone))
		for _, target := range gone {
			s.logEvent(0, "system", "account_removed_auto", target, "reason=email not verified within 48 hours of registration")
		}
	}
	// Guests from open upload links whose single-use invitation expired unused:
	// remove the invitation and the guest account (their uploads, if any, are
	// shares owned by the inviter and stay).
	for _, target := range removedLabels(s.St.Repos().Maintenance().RemoveExpiredLinkGuests(context.Background(), now)) {
		s.logEvent(0, "system", "account_removed_auto", target, "reason=guest invitation expired unused")
	}
	s.St.Repos().Maintenance().RemoveOrphanedLinkInvites(context.Background(), now)
	s.pruneIPBans()
	s.purgeAudit()
	// Remote objects of removed files (queued by the database) and retries.
	s.kickDeletes()
}

// Automatic retention never removes pre-migration plaintext backups or
// pre-import backups (sendora-preimport-*): only this pattern is pruned.
var backupFile = regexp.MustCompile(`^sendora-encrypted-\d{8}-\d{6}-[a-f0-9]{12}\.db$`)

// removedLabels labels each account removed by a clean-up job as
// "user#ID (username)" and logs a clean-up error. The repository has read
// the rows completely, so the single connection is free for the audit records.
func removedLabels(gone []ports.RemovedAccount, err error) []string {
	if err != nil {
		log.Printf("account clean-up: %v", err)
	}
	var out []string
	for _, a := range gone {
		out = append(out, "user#"+strconv.FormatInt(a.ID, 10)+" ("+a.Username+")")
	}
	return out
}

// pruneBackups removes the oldest automatic backups beyond backup_keep and
// returns the names it removed.
func (s *Server) pruneBackups() []string {
	keep := s.St.SettingInt("backup_keep", 7)
	if keep <= 0 {
		return nil
	}
	ents, _ := os.ReadDir(filepath.Join(s.St.DataDir, "backups"))
	var names []string
	for _, e := range ents {
		if backupFile.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var removed []string
	for len(names) > keep {
		if err := os.Remove(filepath.Join(s.St.DataDir, "backups", names[0])); err == nil {
			removed = append(removed, names[0])
		}
		names = names[1:]
	}
	return removed
}
