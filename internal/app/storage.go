// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/storage"
	"github.com/sendora-app/sendora/internal/store"
)

// Object storage (internal/storage): where new share files go, the queue of
// remote objects to delete, the migration job and remote backup copies.

// storageState is the server's view of the storage settings.
type storageState struct {
	mu      sync.Mutex
	gen     uint64 // SettingsGen the cache below belongs to
	cached  bool
	current int64 // location id of the selected backend
	cfg     storage.Config

	draining atomic.Bool // a deletion pass is running
	again    atomic.Bool // more deletions were queued meanwhile

	migMu sync.Mutex
	mig   *migrationJob
}

// storageFromSettings is the configuration the settings select. A tenant in
// multi-tenant mode uses what the platform assigned (DefaultStorage), or, when
// the platform lets its administrators configure their own storage and they
// chose a remote backend, that configuration (marked tenant-managed).
func (s *Server) storageFromSettings() storage.Config {
	return s.storageFrom(s.St.Setting)
}

func (s *Server) storageFrom(get func(string) string) storage.Config {
	c := storage.FromSettings(get)
	if s.tenant != nil {
		if s.tenantStorageEditable() && c.Backend != storage.KindLocal {
			c.TenantManaged = true
		} else {
			c = s.tenant.opts.DefaultStorage
		}
	}
	c.LocalRoot = s.St.DataDir
	return c
}

// validateTenantStorage adds the multi-tenant rules to a configuration a
// tenant's administrator entered: explicit credentials only and endpoints
// that pass the SSRF guard (also checked on every connection).
func (s *Server) validateTenantStorage(ctx context.Context, c storage.Config) error {
	if !c.TenantManaged {
		return nil
	}
	if err := c.ValidateTenantManaged(); err != nil {
		return err
	}
	return s.checkTarget(ctx, c.Endpoint())
}

// storageLocked reports, for a tenant whose storage the platform manages,
// whether updates would change a storage setting other than the remote backup
// switch.
func (s *Server) storageLocked(updates map[string]string) bool {
	if s.tenantStorageEditable() {
		return false
	}
	for k, v := range updates {
		if storage.IsSetting(k) && k != "backup_remote_enabled" && v != s.St.Setting(k) && !(storage.SettingSecret(k) && v == "") {
			return true
		}
	}
	return false
}

// initStorage validates the configured backend at start-up (an invalid
// SENDORA_STORAGE_* configuration stops the server) and records it as a
// location. Interrupted migrations are marked failed.
func (s *Server) initStorage() error {
	cfg := s.storageFromSettings()
	if cfg.Backend == storage.KindNone {
		// A tenant whose storage is not set up: uploads are refused until it
		// is; existing files stay readable where they are.
		return s.St.Repos().StorageMigrations().FailInterrupted(context.Background())
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("storage: %v", err)
	}
	if s.St.SettingBool("backup_remote_enabled") && cfg.Backend == storage.KindLocal {
		log.Printf("WARNING: backup_remote_enabled is on but the storage backend is local: backups are kept in the data directory only")
	}
	if _, err := store.EnsureLocation(s.St.Repos(), cfg); err != nil {
		return err
	}
	if err := s.St.Repos().StorageMigrations().FailInterrupted(context.Background()); err != nil {
		return err
	}
	if cfg.Backend != storage.KindLocal {
		log.Printf("storage: new files go to %s", cfg.Describe())
	}
	return nil
}

// currentStorage returns the location new files are written to.
func (s *Server) currentStorage(ctx context.Context) (int64, storage.Backend, error) {
	gen := s.St.SettingsGen()
	s.stor.mu.Lock()
	if !s.stor.cached || s.stor.gen != gen {
		cfg := s.storageFromSettings()
		if err := cfg.Validate(); err != nil {
			s.stor.mu.Unlock()
			return 0, nil, err
		}
		id, err := store.EnsureLocation(s.St.Repos(), cfg)
		if err != nil {
			s.stor.mu.Unlock()
			return 0, nil, err
		}
		s.stor.gen, s.stor.cached, s.stor.current, s.stor.cfg = gen, true, id, cfg
	}
	id := s.stor.current
	s.stor.mu.Unlock()
	b, err := s.St.Backends().Get(ctx, id)
	return id, b, err
}

// openRemoteFile opens a share file in an object store as a seekable
// plaintext reader. Remote files are always encrypted.
// fileKeyError reports why no key opens a stored file: a legacy (root-derived)
// file or a retired key version is refused with a clear log line; anything
// else counts as a decryption failure.
func (s *Server) fileKeyError(id int64, err error) error {
	if errors.Is(err, store.ErrLegacyFile) || errors.Is(err, keyring.ErrKeyRetired) {
		log.Printf("files: file#%d refused: %v", id, err)
		return err
	}
	log.Printf("files: file#%d: no key: %v", id, err)
	s.noteDecryptFailure(id)
	return errIntegrity
}

func (s *Server) openRemoteFile(ctx context.Context, f FileInfo) (io.ReadSeekCloser, time.Time, error) {
	obj, err := s.St.Backends().OpenFile(ctx, f.storageID, f.longID, "", f.objectKey)
	if err != nil {
		if errors.Is(err, storage.ErrNotExist) {
			return nil, time.Time{}, fs.ErrNotExist
		}
		log.Printf("storage: open file#%d: %v", f.ID, err)
		return nil, time.Time{}, err
	}
	if !f.enc {
		obj.Close()
		s.noteDecryptFailure(f.ID)
		return nil, time.Time{}, errIntegrity
	}
	master, headerID, err := s.St.FileMaster(f.encID)
	if err != nil {
		obj.Close()
		return nil, time.Time{}, s.fileKeyError(f.ID, err)
	}
	r, err := filecrypt.NewReader(obj, obj.Size(), f.Size, master, headerID)
	if err != nil {
		obj.Close()
		if errors.Is(err, filecrypt.ErrCorrupt) {
			s.noteDecryptFailure(f.ID)
			return nil, time.Time{}, errIntegrity
		}
		return nil, time.Time{}, err
	}
	return r, obj.ModTime(), nil
}

// putUploadRemote encrypts one finished upload part and streams it to an
// object store under key: the store never sees plaintext. It returns the
// plaintext SHA-256 and the file id. A failed Put leaves no object behind.
func putUploadRemote(ctx context.Context, b storage.Backend, src, key string, size int64, fileKey []byte) (checksum, encID string, err error) {
	if len(fileKey) != 32 {
		return "", "", errNoFileKey
	}
	var reader io.Reader = bytes.NewReader(nil)
	in, err := os.Open(src)
	if err != nil {
		if !(os.IsNotExist(err) && size == 0) {
			return "", "", err
		}
	} else {
		defer in.Close()
		st, err := in.Stat()
		if err != nil {
			return "", "", err
		}
		if !st.Mode().IsRegular() || st.Size() != size {
			return "", "", errIntegrity
		}
		reader = contextReader{ctx, bufio.NewReaderSize(io.LimitReader(in, size+1), 256<<10)}
	}
	h := sha256.New()
	pr, pw := io.Pipe()
	var id string
	go func() {
		n, fid, err := filecrypt.Encrypt(pw, reader, fileKey, h)
		if err == nil && n != size {
			err = errIntegrity
		}
		id = fid
		pw.CloseWithError(err)
	}()
	err = b.Put(ctx, key, pr, filecrypt.CipherSize(size))
	pr.CloseWithError(errors.New("upload ended"))
	if err != nil {
		b.Delete(context.WithoutCancel(ctx), key)
		if errors.Is(err, errIntegrity) {
			return "", "", errIntegrity
		}
		log.Printf("storage: store upload: %v", err)
		return "", "", err
	}
	return hex.EncodeToString(h.Sum(nil)), id, nil
}

// kickDeletes starts a pass over the queue of remote objects to delete (rows
// queued by the files_remote_deleted trigger or a migration). Passes do not
// overlap; a kick during a pass runs another one afterwards.
func (s *Server) kickDeletes() {
	s.stor.again.Store(true)
	if !s.stor.draining.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.stor.draining.Store(false)
		for s.stor.again.Swap(false) {
			s.drainDeletes()
		}
	}()
}

// drainDeletes processes due queued deletions (bounded per call).
func (s *Server) drainDeletes() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for i := 0; i < 20; i++ {
		done, failed := store.ProcessPendingDeletes(ctx, s.St.Repos(), s.St.Backends(), 200)
		if failed > 0 {
			log.Printf("storage: %d object deletion(s) failed; they are retried later", failed)
		}
		if done < 200 || ctx.Err() != nil {
			return
		}
	}
}

// ---------- settings ----------

// storageSettingsChanged validates the storage settings a PUT /api/settings
// would store as a whole and, when the selected location or its credentials
// change, tests the connection first, so a typo cannot break uploads. It has
// answered when it returns false.
func (s *Server) validateStorageUpdate(w http.ResponseWriter, r *http.Request, updates map[string]string) bool {
	touched := false
	for k := range updates {
		if storage.IsSetting(k) {
			touched = true
		}
	}
	if !touched {
		return true
	}
	if s.storageLocked(updates) {
		jerr(w, 403, "storage is managed by the platform for this organisation")
		return false
	}
	changed := func(k string) bool { v, ok := updates[k]; return ok && v != s.St.Setting(k) }
	if secret := storage.SecretRetypeNeeded(changed, func(k string) bool { _, ok := updates[k]; return ok }, func(k string) bool { return s.St.Setting(k) != "" }); secret != "" {
		jerr(w, 400, "enter the storage secret again when changing the endpoint, account or access key ("+secret+")")
		return false
	}
	get := func(k string) string {
		if v, ok := updates[k]; ok {
			return v
		}
		return s.St.Setting(k)
	}
	next := s.storageFrom(get)
	if next.Backend == storage.KindNone {
		if _, ok := updates["storage_backend"]; ok {
			jerr(w, 400, msgChooseOwnStorage)
			return false
		}
		if get("backup_remote_enabled") == "true" {
			jerr(w, 400, "remote backup copies need an object storage backend (S3, Azure or GCS)")
			return false
		}
		return true
	}
	if err := next.Validate(); err != nil {
		jerr(w, 400, err.Error())
		return false
	}
	if err := s.validateTenantStorage(r.Context(), next); err != nil {
		jerr(w, 400, err.Error())
		return false
	}
	if get("backup_remote_enabled") == "true" && next.Backend == storage.KindLocal {
		jerr(w, 400, "remote backup copies need an object storage backend (S3, Azure or GCS)")
		return false
	}
	cur := s.storageFromSettings()
	nextJS, _ := next.Marshal()
	curJS, _ := cur.Marshal()
	if next.Backend != storage.KindLocal && nextJS != curJS {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		b, err := s.St.Backends().Open(ctx, next)
		if err == nil {
			err = storage.Probe(ctx, b)
		}
		if err != nil {
			me := s.ctxUser(r)
			s.logEvent(me.ID, me.Username, "storage_connection_test_failed", "storage", clip(next.Describe()+": "+err.Error(), 400))
			jerr(w, 400, "storage connection test failed; the settings were not saved: "+clip(err.Error(), 300))
			return false
		}
	}
	return true
}

// ---------- admin endpoints ----------

// storageStatus: GET /api/storage (administrators).
func (s *Server) storageStatus(w http.ResponseWriter, r *http.Request) {
	id, _, err := s.currentStorage(r.Context())
	cfg := s.storageFromSettings()
	out := map[string]any{
		"backend":         cfg.Backend,
		"description":     cfg.Describe(),
		"location":        id,
		"pending_deletes": store.PendingDeletes(s.St.Repos()),
		"remaining":       store.MigrateRemaining(s.St.Repos(), id),
		"backup_remote":   s.St.SettingBool("backup_remote_enabled"),
	}
	if s.tenant != nil {
		// Multi-tenant mode: who decides where this organisation's files go.
		managedBy := "platform"
		if cfg.TenantManaged {
			managedBy = "tenant"
		}
		offer := platform.OfferNone
		if s.tenant.opts.Storage != nil {
			offer = s.tenant.opts.Storage.Offer
		}
		out["tenant"] = map[string]any{
			"editable":        s.tenantStorageEditable(),
			"managed_by":      managedBy,
			"configured":      cfg.Backend != storage.KindNone,
			"limit_applies":   s.platformLimitApplies(),
			"limit_bytes":     s.storageLimit(),
			"used_bytes":      usedBytes(s),
			"offer":           offer,
			"platform_choice": s.tenant.opts.DefaultStorage.Describe(),
			"guarded":         s.guardTargets(),
		}
	}
	if err != nil && cfg.Backend != storage.KindNone { // not set up: the screen shows a banner
		out["error"] = clip(err.Error(), 300)
	}
	usage, uerr := store.StorageUsageByLocation(s.St.Repos(), id)
	if uerr != nil {
		jerr(w, 500, "database error")
		return
	}
	out["locations"] = usage
	out["migration"] = s.migrationStatus()
	jout(w, 200, out)
}

// storageTest: POST /api/storage/test (administrators, step-up). The body may
// carry unsaved storage settings; blank secrets keep the stored ones.
func (s *Server) storageTest(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := decode(r, &in); err != nil && !errors.Is(err, io.EOF) {
		jerr(w, 400, "bad request")
		return
	}
	if !s.tenantStorageEditable() {
		jerr(w, 403, "storage is managed by the platform for this organisation")
		return
	}
	vals := map[string]string{}
	for k, v := range in {
		str, ok := v.(string)
		if b, isBool := v.(bool); isBool {
			str, ok = strconv.FormatBool(b), true
		}
		if !ok || !storage.IsSetting(k) || s.isManagedSetting(k) || (storage.SettingSecret(k) && str == "") {
			continue
		}
		norm, _, err := storage.NormalizeSetting(k, str)
		if err != nil {
			jerr(w, 400, err.Error())
			return
		}
		vals[k] = norm
	}
	changed := func(k string) bool { v, ok := vals[k]; return ok && v != s.St.Setting(k) }
	if secret := storage.SecretRetypeNeeded(changed, func(k string) bool { _, ok := vals[k]; return ok }, func(k string) bool { return s.St.Setting(k) != "" }); secret != "" {
		jerr(w, 400, "enter the storage secret again when changing the endpoint, account or access key ("+secret+")")
		return
	}
	cfg := s.storageFrom(func(k string) string {
		if v, ok := vals[k]; ok {
			return v
		}
		return s.St.Setting(k)
	})
	me := s.ctxUser(r)
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := cfg.Validate()
	if cfg.Backend == storage.KindNone {
		err = errors.New(msgChooseOwnStorage)
	}
	if err == nil {
		err = s.validateTenantStorage(ctx, cfg)
	}
	var b storage.Backend
	if err == nil {
		b, err = s.St.Backends().Open(ctx, cfg)
	}
	if err == nil {
		err = storage.Probe(ctx, b)
	}
	ms := time.Since(start).Milliseconds()
	if err != nil {
		s.logEvent(me.ID, me.Username, "storage_connection_test_failed", "storage", clip(cfg.Describe()+": "+err.Error(), 400))
		jout(w, 200, map[string]any{"ok": false, "error": clip(err.Error(), 400), "description": cfg.Describe(), "ms": ms})
		return
	}
	s.logEvent(me.ID, me.Username, "storage_connection_tested", "storage", cfg.Describe())
	jout(w, 200, map[string]any{"ok": true, "description": cfg.Describe(), "ms": ms})
}

// ---------- migration ----------

type migrationJob struct {
	id     int64
	target int64
	desc   string
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	stats  store.MigrateStats
	status string
}

// migrationDeleteDelay keeps a migrated file's old copy this long, so
// downloads that opened it can finish.
var migrationDeleteDelay = 15 * time.Minute

func (s *Server) migrationStatus() map[string]any {
	s.stor.migMu.Lock()
	job := s.stor.mig
	s.stor.migMu.Unlock()
	var row struct {
		id, target                int64
		status, desc, by, errText string
		total, done, failed       int64
		bytes                     int64
		started                   time.Time
		finished                  *time.Time
	}
	m, err := s.St.Repos().StorageMigrations().Latest(context.Background())
	if err != nil {
		return nil
	}
	row.id, row.status, row.target, row.desc, row.total, row.done, row.failed, row.bytes, row.by, row.started, row.finished, row.errText =
		m.ID, m.Status, m.TargetLocation, m.Target, m.Total, m.Done, m.Failed, m.Bytes, m.StartedBy, m.StartedAt, m.FinishedAt, m.Error
	out := map[string]any{"id": row.id, "status": row.status, "target": row.desc, "total": row.total, "done": row.done, "failed": row.failed,
		"bytes": row.bytes, "started_by": row.by, "started_at": row.started, "finished_at": row.finished, "error": row.errText}
	if job != nil && job.id == row.id {
		job.mu.Lock()
		out["total"], out["done"], out["failed"], out["skipped"], out["bytes"] = job.stats.Total, job.stats.Done, job.stats.Failed, job.stats.Skipped, job.stats.Bytes
		job.mu.Unlock()
	}
	return out
}

// storageMigrateStart: POST /api/storage/migrate (administrators, step-up).
// Copies every file that is not in the current location there, in the
// background; progress is in GET /api/storage.
func (s *Server) storageMigrateStart(w http.ResponseWriter, r *http.Request) {
	me := s.ctxUser(r)
	id, _, err := s.currentStorage(r.Context())
	if err != nil {
		jerr(w, 409, "the storage backend is not usable: "+clip(err.Error(), 200))
		return
	}
	if store.MigrateRemaining(s.St.Repos(), id) == 0 {
		jerr(w, 409, "every file is already in the current storage location")
		return
	}
	job, err := s.startMigration(id, me.Username)
	if err != nil {
		jerr(w, 409, err.Error())
		return
	}
	s.logEvent(me.ID, me.Username, "storage_migration_started", "storage", fmt.Sprintf("migration#%d to %s", job.id, job.desc))
	jout(w, 202, map[string]any{"ok": true, "id": job.id})
}

var errMigrationRunning = errors.New("a storage migration is already running")

// startMigration starts the background migration to target.
func (s *Server) startMigration(target int64, by string) (*migrationJob, error) {
	s.stor.migMu.Lock()
	defer s.stor.migMu.Unlock()
	if s.stor.mig != nil && s.stor.mig.status == "running" {
		return nil, errMigrationRunning
	}
	cfg, err := store.LoadLocation(s.St.Repos(), s.St.DataDir, target)
	if err != nil {
		return nil, err
	}
	mid, err := s.St.Repos().StorageMigrations().Start(context.Background(), target, cfg.Describe(), by)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &migrationJob{id: mid, target: target, desc: cfg.Describe(), cancel: cancel, done: make(chan struct{}), status: "running"}
	s.stor.mig = job
	go s.runMigration(ctx, job)
	return job, nil
}

func (s *Server) runMigration(ctx context.Context, job *migrationJob) {
	defer close(job.done)
	defer job.cancel()
	last := time.Time{}
	save := func(st store.MigrateStats) {
		s.St.Repos().StorageMigrations().Progress(context.Background(), job.id, int64(st.Total), int64(st.Done), int64(st.Failed), st.Bytes)
	}
	stats, err := store.MigrateFiles(ctx, s.St.Repos(), s.St.DataDir, s.St, s.St.Backends(), job.target, store.MigrateOptions{
		DeleteDelay: migrationDeleteDelay,
		Progress: func(st store.MigrateStats) {
			job.mu.Lock()
			job.stats = st
			job.mu.Unlock()
			if time.Since(last) > 2*time.Second {
				last = time.Now()
				save(st)
			}
		},
	})
	save(stats)
	status, detail := "finished", fmt.Sprintf("migration#%d to %s: %d copied, %d failed, %d skipped, %d bytes", job.id, job.desc, stats.Done, stats.Failed, stats.Skipped, stats.Bytes)
	errText := ""
	switch {
	case errors.Is(err, context.Canceled):
		status = "cancelled"
	case err != nil:
		status, errText = "failed", clip(err.Error(), 300)
	case stats.Failed > 0:
		status, errText = "failed", fmt.Sprintf("%d file(s) could not be migrated; they stay readable in their old location", stats.Failed)
	}
	s.St.Repos().StorageMigrations().Finish(context.Background(), job.id, status, errText)
	job.mu.Lock()
	job.status = status
	job.mu.Unlock()
	s.stor.migMu.Lock()
	job.status = status
	s.stor.migMu.Unlock()
	switch status {
	case "finished":
		s.logEvent(0, "system", "storage_migration_finished", "storage", detail)
	case "cancelled":
		s.logEvent(0, "system", "storage_migration_cancelled", "storage", detail)
	default:
		s.logEvent(0, "system", "storage_migration_failed", "storage", clip(detail+"; "+errText, 400))
	}
	s.kickDeletes()
}

// storageMigrateCancel: POST /api/storage/migrate/cancel (administrators).
func (s *Server) storageMigrateCancel(w http.ResponseWriter, r *http.Request) {
	s.stor.migMu.Lock()
	job := s.stor.mig
	running := job != nil && job.status == "running"
	s.stor.migMu.Unlock()
	if !running {
		jerr(w, 409, "no storage migration is running")
		return
	}
	job.cancel()
	<-job.done
	me := s.ctxUser(r)
	s.logEvent(me.ID, me.Username, "storage_migration_cancel_requested", "storage", fmt.Sprintf("migration#%d", job.id))
	jout(w, 200, map[string]any{"ok": true})
}

// stopMigration ends a running migration (process stop).
func (s *Server) stopMigration() {
	s.stor.migMu.Lock()
	job := s.stor.mig
	s.stor.migMu.Unlock()
	if job != nil {
		job.cancel()
		select {
		case <-job.done:
		case <-time.After(5 * time.Second):
		}
	}
}

// ---------- remote backup copies ----------

// copyBackupRemote uploads a finished (SQLCipher-encrypted) backup file to the
// current object store under backups/ and prunes remote copies beyond
// backup_keep. It records the result in the audit log.
func (s *Server) copyBackupRemote(name string) {
	if !s.St.SettingBool("backup_remote_enabled") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	_, b, err := s.currentStorage(ctx)
	if err == nil && b.Kind() == storage.KindLocal {
		err = errors.New("the storage backend is local")
	}
	if err == nil {
		err = putFile(ctx, b, storage.BackupPrefix+name, filepath.Join(s.St.DataDir, "backups", name))
	}
	if err != nil {
		log.Printf("remote backup copy failed: %v", err)
		s.logEvent(0, "system", "backup_remote_failed", name, "remote backup copy failed; details are in the server log")
		return
	}
	s.logEvent(0, "system", "backup_remote_copied", name, "")
	for _, n := range s.pruneRemoteBackups(ctx, b) {
		s.logEvent(0, "system", "backup_remote_pruned", n, "backup_keep="+strconv.Itoa(s.St.SettingInt("backup_keep", 7)))
	}
}

func putFile(ctx context.Context, b storage.Backend, key, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	return b.Put(ctx, key, bufio.NewReaderSize(f, 256<<10), st.Size())
}

// pruneRemoteBackups removes the oldest automatic remote copies beyond
// backup_keep (same name pattern as the local pruning).
func (s *Server) pruneRemoteBackups(ctx context.Context, b storage.Backend) []string {
	keep := s.St.SettingInt("backup_keep", 7)
	if keep <= 0 {
		return nil
	}
	var names []string
	err := b.List(ctx, storage.BackupPrefix, func(i storage.Info) error {
		n := strings.TrimPrefix(i.Key, storage.BackupPrefix)
		if backupFile.MatchString(n) {
			names = append(names, n)
		}
		return nil
	})
	if err != nil {
		log.Printf("remote backup pruning: %v", err)
		return nil
	}
	sort.Strings(names)
	var removed []string
	for len(names) > keep {
		if err := b.Delete(ctx, storage.BackupPrefix+names[0]); err == nil {
			removed = append(removed, names[0])
		}
		names = names[1:]
	}
	return removed
}

// usedBytes is the stored plus reserved bytes of a tenant (its storage limit).
func usedBytes(s *Server) int64 {
	n, _ := s.St.TenantStorageUsage()
	return n
}
