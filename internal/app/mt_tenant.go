// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sendora-app/sendora/internal/netguard"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/storage"
	"github.com/sendora-app/sendora/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// A tenant's server in multi-tenant mode. Everything a tenant has — users,
// sessions, settings, branding, SMTP, sign-in providers, shares, audit log,
// backups — lives in its own database and directory, opened by its own
// *Server. This file holds the few things that differ from single-tenant mode.

// platformIndex is the platform console's entry page in the web build; only
// the console host serves it (mt_console.go).
const platformIndex = "platform.html"

// TenantOptions configures the server of one tenant.
type TenantOptions struct {
	ID, Slug string
	// BaseURL is the tenant's public URL (https://<slug>.<base domain> or its
	// primary custom domain); links and emails use it.
	BaseURL string
	// MailDefault returns the platform's default SMTP value for a tenant SMTP
	// setting key (smtp_host, smtp_port, ...); used while the tenant has no SMTP
	// server of its own. nil = none.
	MailDefault func(key string) string
	// Storage is the tenant's object storage choice from the platform database
	// (internal/platform/storage.go) and DefaultStorage the backend it selects:
	// the platform default with the tenant's prefix tenants/<id>/, the tenant's
	// own bucket, or the local tenant directory. With Storage.TenantManaged the
	// tenant's administrators may configure a bucket of their own instead
	// (storage_* settings of the tenant, Admin -> Storage).
	Storage        *platform.StorageConfig
	DefaultStorage storage.Config
	// PlatformStorage describes the platform default (for the tenant's screen).
	PlatformStorage string
	// AllowPrivateTargets switches the SSRF guard (internal/netguard) off for
	// targets the tenant's administrators configure.
	AllowPrivateTargets bool
}

type tenantState struct {
	opts     TenantOptions
	mailStop chan struct{}
}

var tenantConfigWarned atomic.Bool

// NewTenantServer builds the server of one tenant on its already opened store.
func NewTenantServer(st *store.Store, static fs.FS, version string, opts TenantOptions) (srv *Server, err error) {
	defer func() {
		// newServer panics on configuration and database errors (fatal at the
		// start of a single-tenant server); one tenant must not stop the process.
		if r := recover(); r != nil {
			// A runtime error is a bug, not a configuration error: keep the
			// stack for the operator's report.
			if _, ok := r.(runtime.Error); ok {
				log.Printf("tenant server: %v\n%s", r, debug.Stack())
			}
			srv, err = nil, errors.New("tenant server: "+strings.TrimSpace(strings.SplitN(errString(r), "\n", 2)[0]))
		}
	}()
	if !opts.AllowPrivateTargets {
		st.Backends().Guard = netguard.DialContext
	}
	return newServer(st, static, version, &tenantState{opts: opts, mailStop: make(chan struct{})}), nil
}

// guardTargets reports whether targets configured by this server's
// administrators must pass the SSRF guard: tenants in multi-tenant mode,
// unless the platform allows private targets for the tenant. Single-tenant
// mode is unchanged.
func (s *Server) guardTargets() bool {
	return s.tenant != nil && !s.tenant.opts.AllowPrivateTargets
}

// checkTarget is the save-time SSRF check of a target (host, host:port or
// URL) for a guarded tenant; nil when allowed or not guarded.
func (s *Server) checkTarget(ctx context.Context, target string) error {
	if !s.guardTargets() || strings.TrimSpace(target) == "" {
		return nil
	}
	return netguard.CheckHost(ctx, netguard.HostOf(target))
}

// guardedTargetSettings are the settings naming a server the application
// connects to; for a guarded tenant they must not point at the platform's
// network (the storage endpoints are checked with the storage configuration).
var guardedTargetSettings = []string{"smtp_host", "audit_forward_syslog", "audit_forward_webhook_url"}

// validateTargetUpdates refuses, for a guarded tenant, changed target settings
// that resolve to loopback, private, link-local, CGNAT or metadata addresses.
// The same check runs again on every connection (DNS rebinding). It has
// answered when it returns false.
func (s *Server) validateTargetUpdates(w http.ResponseWriter, r *http.Request, updates map[string]string) bool {
	if !s.guardTargets() {
		return true
	}
	for _, k := range guardedTargetSettings {
		v, ok := updates[k]
		if !ok || v == s.St.Setting(k) {
			continue
		}
		if err := s.checkTarget(r.Context(), v); err != nil {
			jerr(w, 400, k+": "+err.Error())
			return false
		}
	}
	return true
}

const msgChooseOwnStorage = "choose S3, Azure Blob Storage or Google Cloud Storage: the platform provides no storage for this organisation"

// msgStorageNotSetUp answers uploads and new shares of a tenant without storage.
const msgStorageNotSetUp = "Set up storage first under Admin → Storage"

// StorageReady reports whether new files can be stored (false for a tenant
// whose storage is not set up yet).
func (s *Server) StorageReady() bool {
	return s.storageFromSettings().Backend != storage.KindNone
}

// storageAdmits answers 409 when no storage is set up (uploads, reverse
// shares, new shares).
func (s *Server) storageAdmits(w http.ResponseWriter) bool {
	if s.tenant == nil || s.StorageReady() {
		return true
	}
	jerr(w, http.StatusConflict, msgStorageNotSetUp)
	return false
}

// StorageKind is all the platform console may know about a tenant's storage:
// "none", "local", "platform" (the platform's offer) or "own:<backend>" for
// storage the tenant configured itself. No names, endpoints or credentials.
func (s *Server) StorageKind() string {
	cfg := s.storageFromSettings()
	switch {
	case cfg.TenantManaged:
		return "own:" + cfg.Backend
	case cfg.Backend == storage.KindNone:
		return "none"
	case s.tenant != nil && s.tenant.opts.Storage != nil && s.tenant.opts.Storage.Offer == platform.OfferPlatform && cfg.Backend != storage.KindLocal:
		return "platform"
	}
	return "local"
}

// tenantStorageEditable reports whether this tenant's administrators may
// configure their own storage (always true outside multi-tenant mode).
func (s *Server) tenantStorageEditable() bool {
	return s.tenant == nil || (s.tenant.opts.Storage != nil && s.tenant.opts.Storage.TenantManaged)
}

func errString(r any) string {
	switch v := r.(type) {
	case error:
		return v.Error()
	case string:
		return v
	}
	return "unexpected failure"
}

// IsTenant reports whether this server serves a tenant of multi-tenant mode.
func (s *Server) IsTenant() bool { return s.tenant != nil }

// initTenantSchema adds the platform-controlled limits to the tenant's
// database. The user limit is a trigger, so every way of adding an account
// (administrator, registration, sign-in provider) respects it.
func (s *Server) initTenantSchema() error {
	return s.St.Repos().TenantLimits().Enable(context.Background())
}

// SetTenantLimits stores the platform's quotas in the tenant's database (0 = unlimited).
func (s *Server) SetTenantLimits(maxUsers, maxStorage int64) error {
	if s.tenant == nil {
		return errors.New("not a tenant")
	}
	return s.St.Repos().TenantLimits().Set(context.Background(), maxUsers, maxStorage)
}

const msgTenantUserLimit = "the user limit of this organisation has been reached"

// tenantUserAdmits answers 403 when the tenant's user limit is reached (the
// trigger enforces it anyway; this gives the administrator a clear message).
func (s *Server) tenantUserAdmits(w http.ResponseWriter) bool {
	if s.tenant == nil {
		return true
	}
	ctx := context.Background()
	limit, err := s.St.Repos().TenantLimits().MaxUsers(ctx)
	if err != nil || limit <= 0 {
		return true
	}
	n, _ := s.St.Repos().Stats().CountLocalUsers(ctx)
	if n >= limit {
		jerr(w, 403, msgTenantUserLimit)
		return false
	}
	return true
}

// tenantStorageAdmits checks an upload reservation against the tenant's
// storage limit (set by the platform for the storage it provides), inside the
// caller's admission transaction. Storage the tenant configured itself has no
// platform limit.
func (s *Server) tenantStorageAdmits(w http.ResponseWriter, tx ports.Repositories, add int64) bool {
	if s.tenant == nil {
		return true
	}
	// Read through the transaction (the store has one connection): storage of
	// the tenant's own is in use when allowed and a remote backend is chosen.
	ctx := context.Background()
	backend, _ := tx.Quota().StorageBackendSetting(ctx)
	if s.tenantStorageEditable() && backend != "" && backend != storage.KindLocal {
		return true
	}
	limit, err := tx.Quota().TenantStorageLimit(ctx)
	if err != nil || limit <= 0 {
		return true
	}
	stored, serr := tx.Quota().TotalStoredBytes(ctx)
	var rerr error
	var reserved int64
	if serr == nil {
		reserved, rerr = tx.Quota().TotalReservedBytes(ctx)
	}
	if serr != nil || rerr != nil {
		jerr(w, 503, "storage accounting unavailable")
		return false
	}
	if stored+reserved+add > limit {
		jerr(w, 413, msgTenantStorageFull)
		return false
	}
	return true
}

const msgTenantStorageFull = "the storage limit of this organisation is reached: delete old shares or ask the platform administrator for more space"

// platformLimitApplies reports whether the platform's storage limit applies:
// new files go to storage the platform provides (its bucket or the server's
// disk), not to storage the tenant configured itself.
func (s *Server) platformLimitApplies() bool {
	return s.tenant != nil && !s.storageFromSettings().TenantManaged
}

// storageLimit returns the platform's storage limit in bytes (0 = none).
func (s *Server) storageLimit() int64 {
	limit, _ := s.St.Repos().Quota().TenantStorageLimit(context.Background())
	return limit
}

// TenantStats returns the counts the platform console shows: accounts (not
// guests) and stored bytes. Never names or contents.
func (s *Server) TenantStats() (users, storage int64) {
	users, _ = s.St.Repos().Stats().CountLocalUsers(context.Background())
	storage, _ = s.St.TenantStorageUsage()
	return
}

// smtpSetting reads a tenant SMTP setting; a tenant without an SMTP server of
// its own uses the platform's default SMTP settings as a whole.
func (s *Server) smtpSetting(key string) string {
	if s.tenant != nil && s.tenant.opts.MailDefault != nil && strings.TrimSpace(s.St.Setting("smtp_host")) == "" {
		return s.tenant.opts.MailDefault(key)
	}
	return s.St.Setting(key)
}

// mailStopped is closed when a tenant's server is closed (nil = never).
func (s *Server) mailStopped() <-chan struct{} {
	if s.tenant == nil {
		return nil
	}
	return s.tenant.mailStop
}

// initialLastBackup: a tenant is opened and closed many times a day, so the
// daily automatic backup is due by the newest backup's age, not by uptime.
func (s *Server) initialLastBackup() time.Time {
	if s.tenant == nil {
		return time.Time{}
	}
	var newest time.Time
	ents, _ := os.ReadDir(filepath.Join(s.St.DataDir, "backups"))
	for _, e := range ents {
		if !backupFile.MatchString(e.Name()) {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest
}

// BackupDue reports whether the automatic daily backup is due (tenant jobs).
func (s *Server) BackupDue() bool {
	return s.St.SettingBool("backups_enabled") && time.Since(s.initialLastBackup()) > autoBackupInterval
}

// RunTenantMaintenance runs the periodic jobs once (used for tenants that
// are not open, on the platform's schedule): clean-up, expiry mails, audit
// retention and the daily backup when due.
func (s *Server) RunTenantMaintenance() {
	s.maintain()
	if s.BackupDue() {
		s.autoBackup()
	}
}

// RecordPlatformEvent writes a platform action that affects this tenant into
// the tenant's own audit log (the platform's log has the matching record).
func (s *Server) RecordPlatformEvent(admin, action, detail string) {
	s.auditWrite(auditEntry{Category: catAdmin, Action: action, Target: "tenant", Outcome: "ok", Detail: detail,
		ActorName: "platform:" + admin, ActorRole: "platform_admin"}, nil)
}

// ProvisionAdmin creates a tenant administrator without a usable password and
// a one-time "choose your password" link (7 days). With working SMTP (the
// tenant's own or the platform default) the link is emailed and not returned;
// otherwise it is returned once for the platform administrator to pass on.
func (s *Server) ProvisionAdmin(platformAdmin, username, email string) (link string, emailed bool, err error) {
	if s.tenant == nil {
		return "", false, errors.New("not a tenant")
	}
	username = strings.TrimSpace(username)
	if !validUsername(username) {
		return "", false, errors.New(msgInvalidUsername)
	}
	email, err = canonicalEmail(email)
	if err != nil || email == "" {
		return "", false, errors.New("valid email required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(randHex(32)), hashCost)
	if err != nil {
		return "", false, err
	}
	ctx := context.Background()
	id, err := s.St.Repos().Users().CreateProvisionedAdmin(ctx, username, email, string(hash), time.Now().UTC())
	if err != nil {
		if errors.Is(err, ports.ErrTenantUserLimit) {
			return "", false, errors.New(msgTenantUserLimit)
		}
		return "", false, errors.New("username or email already exists")
	}
	tok := randHex(24)
	if err := s.St.Repos().PasswordResets().CreateWelcome(ctx, hashToken(tok), id, time.Now().Add(welcomeTokenTTL)); err != nil {
		return "", false, err
	}
	link = strings.TrimRight(s.BaseURL, "/") + "/reset-password/" + tok
	s.RecordPlatformEvent(platformAdmin, "user_created", s.userTarget(id)+" admin=true")
	if s.smtpConfigured() == nil {
		if derr := s.deliverTemplate(email, "tpl_welcome", map[string]any{
			"RecipientName": username, "Username": username, "LoginURL": strings.TrimRight(s.BaseURL, "/") + "/login",
			"SetPasswordURL": link, "ExpiresDays": "7", "EmailLanguage": "en",
		}); derr == nil {
			return "", true, nil
		}
	}
	return link, false, nil
}

// closeTenant stops a tenant's server: the background jobs (stopJobs) end,
// system_stop is recorded, queued mail is given a moment to go out, then the
// mail workers end and the store is closed. The caller guarantees that no
// request is in flight.
func (s *Server) closeTenant(stopJobs func()) error {
	s.detachCluster()
	s.GracefulStop(10*time.Second, stopJobs, nil, nil)
	deadline := time.Now().Add(10 * time.Second)
	for len(s.mailQueue) > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	// Taking every slot waits for deliveries in progress.
	for i := 0; i < cap(s.mailSlots); i++ {
		select {
		case s.mailSlots <- struct{}{}:
		case <-time.After(time.Until(deadline) + time.Second):
		}
	}
	close(s.tenant.mailStop)
	return s.St.Close()
}
