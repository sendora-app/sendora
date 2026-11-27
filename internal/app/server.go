// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sendora-app/sendora/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	St      *store.Store
	Secret  []byte
	BaseURL string
	Version string
	Static  fs.FS
	Started time.Time

	// SENDORA_FORCE_LOCAL_LOGIN recovery override (see local_login.go).
	forceLocalLogin atomicFlag

	// Request bodies and stalled transfers must not retain bounded work slots forever.
	requestBodyTimeout  time.Duration
	transferIdleTimeout time.Duration

	// Bounded lock stripes serialize mutations without retaining session IDs forever.
	uploadLocks       [64]sync.Mutex
	verificationLocks [64]sync.Mutex
	identityLocks     [64]sync.Mutex
	loginLocks        [64]sync.Mutex
	securityMu        sync.Mutex
	shareThrottle     failThrottle // failed share unlocks, keyed by share id
	setupThrottle     failThrottle // failed setup attempts from all addresses
	oidcSlots         chan struct{}
	securityBuckets   map[string]requestBudget
	ipBans            ipBanState
	mailQueue         chan mailJob
	mailOnce          sync.Once
	dlMailMu          sync.Mutex
	dlMailLast        map[int64]time.Time
	trustedProxies    []*net.IPNet
	mailSlots         chan struct{}
	authSlots         chan struct{}
	downloadMailWake  chan struct{}
	downloadMailOnce  sync.Once
	keyJobWake        chan struct{} // wakes the key-job worker (keys_admin.go)
	keyJobsOnce       sync.Once
	keySettle         time.Duration // wait before the repair pass of an index rotation
	audit             auditState
	fwd               auditForwarder // off-host audit forwarding (audit_forward.go)
	ops               opsState       // readiness and metrics (ops.go)
	uiKeys            uiKeyCache
	mfaUsed           mfaTracker
	waCeremonies      waCeremonies

	// Database import (db_import.go).
	importMu        sync.Mutex
	imp             *preparedImport
	importPreparing atomic.Bool
	importApplying  atomic.Bool
	maintenance     atomic.Bool
	importMaxBytes  int64         // 0 = 4 GiB
	importTTL       time.Duration // 0 = 15 minutes
	importStop      func()        // set by main: stop HTTP server and background jobs
	restartFn       func()        // set by main: stop and exit with ExitRestart (mt_convert.go)
	importExec      func() error  // re-exec of this process
	importExit      func(int)
	importDone      chan struct{}

	// Orderly stop (jobs.go): the maintenance loop's done channel, and the
	// once-only stop and system_stop record.
	jobsDone     atomic.Pointer[chan struct{}]
	stopOnce     sync.Once
	stopRecorded sync.Once

	// One-time code required for first-run setup (empty once an account exists).
	setupCode string

	// Settings set by the server configuration (see config.go).
	managedSettings map[string]bool

	// Step-up re-authentication and the password screening switch (stepup.go).
	accountSecurityState

	// rateWindow overrides the one-minute rate-limit window (tests only).
	rateWindow time.Duration

	// tenant is set when this server serves one tenant in multi-tenant mode
	// (mt_tenant.go); nil in single-tenant mode.
	tenant *tenantState
	// cl is set when the tenant is served by a Cluster replica (cluster.go).
	cl *clusterTenant
	// kek is the tenant-supplied-key administration (kek_admin.go); nil outside the Cluster flavour.
	kek *kekBinding
	// Object storage: current location, deletion queue, migration (storage.go).
	stor storageState
}

func lockStripe(locks *[64]sync.Mutex, key string) func() {
	h := sha256.Sum256([]byte(key))
	mu := &locks[int(h[0])%len(locks)]
	mu.Lock()
	return mu.Unlock
}

// emailBaseURL never trusts a public request Host or forwarded headers for emailed links.
func (s *Server) emailBaseURL(r *http.Request) (string, bool) {
	base := s.BaseURL
	if base == "" {
		base = s.St.Setting("application_url")
	}
	if base == "" {
		base = "http://" + r.Host
		if r.TLS != nil {
			base = "https://" + r.Host
		}
		u, err := url.Parse(base)
		if err != nil || !loopbackHost(u.Hostname()) {
			return "", false
		}
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()))) {
		return "", false
	}
	return strings.TrimRight(base, "/"), true
}

func loopbackHost(host string) bool {
	// *.localhost names resolve to the loopback interface (RFC 6761), which is
	// how tenants are reached in local multi-tenant testing.
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func New(st *store.Store, static fs.FS, version string) *Server {
	return newServer(st, static, version, nil)
}

// newServer builds a server; tenant is nil in single-tenant mode. A tenant's
// server takes its public URL from the platform instead of APP_URL, always
// keeps its own random signing secret in its own database (never JWT_SECRET,
// which all tenants would share) and has no first-run setup code (the
// platform creates its first administrator).
func newServer(st *store.Store, static fs.FS, version string, tenant *tenantState) *Server {
	s := &Server{St: st, Static: static, Version: version, Started: time.Now(), BaseURL: strings.TrimRight(os.Getenv("APP_URL"), "/"), mailSlots: make(chan struct{}, 8), mailQueue: make(chan mailJob, 256), authSlots: make(chan struct{}, 16), oidcSlots: make(chan struct{}, oidcSlotCount), downloadMailWake: make(chan struct{}, 1), keyJobWake: make(chan struct{}, 1), importExec: execSelf, importExit: os.Exit, importDone: make(chan struct{}), tenant: tenant}
	sec := ""
	if tenant != nil {
		s.BaseURL = strings.TrimRight(tenant.opts.BaseURL, "/")
		if err := s.initTenantSchema(); err != nil {
			panic(err)
		}
	} else {
		sec, _ = JWTSecretFromEnv() // validated in main
	}
	if sec == "" {
		sec = st.Setting("jwt_secret")
		if sec == "" {
			sec = randHex(32)
			if err := st.SetSetting("jwt_secret", sec); err != nil {
				panic(err)
			}
		}
	}
	if err := st.Repos().System().ClassifyJWTSecret(context.Background()); err != nil {
		panic(err)
	}
	s.Secret = []byte(sec)
	if err := s.applyConfig(); err != nil {
		panic(fmt.Errorf("configuration: %w", err))
	}
	if err := s.initStorage(); err != nil {
		panic(fmt.Errorf("configuration: %w", err))
	}
	s.loadIPBans()
	// A fresh instance must not be claimed by whoever reaches it first: setup
	// needs a one-time code that only someone with access to the server log (or
	// the deployment's environment) has.
	users, _ := st.Repos().Users().Count(context.Background())
	if users == 0 && tenant == nil {
		s.setupCode = strings.ToUpper(strings.TrimSpace(os.Getenv("SENDORA_SETUP_CODE")))
		if s.setupCode != "" && !validSetupCode(s.setupCode) {
			log.Printf("SENDORA_SETUP_CODE ignored: it must be at least 16 characters and not a repeated or sequential pattern; using a generated code")
			s.setupCode = ""
		}
		if s.setupCode == "" {
			s.setupCode = newSetupCode()
		}
		setupCodeLog("first-run setup code: %s (enter it on the setup page; it changes on every restart until setup is done)", s.setupCode)
	}
	// Reserved rows never represent an observed start. A process restart cannot
	// truthfully promote them; release their capacity and preserve pending jobs.
	if err := st.Repos().DownloadMails().ReleaseAllReserved(context.Background()); err != nil {
		panic(err)
	}
	if err := st.MigrateVerificationAttempts(); err != nil {
		panic(err)
	}
	// Single-instance data directory: snapshots left by a crash must not accumulate.
	entries, err := os.ReadDir(st.DataDir)
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".verified-download-") && !entry.IsDir() {
			if err := os.Remove(path.Join(st.DataDir, entry.Name())); err != nil {
				panic(err)
			}
		}
	}
	// Share directories moved aside for deletion when the process stopped.
	if shareEntries, err := os.ReadDir(path.Join(st.DataDir, "shares")); err == nil {
		for _, entry := range shareEntries {
			if strings.HasPrefix(entry.Name(), ".deleting-") && entry.IsDir() {
				os.RemoveAll(path.Join(st.DataDir, "shares", entry.Name()))
			}
		}
	}
	s.cleanImportFiles()
	return s
}

// setupCodeLog prints the setup code; tests replace it to keep their output readable.
var setupCodeLog = log.Printf

// newSetupCode returns 12 random characters from an alphabet without look-alike
// characters, grouped for typing (about 59 bits).
func newSetupCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, 0, 14)
	for i, c := range b {
		if i == 4 || i == 8 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(c)%len(alphabet)])
	}
	return string(out)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, s.security, s.maintenanceMode, s.auditMiddleware)
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", s.health)
		r.Get("/health/ready", s.ready)
		r.Get("/metrics", s.metrics)
		r.Get("/bootstrap", s.bootstrap)
		r.Get("/capabilities", s.capabilitiesHandler)
		r.Get("/i18n/languages", s.publicUILanguages)
		r.Get("/i18n/{code}", s.publicUIDictionary)
		r.With(s.idempotent).Post("/setup", s.setup)

		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", s.login)
			r.Post("/refresh", s.refresh)
			r.Post("/logout", s.logout)
			r.Post("/forgot-password", s.forgotPassword)
			r.Post("/reset-password", s.resetPassword)
			r.Post("/register", s.register)
			r.Post("/verify-email", s.verifyEmail)
			r.Post("/resend-verification", s.resendVerification)
			r.Post("/mfa-reset/confirm", s.mfaResetConfirm)
			r.Post("/mfa/totp", s.mfaLogin("totp"))
			r.Post("/mfa/recovery", s.mfaLogin("recovery"))
			r.Post("/mfa/webauthn/begin", s.mfaWebAuthnLoginBegin)
			r.Post("/mfa/webauthn/finish", s.mfaWebAuthnLoginFinish)
			r.Get("/providers", s.listPublicProviders)
			r.Get("/email-languages", s.mailLanguages)
			r.Get("/oidc/{uuid}/start", s.oidcStart)
			r.Get("/oidc/{uuid}/callback", s.oidcCallback)
			r.With(s.auth).Post("/step-up", s.stepUpConfirm)
			r.With(s.auth).Post("/step-up/webauthn/begin", s.stepUpBegin)
		})

		// public
		r.Get("/themes/active", s.activeTheme)
		r.Get("/shares/{id}", s.readShare)
		r.Post("/shares/{id}/unlock", s.unlockShare)
		r.Get("/shares/{id}/download", s.downloadShare)
		r.Post("/shares/{id}/download", s.downloadShare)
		r.Get("/shares/{id}/download/*", s.downloadShareFile)
		r.Get("/shares/{id}/preview/*", s.previewShareFile)
		r.Get("/backgrounds", s.listBackgrounds)
		r.Get("/backgrounds/{file}", s.serveBackground)
		r.Get("/branding/{kind}", s.serveBranding)
		r.With(s.idempotent).Post("/reverse-shares/accept", s.acceptInvite)

		// authed
		r.Group(func(r chi.Router) {
			r.Use(s.auth, s.idempotent)
			r.Get("/users/me", s.me)
			r.Put("/users/me", s.updateMe)
			r.Delete("/users/me/providers/{id}", s.unlinkProvider)
			r.Get("/users/me/mfa", s.mfaStatus)
			r.Post("/users/me/mfa/totp/begin", s.mfaTOTPBegin)
			r.Post("/users/me/mfa/totp/confirm", s.mfaTOTPConfirm)
			r.Post("/users/me/mfa/totp/remove", s.mfaTOTPRemove)
			r.Post("/users/me/mfa/recovery/regenerate", s.mfaRecoveryRegenerate)
			r.Post("/users/me/mfa/webauthn/begin", s.mfaWebAuthnRegisterBegin)
			r.Post("/users/me/mfa/webauthn/finish", s.mfaWebAuthnRegisterFinish)
			r.Put("/users/me/mfa/webauthn/{id}", s.mfaWebAuthnRename)
			r.Post("/users/me/mfa/webauthn/{id}/remove", s.mfaWebAuthnRemove)
			r.Get("/users/me/sessions", s.listMySessions)
			r.Post("/users/me/sessions/revoke-others", s.revokeOtherSessions)
			r.Delete("/users/me/sessions/{id}", s.revokeMySession)
			r.With(s.critical("personal_data_exported", "user")).Get("/users/me/export", s.exportMyData)
			r.Post("/users/me/erase", s.eraseMe)
			r.Post("/users/me/terms", s.acceptTerms)

			r.Get("/shares", s.myShares)
			r.Get("/shares/{id}/downloads", s.shareDownloads)
			r.Post("/shares/{id}/expire", s.expireShare)
			r.Post("/shares/{id}/extend", s.extendShare)
			r.Put("/shares/{id}/expiry", s.setShareExpiry)
			r.Post("/shares/{id}/download-limit", s.setDownloadLimit)
			r.Put("/shares/{id}", s.editShare)
			r.Delete("/shares/{id}", s.deleteShare)
			r.Get("/shares/{id}/files", s.listShareFiles)
			r.Delete("/shares/{id}/files/{fileId}", s.deleteShareFile)
			r.Post("/shares/prune-expired", s.pruneMine)

			r.Post("/uploads", s.createUpload)
			r.Get("/uploads/{id}", s.uploadStatus)
			r.Patch("/uploads/{id}/files/{idx}", s.uploadChunk)
			r.Post("/uploads/{id}/complete", s.completeUpload)
			r.Delete("/uploads/{id}", s.abortUpload)

			r.Post("/reverse-shares/invite", s.createInvite)
			r.Get("/reverse-shares/invites", s.listInvites)
			r.Post("/reverse-shares/invites/{id}/revoke", s.revokeInvite)

			// Auditors read the audit log and nothing else (see auditorAllowed).
			r.Group(func(r chi.Router) {
				r.Use(s.auditor, s.adminNetwork)
				r.Get("/audit", s.auditList)
				// An export is recorded BEFORE it is served; without a record there is no export.
				r.With(s.critical("audit_exported", "audit_log")).Get("/audit/export", s.auditExport)
				r.Get("/audit/status", s.auditStatusHandler)
				r.Get("/access-review", s.accessReview)
				r.With(s.critical("access_review_exported", "access_review")).Get("/access-review/export", s.accessReviewExport)
			})

			r.Group(func(r chi.Router) {
				r.Use(s.admin, s.adminNetwork)
				r.Get("/users", s.listUsers)
				r.With(s.critical("user_created", "user")).Post("/users", s.createUser)
				r.With(s.critical("user_updated", "user")).Put("/users/{id}", s.updateUser)
				r.With(s.stepUp, s.critical("user_deleted", "user")).Delete("/users/{id}", s.deleteUser)
				r.With(s.stepUp, s.critical("user_erased", "user")).Post("/users/{id}/erase", s.eraseUser)
				r.With(s.critical("user_force_reset", "user")).Post("/users/{id}/force-reset-password", s.forceReset)
				r.Post("/users/{id}/unlock-login", s.unlockLogin)
				r.With(s.stepUp, s.critical("mfa_reset_requested", "user")).Post("/users/{id}/mfa/reset", s.mfaReset)
				r.Post("/users/{id}/welcome", s.resendWelcome)
				r.With(s.critical("user_disabled", "user")).Post("/users/{id}/disable", s.disableUser)
				r.With(s.critical("user_enabled", "user")).Post("/users/{id}/enable", s.enableUser)
				r.With(s.critical("user_signed_out", "user")).Post("/users/{id}/sessions/revoke", s.adminRevokeSessions)

				r.Get("/settings", s.getSettings)
				r.With(s.critical("settings_changed", "settings")).Put("/settings", s.putSettings)
				r.Post("/settings/branding/{kind}", s.uploadBranding)
				r.Delete("/settings/branding/{kind}", s.deleteBranding)
				r.Post("/backgrounds", s.uploadBackground)
				r.Delete("/backgrounds/{file}", s.deleteBackground)

				r.Get("/stats", s.stats)
				r.Get("/ip-bans", s.listIPBansHandler)
				r.Delete("/ip-bans", s.deleteIPBanHandler)
				r.Get("/logs", s.listLogs)
				r.With(s.critical("audit_exported", "audit_log")).Get("/logs/export", s.exportLogs)
				r.Get("/logs/status", s.logsStatus)

				r.Get("/themes", s.listThemes)
				r.Post("/themes", s.saveTheme)
				r.Delete("/themes/{id}", s.deleteTheme)
				r.Post("/themes/{id}/activate", s.activateTheme)

				r.Get("/auth-providers", s.adminProviders)
				r.With(s.stepUp, s.critical("provider_created", "provider")).Post("/auth-providers", s.createProvider)
				r.With(s.stepUp, s.critical("provider_updated", "provider")).Put("/auth-providers/{id}", s.updateProvider)
				r.With(s.stepUp, s.critical("provider_deleted", "provider")).Delete("/auth-providers/{id}", s.deleteProvider)

				r.Get("/ui-languages", s.listUILanguages)
				r.Get("/ui-languages/{code}/export", s.exportUILanguage)
				r.Post("/ui-languages", s.importUILanguage)
				r.Delete("/ui-languages/{code}", s.deleteUILanguage)
				r.Post("/email-languages", s.createMailLanguage)
				r.Get("/email-templates", s.getTemplates)
				r.Put("/email-templates", s.putTemplates)
				r.Post("/email-templates/test", s.testEmail)
				r.Post("/email-templates/preview", s.previewTemplate)
				r.Get("/email-templates/export", s.exportMailBundle)
				r.Post("/email-templates/import", s.importMailBundle)

				r.Get("/backups", s.listBackups)
				r.With(s.critical("backup_created", "backup")).Post("/backups", s.createBackup)
				// A backup is a full copy of the database: it needs a recent
				// re-authentication and is recorded BEFORE it is served.
				r.With(s.stepUp, s.critical("backup_downloaded", "backup", s.backupDownloadInfo)).Get("/backups/{name}", s.downloadBackup)
				r.With(s.stepUp, s.critical("backup_deleted", "backup")).Delete("/backups/{name}", s.deleteBackup)

				// Tenant key rotation (keys_admin.go, D43): /api/admin/keys.
				r.Get("/admin/keys", s.keysStatus)
				r.With(s.stepUp, s.critical("key_rotation_requested", "keys")).Post("/admin/keys/rotate", s.keysRotate)
				r.With(s.stepUp, s.critical("key_retire_requested", "keys")).Post("/admin/keys/retire", s.keysRetire)
				r.With(s.stepUp, s.critical("files_reencrypt_requested", "keys")).Post("/admin/keys/reencrypt-files", s.keysRekeyFiles)
				// Tenant-supplied KEK (kek_admin.go, D44): /api/admin/kek.
				r.Get("/admin/kek", s.kekStatus)
				r.With(s.stepUp, s.critical("kek_upload_requested", "kek")).Post("/admin/kek/upload", s.kekUpload)
				r.With(s.stepUp, s.critical("kek_replace_requested", "kek")).Post("/admin/kek/replace", s.kekReplace)
				r.With(s.stepUp, s.critical("kek_release_requested", "kek")).Post("/admin/kek/release", s.kekRelease)
				r.With(s.critical("db_import_prepared", "backup")).Post("/backups/import", s.prepareImport)

				r.Get("/storage", s.storageStatus)
				r.With(s.stepUp).Post("/storage/test", s.storageTest)
				r.With(s.stepUp, s.critical("storage_migration_requested", "storage")).Post("/storage/migrate", s.storageMigrateStart)
				r.With(s.stepUp).Post("/storage/migrate/cancel", s.storageMigrateCancel)
				r.With(s.stepUp, s.critical("db_import_applied", "backup")).Post("/backups/import/apply", s.applyImport)

				// Conversion to multi-tenant mode (single-tenant only, mt_convert.go).
				r.Get("/multitenant", s.mtConvStatus)
				r.With(s.stepUp, s.critical("multitenant_conversion_requested", "platform")).Post("/multitenant", s.mtConvSchedule)
				r.With(s.stepUp, s.critical("multitenant_conversion_cancel_requested", "platform")).Delete("/multitenant", s.mtConvCancel)
				r.With(s.stepUp).Post("/multitenant/restart", s.mtConvRestart)
			})
		})
	})
	r.NotFound(s.spa)
	return r
}

// spaCSP restricts what the single-page app may load or do. Styles keep
// 'unsafe-inline' because Vue binds inline style attributes (theme variables).
const spaCSP = "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'"

// spa serves embedded frontend with index.html fallback.
func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if p == "" || p == platformIndex {
		// The platform console's entry page is only served on the console host.
		p = "index.html"
	}
	if strings.HasPrefix(p, "api/") {
		jerr(w, 404, "not found")
		return
	}
	f, err := s.Static.Open(p)
	if err == nil {
		// A directory (e.g. /assets/) is never served: 404, not a broken response.
		if info, serr := f.Stat(); serr != nil || info.IsDir() {
			f.Close()
			if serr == nil && strings.HasPrefix(p, "assets") {
				http.NotFound(w, r)
				return
			}
			err = fmt.Errorf("not a file")
		}
	}
	if err != nil {
		p = "index.html"
		f, err = s.Static.Open(p)
		if err != nil {
			http.Error(w, "frontend not built", 500)
			return
		}
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Security-Policy", spaCSP)
	if p == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	} else if strings.HasPrefix(p, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		http.Error(w, "unreadable", 500)
		return
	}
	http.ServeContent(w, r, p, st.ModTime(), rs)
}

// ---------- helpers ----------

func jout(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jerr(w http.ResponseWriter, code int, msg string) {
	jout(w, code, map[string]any{"error": msg})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v)
}

type ctxKey string

const userKey ctxKey = "user"

func (s *Server) ctxUser(r *http.Request) *User {
	u, _ := r.Context().Value(userKey).(*User)
	return u
}

func withUser(r *http.Request, u *User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userKey, u))
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	jout(w, 200, map[string]any{"status": "ok"})
}

func (s *Server) baseURL(r *http.Request) string {
	if s.BaseURL != "" {
		return s.BaseURL
	}
	if u := s.St.Setting("application_url"); u != "" {
		return strings.TrimRight(u, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// bootstrap: public settings the SPA needs before login.
func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	users, _ := s.St.Repos().Users().Count(context.Background())
	out := map[string]any{
		"setup_needed":                   users == 0,
		"application_name":               s.St.Setting("application_name"),
		"default_language":               s.St.Setting("default_language"),
		"show_language_selector":         s.St.SettingBool("show_language_selector"),
		"allow_reverse_shares":           s.St.SettingBool("allow_reverse_shares"),
		"allow_self_registration":        s.St.SettingBool("allow_self_registration"),
		"registration_available":         s.registrationAvailable(),
		"registration_domain_restricted": s.registrationRestricted(),
		"max_expiry_time":                s.St.SettingInt("max_expiry_time", 30),
		"default_expiry_time":            s.St.SettingInt("default_expiry_time", 7),
		"max_share_size":                 s.St.SettingInt("max_share_size", 2048),
		"has_logo":                       s.St.Setting("ui_logo") != "",
		"has_favicon":                    s.St.Setting("ui_favicon") != "",
		"ui_use_unsplash":                s.St.SettingBool("ui_use_unsplash"),
		"ui_slideshow_seconds":           s.St.SettingInt("ui_slideshow_seconds", 30),
		"background":                     s.backgroundID(),
		"multi_tenant":                   s.tenant != nil,
		"allow_preview":                  s.St.SettingBool("allow_preview"),
		"local_login_enabled":            s.localLoginEnabled(),
		"mfa_policy":                     s.mfaGlobal(),
		"idle_logout_minutes":            s.idleLogoutMinutes(),
		"mfa_totp_enabled":               s.mfaTOTPEnabled(),
		"mfa_reminder_days":              s.mfaReminderDays(),
		"mfa_webauthn_enabled":           s.mfaWebAuthnEnabled(),
		"webauthn_available":             webauthnAvailable(s.mfaAppURL()),
		// AGPL-3.0 section 13: the footer links to the source of the running
		// build on every page. Not a setting; it cannot be switched off.
		"source_url": sourceURLFor(s.Version),
	}
	policy, perr := s.loadSharePolicy()
	if perr != nil {
		// Corrupt stored policy: completion fails closed, so advertise the strictest view.
		policy = sharePolicy{Required: true, MinLength: maxSharePasswordBytes}
	}
	out["require_share_password"] = policy.Required
	out["share_password_min_length"] = policy.MinLength
	out["share_password_require_upper"] = policy.Upper
	out["share_password_require_lower"] = policy.Lower
	out["share_password_require_digit"] = policy.Digit
	out["share_password_require_symbol"] = policy.Symbol
	acct, aerr := s.loadAccountPolicy()
	if aerr != nil {
		acct = strictestAccountPolicy
	}
	out["account_password_min_length"] = acct.MinLength
	out["account_password_require_upper"] = acct.Upper
	out["account_password_require_lower"] = acct.Lower
	out["account_password_require_digit"] = acct.Digit
	out["account_password_require_symbol"] = acct.Symbol
	s.accountSecurityBootstrap(out)
	jout(w, 200, out)
}
