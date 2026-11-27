// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sendora-app/sendora/internal/store"
)

// Tamper-evident audit log (see internal/store/audit.go for the chain). Logging
// is always on. Records never contain passwords, tokens, secrets, link IDs, file
// contents or the values of secret settings; the client IP is stored only while
// the audit_log_ip setting is on.

const (
	auditViewedEvery = 5 * time.Minute
	// auditIPCacheTTL bounds how long the cached audit_log_ip value is trusted
	// when a setting was written without moving SettingsGen.
	auditIPCacheTTL = 30 * time.Second
)

// auditRetryBackoff is the pause before the single retry of a failed write.
var auditRetryBackoff = 50 * time.Millisecond

// Categories and outcomes of audit records.
const (
	catAuth     = "auth"
	catAccount  = "account"
	catAdmin    = "admin"
	catSecurity = "security"
	catShare    = "share"
	catSystem   = "system"
)

var auditCategories = map[string]bool{catAuth: true, catAccount: true, catAdmin: true, catSecurity: true, catShare: true, catSystem: true}
var auditOutcomes = map[string]bool{"ok": true, "denied": true, "failed": true, "attempted": true}

// auditEntry is a record before it is chained.
type auditEntry struct {
	Category, Action, Target, Outcome, Detail string
	ActorID                                   int64
	ActorName, ActorRole                      string
}

// auditReq is the request-scoped state shared by the audit middleware, the
// authentication middleware and logEvent.
type auditReq struct {
	r        *http.Request
	user     atomic.Pointer[User]
	wrote    atomic.Bool // any record was written for this request
	logged   atomic.Bool // the handler itself recorded an outcome
	critical atomic.Pointer[auditEntry]
	// unauth: refused by the auth middleware before any user was known (no,
	// expired, revoked or forged token). Such requests name nobody and anyone on
	// the internet can send them, so they are not recorded.
	unauth atomic.Bool
}

// unauthenticated answers 401 for a request whose credentials do not verify.
func (s *Server) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if st := auditReqFrom(r.Context()); st != nil {
		st.unauth.Store(true)
	}
	jerr(w, http.StatusUnauthorized, "unauthorized")
}

type auditReqKeyType struct{}

var auditReqKey auditReqKeyType

func auditReqFrom(ctx context.Context) *auditReq {
	st, _ := ctx.Value(auditReqKey).(*auditReq)
	return st
}

type auditState struct {
	fails      atomic.Int64
	appended   atomic.Int64
	lastFailed atomic.Bool // the most recent write failed (readiness check)
	reqs       sync.Map    // goroutine id -> *auditReq
	hook       atomic.Pointer[func() error]

	viewMu sync.Mutex
	viewed map[int64]time.Time

	ipCache atomic.Pointer[auditIPSetting]

	// Retention purge state: audit_purge_failed is written when it starts
	// failing, not on every run.
	purgeMu      sync.Mutex
	purgeFailing bool
	purgeSince   time.Time

	dlMu sync.Mutex
	dlAt map[int64]time.Time // download_started records, per share (download_log.go)
}

type auditIPSetting struct {
	gen uint64
	on  bool
	at  time.Time
}

// auditLogIP is the audit_log_ip setting, cached until the settings change.
func (s *Server) auditLogIP() bool {
	gen := s.St.SettingsGen() // read before the value, so a concurrent change is seen next time
	if c := s.audit.ipCache.Load(); c != nil && c.gen == gen && time.Since(c.at) < auditIPCacheTTL {
		return c.on
	}
	on := s.St.SettingBool("audit_log_ip")
	s.audit.ipCache.Store(&auditIPSetting{gen: gen, on: on, at: time.Now()})
	return on
}

// goroutineID identifies the calling goroutine. logEvent has no request
// parameter (and its call sites must not change), so the request a record
// belongs to is found through the goroutine that serves it.
func goroutineID() uint64 {
	var b [48]byte
	n := runtime.Stack(b[:], false)
	s := strings.TrimPrefix(string(b[:n]), "goroutine ")
	if i := strings.IndexByte(s, ' '); i > 0 {
		id, _ := strconv.ParseUint(s[:i], 10, 64)
		return id
	}
	return 0
}

func (s *Server) currentAuditReq() *auditReq {
	if v, ok := s.audit.reqs.Load(goroutineID()); ok {
		return v.(*auditReq)
	}
	return nil
}

func roleOfUser(u *User) string {
	switch {
	case u == nil:
		return "anonymous"
	case u.Admin:
		return "admin"
	case u.Auditor:
		return "auditor"
	case u.IsGuest:
		return "guest"
	}
	return "user"
}

// classifyAction maps an action name to its category and outcome.
func classifyAction(action string) (category, outcome string) {
	outcome = "ok"
	switch {
	case strings.HasSuffix(action, "_failed"):
		outcome = "failed"
	case action == "login_lockout", action == "access_denied", strings.HasSuffix(action, "_denied"):
		outcome = "denied"
	}
	if action == "backup_failed_auto" {
		outcome = "failed"
	}
	switch action {
	case "login_ok", "login_failed", "login_lockout", "logout", "mfa_login_ok", "mfa_failed", "mfa_enrolled", "mfa_removed",
		"session_reuse_detected", "password_changed", "password_reset", "session_revoked", "session_expired_provider",
		"session_expired", "session_expired_idle", "password_expired", "password_expiry_warning_sent":
		return catAuth, outcome
	case "ip_banned", "ip_unbanned", "access_denied", "file_decrypt_failed", "key_fingerprint_changed", "audit_viewed", "audit_exported", "access_review_exported",
		"backup_downloaded",
		"kek_upload_requested", "kek_replace_requested", "kek_release_requested", "kek_step", "kek_switched", "kek_switch_failed", "kek_replaced",
		"kek_replace_failed", "kek_released", "kek_release_failed", "kek_unlocked", "kek_unlock_failed",
		"key_rotation_requested", "key_rotation_completed", "key_rotation_failed", "key_retire_requested", "key_retired", "key_retire_failed", "key_job_started", "files_reencrypt_requested":
		return catSecurity, outcome
	case "system_start", "system_stop", "audit_purged", "audit_purge_failed",
		"backup_created_auto", "backup_failed_auto", "backup_pruned", "share_files_purged", "account_removed_auto",
		"backup_remote_copied", "backup_remote_failed", "backup_remote_pruned",
		"storage_migration_finished", "storage_migration_failed", "storage_migration_cancelled":
		return catSystem, outcome
	case "mfa_reset_requested", "mfa_reset_confirmed", "personal_data_exported", "terms_accepted":
		return catAccount, outcome
	}
	switch {
	case strings.HasPrefix(action, "share"), strings.HasPrefix(action, "download_"), strings.HasPrefix(action, "invite_"):
		return catShare, outcome
	case strings.HasPrefix(action, "user_"):
		return catAccount, outcome
	}
	return catAdmin, outcome
}

// routeCategory is the category of a generic api_mutation record.
func routeCategory(pattern string) string {
	switch {
	case strings.HasPrefix(pattern, "/api/shares"), strings.HasPrefix(pattern, "/api/uploads"), strings.HasPrefix(pattern, "/api/reverse-shares"):
		return catShare
	case strings.HasPrefix(pattern, "/api/auth"):
		return catAuth
	case strings.HasPrefix(pattern, "/api/users"):
		return catAccount
	case pattern == "/api/setup":
		return catSystem
	}
	return catAdmin
}

// auditRole is the role label of an actor.
func (s *Server) auditRole(id int64, name string, st *auditReq) string {
	if st != nil {
		if u := st.user.Load(); u != nil && u.ID == id {
			return roleOfUser(u)
		}
	}
	if id <= 0 {
		if name == "system" {
			return "system"
		}
		return "anonymous"
	}
	admin, auditor, guest, err := s.St.Repos().Users().Roles(context.Background(), id)
	if err != nil {
		return "user"
	}
	return roleOfUser(&User{Admin: admin, Auditor: auditor, IsGuest: guest})
}

// auditWrite chains and stores one record synchronously. A failed write is
// retried once; after that the failure is reported on stderr and counted.
func (s *Server) auditWrite(e auditEntry, st *auditReq) error {
	if !auditCategories[e.Category] {
		e.Category = catAdmin
	}
	if !auditOutcomes[e.Outcome] {
		e.Outcome = "ok"
	}
	var ip string
	if st != nil && st.r != nil && s.auditLogIP() {
		ip = s.clientIP(st.r)
	}
	rec := store.AuditRecord{Category: e.Category, ActorID: e.ActorID, ActorName: clip(e.ActorName, 100), ActorRole: e.ActorRole,
		Action: clip(e.Action, 80), Target: clip(e.Target, 160), Outcome: e.Outcome, Detail: e.Detail, IP: ip}
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(auditRetryBackoff) // let a short lock or busy period pass
		}
		if h := s.audit.hook.Load(); h != nil {
			if err = (*h)(); err != nil {
				continue
			}
		}
		var stored store.AuditRecord
		if stored, err = s.St.AuditAppend(rec); err == nil {
			s.audit.appended.Add(1)
			s.audit.lastFailed.Store(false)
			if st != nil {
				st.wrote.Store(true)
			}
			s.fwd.forward(s, &stored) // asynchronous; never blocks or fails the caller
			return nil
		}
	}
	s.audit.fails.Add(1)
	s.audit.lastFailed.Store(true)
	log.Printf("AUDIT WRITE FAILED (action %s): %v", rec.Action, err)
	return err
}

// logEvent records an audit event synchronously. Call it only when no
// transaction or rows are open on the single database connection. A failure is
// reported on stderr and counted, never raised.
func (s *Server) logEvent(actorID int64, actorName, action, target, detail string) {
	s.ops.countAction(action)
	st := s.currentAuditReq()
	cat, outcome := classifyAction(action)
	e := auditEntry{Category: cat, Action: action, Target: target, Outcome: outcome, Detail: detail,
		ActorID: actorID, ActorName: actorName, ActorRole: s.auditRole(actorID, actorName, st)}
	if s.auditWrite(e, st) == nil && st != nil {
		st.logged.Store(true)
	}
}

// logShare records an authenticated user's action on a share.
func (s *Server) logShare(r *http.Request, action string, shareID int64, detail string) {
	u := s.ctxUser(r)
	if u == nil {
		return
	}
	s.logEvent(u.ID, u.Username, action, "share#"+strconv.FormatInt(shareID, 10), detail)
}

// userTarget labels a user as "user#ID (username)" for the audit log. It must
// not be called while rows or a transaction hold the single database connection.
func (s *Server) userTarget(id int64) string {
	label := "user#" + strconv.FormatInt(id, 10)
	if name, err := s.St.Repos().Users().Username(context.Background(), id); err == nil && name != "" {
		label += " (" + name + ")"
	}
	return label
}

// auditCritical writes an outcome=attempted record BEFORE a critical action
// runs. When the record cannot be stored it answers 503 and returns false, so
// no critical administrative action happens unlogged.
func (s *Server) auditCritical(w http.ResponseWriter, r *http.Request, action, target, detail string) bool {
	u := s.ctxUser(r)
	st := auditReqFrom(r.Context())
	cat, _ := classifyAction(action)
	e := auditEntry{Category: cat, Action: action, Target: target, Outcome: "attempted", Detail: detail, ActorRole: roleOfUser(u)}
	if u != nil {
		e.ActorID, e.ActorName = u.ID, u.Username
	}
	if err := s.auditWrite(e, st); err != nil {
		jerr(w, http.StatusServiceUnavailable, "the audit log is unavailable; the action was not performed")
		return false
	}
	if st != nil {
		e.Outcome = "ok"
		st.critical.Store(&e)
	}
	return true
}

// criticalInfo names the target and detail of a critical record from the
// request. ok=false means the addressed object does not exist: the request is
// answered 404 without running the handler (so nothing is served unrecorded).
type criticalInfo func(r *http.Request) (target, detail string, ok bool)

// critical is the route middleware that audits an action before it runs. noun
// labels the target ("user" gives "user#<id>" when the route has an {id});
// an optional criticalInfo replaces that label and adds a detail.
func (s *Server) critical(action, noun string, info ...criticalInfo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target, detail := noun, ""
			for _, p := range []string{"id", "name"} {
				if v := chi.URLParam(r, p); v != "" {
					target = noun + "#" + clip(v, 60)
					break
				}
			}
			if len(info) > 0 {
				t, d, ok := info[0](r)
				if !ok {
					jerr(w, 404, "not found")
					return
				}
				target, detail = t, d
			}
			if !s.auditCritical(w, r, action, target, detail) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// auditExempt lists mutating routes the generic middleware deliberately does not
// record, each with its reason. TestAuditCoversEveryMutatingRoute keeps it exact.
var auditExempt = map[string]string{
	"POST /api/auth/refresh":                "silent token rotation that every signed-in browser repeats; session reuse and sign-in events are recorded explicitly",
	"PATCH /api/uploads/{id}/files/{idx}":   "one request per uploaded chunk; the upload start and the finished share are recorded",
	"POST /api/auth/mfa/webauthn/begin":     "challenge request without effect; the matching finish request and failures are recorded",
	"POST /api/users/me/mfa/webauthn/begin": "challenge request without effect; the matching finish request is recorded",
	"POST /api/users/me/mfa/totp/begin":     "secret preparation without effect; the confirm request is recorded",
	"POST /api/email-templates/preview":     "renders a preview without storing anything",
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// auditMiddleware gives every request an audit state and, after the handler ran,
// records what the handler did not: denied access for a signed-in user and a
// generic api_mutation entry for mutating requests. When the handler panics, the
// outcome is recorded as status 500 before the panic continues to the
// Recoverer outside this middleware.
func (s *Server) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := &auditReq{r: r}
		r = r.WithContext(context.WithValue(r.Context(), auditReqKey, st))
		gid := goroutineID()
		s.audit.reqs.Store(gid, st)
		defer s.audit.reqs.Delete(gid)
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		defer func() {
			if p := recover(); p != nil {
				s.auditOutcome(r, st, http.StatusInternalServerError)
				panic(p)
			}
		}()
		next.ServeHTTP(ww, r)
		code := ww.Status()
		if code == 0 {
			code = http.StatusOK
		}
		s.auditOutcome(r, st, code)
	})
}

// auditOutcome writes the record of a finished request that its handler did
// not write itself, if any.
func (s *Server) auditOutcome(r *http.Request, st *auditReq, code int) {
	if st.unauth.Load() && st.user.Load() == nil {
		return
	}
	pattern := ""
	if rc := chi.RouteContext(r.Context()); rc != nil {
		pattern = rc.RoutePattern()
	}
	key := r.Method + " " + pattern
	u := st.user.Load()
	e := auditEntry{ActorRole: roleOfUser(u)}
	if u != nil {
		e.ActorID, e.ActorName = u.ID, u.Username
	}
	switch {
	case st.critical.Load() != nil && !st.logged.Load():
		c := st.critical.Load()
		e.Category, e.Action, e.Target = c.Category, c.Action, c.Target
		e.Outcome = outcomeOfStatus(code)
		e.Detail = "status=" + strconv.Itoa(code)
	// Only a known, signed-in user who is refused. Expired, revoked or junk
	// tokens from anywhere are not recorded: they would flood the log.
	case (code == http.StatusUnauthorized || code == http.StatusForbidden) && u != nil && !st.logged.Load():
		e.Category, e.Action, e.Target, e.Outcome = catSecurity, "access_denied", pattern, "denied"
		e.Detail = r.Method + " status=" + strconv.Itoa(code)
	case isMutating(r.Method) && !st.wrote.Load() && auditExempt[key] == "":
		e.Category, e.Action, e.Outcome = routeCategory(pattern), "api_mutation", outcomeOfStatus(code)
		e.Action = key
		e.Detail = "status=" + strconv.Itoa(code)
	default:
		return
	}
	_ = s.auditWrite(e, st)
}

func outcomeOfStatus(code int) string {
	switch {
	case code < 400:
		return "ok"
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return "denied"
	}
	return "failed"
}

// auditAccessDenied records a denied access (for example to a share that belongs
// to somebody else) for the request being served.
func (s *Server) auditAccessDenied(r *http.Request, category, target, detail string) {
	u := s.ctxUser(r)
	st := auditReqFrom(r.Context())
	e := auditEntry{Category: category, Action: "access_denied", Target: target, Outcome: "denied", Detail: detail, ActorRole: roleOfUser(u)}
	if u != nil {
		e.ActorID, e.ActorName = u.ID, u.Username
	}
	if s.auditWrite(e, st) == nil && st != nil {
		st.logged.Store(true)
	}
}

// auditSetActor tells the audit state who the authenticated user of this request is.
func (s *Server) auditSetActor(r *http.Request, u *User) {
	if st := auditReqFrom(r.Context()); st != nil {
		st.user.Store(u)
	}
}

// auditDecryptFailed records that a stored file could not be decrypted (row id only).
func (s *Server) auditDecryptFailed(fileID int64) {
	s.logEvent(0, "system", "file_decrypt_failed", "file#"+strconv.FormatInt(fileID, 10), "")
}

// auditRetentionDays is the effective retention (90..365; an invalid stored
// value falls back to the default instead of shortening the log).
func (s *Server) auditRetentionDays() int {
	n, ok := parseStrictInt(s.St.Setting("audit_retention_days"), store.AuditRetentionMinDays, 365)
	if !ok {
		return 90
	}
	return n
}

// purgeAudit applies the retention; called from maintain(). audit_purge_failed
// is recorded when purging starts to fail, not on every run, and
// /api/audit/status reports the state until a purge succeeds again. A purge
// refused because the chain is broken stays refused: recovery is to verify the
// database offline (sendora-db audit-verify), investigate, and restore a backup
// from before the damage.
func (s *Server) purgeAudit() {
	n, err := s.St.AuditPurge(time.Now().UTC().AddDate(0, 0, -s.auditRetentionDays()))
	a := &s.audit
	a.purgeMu.Lock()
	wasFailing := a.purgeFailing
	a.purgeFailing = err != nil
	if err != nil && !wasFailing {
		a.purgeSince = time.Now().UTC()
	}
	a.purgeMu.Unlock()
	if err != nil {
		log.Printf("audit retention purge: %v", err)
		if !wasFailing {
			detail := "retention purge failed"
			if errors.Is(err, store.ErrAuditPurgeRefused) {
				detail = "retention purge refused: the records to be removed do not verify"
			}
			s.logEvent(0, "system", "audit_purge_failed", "", detail)
		}
		return
	}
	if wasFailing {
		log.Printf("audit retention purge works again")
	}
	if n > 0 {
		s.logEvent(0, "system", "audit_purged", "", strconv.FormatInt(n, 10)+" records past retention")
	}
}

// auditPurgeState reports whether retention purges currently fail, and since when.
func (s *Server) auditPurgeState() (bool, time.Time) {
	s.audit.purgeMu.Lock()
	defer s.audit.purgeMu.Unlock()
	return s.audit.purgeFailing, s.audit.purgeSince
}

// auditStartup records the start of the process and checks the database key.
func (s *Server) auditStartup() {
	// Cluster: tenants open and close on every replica; per-open records
	// would be noise (design 4 item 15).
	if s.cl != nil {
		return
	}
	fp := s.St.KeyFingerprint()
	if old := s.St.Setting("audit_key_fingerprint"); old != "" && old != fp {
		s.logEvent(0, "system", "key_fingerprint_changed", "", "was "+clip(old, 20)+" now "+fp)
	}
	if old := s.St.Setting("audit_key_fingerprint"); old != fp {
		s.St.Repos().System().SetAuditKeyFingerprint(context.Background(), fp)
	}
	s.logEvent(0, "system", "system_start", "", "version="+clip(s.Version, 40)+" key="+fp)
}

// auditShutdown records an orderly stop.
func (s *Server) auditShutdown() {
	if s.cl != nil {
		return
	}
	s.logEvent(0, "system", "system_stop", "", "")
}

// auditStatus verifies the chain incrementally: only records added since the
// last check are walked, with the same result as a full verification.
func (s *Server) auditStatus(ctx context.Context) (store.AuditStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return s.St.AuditVerifyIncremental(ctx)
}

// auditViewedOnce records audit_viewed at most once per period per actor.
func (s *Server) auditViewedOnce(u *User) {
	a := &s.audit
	a.viewMu.Lock()
	if a.viewed == nil {
		a.viewed = map[int64]time.Time{}
	}
	last, ok := a.viewed[u.ID]
	if ok && time.Since(last) < auditViewedEvery {
		a.viewMu.Unlock()
		return
	}
	a.viewed[u.ID] = time.Now()
	a.viewMu.Unlock()
	s.logEvent(u.ID, u.Username, "audit_viewed", "audit_log", "")
}

// auditorAllowed is the allowlist of an auditor session: its own profile and
// password, its own second factors (the /api/users/me/mfa self-service routes
// only ever act on the caller's factors; without them an auditor could not enrol
// when MFA is required), its own sessions, the audit endpoints and the
// read-only access-review report. Everything else is refused.
func auditorAllowed(r *http.Request) bool {
	switch r.URL.Path {
	case "/api/users/me":
		return r.Method == http.MethodGet || r.Method == http.MethodPut
	case "/api/users/me/export":
		return r.Method == http.MethodGet
	case "/api/users/me/terms", "/api/users/me/erase":
		return r.Method == http.MethodPost
	case "/api/audit", "/api/audit/export", "/api/audit/status", "/api/access-review", "/api/access-review/export":
		return r.Method == http.MethodGet
	}
	return mfaSelfServicePath(r.URL.Path) || sessionSelfService(r)
}

// mfaSelfServicePath reports the routes that manage the caller's own factors.
func mfaSelfServicePath(p string) bool {
	return p == "/api/users/me/mfa" || strings.HasPrefix(p, "/api/users/me/mfa/")
}

func (s *Server) auditor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := s.ctxUser(r); u == nil || !(u.Auditor || u.Admin) {
			jerr(w, 403, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clip(v string, n int) string {
	v = strings.ToValidUTF8(v, "")
	if utf8.RuneCountInString(v) <= n {
		return v
	}
	return string([]rune(v)[:n])
}
