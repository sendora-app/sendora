// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

// The platform console (admin.<base domain>): platform administrators manage
// tenants, domains, quotas, the storage configuration hook and platform
// settings. It never reads a tenant's users, shares, files or audit details;
// only counts. Every action is recorded in the platform audit log, and the
// ones that affect a tenant also in that tenant's own audit log.
//
// Sign-in: username + password, then TOTP. A new administrator must enroll a
// TOTP authenticator before anything else (sessions in the "enroll" stage can
// only do that). Destructive actions need a fresh TOTP code (step-up).
//
// The owner of the platform may switch the authenticator requirement off
// (platform_mfa_required=false, SENDORA_PLATFORM_MFA_REQUIRED): administrators
// then sign in with their password only, may still enrol an authenticator, and
// confirm destructive actions with their authenticator code when they have one
// and otherwise with their password. A temporary password set offline
// (sendora-db platform-admin-reset) only allows choosing a new password.

const (
	consoleCookie       = "sendora_platform"
	consoleSessionTTL   = 12 * time.Hour
	consoleIdle         = 30 * time.Minute
	consoleLoginLimit   = 5
	consoleLockDuration = 15 * time.Minute
	consoleMinPassword  = 12
)

type platformConsole struct {
	h         *TenantHost
	router    http.Handler
	setupCode string
	setupFail failThrottle
	limiter   rateLimiter
	// lookupTXT resolves DNS TXT records (custom domain verification); tests replace it.
	lookupTXT func(ctx context.Context, name string) ([]string, error)
	// clock is the time for TOTP checks; tests replace it.
	clock func() time.Time
	// keyList caches the Key management listing for a few seconds: building
	// it opens every tenant on this replica, and the screen polls.
	keyListMu   sync.Mutex
	keyListAt   time.Time
	keyListRows []keyRow
}

// rateLimiter is a small fixed-window counter per key.
type rateLimiter struct {
	mu sync.Mutex
	m  map[string]requestBudget
}

func (l *rateLimiter) allow(key string, limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.m == nil || len(l.m) > 10000 {
		l.m = map[string]requestBudget{}
	}
	b := l.m[key]
	if now.After(b.expires) {
		b = requestBudget{expires: now.Add(window)}
	}
	b.count++
	l.m[key] = b
	return b.count <= limit
}

// allow is the console's request budget; in the Cluster flavour it is shared
// by every replica (design 4.2).
func (c *platformConsole) allow(key string, limit int, window time.Duration) bool {
	if cl := c.h.cfg.Cluster; cl != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		n, err := cl.Limiter.Hit(ctx, "console:"+strconv.FormatInt(window.Milliseconds(), 10), key, window)
		if err == nil {
			return n <= limit
		}
		log.Printf("cluster: shared console budget unavailable, using this replica's: %v", err)
	}
	return c.limiter.allow(key, limit, window)
}

// setupBlocked and setupFailed are the first-run setup throttle (all
// addresses share it), shared by every replica in the Cluster flavour.
func (c *platformConsole) setupBlocked() (time.Duration, bool) {
	if cl := c.h.cfg.Cluster; cl != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if until, blocked, err := cl.Limiter.Blocked(ctx, "console-setup-block", "setup"); err == nil {
			return time.Until(until), blocked
		}
	}
	return c.setupFail.blocked("setup")
}

func (c *platformConsole) setupFailed() {
	if cl := c.h.cfg.Cluster; cl != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		n, err := cl.Limiter.Hit(ctx, "console-setup", "setup", setupFailWindow)
		if err == nil {
			if n >= setupFailLimit {
				cl.Limiter.Block(ctx, "console-setup-block", "setup", time.Now().Add(setupFailBlock))
				cl.Limiter.Reset(ctx, "console-setup", "setup")
			}
			return
		}
	}
	c.setupFail.fail("setup", setupFailLimit, setupFailWindow, setupFailBlock)
}

func newPlatformConsole(h *TenantHost) *platformConsole {
	c := &platformConsole{h: h, lookupTXT: net.DefaultResolver.LookupTXT, clock: time.Now}
	// A Cluster controller never serves the console: a code of its own would
	// only contradict the one the web replicas share.
	controller := h.cfg.Cluster != nil && h.cfg.Cluster.RunJobs
	if h.P.AdminCount() == 0 && !controller {
		c.setupCode = strings.ToUpper(strings.TrimSpace(os.Getenv("SENDORA_PLATFORM_SETUP_CODE")))
		if c.setupCode != "" && !validSetupCode(c.setupCode) {
			log.Printf("SENDORA_PLATFORM_SETUP_CODE ignored: it must be at least 16 characters and not a repeated or sequential pattern; using a generated code")
			c.setupCode = ""
		}
		if c.setupCode == "" {
			c.setupCode = newSetupCode()
		}
		setupCodeLog("platform console setup code: %s (create the first platform administrator at %s; it changes on every restart until done)", c.setupCode, h.ConsoleURL())
	}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, c.secure)
	r.Route("/api/platform", func(r chi.Router) {
		r.Get("/bootstrap", c.bootstrap)
		r.Post("/setup", c.setup)
		r.Post("/login", c.login)
		r.Post("/logout", c.logout)
		r.Group(func(r chi.Router) {
			r.Use(c.session("mfa", "enroll", "full"))
			r.Get("/me", c.me)
			r.Post("/password", c.changePassword)
		})
		r.Group(func(r chi.Router) {
			r.Use(c.session("mfa"))
			r.Post("/login/totp", c.loginTOTP)
		})
		r.Group(func(r chi.Router) {
			// Enrolment: required ("enroll") or voluntary ("full", when the
			// platform does not require an authenticator).
			r.Use(c.session("enroll", "full"))
			r.Post("/mfa/begin", c.mfaBegin)
			r.Post("/mfa/confirm", c.mfaConfirm)
		})
		r.Group(func(r chi.Router) {
			r.Use(c.session("full"))
			r.Get("/tenants", c.listTenants)
			r.Post("/tenants", c.createTenant)
			r.Get("/tenants/{id}", c.getTenant)
			r.Put("/tenants/{id}", c.renameTenant)
			r.Post("/tenants/{id}/suspend", c.setStatus(platform.StatusSuspended))
			r.Post("/tenants/{id}/resume", c.setStatus(platform.StatusActive))
			r.Put("/tenants/{id}/quotas", c.setQuotas)
			r.Post("/tenants/{id}/delete", c.deleteTenant)
			r.Post("/tenants/{id}/domains", c.addDomain)
			r.Post("/tenants/{id}/domains/{domain}/verify", c.verifyDomain)
			r.Delete("/tenants/{id}/domains/{domain}", c.removeDomain)
			r.Put("/tenants/{id}/primary-domain", c.setPrimaryDomain)
			r.Get("/tenants/{id}/storage", c.getStorage)
			r.Put("/tenants/{id}/storage", c.putStorage)
			r.Put("/tenants/{id}/network", c.putNetwork)
			r.Get("/keys", c.listKeys)
			r.Post("/keys/rotate-all", c.rotateAllKeys)
			r.Post("/tenants/{id}/keys/rotate", c.rotateTenantKeys)
			r.Get("/master", c.masterStatus)
			r.Post("/master/rotate", c.masterRotate)
			r.Post("/master/retire", c.masterRetire)
			r.Get("/storage", c.getPlatformStorage)
			r.Put("/storage", c.putPlatformStorage)
			r.Post("/storage/test", c.testPlatformStorage)
			r.Get("/settings", c.getSettings)
			r.Post("/restart", c.restart)
			r.Put("/base-domain", c.putBaseDomain)
			r.Put("/settings", c.putSettings)
			r.Get("/audit", c.audit)
			r.Get("/audit/status", c.auditStatus)
			r.Get("/admins", c.listAdmins)
			r.Post("/admins", c.createAdmin)
			r.Post("/admins/{aid}/delete", c.deleteAdmin)
			r.Post("/admins/{aid}/mfa-reset", c.resetAdminMFA)
		})
	})
	r.NotFound(c.spa)
	c.router = r
	return c
}

func (c *platformConsole) ServeHTTP(w http.ResponseWriter, r *http.Request) { c.router.ServeHTTP(w, r) }

func (c *platformConsole) https() bool { return c.h.scheme == "https" }

// clientIP: the right-most X-Forwarded-For address that is not a trusted
// proxy, only when the peer is one; otherwise the peer.
func (c *platformConsole) clientIP(r *http.Request) string {
	peer := peerHost(r)
	if !c.h.peerTrusted(r) {
		return peer
	}
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			return peer
		}
		trusted := false
		for _, n := range c.h.cfg.TrustedProxies {
			if n.Contains(ip) {
				trusted = true
			}
		}
		if !trusted {
			return ip.String()
		}
	}
	return peer
}

// secure sets the security headers and refuses cross-origin unsafe requests.
func (c *platformConsole) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if c.https() {
			w.Header().Set("Strict-Transport-Security", "max-age=15552000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				jerr(w, 403, "cross-origin request refused")
				return
			}
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || !strings.EqualFold(u.Scheme+"://"+u.Host, c.h.ConsoleURL()) {
					jerr(w, 403, "cross-origin request refused")
					return
				}
			}
			if r.ContentLength != 0 {
				ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
				if ct != "application/json" {
					jerr(w, 415, "application/json required")
					return
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		next.ServeHTTP(w, r)
	})
}

// spa serves the web build with the console's entry page as the fallback.
func (c *platformConsole) spa(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if strings.HasPrefix(p, "api/") {
		jerr(w, 404, "not found")
		return
	}
	static := c.h.cfg.Static
	if p == "" || p == "index.html" {
		p = platformIndex
	}
	f, err := static.Open(p)
	if err == nil {
		if info, serr := f.Stat(); serr != nil || info.IsDir() {
			f.Close()
			err = errors.New("not a file")
		}
	}
	if err != nil {
		if strings.HasPrefix(p, "assets/") {
			http.NotFound(w, r)
			return
		}
		p = platformIndex
		if f, err = static.Open(p); err != nil {
			http.Error(w, "console not built", 500)
			return
		}
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Security-Policy", spaCSP)
	if p == platformIndex {
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

// ---------- sessions ----------

type consoleCtxKey struct{}

type consoleSession struct {
	hash  string
	admin *platform.Admin
	sess  *platform.Session
}

func sessionHash(tok string) string {
	h := sha256.Sum256([]byte("sendora-platform-session\x00" + tok))
	return hex.EncodeToString(h[:])
}

func (c *platformConsole) setCookie(w http.ResponseWriter, tok string, maxAge int) {
	// Host-only (no Domain attribute): never sent to a tenant's subdomain.
	http.SetCookie(w, &http.Cookie{Name: consoleCookie, Value: tok, Path: "/", HttpOnly: true, Secure: c.https(), SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func (c *platformConsole) startSession(w http.ResponseWriter, adminID int64, stage string) error {
	tok := randHex(32)
	if err := c.h.P.CreateSession(sessionHash(tok), adminID, stage, consoleSessionTTL); err != nil {
		return err
	}
	c.setCookie(w, tok, int(consoleSessionTTL/time.Second))
	return nil
}

func (c *platformConsole) currentSession(r *http.Request) *consoleSession {
	ck, err := r.Cookie(consoleCookie)
	if err != nil || len(ck.Value) != 64 {
		return nil
	}
	hash := sessionHash(ck.Value)
	sess, err := c.h.P.SessionFor(hash, consoleIdle)
	if err != nil {
		return nil
	}
	a, err := c.h.P.AdminByID(sess.AdminID)
	if err != nil {
		return nil
	}
	return &consoleSession{hash: hash, admin: a, sess: sess}
}

// session admits requests whose session is in one of the stages.
func (c *platformConsole) session(stages ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cs := c.currentSession(r)
			if cs == nil {
				jerr(w, 401, "unauthorized")
				return
			}
			ok := false
			for _, st := range stages {
				if cs.sess.Stage == st {
					ok = true
				}
			}
			if !ok {
				jerr(w, 403, "complete the sign-in first")
				return
			}
			// A temporary password (offline reset) only allows choosing a new one.
			if cs.admin.MustChangePassword && r.URL.Path != "/api/platform/me" && r.URL.Path != "/api/platform/password" {
				jerr(w, 403, "choose a new password first")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), consoleCtxKey{}, cs)))
		})
	}
}

func consoleFrom(r *http.Request) *consoleSession {
	cs, _ := r.Context().Value(consoleCtxKey{}).(*consoleSession)
	return cs
}

func (c *platformConsole) audit(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	recs, err := c.h.P.AuditPage(before, 100)
	if err != nil {
		jerr(w, 500, "audit log unavailable")
		return
	}
	jout(w, 200, map[string]any{"records": recs})
}

func (c *platformConsole) auditStatus(w http.ResponseWriter, r *http.Request) {
	st, err := c.h.P.St.AuditVerifyIncremental(r.Context())
	if err != nil {
		jerr(w, 500, "verification failed")
		return
	}
	jout(w, 200, st)
}

// record writes a platform audit record for the signed-in administrator.
func (c *platformConsole) record(r *http.Request, action, target, outcome, detail string) {
	var id int64
	name := "anonymous"
	if cs := consoleFrom(r); cs != nil {
		id, name = cs.admin.ID, cs.admin.Username
	}
	if err := c.h.P.Audit(id, name, action, target, outcome, detail, c.clientIP(r)); err != nil {
		log.Printf("platform audit write failed: %v", err)
	}
}

// ---------- sign-in ----------

func (c *platformConsole) bootstrap(w http.ResponseWriter, r *http.Request) {
	jout(w, 200, map[string]any{
		"setup_needed":        c.h.P.AdminCount() == 0,
		"password_min_length": consoleMinPassword,
		"base_domain":         c.h.baseHost + c.h.basePort,
		"console_url":         c.h.ConsoleURL(),
		"version":             c.h.cfg.Version,
		"source_url":          sourceURLFor(c.h.cfg.Version),
	})
}

func (c *platformConsole) checkPassword(pw, username string) string {
	return platformPasswordProblem(pw, username)
}

// platformPasswordProblem screens a platform administrator's password ("" = ok).
func platformPasswordProblem(pw, username string) string {
	switch {
	case len(pw) < consoleMinPassword:
		return fmt.Sprintf("the password must have at least %d characters", consoleMinPassword)
	case len(pw) > 72:
		return "the password must have at most 72 bytes"
	case isTrivialPassword(pw) || isCommonPassword(pw) || containsPersonal(pw, username):
		return "this password is too easy to guess"
	}
	return ""
}

func validAdminName(n string) bool {
	if len(n) < 2 || len(n) > 64 {
		return false
	}
	for _, ch := range n {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '-' || ch == '_' || ch == '@') {
			return false
		}
	}
	return true
}

func (c *platformConsole) setup(w http.ResponseWriter, r *http.Request) {
	if wait, blocked := c.setupBlocked(); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		jerr(w, 429, "too many failed setup attempts; try again later")
		return
	}
	var b struct{ SetupCode, Username, Email, Password string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if c.h.P.AdminCount() > 0 {
		jerr(w, 403, "already set up")
		return
	}
	given := strings.ToUpper(strings.TrimSpace(b.SetupCode))
	if c.setupCode == "" || subtle.ConstantTimeCompare([]byte(given), []byte(c.setupCode)) != 1 {
		c.setupFailed()
		jerr(w, 403, "invalid setup code: use the code printed in the server log")
		return
	}
	b.Username = strings.TrimSpace(b.Username)
	if !validAdminName(b.Username) {
		jerr(w, 400, "invalid username")
		return
	}
	email, err := canonicalEmail(b.Email)
	if err != nil {
		jerr(w, 400, "invalid email")
		return
	}
	if msg := c.checkPassword(b.Password, b.Username); msg != "" {
		jerr(w, 400, msg)
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(b.Password), hashCost)
	if err != nil {
		jerr(w, 400, "invalid password")
		return
	}
	a, err := c.h.P.CreateFirstAdmin(b.Username, email, string(h))
	if err != nil {
		jerr(w, 403, "already set up")
		return
	}
	c.setupCode = ""
	if err := c.startSession(w, a.ID, "enroll"); err != nil {
		jerr(w, 500, "session failed")
		return
	}
	c.h.P.Audit(a.ID, a.Username, "platform_setup", "admin "+a.Username, "ok", "first platform administrator created", c.clientIP(r))
	jout(w, 200, map[string]any{"stage": "enroll"})
}

// decodeLoose decodes a JSON body with snake_case or lowercase field names.
func decodeLoose(r *http.Request, v any) error {
	raw := map[string]json.RawMessage{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&raw); err != nil {
		return err
	}
	norm := map[string]json.RawMessage{}
	for k, val := range raw {
		norm[strings.ReplaceAll(strings.ToLower(k), "_", "")] = val
	}
	b, _ := json.Marshal(norm)
	return json.Unmarshal(b, v)
}

var dummyConsoleHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte(randHex(16)), hashCost)
	return h
})

func (c *platformConsole) login(w http.ResponseWriter, r *http.Request) {
	ip := c.clientIP(r)
	if !c.allow("login:"+ipBanKey(ip), 20, time.Minute) {
		w.Header().Set("Retry-After", "60")
		jerr(w, 429, "too many requests")
		return
	}
	var b struct{ Username, Password string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	a, err := c.h.P.AdminByName(b.Username)
	if err != nil {
		bcrypt.CompareHashAndPassword(dummyConsoleHash(), []byte(b.Password))
		c.h.P.Audit(0, "anonymous", "login_failed", "admin "+clip(b.Username, 64), "failed", "unknown username", ip)
		jerr(w, 401, "invalid username or password")
		return
	}
	if time.Now().Unix() < a.LockedUntil {
		c.h.P.Audit(a.ID, a.Username, "login_lockout", "admin "+a.Username, "denied", "", ip)
		jerr(w, 429, "too many failed sign-in attempts; try again later")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(b.Password)) != nil {
		c.h.P.NoteLoginFailure(a.ID, consoleLoginLimit, consoleLockDuration)
		c.h.P.Audit(a.ID, a.Username, "login_failed", "admin "+a.Username, "failed", "wrong password", ip)
		jerr(w, 401, "invalid username or password")
		return
	}
	c.h.P.NoteLoginSuccess(a.ID)
	stage := c.stageAfterPassword(a)
	if err := c.startSession(w, a.ID, stage); err != nil {
		jerr(w, 500, "session failed")
		return
	}
	detail := "stage=" + stage
	if stage == "full" {
		detail += " (authenticator not required by the platform)"
		c.h.P.Audit(a.ID, a.Username, "login_ok", "admin "+a.Username, "ok", detail, ip)
	} else {
		c.h.P.Audit(a.ID, a.Username, "login_password_ok", "admin "+a.Username, "ok", detail, ip)
	}
	jout(w, 200, map[string]any{"stage": stage, "must_change_password": a.MustChangePassword})
}

// stageAfterPassword is the session stage after a correct password: TOTP or
// enrolment while the platform requires an authenticator, otherwise full.
func (c *platformConsole) stageAfterPassword(a *platform.Admin) string {
	if !c.h.P.MFARequired() {
		return "full"
	}
	if !a.TOTPEnabled {
		return "enroll"
	}
	return "mfa"
}

// changePassword: POST /api/platform/password {current, password}. Required
// after an offline reset (temporary password); also the administrator's own
// password change. The other sessions end; this one continues in its stage.
func (c *platformConsole) changePassword(w http.ResponseWriter, r *http.Request) {
	cs := consoleFrom(r)
	var b struct{ Current, Password string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if !c.allow("password:"+strconv.FormatInt(cs.admin.ID, 10), 10, time.Minute) {
		jerr(w, 429, "too many attempts; try again later")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(cs.admin.PasswordHash), []byte(b.Current)) != nil {
		c.h.P.NoteLoginFailure(cs.admin.ID, consoleLoginLimit, consoleLockDuration)
		c.record(r, "password_change_failed", "admin "+cs.admin.Username, "failed", "wrong current password")
		jerr(w, 403, "the current password is wrong")
		return
	}
	if b.Password == b.Current {
		jerr(w, 400, "choose a password different from the current one")
		return
	}
	if msg := c.checkPassword(b.Password, cs.admin.Username); msg != "" {
		jerr(w, 400, msg)
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(b.Password), hashCost)
	if err != nil {
		jerr(w, 400, "invalid password")
		return
	}
	if err := c.h.P.SetPassword(cs.admin.ID, string(h)); err != nil {
		jerr(w, 500, "database error")
		return
	}
	detail := ""
	if cs.admin.MustChangePassword {
		detail = "temporary password replaced"
	}
	c.record(r, "password_changed", "admin "+cs.admin.Username, "ok", detail)
	stage := cs.sess.Stage
	if err := c.startSession(w, cs.admin.ID, stage); err != nil {
		jerr(w, 500, "session failed")
		return
	}
	jout(w, 200, map[string]any{"ok": true, "stage": stage})
}

// totpCheck verifies a code against an administrator's active TOTP secret
// and burns its time step (no replay).
func (c *platformConsole) totpCheck(a *platform.Admin, code string) bool {
	secret, err := decodeTOTPSecret(a.TOTPSecret)
	if err != nil || !a.TOTPEnabled {
		return false
	}
	counter, ok := totpMatch(secret, code, c.clock())
	return ok && c.h.P.UseTOTPCounter(a.ID, counter)
}

func (c *platformConsole) loginTOTP(w http.ResponseWriter, r *http.Request) {
	cs := consoleFrom(r)
	var b struct{ Code string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if !c.allow("totp:"+strconv.FormatInt(cs.admin.ID, 10), 10, time.Minute) || time.Now().Unix() < cs.admin.LockedUntil {
		jerr(w, 429, "too many attempts; try again later")
		return
	}
	if !c.totpCheck(cs.admin, b.Code) {
		c.h.P.NoteLoginFailure(cs.admin.ID, consoleLoginLimit, consoleLockDuration)
		c.record(r, "mfa_failed", "admin "+cs.admin.Username, "failed", "")
		jerr(w, 401, "invalid code")
		return
	}
	c.h.P.NoteLoginSuccess(cs.admin.ID)
	if err := c.h.P.PromoteSession(cs.hash); err != nil {
		jerr(w, 500, "session failed")
		return
	}
	c.record(r, "login_ok", "admin "+cs.admin.Username, "ok", "")
	jout(w, 200, map[string]any{"stage": "full"})
}

func (c *platformConsole) logout(w http.ResponseWriter, r *http.Request) {
	if cs := c.currentSession(r); cs != nil {
		c.h.P.DeleteSession(cs.hash)
		c.h.P.Audit(cs.admin.ID, cs.admin.Username, "logout", "admin "+cs.admin.Username, "ok", "", c.clientIP(r))
	}
	c.setCookie(w, "", -1)
	jout(w, 200, map[string]any{"ok": true})
}

func (c *platformConsole) me(w http.ResponseWriter, r *http.Request) {
	cs := consoleFrom(r)
	jout(w, 200, map[string]any{"admin": cs.admin, "stage": cs.sess.Stage, "mfa_required": c.h.P.MFARequired(),
		"must_change_password": cs.admin.MustChangePassword})
}

func (c *platformConsole) mfaBegin(w http.ResponseWriter, r *http.Request) {
	cs := consoleFrom(r)
	_, enc, err := newTOTPSecret()
	if err != nil || c.h.P.SetPendingTOTP(cs.admin.ID, enc) != nil {
		jerr(w, 500, "could not start enrolment")
		return
	}
	jout(w, 200, map[string]any{"secret": enc, "uri": totpURI("Sendora platform", cs.admin.Username, enc)})
}

func (c *platformConsole) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	cs := consoleFrom(r)
	var b struct{ Code string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if !c.allow("enroll:"+strconv.FormatInt(cs.admin.ID, 10), 10, time.Minute) {
		jerr(w, 429, "too many attempts; try again later")
		return
	}
	secret, err := decodeTOTPSecret(cs.admin.PendingTOTP)
	if err != nil || cs.admin.PendingTOTP == "" {
		jerr(w, 400, "start the enrolment first")
		return
	}
	counter, ok := totpMatch(secret, b.Code, c.clock())
	if !ok {
		jerr(w, 401, "invalid code")
		return
	}
	if c.h.P.EnableTOTP(cs.admin.ID, counter) != nil || c.h.P.PromoteSession(cs.hash) != nil {
		jerr(w, 500, "enrolment failed")
		return
	}
	c.record(r, "mfa_enrolled", "admin "+cs.admin.Username, "ok", "totp")
	jout(w, 200, map[string]any{"stage": "full"})
}

// stepUp requires a fresh confirmation in the request (destructive actions):
// a current authenticator code, or, for an administrator without an
// authenticator while the platform does not require one, the password.
func (c *platformConsole) stepUp(w http.ResponseWriter, r *http.Request, code string) bool {
	cs := consoleFrom(r)
	if !c.allow("stepup:"+strconv.FormatInt(cs.admin.ID, 10), 10, time.Minute) {
		jerr(w, 429, "too many attempts; try again later")
		return false
	}
	if !cs.admin.TOTPEnabled && !c.h.P.MFARequired() {
		if code == "" || bcrypt.CompareHashAndPassword([]byte(cs.admin.PasswordHash), []byte(code)) != nil {
			c.h.P.NoteLoginFailure(cs.admin.ID, consoleLoginLimit, consoleLockDuration)
			c.record(r, "stepup_failed", "admin "+cs.admin.Username, "failed", "password")
			jerr(w, 403, "your password is required to confirm this action")
			return false
		}
		return true
	}
	if !c.totpCheck(cs.admin, code) {
		c.record(r, "stepup_failed", "admin "+cs.admin.Username, "failed", "")
		jerr(w, 403, "a current authenticator code is required for this action")
		return false
	}
	c.h.P.TouchMFA(cs.hash)
	return true
}

// ---------- tenants ----------

type tenantView struct {
	*platform.Tenant
	URL     string `json:"url"`
	Open    bool   `json:"open"`
	Primary string `json:"primary_host"`
}

func (c *platformConsole) view(t *platform.Tenant) tenantView {
	route := platform.Route{ID: t.ID, Slug: t.Slug, Status: t.Status, PrimaryDomain: t.PrimaryDomain}
	v := tenantView{Tenant: t, URL: c.h.tenantURL(route), Primary: c.h.primaryHost(route)}
	c.h.mu.Lock()
	_, v.Open = c.h.open[t.ID]
	c.h.mu.Unlock()
	return v
}

func (c *platformConsole) listTenants(w http.ResponseWriter, r *http.Request) {
	ts, err := c.h.P.Tenants(r.URL.Query().Get("q"))
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	out := make([]tenantView, 0, len(ts))
	for _, t := range ts {
		out = append(out, c.view(t))
	}
	jout(w, 200, map[string]any{"tenants": out})
}

func (c *platformConsole) tenantParam(w http.ResponseWriter, r *http.Request) *platform.Tenant {
	t, err := c.h.P.Tenant(chi.URLParam(r, "id"))
	if err != nil || t.Status == platform.StatusImporting {
		jerr(w, 404, "not found")
		return nil
	}
	return t
}

func tenantTarget(t *platform.Tenant) string { return "tenant " + t.Slug + " (" + t.ID + ")" }

func (c *platformConsole) createTenant(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Slug, Name, AdminUsername, AdminEmail string
		MaxUsers, MaxStorageBytes             *int64
		StorageOffer                          string
		AllowOwnStorage                       *bool
	}
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	maxUsers := c.h.P.SettingInt("default_max_users", 0)
	maxStorage := c.h.P.SettingInt("default_max_storage_bytes", 0)
	if b.MaxUsers != nil {
		maxUsers = *b.MaxUsers
	}
	if b.MaxStorageBytes != nil {
		maxStorage = *b.MaxStorageBytes
	}
	if strings.TrimSpace(b.AdminUsername) == "" {
		b.AdminUsername = strings.SplitN(strings.TrimSpace(b.AdminEmail), "@", 2)[0]
	}
	cs := consoleFrom(r)
	allowOwn := b.AllowOwnStorage == nil || *b.AllowOwnStorage
	if b.StorageOffer == "" {
		b.StorageOffer = c.h.P.NewTenantOffer()
	}
	if err := c.h.P.CheckOffer(b.StorageOffer); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	t, link, emailed, err := c.h.CreateTenant(cs.admin.Username, b.Slug, b.Name, b.AdminUsername, b.AdminEmail, maxUsers, maxStorage, b.StorageOffer, allowOwn)
	if err != nil {
		c.record(r, "tenant_create_failed", "tenant "+clip(b.Slug, 64), "failed", clip(err.Error(), 200))
		jerr(w, 400, err.Error())
		return
	}
	offer := b.StorageOffer
	if offer == "" {
		offer = platform.OfferNone
	}
	detail := fmt.Sprintf("admin=%s max_users=%d max_storage_bytes=%d storage_offer=%s own_storage_allowed=%t welcome=", clip(b.AdminUsername, 64), maxUsers, maxStorage, offer, allowOwn)
	if emailed {
		detail += "emailed"
	} else {
		detail += "link shown once"
	}
	c.record(r, "tenant_created", tenantTarget(t), "ok", detail)
	t, _ = c.h.P.Tenant(t.ID)
	jout(w, 201, map[string]any{"tenant": c.view(t), "welcome_emailed": emailed, "setup_link": link})
}

func (c *platformConsole) getTenant(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	domains, _ := c.h.P.Domains(t.ID)
	type domainView struct {
		platform.Domain
		RecordName  string `json:"record_name,omitempty"`
		RecordValue string `json:"record_value,omitempty"`
	}
	dv := []domainView{}
	for _, d := range domains {
		v := domainView{Domain: d}
		if !d.Verified {
			v.RecordName, v.RecordValue = platform.VerifyRecordName(d.Domain), platform.VerifyRecordValue(d.VerifyToken)
		}
		v.VerifyToken = ""
		dv = append(dv, v)
	}
	sv, _ := c.storageView(t)
	jout(w, 200, map[string]any{"tenant": c.view(t), "subdomain": platform.SubdomainHost(t.Slug, c.h.baseHost), "domains": dv, "storage": sv})
}

func (c *platformConsole) renameTenant(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	var b struct{ Name string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if err := c.h.P.SetName(t.ID, b.Name); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	c.record(r, "tenant_renamed", tenantTarget(t), "ok", "name="+clip(b.Name, 200))
	jout(w, 200, map[string]any{"ok": true})
}

func (c *platformConsole) setStatus(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t := c.tenantParam(w, r)
		if t == nil {
			return
		}
		if err := c.h.SetTenantStatus(consoleFrom(r).admin.Username, t.ID, status); err != nil {
			jerr(w, 400, err.Error())
			return
		}
		action := "tenant_resumed"
		if status == platform.StatusSuspended {
			action = "tenant_suspended"
		}
		c.record(r, action, tenantTarget(t), "ok", "")
		jout(w, 200, map[string]any{"ok": true, "status": status})
	}
}

func (c *platformConsole) setQuotas(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	var b struct {
		MaxUsers        int64
		MaxStorageBytes *int64
		Code            string
	}
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	maxStorage := t.MaxStorageBytes
	if b.MaxStorageBytes != nil {
		maxStorage = *b.MaxStorageBytes
	}
	// The storage limit has one source of truth (max_storage_bytes) and is
	// changed with a fresh confirmation (also from the Storage card).
	if maxStorage != t.MaxStorageBytes && !c.stepUp(w, r, b.Code) {
		return
	}
	b.MaxStorageBytes = &maxStorage
	if err := c.h.SetTenantQuotas(consoleFrom(r).admin.Username, t.ID, b.MaxUsers, maxStorage); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	c.record(r, "tenant_quota_changed", tenantTarget(t), "ok", fmt.Sprintf("max_users %d->%d max_storage_bytes %d->%d", t.MaxUsers, b.MaxUsers, t.MaxStorageBytes, maxStorage))
	jout(w, 200, map[string]any{"ok": true})
}

func (c *platformConsole) deleteTenant(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	var b struct {
		Confirm, Code string
		// Force deletes the tenant even when objects in object storage could
		// not be removed (an unreachable own bucket); they are listed in the audit log.
		Force bool
	}
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if b.Confirm != t.Slug {
		jerr(w, 400, "type the tenant's subdomain to confirm")
		return
	}
	if !c.stepUp(w, r, b.Code) {
		return
	}
	res, err := c.h.DeleteTenant(t.ID, b.Force)
	if err != nil {
		c.record(r, "tenant_delete_failed", tenantTarget(t), "failed", clip(err.Error(), 300))
		jerr(w, 409, err.Error())
		return
	}
	detail := fmt.Sprintf("database, files and backups removed; %d object(s) removed from object storage", res.Removed)
	if len(res.Failed) > 0 {
		detail += "; NOT removed (forced): " + strings.Join(res.Failed, "; ")
	}
	c.record(r, "tenant_deleted", tenantTarget(t), "ok", clip(detail, 1000))
	jout(w, 200, map[string]any{"ok": true, "objects_removed": res.Removed, "objects_failed": res.Failed})
}

// ---------- domains ----------

func (c *platformConsole) tenantEvent(t *platform.Tenant, r *http.Request, action, detail string) {
	actor := consoleFrom(r).admin.Username
	c.h.withTenant(t.ID, func(s *Server) error { s.RecordPlatformEvent(actor, action, detail); return nil })
}

func (c *platformConsole) addDomain(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	var b struct{ Domain string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	// A custom domain is a host name; a pasted scheme, port or path is dropped.
	if h, _, err := SplitBaseDomain(strings.SplitN(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(b.Domain), "https://"), "http://"), "/", 2)[0]); err == nil {
		b.Domain = h
	}
	d, err := c.h.P.AddCustomDomain(t.ID, b.Domain, c.h.baseHost)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	c.record(r, "tenant_domain_added", tenantTarget(t), "ok", "domain="+d.Domain)
	c.tenantEvent(t, r, "tenant_domain_added", "domain="+d.Domain)
	jout(w, 201, map[string]any{"domain": d.Domain, "record_name": platform.VerifyRecordName(d.Domain), "record_value": platform.VerifyRecordValue(d.VerifyToken)})
}

func (c *platformConsole) verifyDomain(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	name := strings.ToLower(chi.URLParam(r, "domain"))
	domains, _ := c.h.P.Domains(t.ID)
	var d *platform.Domain
	for i := range domains {
		if domains[i].Domain == name {
			d = &domains[i]
		}
	}
	if d == nil {
		jerr(w, 404, "not found")
		return
	}
	if !d.Verified {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		recs, err := c.lookupTXT(ctx, platform.VerifyRecordName(d.Domain))
		want := platform.VerifyRecordValue(d.VerifyToken)
		found := false
		for _, v := range recs {
			if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(v)), []byte(want)) == 1 {
				found = true
			}
		}
		if err != nil || !found {
			c.record(r, "tenant_domain_verify_failed", tenantTarget(t), "failed", "domain="+d.Domain)
			jerr(w, 409, "the TXT record was not found (DNS changes can take a while)")
			return
		}
		if err := c.h.P.MarkDomainVerified(t.ID, d.Domain); err != nil {
			jerr(w, 500, "database error")
			return
		}
		c.record(r, "tenant_domain_verified", tenantTarget(t), "ok", "domain="+d.Domain)
		c.tenantEvent(t, r, "tenant_domain_verified", "domain="+d.Domain)
	}
	jout(w, 200, map[string]any{"ok": true, "verified": true})
}

func (c *platformConsole) removeDomain(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	name := strings.ToLower(chi.URLParam(r, "domain"))
	if err := c.h.P.RemoveCustomDomain(t.ID, name); err != nil {
		jerr(w, 404, "not found")
		return
	}
	c.record(r, "tenant_domain_removed", tenantTarget(t), "ok", "domain="+name)
	c.tenantEvent(t, r, "tenant_domain_removed", "domain="+name)
	c.h.reopen(t.ID)
	jout(w, 200, map[string]any{"ok": true})
}

func (c *platformConsole) setPrimaryDomain(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	var b struct{ Domain string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	d := strings.ToLower(strings.TrimSpace(b.Domain))
	if d == platform.SubdomainHost(t.Slug, c.h.baseHost) {
		d = ""
	}
	if err := c.h.P.SetPrimaryDomain(t.ID, d); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	c.record(r, "tenant_primary_domain_changed", tenantTarget(t), "ok", "domain="+b.Domain)
	c.tenantEvent(t, r, "tenant_primary_domain_changed", "domain="+b.Domain)
	// The tenant's links, cookies and passkeys follow its URL: reopen it.
	c.h.reopen(t.ID)
	jout(w, 200, map[string]any{"ok": true})
}

// ---------- storage ----------

// storageTestTimeout bounds a connection test from the console.
const storageTestTimeout = 30 * time.Second

// probeStorage opens cfg and writes, reads and deletes a probe object.
func (c *platformConsole) probeStorage(ctx context.Context, cfg storage.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, storageTestTimeout)
	defer cancel()
	b, err := c.h.openBackend(ctx, cfg)
	if err != nil {
		return err
	}
	return storage.Probe(ctx, b)
}

// storageForm reads the platform default storage form {settings} (storage_*).
type storageForm struct {
	Mode          string            `json:"mode"`
	Settings      map[string]string `json:"settings"`
	TenantManaged bool              `json:"tenant_managed"`
}

func readStorageForm(r *http.Request) (storageForm, error) {
	var raw struct {
		Mode          string         `json:"mode"`
		Settings      map[string]any `json:"settings"`
		TenantManaged bool           `json:"tenant_managed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return storageForm{}, err
	}
	f := storageForm{Mode: raw.Mode, TenantManaged: raw.TenantManaged, Settings: map[string]string{}}
	for k, v := range raw.Settings {
		switch x := v.(type) {
		case string:
			f.Settings[k] = x
		case bool:
			f.Settings[k] = strconv.FormatBool(x)
		default:
			return storageForm{}, fmt.Errorf("%s: invalid value", k)
		}
	}
	return f, nil
}

// storageView is what the console may know about a tenant's storage: the
// platform's decision (offer, own storage allowed), the kind of storage in
// use ("own:s3", "platform", "local", "none") and the bytes stored. Never the
// configuration of the tenant's own storage (bucket, endpoint, prefix,
// account, keys): that is the tenant's business.
func (c *platformConsole) storageView(t *platform.Tenant) (map[string]any, error) {
	sc, err := c.h.P.Storage(t.ID)
	if err != nil {
		return nil, err
	}
	kind := ""
	c.h.withTenant(t.ID, func(s *Server) error { kind = s.StorageKind(); return nil })
	def := c.h.P.PlatformStorage()
	return map[string]any{
		"offer":             sc.Offer,
		"tenant_managed":    sc.TenantManaged,
		"kind":              kind,
		"usage_bytes":       t.StatStorage,
		"max_storage_bytes": t.MaxStorageBytes,
		"limit_applies":     !strings.HasPrefix(kind, "own:"),
		"platform_backend":  def.Backend,
	}, nil
}

func (c *platformConsole) getStorage(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	v, err := c.storageView(t)
	if err != nil {
		jerr(w, 404, "not found")
		return
	}
	jout(w, 200, v)
}

// putStorage: PUT /api/platform/tenants/{id}/storage {offer, tenant_managed}.
// The platform offers its bucket or the server's disk, or nothing, and allows
// or forbids storage of the tenant's own; the tenant is reopened so its server
// applies the decision to new files.
func (c *platformConsole) putStorage(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	var b struct {
		Offer         string `json:"offer"`
		TenantManaged bool   `json:"tenant_managed"`
		// MaxStorageBytes is the storage limit for platform-provided storage
		// (the max_storage_bytes quota; nil = unchanged).
		MaxStorageBytes *int64 `json:"max_storage_bytes"`
		Code            string `json:"code"`
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	prev, err := c.h.P.Storage(t.ID)
	if err != nil {
		jerr(w, 404, "not found")
		return
	}
	limitChange := b.MaxStorageBytes != nil && *b.MaxStorageBytes != t.MaxStorageBytes
	if limitChange && *b.MaxStorageBytes < 0 {
		jerr(w, 400, "the storage limit cannot be negative")
		return
	}
	// One save, one fresh confirmation for the storage limit.
	if limitChange && !c.stepUp(w, r, b.Code) {
		return
	}
	if b.Offer != prev.Offer {
		if err := c.h.P.CheckOffer(b.Offer); err != nil {
			jerr(w, 400, err.Error())
			return
		}
	}
	if err := c.h.P.SetStorage(t.ID, b.Offer, b.TenantManaged); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	detail := fmt.Sprintf("offer %s -> %s; own storage allowed %t -> %t", prev.Offer, b.Offer, prev.TenantManaged, b.TenantManaged)
	c.record(r, "tenant_storage_changed", tenantTarget(t), "ok", detail)
	c.tenantEvent(t, r, "tenant_storage_changed", detail)
	if limitChange {
		if err := c.h.SetTenantQuotas(consoleFrom(r).admin.Username, t.ID, t.MaxUsers, *b.MaxStorageBytes); err != nil {
			jerr(w, 400, err.Error())
			return
		}
		c.record(r, "tenant_quota_changed", tenantTarget(t), "ok", fmt.Sprintf("max_storage_bytes %d->%d (storage limit)", t.MaxStorageBytes, *b.MaxStorageBytes))
	}
	c.h.reopen(t.ID)
	t, _ = c.h.P.Tenant(t.ID)
	v, _ := c.storageView(t)
	jout(w, 200, v)
}

func (c *platformConsole) answerProbe(w http.ResponseWriter, r *http.Request, cfg storage.Config, action, target string) {
	if cfg.Backend == storage.KindLocal {
		jout(w, 200, map[string]any{"ok": true, "description": cfg.Describe(), "ms": 0})
		return
	}
	start := time.Now()
	err := c.probeStorage(r.Context(), cfg)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		c.record(r, action, target, "failed", clip(cfg.Describe()+": "+err.Error(), 300))
		jout(w, 200, map[string]any{"ok": false, "error": clip(err.Error(), 400), "description": cfg.Describe(), "ms": ms})
		return
	}
	c.record(r, action, target, "ok", cfg.Describe())
	jout(w, 200, map[string]any{"ok": true, "description": cfg.Describe(), "ms": ms})
}

// managedStorage lists the platform storage settings set by the environment,
// under their storage_* names.
func (c *platformConsole) managedStorage() []string {
	out := []string{}
	for k := range c.h.cfg.Managed {
		if platform.IsStorageSetting(k) {
			out = append(out, strings.TrimPrefix(k, "platform_"))
		}
	}
	return out
}

// getPlatformStorage: GET /api/platform/storage, the platform default backend.
func (c *platformConsole) getPlatformStorage(w http.ResponseWriter, r *http.Request) {
	all := c.h.P.StorageSettings()
	settings, set := map[string]string{}, map[string]bool{}
	for k, v := range all {
		if storage.SettingSecret(k) {
			set[k], settings[k] = v != "", ""
			continue
		}
		settings[k] = v
	}
	def := c.h.P.PlatformStorage()
	jout(w, 200, map[string]any{"settings": settings, "set": set, "managed": c.managedStorage(), "description": def.Describe(),
		"tenant_prefix": platform.TenantPrefix("<tenant id>")})
}

func (c *platformConsole) platformStorageNext(f storageForm) (map[string]string, storage.Config, error) {
	in := map[string]string{}
	for k, v := range f.Settings {
		if c.h.cfg.Managed["platform_"+k] {
			continue
		}
		in[k] = v
	}
	next, err := platform.MergeStorageSettings(c.h.P.StorageSettings(), in)
	if err != nil {
		return nil, storage.Config{}, err
	}
	cfg := storage.FromSettings(func(k string) string { return next[k] })
	if err := cfg.Validate(); err != nil {
		return nil, storage.Config{}, err
	}
	return next, cfg, nil
}

// putPlatformStorage: PUT /api/platform/storage {settings}. A changed remote
// configuration is tested first; open tenants are reopened so new files go to
// the new location (earlier files stay readable where they are).
func (c *platformConsole) putPlatformStorage(w http.ResponseWriter, r *http.Request) {
	f, err := readStorageForm(r)
	if err != nil {
		jerr(w, 400, "invalid request")
		return
	}
	next, cfg, err := c.platformStorageNext(f)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	if cfg.Backend == storage.KindLocal && c.h.P.NewTenantOffer() == platform.OfferPlatform {
		jerr(w, 400, "new tenants are offered the platform bucket: change \"Storage for new tenants\" first")
		return
	}
	cur := c.h.P.PlatformStorage()
	curJS, _ := cur.Marshal()
	nextJS, _ := cfg.Marshal()
	if cfg.Backend != storage.KindLocal && curJS != nextJS {
		if err := c.probeStorage(r.Context(), cfg); err != nil {
			c.record(r, "platform_storage_test_failed", "storage", "failed", clip(cfg.Describe()+": "+err.Error(), 300))
			jerr(w, 400, "storage connection test failed; the settings were not saved: "+clip(err.Error(), 300))
			return
		}
	}
	changed, err := c.h.P.PutStorageSettings(next, c.h.cfg.Managed)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if len(changed) > 0 {
		c.record(r, "platform_storage_changed", "storage", "ok", clip(cur.Describe()+" -> "+cfg.Describe()+"; keys="+strings.Join(changed, ","), 400))
		c.h.reopenAll()
	}
	jout(w, 200, map[string]any{"ok": true, "description": cfg.Describe()})
}

// testPlatformStorage: POST /api/platform/storage/test with an unsaved form.
func (c *platformConsole) testPlatformStorage(w http.ResponseWriter, r *http.Request) {
	f, err := readStorageForm(r)
	if err != nil {
		jerr(w, 400, "invalid request")
		return
	}
	_, cfg, err := c.platformStorageNext(f)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	c.answerProbe(w, r, cfg, "platform_storage_tested", "storage")
}

// ---------- network targets (SSRF guard) ----------

// putNetwork: PUT /api/platform/tenants/{id}/network {allow_private_targets,
// code}. Allowing a tenant's administrators to reach private, loopback and
// link-local addresses needs a step-up and is audited on both sides.
func (c *platformConsole) putNetwork(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	var b struct {
		AllowPrivateTargets bool
		Code                string
	}
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if b.AllowPrivateTargets == t.AllowPrivateTargets {
		jout(w, 200, map[string]any{"ok": true})
		return
	}
	if !c.stepUp(w, r, b.Code) {
		return
	}
	if err := c.h.P.SetAllowPrivateTargets(t.ID, b.AllowPrivateTargets); err != nil {
		jerr(w, 500, "database error")
		return
	}
	detail := fmt.Sprintf("allow_private_targets %t -> %t", t.AllowPrivateTargets, b.AllowPrivateTargets)
	c.record(r, "tenant_network_policy_changed", tenantTarget(t), "ok", detail)
	c.tenantEvent(t, r, "tenant_network_policy_changed", detail)
	c.h.reopen(t.ID)
	jout(w, 200, map[string]any{"ok": true})
}

// ---------- base domain ----------

// putBaseDomain: PUT /api/platform/base-domain {host, port, code}: stores the
// base domain in DATA_DIR/sendora-mode.json (SENDORA_BASE_DOMAIN wins when
// set); it applies after a restart. Re-authentication and audit.
func (c *platformConsole) putBaseDomain(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("SENDORA_BASE_DOMAIN") != "" {
		jerr(w, 409, "the base domain is set by SENDORA_BASE_DOMAIN")
		return
	}
	var b struct{ Host, Port, Code string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	combined := strings.ToLower(strings.TrimSpace(b.Host))
	if p := strings.TrimSpace(b.Port); p != "" {
		combined += ":" + p
	}
	host, port, err := SplitBaseDomain(combined)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	next := JoinBaseDomain(host, port)
	cur := c.h.baseHost + c.h.basePort
	if next == cur {
		jout(w, 200, map[string]any{"ok": true, "base_domain": next})
		return
	}
	if !c.stepUp(w, r, b.Code) {
		return
	}
	pm, _ := ReadPersistedMode(c.h.P.DataDir)
	if pm == nil {
		pm = &PersistedMode{Mode: "multi-tenant"}
	}
	pm.BaseDomain = next
	if err := writeFile0600(filepath.Join(c.h.P.DataDir, ModeFile), pm); err != nil {
		jerr(w, 500, "could not store the base domain")
		return
	}
	c.record(r, "platform_base_domain_changed", "settings", "ok", cur+" -> "+next+" (applies after a restart)")
	jout(w, 200, map[string]any{"ok": true, "base_domain": next, "restart_needed": true})
}

// ---------- restart ----------

// restart: POST /api/platform/restart {code}: an orderly stop of every tenant
// and the console, then the process restarts itself (RestartMode); needs a
// fresh confirmation and is audited.
func (c *platformConsole) restart(w http.ResponseWriter, r *http.Request) {
	var b struct{ Code string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if c.h.restartFn == nil {
		jerr(w, 409, "restarting is not available here; restart the server")
		return
	}
	if !c.stepUp(w, r, b.Code) {
		return
	}
	c.record(r, "restart_requested", "platform", "ok", "mode="+RestartMode())
	jout(w, 202, map[string]any{"ok": true, "mode": RestartMode()})
	go func() {
		time.Sleep(500 * time.Millisecond)
		c.h.restartFn()
	}()
}

// ---------- settings ----------

func (c *platformConsole) getSettings(w http.ResponseWriter, r *http.Request) {
	managed := []string{}
	for k := range c.h.cfg.Managed {
		managed = append(managed, k)
	}
	jout(w, 200, map[string]any{"settings": c.h.P.Settings(), "managed": managed, "base_domain": c.h.baseHost + c.h.basePort,
		"restart_available": c.h.restartFn != nil, "restart_mode": RestartMode(),
		"base_host": c.h.baseHost, "base_port": strings.TrimPrefix(c.h.basePort, ":"), "base_domain_managed": os.Getenv("SENDORA_BASE_DOMAIN") != "",
		"max_open_tenants_now": len(c.h.OpenTenants())})
}

func (c *platformConsole) putSettings(w http.ResponseWriter, r *http.Request) {
	in := map[string]string{}
	raw := map[string]any{}
	if json.NewDecoder(r.Body).Decode(&raw) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	// "code": the step-up for platform_mfa_required (not a setting).
	code, _ := raw["code"].(string)
	delete(raw, "code")
	for k, v := range raw {
		switch x := v.(type) {
		case string:
			in[k] = x
		case float64:
			if x != math.Trunc(x) || math.Abs(x) > 1<<53 {
				jerr(w, 400, k+": invalid value")
				return
			}
			in[k] = strconv.FormatInt(int64(x), 10)
		case bool:
			in[k] = strconv.FormatBool(x)
		default:
			jerr(w, 400, k+": invalid value")
			return
		}
	}
	// Switching the authenticator requirement is the platform owner's
	// decision: it needs a fresh confirmation and has its own audit record.
	oldMFA := c.h.P.MFARequired()
	mfaChange := false
	if v, ok := in["platform_mfa_required"]; ok {
		norm, err := platform.NormalizeSetting("platform_mfa_required", v)
		if err != nil {
			jerr(w, 400, "platform_mfa_required: "+err.Error())
			return
		}
		in["platform_mfa_required"] = norm
		mfaChange = (norm == "true") != oldMFA
	}
	// The storage offer for new tenants: re-authentication, and the platform
	// bucket only while a platform default backend exists.
	oldOffer := c.h.P.NewTenantOffer()
	offerChange := false
	if v, ok := in["new_tenant_storage_offer"]; ok {
		norm, err := platform.NormalizeSetting("new_tenant_storage_offer", v)
		if err != nil {
			jerr(w, 400, "new_tenant_storage_offer: "+err.Error())
			return
		}
		if err := c.h.P.CheckOffer(norm); err != nil {
			jerr(w, 400, err.Error())
			return
		}
		in["new_tenant_storage_offer"] = norm
		offerChange = norm != oldOffer
	}
	if ((mfaChange && !c.h.cfg.Managed["platform_mfa_required"]) || (offerChange && !c.h.cfg.Managed["new_tenant_storage_offer"])) && !c.stepUp(w, r, code) {
		return
	}
	changed, err := c.h.P.PutSettings(in, c.h.cfg.Managed)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	c.record(r, "platform_settings_changed", "settings", "ok", "keys="+strings.Join(changed, ","))
	if offerChange {
		c.record(r, "platform_new_tenant_storage_changed", "settings", "ok", fmt.Sprintf("new_tenant_storage_offer %s -> %s", oldOffer, c.h.P.NewTenantOffer()))
	}
	if mfaChange {
		newMFA := c.h.P.MFARequired()
		detail := fmt.Sprintf("platform_mfa_required %t -> %t", oldMFA, newMFA)
		if !newMFA {
			detail += "; platform administrators can sign in with a password only"
		} else {
			// Sessions that were opened without a second factor end.
			c.h.P.EndSessionsWithoutMFA()
			detail += "; sessions of administrators without an authenticator were ended"
		}
		c.record(r, "platform_mfa_requirement_changed", "settings", "ok", detail)
	}
	jout(w, 200, map[string]any{"ok": true})
}

// ---------- administrators ----------

func (c *platformConsole) listAdmins(w http.ResponseWriter, r *http.Request) {
	as, err := c.h.P.Admins()
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	jout(w, 200, map[string]any{"admins": as})
}

func (c *platformConsole) createAdmin(w http.ResponseWriter, r *http.Request) {
	var b struct{ Username, Email, Password, Code string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if !c.stepUp(w, r, b.Code) {
		return
	}
	b.Username = strings.TrimSpace(b.Username)
	if !validAdminName(b.Username) {
		jerr(w, 400, "invalid username")
		return
	}
	email, err := canonicalEmail(b.Email)
	if err != nil {
		jerr(w, 400, "invalid email")
		return
	}
	if msg := c.checkPassword(b.Password, b.Username); msg != "" {
		jerr(w, 400, msg)
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(b.Password), hashCost)
	a, err := c.h.P.CreateAdmin(b.Username, email, string(h))
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	c.record(r, "platform_admin_created", "admin "+a.Username, "ok", "")
	jout(w, 201, a)
}

func (c *platformConsole) adminParam(w http.ResponseWriter, r *http.Request) *platform.Admin {
	id, _ := strconv.ParseInt(chi.URLParam(r, "aid"), 10, 64)
	a, err := c.h.P.AdminByID(id)
	if err != nil {
		jerr(w, 404, "not found")
		return nil
	}
	return a
}

func (c *platformConsole) deleteAdmin(w http.ResponseWriter, r *http.Request) {
	a := c.adminParam(w, r)
	if a == nil {
		return
	}
	var b struct{ Code string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if !c.stepUp(w, r, b.Code) {
		return
	}
	if err := c.h.P.DeleteAdmin(a.ID); err != nil {
		jerr(w, 409, err.Error())
		return
	}
	c.record(r, "platform_admin_deleted", "admin "+a.Username, "ok", "")
	jout(w, 200, map[string]any{"ok": true})
}

func (c *platformConsole) resetAdminMFA(w http.ResponseWriter, r *http.Request) {
	a := c.adminParam(w, r)
	if a == nil {
		return
	}
	var b struct{ Code string }
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if a.ID == consoleFrom(r).admin.ID {
		jerr(w, 400, "another administrator must reset your authenticator")
		return
	}
	if !c.stepUp(w, r, b.Code) {
		return
	}
	if err := c.h.P.ResetTOTP(a.ID); err != nil {
		jerr(w, 500, "database error")
		return
	}
	c.record(r, "platform_admin_mfa_reset", "admin "+a.Username, "ok", "")
	jout(w, 200, map[string]any{"ok": true})
}
