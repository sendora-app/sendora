// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const msgAdminAuditorExclusive = "an account cannot be both administrator and auditor"

type User struct {
	ID                   int64  `json:"id"`
	Username             string `json:"username"`
	Name                 string `json:"name"`
	Email                string `json:"email"`
	Admin                bool   `json:"admin"`
	MustChangePassword   bool   `json:"must_change_password"`
	IsGuest              bool   `json:"is_guest"`
	Auditor              bool   `json:"auditor"`
	EmailVerified        bool   `json:"email_verified"`
	CreatedAt            string `json:"created_at"`
	Language             string `json:"language"`
	UILanguage           string `json:"ui_language"`
	QuotaBytes           int64  `json:"quota_bytes"`
	QuotaInheritsDefault bool   `json:"quota_inherits_default"`
	MFAPolicy            string `json:"mfa_policy"`
	MFAEnabled           bool   `json:"mfa_enabled"`
	MFARequired          bool   `json:"mfa_required"`
	MFAEnrollRequired    bool   `json:"mfa_enroll_required"`
	Disabled             bool   `json:"disabled"`
	DisabledReason       string `json:"disabled_reason,omitempty"`
	// PasswordChangedAt is when the local password was last set (RFC 3339, empty
	// when unknown or without a local password); see password_rotation.go.
	PasswordChangedAt      string `json:"password_changed_at,omitempty"`
	PasswordRotationExempt bool   `json:"password_rotation_exempt"`
	passwordChangedAt      sql.NullTime
	sessionID              string // session (refresh-token family) of the request's access token
	authMethod             string // how that session was signed in (see sessions.go)
	mfaEpoch               int64  `json:"-"`
	loginFailures          int64  `json:"-"`
	loginLockedUntil       int64  `json:"-"`
	passwordHash           string
}

// userFromRecord turns a repository record (or its lookup error) into a User,
// validating the quota and language fields.
func userFromRecord(rec ports.UserRecord, err error) (*User, error) {
	if err != nil {
		return nil, err
	}
	u := &User{ID: rec.ID, Username: rec.Username, Name: rec.Name, Email: rec.Email, Admin: rec.Admin, MustChangePassword: rec.MustChangePassword,
		IsGuest: rec.IsGuest, Auditor: rec.Auditor, EmailVerified: rec.EmailVerified, CreatedAt: rec.CreatedAt, passwordHash: rec.PasswordHash,
		Language: rec.Language, UILanguage: rec.UILanguage, loginFailures: rec.LoginFailures, loginLockedUntil: rec.LoginLockedUntil,
		MFAPolicy: rec.MFAPolicy, mfaEpoch: rec.MFAEpoch, Disabled: rec.Disabled, DisabledReason: rec.DisabledReason,
		PasswordRotationExempt: rec.PasswordRotationExempt}
	if rec.PasswordChangedAt != nil {
		u.passwordChangedAt = sql.NullTime{Time: *rec.PasswordChangedAt, Valid: true}
	}
	if u.passwordChangedAt.Valid && u.passwordHash != "" {
		u.PasswordChangedAt = u.passwordChangedAt.Time.UTC().Format(time.RFC3339)
	}
	u.QuotaBytes, u.QuotaInheritsDefault, err = store.ResolveQuota(optString(rec.QuotaBytes), optString(rec.QuotaInheritsDefault), optString(rec.DefaultQuota))
	if err != nil {
		return nil, err
	}
	if !store.ValidMailCode(u.Language) {
		u.Language = "en"
	}
	if !store.ValidUICodeSyntax(u.UILanguage) {
		u.UILanguage = "en"
	}
	return u, err
}

// optString is the nullable-string form store.ResolveQuota takes.
func optString(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

// credGuard is the compare-and-set condition for writes that must not apply
// after u's identity or credentials changed.
func credGuard(u *User) ports.CredentialGuard {
	return ports.CredentialGuard{PasswordHash: u.passwordHash, Email: u.Email, MustChangePassword: u.MustChangePassword}
}

// nullTimeOf and nullStringOf turn repository pointers (nil = NULL) back into
// the nullable values the session code works with.
func nullTimeOf(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func nullStringOf(p *string) sql.NullString { return optString(p) }

// revokeAllOf adapts SessionRepository.RevokeAllForUser on r to the plain
// per-account delete steps of a transaction.
func revokeAllOf(r ports.Repositories) func(context.Context, int64) error {
	return func(ctx context.Context, uid int64) error {
		_, err := r.Sessions().RevokeAllForUser(ctx, uid)
		return err
	}
}

func (s *Server) userByID(id int64) (*User, error) {
	return userFromRecord(s.St.Repos().Users().ByID(context.Background(), id))
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (s *Server) accessToken(u *User) string { return s.accessTokenAt(u, time.Now()) }

// accessTokenAt records when the session was signed in (auth_time), so actions
// that need a recent sign-in can check it; refresh carries the original time.
func (s *Server) accessTokenAt(u *User, authTime time.Time) string {
	claims := jwt.MapClaims{
		"sub":        strconv.FormatInt(u.ID, 10),
		"purpose":    "access",
		"jti":        randHex(16),
		"credential": s.credentialVersion(u),
		"auth_time":  authTime.Unix(),
		"exp":        time.Now().Add(15 * time.Minute).Unix(),
	}
	if u.sessionID != "" {
		claims["sid"], claims["amr"] = u.sessionID, u.authMethod // revoked with its session (sessions.go)
	}
	// Required but not yet enrolled: the token only reaches the enrolment routes.
	// It is decided when a token is issued (login/refresh), so a stricter policy
	// takes effect at the next login or refresh, not in the middle of a session.
	if s.mfaEnrollRequired(u) {
		claims["mfa_enroll"] = true
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	str, _ := t.SignedString(s.key(keyAccess))
	return str
}

// sessionMaxAge is the absolute lifetime of a session: refreshing never extends
// it beyond this time after the original sign-in.
const sessionMaxAge = 30 * 24 * time.Hour

// requestAuthTime returns the sign-in time recorded in the request's (already
// validated) access token, or the zero time.
func (s *Server) requestAuthTime(r *http.Request) time.Time {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return s.key(keyAccess), nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired()); err != nil {
		return time.Time{}
	}
	if v, ok := claims["auth_time"].(float64); ok && v > 0 {
		return time.Unix(int64(v), 0)
	}
	return time.Time{}
}

// issueSession starts a new session after a sign-in (password, second factor,
// provider, setup, registration or invite) and records the sign-in time.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, u *User) bool {
	if u.authMethod == "" && !u.IsGuest {
		u.authMethod = authMethodPassword // a fresh sign-in never inherits a stale token's method
	}
	// A password past its maximum age must be changed first (password_rotation.go).
	s.flagExpiredPassword(u)
	ok := s.issueSessionSince(w, r, u, time.Now())
	if ok && !u.IsGuest {
		s.recordLastLogin(u.ID)
	}
	return ok
}

// sessionStartOf is the sign-in time of the current request's session, used when
// a profile or security change re-issues the session: it must not restart the
// 30-day limit or the recent-sign-in window.
func (s *Server) sessionStartOf(r *http.Request) time.Time {
	if t := s.requestAuthTime(r); !t.IsZero() && time.Since(t) < sessionMaxAge {
		return t
	}
	return time.Now()
}

func (s *Server) issueSessionSince(w http.ResponseWriter, r *http.Request, u *User, start time.Time) bool {
	rt := randHex(32)
	now := time.Now()
	exp := start.Add(sessionMaxAge)
	sid, method := randHex(16), s.sessionMethodFor(r, u)
	ua, ip := s.sessionClientInfo(r)
	n, err := s.St.Repos().Sessions().StartGuarded(context.Background(), ports.NewRefreshToken{Hash: hashToken(rt), UserID: u.ID, ExpiresAt: exp, IssuedAt: now, Started: start, SessionID: sid, UserAgent: ua, IP: ip, Method: method}, credGuard(u))
	if err != nil {
		return false
	}
	if n != 1 {
		return false
	}
	u.sessionID, u.authMethod = sid, method
	http.SetCookie(w, &http.Cookie{Name: "refresh", Value: rt, Path: "/api/auth", Expires: exp, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: s.secureCookies(r)})
	return true
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(h, "Bearer ")
		if tok == "" || tok == h {
			s.unauthenticated(w, r)
			return
		}
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tok, claims, func(t *jwt.Token) (any, error) { return s.key(keyAccess), nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
		if err != nil {
			s.unauthenticated(w, r)
			return
		}
		if revoked, err := s.St.Repos().Sessions().CountRevokedAccess(context.Background(), hashToken(tok), time.Now()); err != nil || revoked != 0 {
			s.unauthenticated(w, r)
			return
		}
		id, _ := strconv.ParseInt(fmt.Sprint(claims["sub"]), 10, 64)
		u, err := s.userByID(id)
		if err != nil || claims["purpose"] != "access" || claims["credential"] != s.credentialVersion(u) {
			s.unauthenticated(w, r)
			return
		}
		// From here on the caller is a verified, existing user: a refusal below is
		// recorded as access_denied with this actor (unverified tokens are not).
		s.auditSetActor(r, u)
		if !s.sessionStillValid(w, u, claims) {
			return
		}
		if u.IsGuest {
			if valid, err := s.St.Repos().ReverseInvites().CountOpenForGuest(context.Background(), u.ID, time.Now()); err != nil || valid != 1 {
				jerr(w, 403, "invite no longer valid")
				return
			}
			if !(r.Method == http.MethodGet && r.URL.Path == "/api/users/me") && r.URL.Path != "/api/uploads" && !strings.HasPrefix(r.URL.Path, "/api/uploads/") {
				jerr(w, 403, "guest session is upload-only")
				return
			}
		}
		if u.Auditor && !auditorAllowed(r) {
			jerr(w, 403, "auditor accounts are read-only")
			return
		}
		if s.expiredPasswordBlocked(w, u) {
			return
		}
		if u.MustChangePassword && !(r.URL.Path == "/api/users/me" && (r.Method == http.MethodGet || r.Method == http.MethodPut)) {
			jerr(w, 403, "password change required")
			return
		}
		if enroll, _ := claims["mfa_enroll"].(bool); enroll && !mfaEnrollAllowed(r) {
			jerr(w, 403, "mfa enrollment required")
			return
		}
		if s.termsBlocked(w, r, u) {
			return
		}
		next.ServeHTTP(w, withUser(r, u))
	})
}

func (s *Server) admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := s.ctxUser(r); u == nil || !u.Admin {
			jerr(w, 403, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) sessionResponse(w http.ResponseWriter, r *http.Request, u *User) {
	if u == nil {
		jerr(w, 500, "user policy unavailable")
		return
	}
	if !s.issueSession(w, r, u) {
		jerr(w, 401, "session changed; log in again")
		return
	}
	s.noteSignIn(r, u)
	s.fillMFA(u)
	jout(w, 200, map[string]any{"access_token": s.accessToken(u), "user": u})
}

// ---------- setup / login ----------

type credentials struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Language   string `json:"language"`
	UILanguage string `json:"ui_language"`
	SetupCode  string `json:"setup_code"`
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	// All addresses share this limit: many sources cannot add up to a code search.
	if wait, blocked := s.setupThrottle.blocked("setup"); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		jerr(w, 429, "too many failed setup attempts; try again later")
		return
	}
	n, _ := s.St.Repos().Users().Count(context.Background())
	if n > 0 {
		jerr(w, 403, "already set up")
		return
	}
	var c credentials
	if decode(r, &c) != nil || c.Username == "" {
		jerr(w, 400, "username and password required")
		return
	}
	if !validUsername(c.Username) {
		jerr(w, 400, msgInvalidUsername)
		return
	}
	given := strings.ToUpper(strings.TrimSpace(c.SetupCode))
	if s.setupCode == "" || subtle.ConstantTimeCompare([]byte(given), []byte(s.setupCode)) != 1 {
		s.setupThrottle.fail("setup", setupFailLimit, setupFailWindow, setupFailBlock)
		markAuthFailure(w)
		jerr(w, 403, "invalid setup code: use the code printed in the server log")
		return
	}
	if !s.requireAccountPassword(w, r, c.Password, c.Username, c.Email) {
		return
	}
	email, err := canonicalEmail(c.Email)
	if err != nil {
		jerr(w, 400, "invalid email")
		return
	}
	c.Email = email
	if c.Language == "" {
		c.Language = "en"
	}
	if !s.St.ValidMailLanguage(c.Language) {
		jerr(w, 400, "unsupported language")
		return
	}
	if c.UILanguage == "" {
		c.UILanguage = "en"
	}
	if !s.St.ValidUILanguage(c.UILanguage) {
		jerr(w, 400, "unsupported UI language")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(c.Password), hashCost)
	if err != nil {
		jerr(w, 400, "invalid password (8-72 bytes required)")
		return
	}
	id, created, err := s.St.Repos().Users().CreateFirstAdmin(context.Background(), ports.NewUser{Username: c.Username, Name: c.Name, Email: c.Email, PasswordHash: string(hash), Language: c.Language, UILanguage: c.UILanguage, PasswordChangedAt: time.Now().UTC()})
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	if !created {
		jerr(w, 403, "already set up")
		return
	}
	s.noteCreatedBy(id, "setup")
	u, _ := s.userByID(id)
	s.sessionResponse(w, r, u)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalLogin(w) {
		return
	}
	var c credentials
	if decode(r, &c) != nil {
		jerr(w, 400, "bad request")
		return
	}
	u, err := userFromRecord(s.St.Repos().Users().FindLocalByUsername(context.Background(), c.Username))
	if err != nil {
		email, emailErr := canonicalEmail(c.Username)
		if emailErr == nil && email != "" {
			u, err = userFromRecord(s.St.Repos().Users().FindLocalByUniqueEmail(context.Background(), email))
		}
	}
	if err != nil || u.passwordHash == "" {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(c.Password)) // equal timing
		// Never record the typed username: it may be a mistyped password.
		if err == nil {
			s.logEvent(u.ID, u.Username, "login_failed", "", "")
		} else {
			s.logEvent(0, "unknown", "login_failed", "", "")
		}
		rejectLogin(w)
		return
	}
	unlock := onceUnlock(s.stripe(&s.loginLocks, strconv.FormatInt(u.ID, 10)))
	defer unlock()
	// Reload after acquiring the account lock; aliases and peers share one counter.
	u, err = s.userByID(u.ID)
	if err != nil || u.IsGuest || u.passwordHash == "" || u.loginLockedUntil > time.Now().Unix() {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(c.Password)) // equal timing
		if err == nil && !u.IsGuest {
			s.logEvent(u.ID, u.Username, "login_failed", "", "account locked")
		}
		unlock()
		rejectLogin(w)
		return
	}
	// QueryRow has released its connection before the expensive password comparison.
	matched := bcrypt.CompareHashAndPassword([]byte(u.passwordHash), []byte(c.Password)) == nil
	now := time.Now().Unix()
	failures, lockedUntil := int64(0), int64(0)
	// A correct password only completes the first step when a second factor is
	// due: the failure counter is then kept (and only reset after MFA succeeds).
	needMFA := matched && u.EmailVerified && s.mfaGate(u)
	if needMFA {
		failures, lockedUntil = u.loginFailures, u.loginLockedUntil
		if lockedUntil != 0 && lockedUntil <= now {
			failures, lockedUntil = 0, 0
		}
	}
	if !matched {
		failures = u.loginFailures + 1
		if u.loginLockedUntil != 0 && u.loginLockedUntil <= now {
			failures = 1
		}
		if failures >= 5 {
			lockedUntil = now + int64((15*time.Minute)/time.Second)
		}
	}
	// A concurrent identity/credential mutation must not inherit an old attempt.
	n, err := s.St.Repos().Users().RecordLoginAttempt(context.Background(), u.ID, failures, lockedUntil, credGuard(u))
	if err != nil {
		unlock()
		rejectLogin(w)
		return
	}
	if n != 1 || !matched {
		if !matched {
			s.logEvent(u.ID, u.Username, "login_failed", "", "")
			if lockedUntil > 0 {
				s.logEvent(u.ID, u.Username, "login_lockout", "", "locked after repeated failures")
			}
		}
		unlock()
		rejectLogin(w)
		return
	}
	if s.refuseDisabledSignIn(w, u, "") {
		return
	}
	s.rehashPassword(u, c.Password) // upgrade an older, cheaper hash before the credential version is used
	if !u.EmailVerified {
		jout(w, 403, map[string]any{"error": "email not verified", "needs_verification": true})
		return
	}
	if needMFA {
		s.mfaChallenge(w, u)
		return
	}
	s.logEvent(u.ID, u.Username, "login_ok", "", "")
	s.sessionResponse(w, r, u)
}

// refreshReuseGrace: a rotated refresh token presented again within this time is
// treated as a race (two tabs refreshing at once, a response lost on the way)
// and only refused; later reuse means the token was copied.
const refreshReuseGrace = 60 * time.Second

func (s *Server) clearRefreshCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "refresh", Value: "", Path: "/api/auth", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secureCookies(r)})
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("refresh")
	if err != nil {
		jerr(w, 401, "no session")
		return
	}
	// Read before the transaction takes the only connection.
	idleMinutes, providerHours := s.idleLogoutMinutes(), s.providerSessionMaxHours()
	ua, ip := s.sessionClientInfo(r)
	adminIdle := s.adminIdleLogoutMinutes()
	tx, err := s.St.Repos().Begin(context.Background())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	// endWith refuses the refresh, keeping the token deleted, and clears the cookie.
	endWith := func(msg string) {
		tx.Commit()
		s.clearRefreshCookie(w, r)
		jerr(w, 401, msg)
	}
	end := func() { endWith("session expired") }
	consumed, err := tx.Sessions().ConsumeLive(context.Background(), hashToken(c.Value), time.Now())
	if err != nil {
		// A token that is still stored but past its absolute expiry (maintenance
		// removes those periodically): the session ended at its 30-day limit.
		if expired, err := tx.Sessions().Consume(context.Background(), hashToken(c.Value)); err == nil {
			end()
			s.logEvent(expired, s.usernameOf(expired), "session_expired", "", "absolute session limit reached")
			return
		}
		if victim, spentAt, err := tx.Sessions().FindSpent(context.Background(), hashToken(c.Value), time.Now()); err == nil {
			if time.Since(spentAt) < refreshReuseGrace {
				// Probably a parallel refresh from another tab: refuse without
				// touching the cookie, which may already hold the new token.
				jerr(w, 401, "session expired")
				return
			}
			// A rotated token presented again later means it was copied: revoke
			// the whole session family so the copy stops working too.
			tx.Sessions().RevokeAllForUser(context.Background(), victim)
			tx.Sessions().DeleteSpentForUser(context.Background(), victim)
			if tx.Commit() == nil {
				s.logEvent(victim, s.usernameOf(victim), "session_reuse_detected", "", "all sessions signed out")
			}
		}
		// Release the only connection before clearRefreshCookie reads settings.
		tx.Rollback()
		s.clearRefreshCookie(w, r)
		jerr(w, 401, "session expired")
		return
	}
	uid := consumed.UserID
	issued, started := nullTimeOf(consumed.IssuedAt), nullTimeOf(consumed.Started)
	sid, method := nullStringOf(consumed.SessionID), nullStringOf(consumed.Method)
	now := time.Now()
	start, authTime := now, time.Time{}
	if started.Valid {
		start, authTime = started.Time, started.Time
	} else if issued.Valid {
		start = issued.Time // older token: cap the session, but no recent sign-in
	}
	if now.Sub(start) >= sessionMaxAge {
		end()
		s.logEvent(uid, s.usernameOf(uid), "session_expired", "", "absolute session limit reached")
		return
	}
	u, err := userFromRecord(tx.Users().ByID(context.Background(), uid))
	if err != nil {
		end()
		return
	}
	if u.Disabled {
		endWith(msgAccountDisabled)
		return
	}
	if providerOnlySession(u, method.String) && now.Sub(start) >= time.Duration(providerHours)*time.Hour {
		// Deprovisioning at the identity provider must take effect: after this
		// limit the user signs in at the provider again.
		endWith(msgProviderSessionExpired)
		s.logEvent(u.ID, u.Username, "session_expired_provider", s.userTarget(u.ID), "after "+strconv.Itoa(providerHours)+" hours")
		return
	}
	if u.IsGuest {
		if valid, err := tx.ReverseInvites().CountOpenForGuest(context.Background(), uid, time.Now()); err != nil || valid != 1 {
			end()
			return
		}
	} else {
		if u.passwordHash == "" {
			// An account without a local password exists only through its sign-in
			// provider: when the link is removed or the provider is disabled, the
			// session ends at the next refresh.
			if links, err := tx.AuthProviders().CountEnabledLinks(context.Background(), uid); err != nil || links == 0 {
				end()
				return
			}
		}
		if issued.Valid && idleExpired(effectiveIdleMinutes(idleMinutes, adminIdle, u.Admin), issued.Time, time.Now()) {
			end() // abandoned session
			s.logEvent(u.ID, u.Username, "session_expired_idle", "", "idle_logout_minutes="+strconv.Itoa(idleMinutes))
			return
		}
	}
	// Only a successful rotation records the old token as spent.
	if err := tx.Sessions().MarkSpent(context.Background(), hashToken(c.Value), uid, now, start.Add(sessionMaxAge)); err != nil {
		jerr(w, 500, "session failed")
		return
	}
	rt, exp := randHex(32), start.Add(sessionMaxAge)
	if !sid.Valid || sid.String == "" {
		sid = sql.NullString{String: randHex(16), Valid: true}
	}
	if method.String == "" {
		method.String = authMethodPassword
		if u.IsGuest {
			method.String = authMethodInvite
		}
	}
	// The session keeps its id; the user agent and address are the latest seen.
	if err := tx.Sessions().Insert(context.Background(), ports.NewRefreshToken{Hash: hashToken(rt), UserID: uid, ExpiresAt: exp, IssuedAt: now, Started: start, SessionID: sid.String, UserAgent: ua, IP: ip, Method: method.String}); err != nil {
		jerr(w, 500, "session failed")
		return
	}
	u.sessionID, u.authMethod = sid.String, method.String
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "session failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "refresh", Value: rt, Path: "/api/auth", Expires: exp, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secureCookies(r)})
	s.fillMFA(u) // the transaction above has committed and released the connection
	jout(w, 200, map[string]any{"access_token": s.accessTokenAt(u, authTime), "user": u})
}

// logout ends the session. It runs without the auth middleware (an expired
// access token must still be able to sign out), so the user is identified from
// the presented access token or refresh cookie for the audit record; invalid
// credentials never make logout fail, they only leave the record anonymous.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	var uid int64
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := jwt.MapClaims{}
	if tok != "" {
		if _, err := jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return s.key(keyAccess), nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired()); err == nil && claims["purpose"] == "access" {
			if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
				s.St.Repos().Sessions().RevokeAccessToken(context.Background(), hashToken(tok), exp.Time)
			}
			uid, _ = strconv.ParseInt(fmt.Sprint(claims["sub"]), 10, 64)
		}
	}
	if c, err := r.Cookie("refresh"); err == nil {
		if owner, err := s.St.Repos().Sessions().Consume(context.Background(), hashToken(c.Value)); err == nil && uid == 0 {
			uid = owner
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "refresh", Path: "/api/auth", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secureCookies(r)})
	if uid > 0 {
		if u, err := s.userByID(uid); err == nil {
			s.auditSetActor(r, u)
			s.logEvent(u.ID, u.Username, "logout", "", "")
		}
	}
	jout(w, 200, map[string]any{"ok": true})
}

// ---------- password reset ----------

func (s *Server) forgotPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalLogin(w) {
		return
	}
	var c credentials
	decode(r, &c)
	// always respond the same to avoid user enumeration
	defer jout(w, 200, map[string]any{"ok": true})
	email, err := canonicalEmail(c.Email)
	if err != nil || email == "" {
		return
	}
	u, err := userFromRecord(s.St.Repos().Users().FindVerifiedByUniqueEmail(context.Background(), email))
	if err != nil || !s.allowRequest("reset:"+strconv.FormatInt(u.ID, 10), 1, time.Minute) {
		return
	}
	base, ok := s.emailBaseURL(r)
	if !ok {
		return
	}
	tok := randHex(24)
	n, err := s.St.Repos().PasswordResets().CreateForVerified(context.Background(), hashToken(tok), u.ID, time.Now().Add(time.Hour), u.Email, u.passwordHash)
	if err != nil {
		return
	}
	if n != 1 {
		return
	}
	url := base + "/reset-password/" + tok
	go func() {
		if err := s.deliverTemplate(u.Email, "tpl_password_reset", map[string]any{"URL": url}); err != nil {
			s.St.Repos().PasswordResets().Delete(context.Background(), hashToken(tok))
		}
	}()
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalLogin(w) {
		return
	}
	var b struct{ Token, Password string }
	if decode(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if !s.requireAccountPassword(w, r, b.Password, s.resetTokenIdentity(b.Token)...) {
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(b.Password), hashCost)
	if err != nil {
		jerr(w, 400, "invalid password")
		return
	}
	uid, err := s.St.Repos().PasswordResets().UserFor(context.Background(), hashToken(b.Token), time.Now())
	if err != nil {
		jerr(w, 400, "invalid or expired token")
		return
	}
	unlock := s.stripe(&s.loginLocks, strconv.FormatInt(uid, 10))
	defer unlock()
	// Reuse check last: it is the slow one (bcrypt per remembered password).
	currentHash, _ := s.St.Repos().Users().PasswordHash(context.Background(), uid)
	if s.refusePasswordReuse(w, uid, currentHash, b.Password) {
		return
	}
	historyDepth := s.passwordHistoryDepth()
	tx, err := s.St.Repos().Begin(context.Background())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	var kind string
	if uid, kind, err = tx.PasswordResets().Consume(context.Background(), hashToken(b.Token), time.Now(), uid); err != nil {
		jerr(w, 400, "invalid or expired token")
		return
	}
	if err := rememberPasswordTx(tx, uid, historyDepth); err != nil {
		jerr(w, 500, "password reset failed")
		return
	}
	for _, step := range []func() error{
		func() error {
			_, err := tx.Users().SetPasswordAfterReset(context.Background(), uid, string(hash), time.Now().UTC())
			return err
		},
		func() error { return tx.PasswordResets().DeleteForUser(context.Background(), uid) },
		func() error { _, err := tx.Sessions().RevokeAllForUser(context.Background(), uid); return err },
	} {
		if err := step(); err != nil {
			jerr(w, 500, "password reset failed")
			return
		}
	}
	if kind == "welcome" {
		// The link only reached the mailbox owner, which proves the address.
		if err := tx.Users().MarkEmailVerified(context.Background(), uid); err != nil {
			jerr(w, 500, "password reset failed")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "password reset failed")
		return
	}
	// Recorded as the account it belongs to: whoever holds the link acts for it.
	how := "via reset link"
	if kind == "welcome" {
		how = "first password via welcome link"
	}
	s.logEvent(uid, s.usernameOf(uid), "password_reset", s.userTarget(uid), how)
	if kind != "welcome" { // a welcome link sets the first password; nothing changed
		s.notifyUserID(r, uid, "password_changed")
	}
	jout(w, 200, map[string]any{"ok": true})
}

// ---------- self registration ----------

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalLogin(w) {
		return
	}
	if !s.St.SettingBool("allow_self_registration") {
		jerr(w, 403, "registration disabled")
		return
	}
	var c credentials
	if decode(r, &c) != nil || c.Username == "" {
		jerr(w, 400, "username, email and password required")
		return
	}
	if !validUsername(c.Username) {
		jerr(w, 400, msgInvalidUsername)
		return
	}
	if !s.requireAccountPassword(w, r, c.Password, c.Username, c.Email) {
		return
	}
	email, err := canonicalEmail(c.Email)
	if err != nil || email == "" {
		jerr(w, 400, "valid email required")
		return
	}
	domains, derr := s.registrationDomainList()
	if derr != nil {
		jerr(w, 500, "registration temporarily unavailable")
		return
	}
	if !domainAllowed(domains, email) {
		jerr(w, 400, "registration is not available for this email domain")
		return
	}
	c.Email = email
	if c.Language == "" {
		c.Language = "en"
	}
	if !s.St.ValidMailLanguage(c.Language) {
		jerr(w, 400, "unsupported language")
		return
	}
	if c.UILanguage == "" {
		c.UILanguage = "en"
	}
	if !s.St.ValidUILanguage(c.UILanguage) {
		jerr(w, 400, "unsupported UI language")
		return
	}
	if !s.tenantUserAdmits(w) {
		return
	}
	// Public registration always verifies ownership; legacy settings cannot bypass it.
	verify := true
	if verify {
		if err := s.smtpConfigured(); err != nil {
			jerr(w, 503, "registration temporarily unavailable: email is not configured")
			return
		}
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(c.Password), hashCost)
	id, err := s.St.Repos().Users().CreateRegistered(context.Background(), ports.NewUser{Username: c.Username, Name: c.Name, Email: c.Email, PasswordHash: string(hash),
		EmailVerified: !verify, Language: c.Language, UILanguage: c.UILanguage, PendingRegistration: verify, PasswordChangedAt: time.Now().UTC()})
	if err != nil {
		// Usernames are visible to share recipients anyway, so a taken username is
		// reported. A taken email address gets the same answer as a successful
		// registration, so registration cannot reveal who has an account.
		taken, _ := s.St.Repos().Users().CountByUsernameFold(context.Background(), c.Username)
		if taken > 0 {
			jerr(w, 400, "username already in use")
			return
		}
		if email, _ := canonicalEmail(c.Email); email != "" && !s.emailAvailable(email, 0) {
			jout(w, 201, map[string]any{"needs_verification": true})
			return
		}
		jerr(w, 500, "registration failed")
		return
	}
	s.noteCreatedBy(id, "self-registration")
	u, err := s.userByID(id)
	if err != nil {
		jerr(w, 500, "user policy unavailable")
		return
	}
	if verify {
		s.sendVerification(u)
		jout(w, 201, map[string]any{"needs_verification": true})
		return
	}
	s.sessionResponse(w, r, u)
}

func (s *Server) sendVerification(u *User) {
	if !s.allowRequest("verification-mail:"+strconv.FormatInt(u.ID, 10)+":"+u.Email, 1, time.Minute) {
		return
	}
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return
	}
	code := fmt.Sprintf("%08d", n.Int64())
	s.St.Repos().EmailVerifications().Put(context.Background(), u.ID, code, time.Now().Add(30*time.Minute))
	s.queueMail(u.Email, "Verify your email", "tpl_verify_email", map[string]any{"Code": code})
}

func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalLogin(w) {
		return
	}
	var b struct{ Email, Code string }
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	email, err := canonicalEmail(b.Email)
	if err != nil || email == "" {
		jerr(w, 400, "invalid or expired code")
		return
	}
	b.Email = email
	unlock := s.stripe(&s.verificationLocks, b.Email)
	defer unlock()
	uid, code, exp, pending, err := s.St.Repos().EmailVerifications().FindByUniqueEmail(context.Background(), b.Email)
	if err != nil || time.Now().After(exp) {
		jerr(w, 400, "invalid or expired code")
		return
	}
	attempts, err := s.St.Repos().EmailVerifications().RecordAttempt(context.Background(), uid, time.Now().Add(30*time.Minute), time.Now())
	if err != nil || attempts > 5 {
		jerr(w, 429, "too many verification attempts; try again later")
		return
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(strings.TrimSpace(b.Code))) != 1 {
		jerr(w, 400, "invalid or expired code")
		return
	}
	tx, err := s.St.Repos().Begin(context.Background())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	n, err := tx.Users().VerifyEmailWithCode(context.Background(), uid, b.Email, code, time.Now())
	if err != nil {
		jerr(w, 500, "verification failed")
		return
	}
	if n != 1 {
		jerr(w, 400, "invalid or expired code")
		return
	}
	for _, del := range []func(context.Context, int64) error{tx.EmailVerifications().DeleteAttempts, tx.EmailVerifications().DeleteForUser} {
		if err := del(context.Background(), uid); err != nil {
			jerr(w, 500, "verification failed")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "verification failed")
		return
	}
	// Only a fresh self-registration is signed in by proving the mailbox. Any
	// other account (for example one whose address was changed later) must sign
	// in with its password: possession of the mailbox is not a login.
	if !pending {
		jout(w, 200, map[string]any{"ok": true, "verified": true})
		return
	}
	u, _ := s.userByID(uid)
	if u == nil {
		jerr(w, 500, "user policy unavailable")
		return
	}
	s.sessionOrChallenge(w, r, u)
}

func (s *Server) resendVerification(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalLogin(w) {
		return
	}
	var b struct{ Email string }
	decode(r, &b)
	email, err := canonicalEmail(b.Email)
	if err == nil && email != "" {
		if u, err := userFromRecord(s.St.Repos().Users().FindUnverifiedByUniqueEmail(context.Background(), email)); err == nil {
			s.sendVerification(u)
		}
	}
	jout(w, 200, map[string]any{"ok": true})
}

// ---------- profile ----------

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	providers, _ := s.St.Repos().AuthProviders().ListLinked(context.Background(), u.ID)
	linked := []map[string]any{}
	for _, p := range providers {
		linked = append(linked, map[string]any{"id": p.ID, "name": p.Name, "type": p.Type})
	}
	usage, err := s.St.UserStorageUsage(u.ID)
	if err != nil {
		jerr(w, 500, "storage usage unavailable")
		return
	}
	u.QuotaBytes, u.QuotaInheritsDefault = usage.QuotaBytes, usage.QuotaInheritsDefault
	s.fillMFA(u)
	out := map[string]any{"version": s.Version, "user": u, "providers": linked, "has_password": u.passwordHash != "", "terms_pending": s.termsPending(u), "quota_inherits_default": usage.QuotaInheritsDefault, "quota_bytes": usage.QuotaBytes, "storage_used_bytes": usage.StoredBytes, "storage_reserved_bytes": usage.ReservedBytes, "storage_available_bytes": usage.AvailableBytes, "storage_ready": s.tenant == nil || s.StorageReady()}
	s.passwordExpiryFields(u, out)
	jout(w, 200, out)
}

func (s *Server) updateMe(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	if u.IsGuest {
		jerr(w, 403, "guest session is upload-only")
		return
	}
	var b struct {
		Name            string  `json:"name"`
		Email           string  `json:"email"`
		Password        string  `json:"password"`
		CurrentPassword string  `json:"current_password"`
		Language        *string `json:"language"`
		UILanguage      *string `json:"ui_language"`
	}
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	unlock := s.stripe(&s.loginLocks, strconv.FormatInt(u.ID, 10))
	defer unlock()
	email, err := canonicalEmail(b.Email)
	if err != nil {
		jerr(w, 400, "invalid email")
		return
	}
	if email != u.Email {
		// A self-service address change must not bypass the registration domain list.
		domains, derr := s.registrationDomainList()
		if derr != nil {
			jerr(w, 500, "registration temporarily unavailable")
			return
		}
		if !domainAllowed(domains, email) {
			jerr(w, 400, "this email domain is not allowed")
			return
		}
	}
	language := u.Language
	if b.Language != nil {
		language = *b.Language
		if language == "" {
			language = "en"
		}
		if !s.St.ValidMailLanguage(language) {
			jerr(w, 400, "unsupported language")
			return
		}
	}
	uiLanguage := u.UILanguage
	if b.UILanguage != nil {
		uiLanguage = *b.UILanguage
		if !s.St.ValidUILanguage(uiLanguage) {
			jerr(w, 400, "unsupported UI language")
			return
		}
	}
	emailChanged := email != strings.ToLower(strings.TrimSpace(u.Email))
	if !s.emailAvailable(email, u.ID) {
		jerr(w, 400, "email already in use")
		return
	}
	if (b.Password != "" || emailChanged) && u.passwordHash != "" && !u.MustChangePassword {
		if s.stepUpLocked(w, u) {
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(u.passwordHash), []byte(b.CurrentPassword)) != nil {
			s.stepUpFailed(w, u)
			jerr(w, 400, "current password incorrect")
			return
		}
	}
	// Accounts without a local password cannot confirm with one: require a recent
	// sign-in through their provider instead, so a stolen access token cannot add
	// a permanent local password or redirect the email.
	if (b.Password != "" || emailChanged) && u.passwordHash == "" && time.Since(s.requestAuthTime(r)) > recentSignIn {
		jerr(w, 403, msgRecentSignIn)
		return
	}
	passwordHash := u.passwordHash
	mustChange := u.MustChangePassword
	if b.Password != "" {
		if !s.requireAccountPassword(w, r, b.Password, u.Username, email) {
			return
		}
		if s.refusePasswordReuse(w, u.ID, u.passwordHash, b.Password) {
			return
		}
		h, err := bcrypt.GenerateFromPassword([]byte(b.Password), hashCost)
		if err != nil {
			jerr(w, 400, "invalid password")
			return
		}
		passwordHash, mustChange = string(h), false
	}
	historyDepth := s.passwordHistoryDepth()
	tx, err := s.St.Repos().Begin(context.Background())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	verified := u.EmailVerified
	if emailChanged {
		verified = email == ""
	}
	if b.Password != "" {
		if err := rememberPasswordTx(tx, u.ID, historyDepth); err != nil {
			jerr(w, 500, "profile update failed")
			return
		}
	}
	n, err := tx.Users().UpdateProfile(context.Background(), u.ID, ports.ProfileUpdate{Name: b.Name, Email: email, EmailVerified: verified, PasswordHash: passwordHash, MustChangePassword: mustChange,
		Language: language, UILanguage: b.UILanguage, PasswordChanged: b.Password != "", ChangedAt: time.Now().UTC()}, credGuard(u))
	if err != nil {
		jerr(w, 400, "profile update failed")
		return
	}
	if n != 1 {
		jerr(w, 409, "profile changed; retry")
		return
	}
	if emailChanged || b.Password != "" {
		for _, del := range []func(context.Context, int64) error{revokeAllOf(tx), tx.PasswordResets().DeleteForUser, tx.EmailVerifications().DeleteForUser} {
			if err := del(context.Background(), u.ID); err != nil {
				jerr(w, 500, "profile update failed")
				return
			}
		}
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "profile update failed")
		return
	}
	nu, err := s.userByID(u.ID)
	if err != nil {
		jerr(w, 500, "profile update failed")
		return
	}
	if emailChanged {
		s.noteEmailChange(u.ID, u)
	}
	if emailChanged && email != "" {
		s.sendVerification(nu)
	}
	nu.sessionID, nu.authMethod = u.sessionID, u.authMethod // the returned token stays bound to this session
	if b.Password != "" {
		s.logEvent(u.ID, u.Username, "password_changed", s.userTarget(u.ID), "own profile")
		s.notifySecurity(r, u, "password_changed") // to the address the account had before
	}
	if emailChanged || b.Password != "" {
		s.issueSessionSince(w, r, nu, s.sessionStartOf(r))
	}
	s.fillMFA(nu)
	jout(w, 200, map[string]any{"user": nu, "access_token": s.accessTokenAt(nu, s.requestAuthTime(r))})
}

func (s *Server) unlinkProvider(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	pid, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	links, _ := s.St.Repos().AuthProviders().CountLinks(context.Background(), u.ID)
	if s.localLoginStoredOff() {
		// A password cannot sign in while local login is off: keep another enabled external link.
		others, _ := s.St.Repos().AuthProviders().CountEnabledLinksExcept(context.Background(), u.ID, pid)
		mine, _ := s.St.Repos().AuthProviders().CountEnabledLink(context.Background(), u.ID, pid)
		if mine > 0 && others == 0 {
			jerr(w, 400, msgUnlinkLockout)
			return
		}
	} else if u.passwordHash == "" && links <= 1 {
		jerr(w, 400, "set a password before unlinking your only login method")
		return
	}
	s.St.Repos().AuthProviders().Unlink(context.Background(), u.ID, pid)
	jout(w, 200, map[string]any{"ok": true})
}

// ---------- admin: users ----------

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	recs, err := s.St.Repos().Users().ListLocal(context.Background())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	users := []*User{}
	for _, rec := range recs {
		u, err := userFromRecord(rec, nil)
		if err != nil {
			jerr(w, 500, "user list unavailable")
			return
		}
		users = append(users, u)
	}
	// Where each account comes from: a local password and/or linked providers.
	sources := map[int64][]string{}
	if links, lerr := s.St.Repos().AuthProviders().ListLinkTypes(context.Background()); lerr == nil {
		for _, l := range links {
			if have := sources[l.UserID]; len(have) == 0 || have[len(have)-1] != l.Type {
				sources[l.UserID] = append(have, l.Type)
			}
		}
	}
	type adminUser struct {
		*User
		Sources []string `json:"sources"`
		*store.StorageUsage
		QuotaBytes           int64 `json:"quota_bytes"`
		QuotaInheritsDefault bool  `json:"quota_inherits_default"`
		LoginLockedUntil     int64 `json:"login_locked_until"`
	}
	out := []adminUser{}
	for _, u := range users {
		usage, err := s.St.UserStorageUsage(u.ID)
		if err != nil {
			jerr(w, 500, "storage usage unavailable")
			return
		}
		s.fillMFA(u)
		src := []string{}
		if u.passwordHash != "" {
			src = append(src, "local")
		}
		src = append(src, sources[u.ID]...)
		out = append(out, adminUser{User: u, Sources: src, StorageUsage: usage, QuotaBytes: usage.QuotaBytes, QuotaInheritsDefault: usage.QuotaInheritsDefault, LoginLockedUntil: u.loginLockedUntil})
	}
	jout(w, 200, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var b struct {
		credentials
		Admin                bool   `json:"admin"`
		Auditor              bool   `json:"auditor"`
		MustChangePassword   bool   `json:"must_change_password"`
		QuotaBytes           *int64 `json:"quota_bytes"`
		QuotaInheritsDefault *bool  `json:"quota_inherits_default"`
		SendWelcome          bool   `json:"send_welcome"`
	}
	if decode(r, &b) != nil || b.Username == "" {
		jerr(w, 400, "username and password required")
		return
	}
	if !validUsername(b.Username) {
		jerr(w, 400, msgInvalidUsername)
		return
	}
	if b.Admin && b.Auditor {
		jerr(w, 400, msgAdminAuditorExclusive)
		return
	}
	if !s.requireAccountPassword(w, r, b.Password, b.Username, b.Email) {
		return
	}
	email, err := canonicalEmail(b.Email)
	if err != nil {
		jerr(w, 400, "invalid email")
		return
	}
	b.Email = email
	if b.Language == "" {
		b.Language = "en"
	}
	if !s.St.ValidMailLanguage(b.Language) {
		jerr(w, 400, "unsupported language")
		return
	}
	if b.UILanguage == "" {
		b.UILanguage = "en"
	}
	if !s.St.ValidUILanguage(b.UILanguage) {
		jerr(w, 400, "unsupported UI language")
		return
	}
	if _, ok := quotaChoice(b.QuotaBytes, b.QuotaInheritsDefault); !ok {
		jerr(w, 400, "invalid quota choice")
		return
	}
	if !s.tenantUserAdmits(w) {
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(b.Password), hashCost)
	id, err := s.St.Repos().Users().Create(context.Background(), ports.NewUser{Username: b.Username, Name: b.Name, Email: b.Email, PasswordHash: string(h), Admin: b.Admin,
		MustChangePassword: b.MustChangePassword, Language: b.Language, UILanguage: b.UILanguage, PasswordChangedAt: time.Now().UTC(), QuotaBytes: b.QuotaBytes})
	if err != nil {
		jerr(w, 400, "username already exists")
		return
	}
	if b.Auditor {
		if err := s.St.Repos().Users().SetAuditorIfNotAdmin(context.Background(), id); err != nil {
			s.St.Repos().Users().Delete(context.Background(), id)
			jerr(w, 500, "user creation failed")
			return
		}
	}
	me := s.ctxUser(r)
	s.noteCreatedBy(id, s.userTarget(me.ID))
	u, err := s.userByID(id)
	if err != nil {
		jerr(w, 500, "user policy unavailable")
		return
	}
	out := struct {
		*User
		WelcomeEmail string `json:"welcome_email,omitempty"`
		WelcomeNote  string `json:"welcome_note,omitempty"`
	}{User: u}
	detail := ""
	if b.SendWelcome {
		// The user is already created: a failed mail must never undo that.
		out.WelcomeEmail, out.WelcomeNote = s.sendWelcome(r, me, u)
		detail = "welcome=" + out.WelcomeEmail
	}
	s.logEvent(me.ID, me.Username, "user_created", s.userTarget(id), detail)
	jout(w, 201, out)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var b struct {
		Name, Email          *string
		Password             string
		Admin                *bool   `json:"admin"` // omitted = unchanged
		Auditor              *bool   `json:"auditor"`
		QuotaBytes           *int64  `json:"quota_bytes"`
		QuotaInheritsDefault *bool   `json:"quota_inherits_default"`
		MFAPolicy            *string `json:"mfa_policy"`
		RotationExempt       *bool   `json:"password_rotation_exempt"` // omitted = unchanged
	}
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	inheritance, ok := quotaChoice(b.QuotaBytes, b.QuotaInheritsDefault)
	if !ok {
		jerr(w, 400, "invalid quota choice")
		return
	}
	if b.MFAPolicy != nil && !validMFAUserPolicy(*b.MFAPolicy) {
		jerr(w, 400, "mfa_policy must be inherit, required or exempt")
		return
	}
	me := s.ctxUser(r)
	if b.MFAPolicy != nil && *b.MFAPolicy == "required" && id == me.ID && !s.userHasFactor(me) {
		jerr(w, 400, msgMFAEnforceSelf)
		return
	}
	if id == me.ID && b.Admin != nil && !*b.Admin {
		jerr(w, 400, "cannot remove your own admin rights")
		return
	}
	if b.Password != "" && id != me.ID {
		// An administrator who could set a password could sign in as the user and
		// read their shares. The user chooses their own password through a link
		// that only reaches their mailbox.
		jerr(w, 400, msgAdminNoPassword)
		return
	}
	if b.Password != "" && !s.requireAccountPassword(w, r, b.Password, me.Username, me.Email) {
		return
	}
	unlock := s.stripe(&s.loginLocks, strconv.FormatInt(id, 10))
	defer unlock()
	target, err := s.userByID(id)
	if err != nil || target.IsGuest {
		jerr(w, 404, "not found")
		return
	}
	name, email := target.Name, target.Email
	if b.Name != nil {
		name = *b.Name
	}
	if b.Email != nil {
		var err error
		if email, err = canonicalEmail(*b.Email); err != nil || !s.emailAvailable(email, id) {
			jerr(w, 400, "invalid or already used email")
			return
		}
	}
	admin := target.Admin
	if b.Admin != nil {
		admin = *b.Admin
	}
	if target.Admin && !admin && s.refuseLastExternalAdmin(w, id, 0) {
		return
	}
	// Another user's address changed by an administrator is unverified again, so
	// the administrator cannot use it to take over the account.
	emailChangedByAdmin := id != me.ID && !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(target.Email))
	newAuditor := target.Auditor
	if b.Auditor != nil {
		newAuditor = *b.Auditor
	}
	if admin && newAuditor {
		jerr(w, 400, msgAdminAuditorExclusive)
		return
	}
	if (admin != target.Admin || newAuditor != target.Auditor) && !s.requireStepUp(w, r) {
		return
	}
	if s.refuseErased(w, id) {
		return
	}
	hash := target.passwordHash
	if b.Password != "" {
		// Last of the password checks: the reuse check is the slow one.
		if s.refusePasswordReuse(w, id, target.passwordHash, b.Password) {
			return
		}
		h, err := bcrypt.GenerateFromPassword([]byte(b.Password), hashCost)
		if err != nil {
			jerr(w, 400, "invalid password")
			return
		}
		hash = string(h)
	}
	historyDepth := s.passwordHistoryDepth()
	tx, err := s.St.Repos().Begin(context.Background())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	if b.Password != "" {
		if err := rememberPasswordTx(tx, id, historyDepth); err != nil {
			jerr(w, 500, "user update failed")
			return
		}
	}
	n, err := tx.Users().AdminUpdate(context.Background(), id, ports.AdminUserUpdate{Name: name, Email: email, Admin: admin, PasswordHash: hash, QuotaBytes: b.QuotaBytes,
		QuotaInheritsDefault: inheritance, MFAPolicy: b.MFAPolicy, RotationExempt: b.RotationExempt, EmailUnverified: emailChangedByAdmin,
		PasswordChanged: b.Password != "", ChangedAt: time.Now().UTC()}, credGuard(target))
	if err != nil {
		jerr(w, 400, "user update failed")
		return
	}
	if n != 1 {
		jerr(w, 409, "user changed; retry")
		return
	}
	if err := tx.Users().SetAuditor(context.Background(), id, newAuditor); err != nil {
		jerr(w, 500, "user update failed")
		return
	}
	if b.Password != "" || email != target.Email {
		for _, del := range []func(context.Context, int64) error{revokeAllOf(tx), tx.PasswordResets().DeleteForUser, tx.EmailVerifications().DeleteForUser, tx.MFA().DeleteResetRequestsForUser} {
			if err := del(context.Background(), id); err != nil {
				jerr(w, 500, "user update failed")
				return
			}
		}
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "user update failed")
		return
	}
	u, err := s.userByID(id)
	if errors.Is(err, ports.ErrNotFound) {
		jerr(w, 404, "not found")
		return
	}
	if err != nil {
		jerr(w, 500, "user policy unavailable")
		return
	}
	me2 := s.ctxUser(r)
	detail := ""
	if b.Password != "" {
		detail = "password changed"
	}
	s.logEvent(me2.ID, me2.Username, "user_updated", s.userTarget(id), detail)
	if email != target.Email {
		s.noteEmailChange(id, me2)
	}
	if emailChangedByAdmin {
		s.logEvent(me2.ID, me2.Username, "user_email_changed", s.userTarget(id), "email_verified reset")
		s.notifyEmailChanged(target)
	}
	if target.Admin != admin || target.Auditor != newAuditor {
		s.noteRoleChange(id, me2)
		s.logEvent(me2.ID, me2.Username, "user_role_changed", s.userTarget(id), "admin="+strconv.FormatBool(admin)+" auditor="+strconv.FormatBool(newAuditor))
	}
	if b.MFAPolicy != nil && *b.MFAPolicy != target.MFAPolicy {
		s.logEvent(me2.ID, me2.Username, "mfa_policy_changed", s.userTarget(id), "policy="+*b.MFAPolicy)
	}
	if b.RotationExempt != nil && *b.RotationExempt != target.PasswordRotationExempt {
		s.logEvent(me2.ID, me2.Username, "password_rotation_exempt_changed", s.userTarget(id), "exempt="+strconv.FormatBool(*b.RotationExempt))
	}
	if b.Password != "" {
		s.logEvent(me2.ID, me2.Username, "password_changed", s.userTarget(id), "administrator, own account")
		s.notifySecurity(r, target, "password_changed")
	}
	s.fillMFA(u)
	jout(w, 200, u)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == s.ctxUser(r).ID {
		jerr(w, 400, "cannot delete yourself")
		return
	}
	if s.refuseLastExternalAdmin(w, id, 0) {
		return
	}
	deletedLabel := s.userTarget(id) // resolve the name before the account disappears
	unlock := s.stripe(&s.loginLocks, strconv.FormatInt(id, 10))
	defer unlock()
	unlockUploads := s.LockUserUploads(id)
	defer unlockUploads()
	tx, err := s.St.Repos().Begin(context.Background())
	if err != nil {
		jerr(w, 500, "user deletion failed")
		return
	}
	defer tx.Rollback()
	// Take the database write lock before discovery, so admissions cannot slip in.
	n, err := tx.Users().LockForDelete(context.Background(), id)
	if err != nil {
		jerr(w, 500, "user deletion failed")
		return
	}
	if n != 1 {
		jerr(w, 404, "not found")
		return
	}
	var dirs []string
	uploads, err := tx.Users().OwnedUploadIDs(context.Background(), id)
	if err != nil {
		jerr(w, 500, "user deletion failed")
		return
	}
	for _, name := range uploads {
		dirs = append(dirs, s.uploadDir(name))
	}
	shares, err := tx.Users().OwnedShareLongIDs(context.Background(), id)
	if err != nil {
		jerr(w, 500, "user deletion failed")
		return
	}
	for _, name := range shares {
		dir, derr := store.ShareDir(s.St.DataDir, name)
		if derr != nil {
			continue // malformed long ID: nothing safe to remove
		}
		dirs = append(dirs, dir)
	}
	if err := tx.Users().DeleteWithOwnedData(context.Background(), id); err != nil {
		jerr(w, 500, "user deletion failed")
		return
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "user deletion failed")
		return
	}
	s.kickDeletes() // remote objects of the removed shares (queued by the delete)
	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			jerr(w, 500, "user deleted but file cleanup failed")
			return
		}
	}
	me := s.ctxUser(r)
	s.logEvent(me.ID, me.Username, "user_deleted", deletedLabel, "")
	jout(w, 200, map[string]any{"ok": true})
}

func (s *Server) forceReset(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	unlock := s.stripe(&s.loginLocks, strconv.FormatInt(id, 10))
	defer unlock()
	n, err := s.St.Repos().Users().ForcePasswordChange(context.Background(), id)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if n != 1 {
		jerr(w, 404, "not found")
		return
	}
	s.St.Repos().Sessions().RevokeAllForUser(context.Background(), id)
	me := s.ctxUser(r)
	// The user chooses the new password through a link that only reaches their
	// verified mailbox; the administrator never sees the link.
	outcome, note := s.sendAdminPasswordReset(r, me, id)
	s.logEvent(me.ID, me.Username, "user_force_reset", s.userTarget(id), "")
	s.logEvent(me.ID, me.Username, "user_password_reset_sent", s.userTarget(id), "reset_email="+outcome)
	out := map[string]any{"ok": true, "reset_email": outcome}
	if note != "" {
		out["reset_note"] = note
	}
	jout(w, 200, out)
}
