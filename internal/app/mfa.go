// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/webauthnlite"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Multi-factor authentication: TOTP and recovery codes (WebAuthn plugs in through
// the same helpers, see userHasFactor / mfaChallenge / completeMFALogin /
// mfaFactorsChanged).
//
// Global policy (settings mfa_policy): off | optional | admins | privileged | all.
//   off       MFA is switched off completely (no gate, no enrolment); also the
//             emergency switch if everybody is locked out.
//   optional  users may enrol themselves.
//   admins    required for administrators.
//   privileged required for administrators and auditors.
//   all       required for every local account.
// Per user (users.mfa_policy): inherit | required | exempt. An exempt user is
// never forced to enrol; a user that did enrol keeps using the factor.
// Guests and accounts without a local password (external providers only) are
// outside Sendora's MFA: the provider's own MFA applies.

const (
	mfaTokenTTL        = 5 * time.Minute
	recoveryCodeCount  = 10
	recoveryAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // 32 symbols = 5 bits each
	msgMFAExpired      = "mfa session expired; sign in again"
	msgMFANotEnabled   = "multi-factor authentication is not enabled"
	msgMFARequiredKeep = "multi-factor authentication is required for your account; add another method first"
	msgMFAEnforceSelf  = "set up multi-factor authentication for your own account first (Profile → Security), then enforce it"
)

// webauthnAvailable reports whether passkeys can work for this application URL:
// it must be a secure origin (https, or http on localhost) with a usable RP ID.
// It is a variable so tests can force it.
var webauthnAvailable = func(appURL string) bool {
	_, ok := webauthnlite.RPFromAppURL(appURL)
	return ok
}

// mfaTracker remembers consumed mfa_token ids until they expire.
type mfaTracker struct {
	mu   sync.Mutex
	used map[string]time.Time
}

func (t *mfaTracker) has(jti string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	exp, ok := t.used[jti]
	return ok && time.Now().Before(exp)
}

// mark records a token as spent; it returns false if it already was.
func (t *mfaTracker) mark(jti string, exp time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if t.used == nil {
		t.used = map[string]time.Time{}
	}
	for k, e := range t.used {
		if !now.Before(e) {
			delete(t.used, k)
		}
	}
	if e, ok := t.used[jti]; ok && now.Before(e) {
		return false
	}
	t.used[jti] = exp
	return true
}

// ---------- settings & policy ----------

func validateMFASetting(key, val string) (owned bool, err error) {
	switch key {
	case "mfa_policy":
		switch val {
		case "off", "optional", "admins", "privileged", "all":
			return true, nil
		}
		return true, fmt.Errorf("mfa_policy must be one of off, optional, admins, privileged, all")
	case "mfa_totp_enabled", "mfa_webauthn_enabled":
		if _, ok := parseStrictBool(val); !ok {
			return true, fmt.Errorf("%s must be true or false", key)
		}
		return true, nil
	case "mfa_reminder_days":
		if _, ok := parseStrictInt(val, 0, mfaReminderMaxDays); !ok {
			return true, fmt.Errorf("mfa_reminder_days must be a whole number of days from 0 to %d (0 = ask again at every sign-in)", mfaReminderMaxDays)
		}
		return true, nil
	}
	return false, nil
}

// How long a dismissed "two-step verification is not set up" reminder stays away.
const (
	mfaReminderDefaultDays = 1
	mfaReminderMaxDays     = 365
)

func (s *Server) mfaReminderDays() int {
	n, ok := parseStrictInt(s.St.Setting("mfa_reminder_days"), 0, mfaReminderMaxDays)
	if !ok {
		return mfaReminderDefaultDays
	}
	return n
}

// mfaGlobal is the stored policy; a corrupt value fails closed to "all".
func (s *Server) mfaGlobal() string {
	switch v := s.St.Setting("mfa_policy"); v {
	case "off", "optional", "admins", "privileged", "all":
		return v
	}
	return "all"
}

func (s *Server) mfaAppURL() string {
	if s.BaseURL != "" {
		return s.BaseURL
	}
	return strings.TrimRight(s.St.Setting("application_url"), "/")
}

func (s *Server) mfaTOTPEnabled() bool {
	v, ok := parseStrictBool(s.St.Setting("mfa_totp_enabled"))
	return !ok || v
}

func (s *Server) mfaWebAuthnEnabled() bool {
	v, ok := parseStrictBool(s.St.Setting("mfa_webauthn_enabled"))
	return (!ok || v) && webauthnAvailable(s.mfaAppURL())
}

type mfaFactors struct {
	TOTP     bool
	WebAuthn int
	Recovery int // unused recovery codes
}

func (s *Server) loadFactors(uid int64) mfaFactors {
	var f mfaFactors
	ctx, m := context.Background(), s.St.Repos().MFA()
	if n, err := m.CountConfirmedTOTP(ctx, uid); err == nil {
		f.TOTP = n > 0
	}
	if n, err := m.CountWebAuthn(ctx, uid); err == nil {
		f.WebAuthn = n
	}
	if n, err := m.CountUnusedRecoveryCodes(ctx, uid); err == nil {
		f.Recovery = n
	}
	return f
}

// userHasFactor: the user has at least one usable (method enabled) second factor.
// It ignores the global policy so it can also guard policy changes.
func (s *Server) userHasFactor(u *User) bool {
	if u == nil || u.IsGuest {
		return false
	}
	f := s.loadFactors(u.ID)
	return (s.mfaTOTPEnabled() && f.TOTP) || (s.mfaWebAuthnEnabled() && f.WebAuthn > 0)
}

// mfaGate: this login must complete a second step.
func (s *Server) mfaGate(u *User) bool {
	return u != nil && !u.IsGuest && u.passwordHash != "" && s.mfaGlobal() != "off" && s.userHasFactor(u)
}

// mfaRequired: the effective policy obliges this user to have a factor.
func (s *Server) mfaRequired(u *User) bool {
	global := s.mfaGlobal()
	if u == nil || u.IsGuest || u.passwordHash == "" || global == "off" {
		return false
	}
	if !s.mfaTOTPEnabled() && !s.mfaWebAuthnEnabled() {
		return false // nothing to enrol with: never lock people out
	}
	switch u.MFAPolicy {
	case "exempt":
		return false
	case "inherit":
		switch global {
		case "admins":
			return u.Admin
		case "privileged":
			return u.Admin || u.Auditor
		case "all":
			return true
		}
		return false
	}
	return true // "required" and any unknown value fail closed
}

func (s *Server) mfaEnrollRequired(u *User) bool {
	return s.mfaRequired(u) && !s.userHasFactor(u)
}

// fillMFA computes the derived JSON fields. It runs queries: never call it with
// a transaction open on the single database connection.
func (s *Server) fillMFA(u *User) {
	if u == nil || u.IsGuest {
		return
	}
	u.MFAEnabled = s.userHasFactor(u)
	u.MFARequired = s.mfaRequired(u)
	u.MFAEnrollRequired = u.MFARequired && !u.MFAEnabled
}

// ---------- failure counter shared with the password lock ----------

func (s *Server) noteAuthFailure(u *User) {
	now := time.Now().Unix()
	failures := u.loginFailures + 1
	if u.loginLockedUntil != 0 && u.loginLockedUntil <= now {
		failures = 1
	}
	locked := int64(0)
	if failures >= 5 {
		locked = now + int64((15*time.Minute)/time.Second)
	}
	s.St.Repos().Users().SetLoginFailures(context.Background(), u.ID, int64(failures), locked)
	if locked > 0 {
		s.logEvent(u.ID, u.Username, "login_lockout", "", "locked after repeated failures")
	}
}

func (s *Server) clearAuthFailures(id int64) {
	s.St.Repos().Users().ClearLoginFailures(context.Background(), id)
}

func rejectMFA(w http.ResponseWriter) {
	time.Sleep(300 * time.Millisecond)
	jerr(w, http.StatusUnauthorized, "invalid code")
}

// ---------- login gate ----------

func (s *Server) mfaMethods(u *User) []string {
	f := s.loadFactors(u.ID)
	out := []string{}
	if s.mfaTOTPEnabled() && f.TOTP {
		out = append(out, "totp")
	}
	if s.mfaWebAuthnEnabled() && f.WebAuthn > 0 {
		out = append(out, "webauthn")
	}
	if f.Recovery > 0 {
		out = append(out, "recovery")
	}
	return out
}

func (s *Server) mfaToken(u *User) string {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":        strconv.FormatInt(u.ID, 10),
		"purpose":    "mfa",
		"jti":        randHex(16),
		"credential": s.credentialVersion(u),
		"exp":        time.Now().Add(mfaTokenTTL).Unix(),
	})
	str, _ := t.SignedString(s.key(keyMFA))
	return str
}

// parseMFAToken validates signature, expiry and purpose. The caller still has to
// compare the credential claim with the reloaded user.
func (s *Server) parseMFAToken(tok string) (uid int64, jti, cred string, exp time.Time, ok bool) {
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return s.key(keyMFA), nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired()); err != nil {
		return 0, "", "", time.Time{}, false
	}
	if claims["purpose"] != "mfa" {
		return 0, "", "", time.Time{}, false
	}
	id, err := strconv.ParseInt(fmt.Sprint(claims["sub"]), 10, 64)
	jtiV, _ := claims["jti"].(string)
	credV, _ := claims["credential"].(string)
	e, err2 := claims.GetExpirationTime()
	if err != nil || jtiV == "" || credV == "" || err2 != nil || e == nil || s.mfaUsed.has(jtiV) {
		return 0, "", "", time.Time{}, false
	}
	return id, jtiV, credV, e.Time, true
}

// mfaChallenge answers a successful first factor with the pending second step.
func (s *Server) mfaChallenge(w http.ResponseWriter, u *User) {
	jout(w, 200, map[string]any{
		"mfa_required": true,
		"mfa_token":    s.mfaToken(u),
		"methods":      s.mfaMethods(u),
		"expires_in":   int(mfaTokenTTL / time.Second),
	})
}

// sessionOrChallenge issues a session unless the account has a second step.
func (s *Server) sessionOrChallenge(w http.ResponseWriter, r *http.Request, u *User) {
	if s.mfaGate(u) {
		s.mfaChallenge(w, u)
		return
	}
	s.sessionResponse(w, r, u)
}

// completeMFALogin finishes a login after any second factor succeeded.
func (s *Server) completeMFALogin(w http.ResponseWriter, r *http.Request, u *User, method string) {
	if s.refuseDisabledSignIn(w, u, method) {
		return
	}
	s.clearAuthFailures(u.ID)
	s.logEvent(u.ID, u.Username, "mfa_login_ok", "", method)
	s.logEvent(u.ID, u.Username, "login_ok", "", "")
	nu, err := s.userByID(u.ID)
	if err != nil {
		jerr(w, 500, "user policy unavailable")
		return
	}
	s.sessionResponse(w, r, nu)
}

// mfaLogin is the shared handler for the code based second factors.
func (s *Server) mfaLogin(method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireLocalLogin(w) {
			return
		}
		var b struct {
			MFAToken string `json:"mfa_token"`
			Code     string `json:"code"`
		}
		if decode(r, &b) != nil {
			jerr(w, 400, "bad request")
			return
		}
		uid, jti, cred, exp, ok := s.parseMFAToken(b.MFAToken)
		if !ok {
			jerr(w, 401, msgMFAExpired)
			return
		}
		unlock := onceUnlock(s.stripe(&s.loginLocks, strconv.FormatInt(uid, 10)))
		defer unlock()
		u, err := s.userByID(uid)
		if err != nil || u.IsGuest || cred != s.credentialVersion(u) {
			jerr(w, 401, msgMFAExpired)
			return
		}
		if s.mfaGlobal() == "off" {
			jerr(w, 409, msgMFANotEnabled)
			return
		}
		if u.loginLockedUntil > time.Now().Unix() {
			s.logEvent(u.ID, u.Username, "mfa_failed", "", "account locked")
			unlock()
			rejectMFA(w)
			return
		}
		good := false
		switch method {
		case "totp":
			good = s.verifyTOTPLogin(u, b.Code)
		case "recovery":
			good = s.verifyRecoveryCode(u.ID, b.Code)
		}
		if !good {
			s.noteAuthFailure(u)
			s.logEvent(u.ID, u.Username, "mfa_failed", "", method)
			unlock()
			rejectMFA(w)
			return
		}
		if !s.spendMFAToken(jti, exp) {
			jerr(w, 401, msgMFAExpired)
			return
		}
		s.completeMFALogin(w, r, u, method)
	}
}

// verifyTOTPLogin checks a code and burns its time step (replay protection).
func (s *Server) verifyTOTPLogin(u *User, code string) bool {
	if !s.mfaTOTPEnabled() {
		return false
	}
	enc, last, err := s.St.Repos().MFA().ConfirmedTOTP(context.Background(), u.ID)
	if err != nil {
		return false
	}
	secret, err := decodeTOTPSecret(enc)
	if err != nil {
		return false
	}
	counter, ok := totpMatch(secret, code, time.Now())
	if !ok || counter <= last {
		return false
	}
	n, err := s.St.Repos().MFA().AdvanceTOTPCounter(context.Background(), u.ID, counter)
	if err != nil {
		return false
	}
	return n == 1
}

// ---------- recovery codes ----------

func newRecoveryCode() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(recoveryAlphabet[c&31])
	}
	return sb.String()
}

func normalizeRecoveryCode(code string) (string, bool) {
	code = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	if len(code) != 16 {
		return "", false
	}
	for _, c := range code {
		if !strings.ContainsRune(recoveryAlphabet, c) {
			return "", false
		}
	}
	return code, true
}

func hashRecoveryCode(normalized string) string {
	h := sha256.Sum256([]byte("sendora-recovery:" + normalized))
	return hex.EncodeToString(h[:])
}

// verifyRecoveryCode consumes a code atomically; reuse fails.
func (s *Server) verifyRecoveryCode(uid int64, code string) bool {
	n, ok := normalizeRecoveryCode(code)
	if !ok {
		return false
	}
	c, err := s.St.Repos().MFA().UseRecoveryCode(context.Background(), uid, hashRecoveryCode(n))
	if err != nil {
		return false
	}
	return c == 1
}

// regenerateRecoveryCodes replaces all codes of a user and returns the new ones.
func (s *Server) regenerateRecoveryCodes(uid int64) ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := tx.MFA().DeleteRecoveryCodes(ctx, uid); err != nil {
		return nil, err
	}
	for i := range codes {
		codes[i] = newRecoveryCode()
		n, _ := normalizeRecoveryCode(codes[i])
		if err := tx.MFA().AddRecoveryCode(ctx, uid, hashRecoveryCode(n)); err != nil {
			return nil, err
		}
	}
	return codes, tx.Commit()
}

// ---------- enrolment (authenticated) ----------

func mfaEnrollAllowed(r *http.Request) bool {
	p := r.URL.Path
	if p == "/api/users/me" {
		return r.Method == http.MethodGet || r.Method == http.MethodPut
	}
	return p == "/api/users/me/mfa" || strings.HasPrefix(p, "/api/users/me/mfa/")
}

// confirmMFAPassword re-checks the account password for sensitive actions. Wrong
// attempts count towards the shared lock.
func (s *Server) confirmMFAPassword(w http.ResponseWriter, u *User, password string) bool {
	if u.passwordHash == "" {
		jerr(w, 400, "set a password before using multi-factor authentication")
		return false
	}
	if s.stepUpLocked(w, u) {
		return false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.passwordHash), []byte(password)) == nil {
		return true
	}
	s.stepUpFailed(w, u)
	time.Sleep(300 * time.Millisecond)
	jerr(w, 401, "incorrect password")
	return false
}

// mfaFactorsChanged is called after any factor was added, removed or reset: it
// bumps the epoch (old access tokens die), drops every refresh token and answers
// with a fresh session for the caller.
func (s *Server) mfaFactorsChanged(w http.ResponseWriter, r *http.Request, uid int64, extra map[string]any) {
	s.St.Repos().Users().BumpMFAEpoch(context.Background(), uid)
	s.St.Repos().Sessions().RevokeAllForUser(context.Background(), uid)
	nu, err := s.userByID(uid)
	if err != nil {
		jerr(w, 500, "user policy unavailable")
		return
	}
	if !s.issueSessionSince(w, r, nu, s.sessionStartOf(r)) {
		jerr(w, 401, "session changed; log in again")
		return
	}
	s.fillMFA(nu)
	out := map[string]any{"ok": true, "access_token": s.accessTokenAt(nu, s.requestAuthTime(r)), "user": nu}
	for k, v := range extra {
		out[k] = v
	}
	jout(w, 200, out)
}

func (s *Server) requireMFAOn(w http.ResponseWriter, u *User, totp bool) bool {
	if u.IsGuest || s.mfaGlobal() == "off" || (totp && !s.mfaTOTPEnabled()) {
		jerr(w, 409, msgMFANotEnabled)
		return false
	}
	return true
}

func (s *Server) webauthnCredentials(uid int64) []map[string]any {
	out := []map[string]any{}
	creds, err := s.St.Repos().MFA().ListWebAuthn(context.Background(), uid)
	if err != nil {
		return out
	}
	for _, c := range creds {
		out = append(out, map[string]any{"id": c.RowID, "name": c.Name, "created_at": c.CreatedAt, "last_used_at": c.LastUsedAt})
	}
	return out
}

// mfaStatus: GET /api/users/me/mfa
func (s *Server) mfaStatus(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	f := s.loadFactors(u.ID)
	creds := s.webauthnCredentials(u.ID)
	jout(w, 200, map[string]any{
		"policy":          s.mfaGlobal(),
		"user_policy":     u.MFAPolicy,
		"required":        s.mfaRequired(u),
		"enroll_required": s.mfaEnrollRequired(u),
		"totp":            map[string]any{"enabled": s.mfaTOTPEnabled(), "enrolled": f.TOTP},
		"webauthn": map[string]any{
			"enabled":     s.mfaWebAuthnEnabled(),
			"available":   webauthnAvailable(s.mfaAppURL()),
			"credentials": creds,
		},
		"recovery_codes_remaining": f.Recovery,
		"has_password":             u.passwordHash != "",
	})
}

// mfaTOTPBegin: POST /api/users/me/mfa/totp/begin {password}
func (s *Server) mfaTOTPBegin(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	var b struct {
		Password string `json:"password"`
	}
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	if !s.requireMFAOn(w, u, true) || !s.confirmMFAPassword(w, u, b.Password) {
		return
	}
	if s.loadFactors(u.ID).TOTP {
		jerr(w, 409, "an authenticator is already set up; remove it first")
		return
	}
	_, enc, err := newTOTPSecret()
	if err != nil {
		jerr(w, 500, "could not create secret")
		return
	}
	if err := s.St.Repos().MFA().StartTOTP(context.Background(), u.ID, enc); err != nil {
		jerr(w, 500, "could not store secret")
		return
	}
	issuer := s.St.Setting("application_name")
	if issuer == "" {
		issuer = "Sendora"
	}
	jout(w, 200, map[string]any{"secret": enc, "uri": totpURI(issuer, u.Username, enc), "issuer": issuer, "account": u.Username, "digits": totpDigits, "period": totpPeriod})
}

// mfaTOTPConfirm: POST /api/users/me/mfa/totp/confirm {code}
func (s *Server) mfaTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	var b struct {
		Code string `json:"code"`
	}
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	if !s.requireMFAOn(w, u, true) {
		return
	}
	enc, confirmed, err := s.St.Repos().MFA().TOTP(context.Background(), u.ID)
	if err != nil || confirmed {
		jerr(w, 409, "start the setup first")
		return
	}
	secret, err := decodeTOTPSecret(enc)
	if err != nil {
		jerr(w, 500, "invalid secret")
		return
	}
	counter, ok := totpMatch(secret, b.Code, time.Now())
	if !ok {
		time.Sleep(300 * time.Millisecond)
		jerr(w, 400, "invalid code")
		return
	}
	hadCodes := s.loadFactors(u.ID).Recovery > 0
	n, err := s.St.Repos().MFA().ConfirmTOTP(context.Background(), u.ID, counter)
	if err != nil {
		jerr(w, 500, "could not save")
		return
	}
	if n != 1 {
		jerr(w, 409, "start the setup first")
		return
	}
	extra := map[string]any{}
	if !hadCodes {
		codes, err := s.regenerateRecoveryCodes(u.ID)
		if err != nil {
			jerr(w, 500, "could not create recovery codes")
			return
		}
		extra["recovery_codes"] = codes
	}
	s.logEvent(u.ID, u.Username, "mfa_enrolled", "", "totp")
	s.notifySecurity(r, u, "mfa_factor_changed")
	s.mfaFactorsChanged(w, r, u.ID, extra)
}

// mfaTOTPRemove: POST /api/users/me/mfa/totp/remove {password}
func (s *Server) mfaTOTPRemove(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	var b struct {
		Password string `json:"password"`
	}
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	if u.IsGuest {
		jerr(w, 409, msgMFANotEnabled)
		return
	}
	if !s.confirmMFAPassword(w, u, b.Password) {
		return
	}
	f := s.loadFactors(u.ID)
	if !f.TOTP {
		jerr(w, 404, "no authenticator is set up")
		return
	}
	if s.mfaRequired(u) && !(s.mfaWebAuthnEnabled() && f.WebAuthn > 0) {
		jerr(w, 409, msgMFARequiredKeep)
		return
	}
	s.St.Repos().MFA().DeleteTOTP(context.Background(), u.ID)
	if f.WebAuthn == 0 {
		s.St.Repos().MFA().DeleteRecoveryCodes(context.Background(), u.ID)
	}
	s.logEvent(u.ID, u.Username, "mfa_removed", "", "totp")
	s.notifySecurity(r, u, "mfa_factor_changed")
	s.mfaFactorsChanged(w, r, u.ID, nil)
}

// mfaRecoveryRegenerate: POST /api/users/me/mfa/recovery/regenerate {password}
func (s *Server) mfaRecoveryRegenerate(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	var b struct {
		Password string `json:"password"`
	}
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	if !s.requireMFAOn(w, u, false) || !s.confirmMFAPassword(w, u, b.Password) {
		return
	}
	if !s.userHasFactor(u) {
		jerr(w, 409, "set up a second factor first")
		return
	}
	codes, err := s.regenerateRecoveryCodes(u.ID)
	if err != nil {
		jerr(w, 500, "could not create recovery codes")
		return
	}
	s.logEvent(u.ID, u.Username, "mfa_enrolled", "", "recovery codes regenerated")
	s.notifySecurity(r, u, "recovery_codes_regenerated")
	jout(w, 200, map[string]any{"ok": true, "recovery_codes": codes})
}

// ---------- admin ----------

func validMFAUserPolicy(v string) bool { return v == "inherit" || v == "required" || v == "exempt" }
