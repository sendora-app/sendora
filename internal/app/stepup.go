// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/webauthnlite"
	"golang.org/x/crypto/bcrypt"
)

// Step-up re-authentication for critical administrator actions.
//
// A critical action (user delete/erase, role changes, sign-in providers,
// security settings, backup download/delete/restore, MFA reset requests) needs
// a re-authentication within admin_stepup_minutes (default 5). A sign-in counts
// as one (the session's auth_time); otherwise POST /api/auth/step-up confirms
// with the second factor when the administrator has one (TOTP code or WebAuthn
// assertion), else the current password. Administrators who sign in only
// through a provider and have no factor must sign in at the provider again.
//
// A confirmation is remembered in memory for the session it was made in (user
// and sign-in time, which a refresh carries over), never in a token: it ends
// with the window, at the next sign-in and when the process restarts.

const (
	settingStepUpMinutes   = "admin_stepup_minutes"
	settingAdminIdle       = "admin_idle_logout_minutes"
	stepUpDefaultMinutes   = 5
	stepUpMaxMinutes       = 60
	adminIdleDefault       = 15
	msgStepUpRequired      = "re-authentication required"
	msgStepUpProvider      = "sign in again at your sign-in provider to confirm this action"
	msgStepUpWrong         = "the confirmation was not accepted"
	waKindStepUp           = "stepup"
	stepUpCode             = "stepup_required"
	stepUpStateCap         = 4096
	msgTermsSettingsNeeded = "set the terms URL and the terms version before requiring acceptance"
)

// accountSecurityState is embedded in Server.
type accountSecurityState struct {
	// passwordScreenOff switches the common-password and personal-data checks
	// off (test fixtures only; there is no setting for it).
	passwordScreenOff bool

	stepUpMu sync.Mutex
	stepUps  map[stepUpKey]time.Time
}

type stepUpKey struct {
	uid     int64
	session int64 // the session's sign-in time (unix seconds)
}

// ---------- settings ----------

// validateAccountSecuritySetting validates the settings added for security
// notifications, password screening, step-up, the administrator network
// restriction and the privacy/terms links. owned is false for other keys.
func validateAccountSecuritySetting(key string, val *string) (owned bool, err error) {
	v := *val
	switch key {
	case "notify_new_signin", settingBreachCheck, "terms_acceptance_required":
		if _, ok := parseStrictBool(v); !ok {
			return true, fmt.Errorf("%s must be true or false", key)
		}
	case settingStepUpMinutes:
		if _, ok := parseStrictInt(v, 1, stepUpMaxMinutes); !ok {
			return true, fmt.Errorf("%s must be a whole number from %d to %d", key, 1, stepUpMaxMinutes)
		}
	case settingAdminIdle:
		if _, ok := parseStrictInt(v, 0, idleLogoutMax); !ok {
			return true, fmt.Errorf("%s must be a whole number of minutes from 0 to %d (0 = never)", key, idleLogoutMax)
		}
	case settingAdminIPAllowlist:
		if len(v) > 4096 {
			return true, fmt.Errorf("allowlist too long")
		}
		_, canonical, e := parseIPList(v)
		if e != nil {
			return true, e
		}
		*val = strings.Join(canonical, "\n")
	case "privacy_url", "terms_url":
		v = strings.TrimSpace(v)
		if v != "" {
			u, e := url.Parse(v)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(v) > 500 || !plainText(v, 500) {
				return true, fmt.Errorf("%s must be an https:// address", key)
			}
		}
		*val = v
	case "terms_version":
		v = strings.TrimSpace(v)
		if !plainText(v, 40) {
			return true, fmt.Errorf("terms version must be at most 40 characters without control characters")
		}
		*val = v
	default:
		return false, nil
	}
	return true, nil
}

func (s *Server) adminStepUpMinutes() int {
	n, ok := parseStrictInt(s.St.Setting(settingStepUpMinutes), 1, stepUpMaxMinutes)
	if !ok {
		return stepUpDefaultMinutes
	}
	return n
}

// adminIdleLogoutMinutes: 0 means administrators follow idle_logout_minutes.
func (s *Server) adminIdleLogoutMinutes() int {
	n, ok := parseStrictInt(s.St.Setting(settingAdminIdle), 0, idleLogoutMax)
	if !ok {
		return adminIdleDefault
	}
	return n
}

// effectiveIdleMinutes is the inactivity window of a session: administrators
// get the stricter of the two windows when admin_idle_logout_minutes is set.
func effectiveIdleMinutes(global, admin int, isAdmin bool) int {
	if !isAdmin || admin == 0 {
		return global
	}
	if global == 0 || admin < global {
		return admin
	}
	return global
}

// accountSecurityBootstrap adds the public values the browser needs before sign-in.
func (s *Server) accountSecurityBootstrap(out map[string]any) {
	out["admin_idle_logout_minutes"] = s.adminIdleLogoutMinutes()
	out["privacy_url"] = s.St.Setting("privacy_url")
	out["terms_url"] = s.St.Setting("terms_url")
	required, _ := parseStrictBool(s.St.Setting("terms_acceptance_required"))
	out["terms_acceptance_required"] = required
	out["terms_version"] = s.St.Setting("terms_version")
}

// securitySettingKey reports the settings whose change needs a step-up.
func securitySettingKey(k string) bool {
	for _, p := range []string{"mfa_", "audit_", "ip_ban_", "account_password_", "admin_", "storage_", "backup_remote_"} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	switch k {
	case settingLocalLogin, "application_url", "provider_session_max_hours", settingBreachCheck, "notify_new_signin":
		return true
	}
	return false
}

// guardSettingsUpdate runs before PUT /api/settings stores anything: a change of
// a security setting needs a step-up, the administrator network list must keep
// the caller's own address, and requiring terms acceptance needs the terms.
// It has answered when it returns false.
func (s *Server) guardSettingsUpdate(w http.ResponseWriter, r *http.Request, updates map[string]string) bool {
	changed := func(k string) bool { v, ok := updates[k]; return ok && v != s.St.Setting(k) }
	for k := range updates {
		if securitySettingKey(k) && changed(k) {
			if !s.requireStepUp(w, r) {
				return false
			}
			break
		}
	}
	if changed(settingAdminIPAllowlist) {
		if msg := s.adminAllowlistExcludesCaller(r, updates[settingAdminIPAllowlist]); msg != "" {
			jerr(w, 400, msg)
			return false
		}
	}
	value := func(k string) string {
		if v, ok := updates[k]; ok {
			return v
		}
		return s.St.Setting(k)
	}
	if req, _ := parseStrictBool(value("terms_acceptance_required")); req && (value("terms_url") == "" || value("terms_version") == "") {
		jerr(w, 400, msgTermsSettingsNeeded)
		return false
	}
	return true
}

// ---------- the check ----------

// stepUpFresh reports whether the caller re-authenticated (or signed in) within
// the step-up window.
func (s *Server) stepUpFresh(r *http.Request, u *User) bool {
	auth := s.requestAuthTime(r)
	if auth.IsZero() {
		return false
	}
	window := time.Duration(s.adminStepUpMinutes()) * time.Minute
	now := time.Now()
	if now.Sub(auth) <= window {
		return true
	}
	s.stepUpMu.Lock()
	// The first access token and the stored session start of one sign-in can
	// differ by a second (two clock reads), so the neighbouring seconds count too.
	for d := int64(-1); d <= 1; d++ {
		if at, ok := s.stepUps[stepUpKey{u.ID, auth.Unix() + d}]; ok && now.Sub(at) <= window {
			s.stepUpMu.Unlock()
			return true
		}
	}
	s.stepUpMu.Unlock()
	// Cluster: the confirmation may have been made on another replica.
	for d := int64(-1); d <= 1; d++ {
		if at, ok := s.sharedStepUpAt(u.ID, auth.Unix()+d); ok && now.Sub(at) <= window {
			return true
		}
	}
	return false
}

// stepUpMethods lists how the caller can confirm: the second factor when there
// is one (preferred), otherwise the password; empty means "sign in again".
func (s *Server) stepUpMethods(u *User) []string {
	out := []string{}
	if s.mfaGlobal() != "off" && !u.IsGuest {
		f := s.loadFactors(u.ID)
		if s.mfaTOTPEnabled() && f.TOTP {
			out = append(out, "totp")
		}
		if s.mfaWebAuthnEnabled() && f.WebAuthn > 0 {
			out = append(out, "webauthn")
		}
	}
	if len(out) == 0 && u.passwordHash != "" {
		out = append(out, "password")
	}
	return out
}

// requireStepUp answers 401 {code: stepup_required} unless the caller has a
// fresh re-authentication. It has answered when it returns false.
func (s *Server) requireStepUp(w http.ResponseWriter, r *http.Request) bool {
	u := s.ctxUser(r)
	if u == nil {
		s.unauthenticated(w, r)
		return false
	}
	if s.stepUpFresh(r, u) {
		return true
	}
	methods := s.stepUpMethods(u)
	jout(w, http.StatusUnauthorized, map[string]any{"error": msgStepUpRequired, "code": stepUpCode, "methods": methods,
		"reauth": len(methods) == 0 || s.requestAuthTime(r).IsZero(), "minutes": s.adminStepUpMinutes()})
	return false
}

// stepUp is the route middleware for critical administrator actions.
func (s *Server) stepUp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.requireStepUp(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recordStepUp(uid int64, session time.Time) {
	now := time.Now()
	s.recordLocalStepUp(uid, session, now)
	// Cluster: before answering, so the next request may reach any replica.
	s.shareStepUp(uid, session, now)
}

func (s *Server) recordLocalStepUp(uid int64, session, now time.Time) {
	s.stepUpMu.Lock()
	defer s.stepUpMu.Unlock()
	if s.stepUps == nil {
		s.stepUps = map[stepUpKey]time.Time{}
	}
	if len(s.stepUps) >= stepUpStateCap {
		for k, at := range s.stepUps {
			if now.Sub(at) > stepUpMaxMinutes*time.Minute {
				delete(s.stepUps, k)
			}
		}
		if len(s.stepUps) >= stepUpStateCap {
			s.stepUps = map[stepUpKey]time.Time{} // never unbounded; people confirm again
		}
	}
	s.stepUps[stepUpKey{uid, session.Unix()}] = now
}

// ---------- endpoints ----------

// stepUpBegin: POST /api/auth/step-up/webauthn/begin (administrators). Returns
// a WebAuthn assertion challenge for the caller's own security keys.
func (s *Server) stepUpBegin(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	if u == nil || !u.Admin {
		jerr(w, 403, "forbidden")
		return
	}
	rp, rpOK := s.waRP()
	creds := s.waLoadCredentials(u.ID)
	if !rpOK || len(creds) == 0 || s.mfaGlobal() == "off" || !s.mfaWebAuthnEnabled() {
		jerr(w, 409, msgMFANotEnabled)
		return
	}
	challenge, err := webauthnlite.NewChallenge()
	if err != nil {
		jerr(w, 500, "could not create challenge")
		return
	}
	id, err := s.waBeginCeremony(waKindStepUp, u.ID, "", challenge)
	if err != nil {
		jerr(w, 500, "could not create challenge")
		return
	}
	jout(w, 200, map[string]any{"challenge_id": id, "options": webauthnlite.RequestOptions(rp, challenge, credIDs(creds))})
}

// stepUpConfirm: POST /api/auth/step-up {password | code | challenge_id+credential}
// (administrators). Wrong attempts count towards the account lock.
func (s *Server) stepUpConfirm(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	if u == nil || !u.Admin {
		jerr(w, 403, "forbidden")
		return
	}
	var b struct {
		Password    string              `json:"password"`
		Code        string              `json:"code"`
		ChallengeID string              `json:"challenge_id"`
		Credential  waBrowserCredential `json:"credential"`
	}
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	session := s.requestAuthTime(r)
	methods := s.stepUpMethods(u)
	if session.IsZero() || len(methods) == 0 {
		jout(w, http.StatusForbidden, map[string]any{"error": msgStepUpProvider, "code": stepUpCode, "reauth": true})
		return
	}
	has := func(m string) bool {
		for _, x := range methods {
			if x == m {
				return true
			}
		}
		return false
	}
	unlock := onceUnlock(s.stripe(&s.loginLocks, strconv.FormatInt(u.ID, 10)))
	defer unlock()
	if s.stepUpLocked(w, u) {
		return
	}
	method, ok := "", false
	switch {
	case b.ChallengeID != "" && has("webauthn"):
		method, ok = "webauthn", s.verifyStepUpAssertion(u, b.ChallengeID, b.Credential)
	case b.Code != "" && has("totp"):
		method, ok = "totp", s.verifyTOTPLogin(u, b.Code)
	case b.Password != "" && has("password"):
		method, ok = "password", bcrypt.CompareHashAndPassword([]byte(u.passwordHash), []byte(b.Password)) == nil
	default:
		jout(w, 400, map[string]any{"error": msgStepUpWrong, "methods": methods})
		return
	}
	if !ok {
		s.stepUpFailed(w, u)
		s.logEvent(u.ID, u.Username, "stepup_failed", "", method)
		unlock()
		time.Sleep(300 * time.Millisecond)
		jout(w, 400, map[string]any{"error": msgStepUpWrong, "methods": methods})
		return
	}
	s.clearAuthFailures(u.ID)
	s.recordStepUp(u.ID, session)
	s.logEvent(u.ID, u.Username, "stepup_ok", "", method)
	jout(w, 200, map[string]any{"ok": true, "minutes": s.adminStepUpMinutes()})
}

// verifyStepUpAssertion checks a WebAuthn assertion against a step-up challenge.
func (s *Server) verifyStepUpAssertion(u *User, challengeID string, c waBrowserCredential) bool {
	rp, rpOK := s.waRP()
	challenge, found := s.waTakeCeremony(challengeID, waKindStepUp, u.ID, "")
	if !rpOK || !found {
		return false
	}
	id, idOK := c.credentialID()
	if !idOK {
		return false
	}
	var stored *waStoredCred
	for _, sc := range s.waLoadCredentials(u.ID) {
		if subtle.ConstantTimeCompare(sc.ID, id) == 1 {
			sc := sc
			stored = &sc
			break
		}
	}
	if stored == nil {
		return false
	}
	clientData, e1 := webauthnlite.DecodeBase64URL(c.Response.ClientDataJSON)
	authData, e2 := webauthnlite.DecodeBase64URL(c.Response.AuthenticatorData)
	sig, e3 := webauthnlite.DecodeBase64URL(c.Response.Signature)
	if e1 != nil || e2 != nil || e3 != nil {
		return false
	}
	newCount, err := webauthnlite.VerifyAssertion(rp, challenge, stored.Credential, clientData, authData, sig)
	if err != nil {
		return false
	}
	s.St.Repos().MFA().RecordWebAuthnUse(context.Background(), stored.rowID, u.ID, int64(newCount))
	return true
}
