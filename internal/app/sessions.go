// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"database/sql"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

// Session management (ASVS 3.3.4). A session is a refresh-token family: it keeps
// one session_id across rotations, and the access tokens issued for it carry
// that id (claim "sid"). The authentication middleware refuses an access token
// whose session no longer has a refresh token, so revoking a session (or
// signing a user out everywhere) also ends its access tokens before their
// 15 minutes are up.

const (
	settingProviderSessionMaxHours = "provider_session_max_hours"
	providerSessionMaxHoursDefault = 24
	providerSessionMaxHoursLimit   = 720 // 30 days, the absolute session lifetime

	authMethodPassword = "password"
	authMethodProvider = "provider"
	authMethodInvite   = "invite"

	sessionUserAgentMax = 200

	msgProviderSessionExpired = "your sign-in through the identity provider has expired; sign in again"
	msgSessionNotFound        = "session not found"
)

// The setting is validated like every numeric setting (admin screen and
// configuration loader alike).
func init() {
	intSettings[settingProviderSessionMaxHours] = [2]int{1, providerSessionMaxHoursLimit}
}

// providerSessionMaxHours is the effective limit for sessions that exist only
// through a sign-in provider. A corrupt stored value falls back to the default.
func (s *Server) providerSessionMaxHours() int {
	n, ok := parseStrictInt(s.St.Setting(settingProviderSessionMaxHours), 1, providerSessionMaxHoursLimit)
	if !ok {
		return providerSessionMaxHoursDefault
	}
	return n
}

// providerOnlySession reports whether the provider limit applies: the session
// was started through a provider, or the account has no local password at all.
func providerOnlySession(u *User, method string) bool {
	return u != nil && !u.IsGuest && (method == authMethodProvider || u.passwordHash == "")
}

// cleanUserAgent keeps a printable, bounded user agent for the session list.
func cleanUserAgent(ua string) string {
	ua = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(ua, ""))
	return clip(strings.TrimSpace(ua), sessionUserAgentMax)
}

// sessionClientInfo returns the user agent and, only while audit_log_ip is on,
// the client address to store with a session. It reads settings, so it must run
// before a transaction takes the only database connection.
func (s *Server) sessionClientInfo(r *http.Request) (ua, ip string) {
	ua = cleanUserAgent(r.UserAgent())
	if s.auditLogIP() {
		ip = s.clientIP(r)
	}
	return ua, ip
}

// requestClaims returns the verified claims of the request's access token, or nil.
func (s *Server) requestClaims(r *http.Request) jwt.MapClaims {
	h := r.Header.Get("Authorization")
	tok := strings.TrimPrefix(h, "Bearer ")
	if tok == "" || tok == h {
		return nil
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return s.key(keyAccess), nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired()); err != nil || claims["purpose"] != "access" {
		return nil
	}
	return claims
}

// sessionMethodFor decides how a new session row was signed in: an explicit
// choice on the user (provider sign-in, invite), else the method of the session
// that is being re-issued (profile or factor change), else a password.
func (s *Server) sessionMethodFor(r *http.Request, u *User) string {
	if u.authMethod != "" {
		return u.authMethod
	}
	if u.IsGuest {
		return authMethodInvite
	}
	if c := s.requestClaims(r); c != nil {
		if m, _ := c["amr"].(string); m == authMethodProvider || m == authMethodPassword {
			return m
		}
	}
	return authMethodPassword
}

// sessionAlive reports whether the session of an access token still exists.
func (s *Server) sessionAlive(uid int64, sid string) bool {
	n, err := s.St.Repos().Sessions().CountLive(context.Background(), sid, uid, time.Now())
	return err == nil && n > 0
}

// sessionStillValid is the authentication middleware's check for a verified
// access token: a disabled account and a revoked session are refused at once
// (401, so the browser tries a refresh, which fails too). It also hands the
// session details to the user for tokens minted during this request.
func (s *Server) sessionStillValid(w http.ResponseWriter, u *User, claims jwt.MapClaims) bool {
	if u.Disabled {
		jerr(w, http.StatusUnauthorized, msgAccountDisabled)
		return false
	}
	sid, _ := claims["sid"].(string)
	if sid == "" {
		return true // tokens issued without a session id (tests, older releases) expire on their own
	}
	if !s.sessionAlive(u.ID, sid) {
		jerr(w, http.StatusUnauthorized, "session ended")
		return false
	}
	u.sessionID = sid
	u.authMethod, _ = claims["amr"].(string)
	return true
}

// recordLastLogin records the time of a successful sign-in (password, second
// factor, provider) for the access-review report.
func (s *Server) recordLastLogin(uid int64) {
	s.St.Repos().Users().RecordLastLogin(context.Background(), uid, time.Now().UTC())
}

// sessionSelfService reports the routes on which any signed-in account
// (auditors included) manages its own sessions.
func sessionSelfService(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case p == "/api/users/me/sessions":
		return r.Method == http.MethodGet
	case p == "/api/users/me/sessions/revoke-others":
		return r.Method == http.MethodPost
	case strings.HasPrefix(p, "/api/users/me/sessions/"):
		return r.Method == http.MethodDelete
	}
	return false
}

type sessionInfo struct {
	ID         string     `json:"id"`
	CreatedAt  *time.Time `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	UserAgent  string     `json:"user_agent"`
	IP         string     `json:"ip,omitempty"`
	Method     string     `json:"method"`
	Current    bool       `json:"current"`
}

func nullTimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

// listMySessions: GET /api/users/me/sessions, newest first; the session of the
// request is flagged as current.
func (s *Server) listMySessions(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	// A session has one live row; should a race leave two, the newest one is shown.
	live, err := s.St.Repos().Sessions().ListLive(context.Background(), u.ID, time.Now())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	out := []sessionInfo{}
	seen := map[string]int{}
	for _, ls := range live {
		si := sessionInfo{ID: ls.SessionID, ExpiresAt: ls.ExpiresAt, UserAgent: ls.UserAgent, IP: ls.IP, Method: ls.Method}
		started, used := nullTimeOf(ls.Started), nullTimeOf(ls.IssuedAt)
		if !started.Valid {
			started = used // older row: the issue time is the best known start
		}
		si.CreatedAt, si.LastUsedAt = nullTimePtr(started), nullTimePtr(used)
		si.ExpiresAt = si.ExpiresAt.UTC()
		if si.Method == "" {
			si.Method = authMethodPassword
		}
		si.Current = u.sessionID != "" && si.ID == u.sessionID
		if i, dup := seen[si.ID]; dup {
			if sessionBefore(si, out[i]) {
				out[i] = si
			}
			continue
		}
		seen[si.ID] = len(out)
		out = append(out, si)
	}
	// Newest activity first; the current session leads.
	sort.SliceStable(out, func(i, j int) bool { return sessionBefore(out[i], out[j]) })
	jout(w, 200, map[string]any{"sessions": out, "ip_logging": s.auditLogIP()})
}

func sessionBefore(a, b sessionInfo) bool {
	if a.Current != b.Current {
		return a.Current
	}
	at, bt := time.Time{}, time.Time{}
	if a.LastUsedAt != nil {
		at = *a.LastUsedAt
	}
	if b.LastUsedAt != nil {
		bt = *b.LastUsedAt
	}
	return at.After(bt)
}

// revokeMySession: DELETE /api/users/me/sessions/{id}. Revoking the current
// session signs this browser out as well.
func (s *Server) revokeMySession(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	sid := chi.URLParam(r, "id")
	if sid == "" || len(sid) > 64 {
		jerr(w, 404, msgSessionNotFound)
		return
	}
	n, err := s.St.Repos().Sessions().RevokeSession(context.Background(), u.ID, sid)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if n == 0 {
		jerr(w, 404, msgSessionNotFound)
		return
	}
	current := sid == u.sessionID
	detail := "one session"
	if current {
		detail = "current session"
	}
	s.logEvent(u.ID, u.Username, "session_revoked", s.userTarget(u.ID), detail)
	jout(w, 200, map[string]any{"ok": true, "current": current})
}

// revokeOtherSessions: POST /api/users/me/sessions/revoke-others keeps only the
// session of this request.
func (s *Server) revokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	n, err := s.St.Repos().Sessions().RevokeOtherSessions(context.Background(), u.ID, u.sessionID)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	s.logEvent(u.ID, u.Username, "session_revoked", s.userTarget(u.ID), "other sessions: "+strconv.FormatInt(n, 10))
	jout(w, 200, map[string]any{"ok": true, "revoked": n})
}

// adminRevokeSessions: POST /api/users/{id}/sessions/revoke (administrators)
// signs a user out everywhere: every refresh token is deleted, which also ends
// the access tokens of those sessions at once.
func (s *Server) adminRevokeSessions(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		jerr(w, 404, "not found")
		return
	}
	if guest, err := s.St.Repos().Users().IsGuest(context.Background(), id); err != nil || guest {
		jerr(w, 404, "not found")
		return
	}
	n, err := s.St.Repos().Sessions().RevokeAllForUser(context.Background(), id)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	me := s.ctxUser(r)
	s.logEvent(me.ID, me.Username, "user_signed_out", s.userTarget(id), "sessions: "+strconv.FormatInt(n, 10))
	jout(w, 200, map[string]any{"ok": true, "revoked": n})
}
