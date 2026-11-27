// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type requestBudget struct {
	count   int
	expires time.Time
}

const maxSecurityBuckets = 4096

// Budgets are keyed by the client address from clientIP: the TCP peer, or the
// forwarded client address only when the peer is a configured trusted proxy.
// The map is bounded; when it is full, expired entries and then the entries
// closest to expiry are evicted instead of refusing every new client.
func (s *Server) allowRequest(key string, limit int, window time.Duration) bool {
	return s.allowN(key, 1, limit, window)
}

// allowN charges n units against a fixed-window budget in one step.
func (s *Server) allowN(key string, n, limit int, window time.Duration) bool {
	if allowed, handled := s.sharedAllowN(key, n, limit, window); handled {
		return allowed
	}
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	now := time.Now()
	if s.securityBuckets == nil {
		s.securityBuckets = make(map[string]requestBudget)
	}
	b := s.securityBuckets[key]
	if !now.Before(b.expires) {
		if len(s.securityBuckets) >= maxSecurityBuckets {
			s.evictBuckets(now)
		}
		b = requestBudget{expires: now.Add(window)}
	}
	if b.count+n > limit {
		return false
	}
	b.count += n
	s.securityBuckets[key] = b
	return true
}

// evictBuckets frees room: all expired budgets first, then (if still full) the
// quarter of entries that expire soonest. The caller holds securityMu.
func (s *Server) evictBuckets(now time.Time) {
	for k, v := range s.securityBuckets {
		if !now.Before(v.expires) {
			delete(s.securityBuckets, k)
		}
	}
	if len(s.securityBuckets) < maxSecurityBuckets {
		return
	}
	type entry struct {
		key     string
		expires time.Time
	}
	all := make([]entry, 0, len(s.securityBuckets))
	for k, v := range s.securityBuckets {
		all = append(all, entry{k, v.expires})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].expires.Before(all[j].expires) })
	for _, e := range all[:len(all)/4+1] {
		delete(s.securityBuckets, e.key)
	}
}

// routeClass names the rate-limit bucket of a sensitive route so that flooding
// one kind of request (say, share unlock) cannot lock others out (say, login).
// The empty class means the route is not rate limited here.
func routeClass(r *http.Request) (class string, limit int) {
	p := r.URL.Path
	switch {
	case p == "/api/setup":
		return "setup", 60
	case p == "/api/reverse-shares/accept" && r.Method == http.MethodPost:
		return "accept", 60
	case strings.HasSuffix(p, "/unlock"):
		return "unlock", 60
	case strings.HasPrefix(p, "/api/auth/oidc/"):
		return "oidc", 60
	case r.Method == http.MethodPost && (strings.HasPrefix(p, "/api/auth/mfa/") || strings.HasPrefix(p, "/api/users/me/mfa/")):
		return "mfa", 30
	case r.Method == http.MethodPut && p == "/api/users/me":
		return "profile", 60
	case r.Method == http.MethodPost && (p == "/api/auth/refresh" || p == "/api/auth/logout"):
		return "refresh", 240
	case r.Method == http.MethodPost && p == "/api/auth/login":
		return "login", 60
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/api/auth/"):
		return "auth", 60
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && isPublicTransfer(p):
		return "download", 120
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/api/i18n/"):
		return "i18n", 120
	}
	return "", 0
}

// isPublicTransfer matches /api/shares/{id}/download[/...] and /preview/...
func isPublicTransfer(p string) bool {
	rest := strings.TrimPrefix(p, "/api/shares/")
	if rest == p {
		return false
	}
	parts := strings.SplitN(rest, "/", 3)
	return len(parts) >= 2 && (parts[1] == "download" || parts[1] == "preview")
}

// rateLimitWindow is the period of the per-route request budgets: one minute,
// unless a test lengthens it (slow test machines must still reach the limit).
func (s *Server) rateLimitWindow() time.Duration {
	if s.rateWindow > 0 {
		return s.rateWindow
	}
	return time.Minute
}

func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if s.requestHTTPS(r) || s.secureCookies(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=15552000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.Method == http.MethodPost && (strings.HasPrefix(r.URL.Path, "/api/auth/") || r.URL.Path == "/api/setup") {
			ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
			if ct != "" && ct != "application/json" {
				jerr(w, 415, "application/json required")
				return
			}
		}
		// Cookies are never sufficient authority for a cross-origin unsafe request.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				jerr(w, 403, "cross-origin request refused")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && !s.sameOrigin(r, origin) {
				jerr(w, 403, "cross-origin request refused")
				return
			}
		}
		class, classLimit := routeClass(r)
		sensitive := class != "" && class != "download"
		// Apply before acquiring a slot or entering handlers that read request bodies.
		// Do not clear this deadline on return: net/http may still drain unread bytes.
		if r.Body != nil && r.Body != http.NoBody {
			rc := http.NewResponseController(w)
			timeout := s.requestBodyTimeout
			if timeout <= 0 {
				timeout = 30 * time.Second
			}
			// Chunk uploads and the (up to 4 GiB) database import are large transfers:
			// they only need to keep moving at a minimum speed, not finish in 30 s.
			if (r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/uploads/")) ||
				(r.Method == http.MethodPost && r.URL.Path == "/api/backups/import") {
				timeout = s.transferTimeout()
				r.Body = &idleRequestBody{ReadCloser: r.Body, controller: rc, timeout: timeout}
			}
			if err := rc.SetReadDeadline(time.Now().Add(timeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
				jerr(w, 503, "request deadline unavailable")
				return
			}
		}
		if sensitive && class != "refresh" && class != "i18n" {
			if wait, banned := s.ipBlocked(s.clientIP(r)); banned {
				w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
				jerr(w, 429, "too many failed attempts from this address; try again later")
				return
			}
		}
		// Only failed sign-in steps count, not signed-in requests whose access token
		// expired (for example the two-step settings under /api/users/me). Routes
		// that mix both kinds (setup, profile update, the step-up endpoints behind
		// an access token) count only the requests a handler flagged as a rejected
		// credential check (markAuthFailure).
		signInStep := class == "login" || class == "unlock" || class == "auth" || (class == "mfa" && strings.HasPrefix(r.URL.Path, "/api/auth/mfa/"))
		flagged := class == "setup" || class == "profile" || (class == "mfa" && strings.HasPrefix(r.URL.Path, "/api/users/me/mfa/"))
		if sensitive && (signInStep || flagged) {
			rec := &statusRecorder{ResponseWriter: w, status: 200}
			w = rec
			ip := s.clientIP(r)
			defer func() {
				if rec.failed || (signInStep && (rec.status == 401 || rec.status == 403)) {
					s.noteIPFailure(ip)
				}
			}()
		}
		if sensitive {
			// OIDC redirects wait on an external identity provider: they get their
			// own pool so a slow issuer cannot occupy the slots password logins need.
			slots := s.authSlots
			if class == "oidc" && s.oidcSlots != nil {
				slots = s.oidcSlots
			}
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				jerr(w, 429, "too many concurrent authentication requests")
				return
			}
			// IPv6 clients are grouped by /64, like the address block, so rotating
			// addresses inside one prefix does not multiply the budget.
			if !s.allowRequest(class+":"+ipBanKey(s.clientIP(r)), classLimit, s.rateLimitWindow()) {
				w.Header().Set("Retry-After", "60")
				jerr(w, 429, "too many requests")
				return
			}
		}
		if class == "download" && !s.allowRequest("download:"+ipBanKey(s.clientIP(r)), classLimit, s.rateLimitWindow()) {
			w.Header().Set("Retry-After", "60")
			jerr(w, 429, "too many download requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) sameOrigin(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	expected := s.BaseURL
	if expected == "" {
		expected = s.St.Setting("application_url")
	}
	if expected == "" {
		scheme := "http"
		if s.requestHTTPS(r) {
			scheme = "https"
		}
		expected = scheme + "://" + r.Host
	}
	e, err := url.Parse(expected)
	if err != nil || u.Scheme != e.Scheme {
		return false
	}
	if strings.EqualFold(u.Host, e.Host) {
		return true
	}
	// localhost, 127.0.0.0/8 and ::1 reach the same local server: treat them as
	// one origin when the configured address is loopback, on the same port.
	return isLoopbackHost(u.Hostname()) && isLoopbackHost(e.Hostname()) && originPort(u) == originPort(e)
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func originPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (s *Server) secureCookies(r *http.Request) bool {
	if s.requestHTTPS(r) {
		return true
	}
	base := s.BaseURL
	if base == "" {
		base = s.St.Setting("application_url")
	}
	u, err := url.Parse(base)
	return err == nil && u.Scheme == "https"
}

func (s *Server) credentialVersion(u *User) string {
	h := hmac.New(sha256.New, s.key(keyCredential))
	fmt.Fprintf(h, "%d:%s:%s:%t", u.ID, u.passwordHash, u.Email, u.MustChangePassword)
	if u.mfaEpoch != 0 {
		fmt.Fprintf(h, ":mfa%d", u.mfaEpoch) // factor changes revoke older tokens; unchanged for epoch 0
	}
	return hex.EncodeToString(h.Sum(nil))
}

func canonicalEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", nil
	}
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email {
		return "", fmt.Errorf("valid email address required")
	}
	return strings.ToLower(a.Address), nil
}

func (s *Server) emailAvailable(email string, except int64) bool {
	if email == "" {
		return true
	}
	n, err := s.St.Repos().Users().CountOtherWithEmail(context.Background(), email, except)
	return err == nil && n == 0
}
