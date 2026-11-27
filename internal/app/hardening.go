// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// markAuthFailure tells the request-security middleware that this request failed
// a credential check, so it counts towards the IP ban even though the status
// code (400, or a 401 that must not be mistaken for an expired session) alone
// would not.
func markAuthFailure(w http.ResponseWriter) {
	for w != nil {
		if rec, ok := w.(*statusRecorder); ok {
			rec.failed = true
			return
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}

// failThrottle counts failures per key in a fixed window and blocks the key for
// a while once the limit is reached. It is in memory and bounded.
type failThrottle struct {
	mu sync.Mutex
	m  map[string]*failEntry
}

type failEntry struct {
	count        int
	windowEnds   time.Time
	blockedUntil time.Time
}

const maxThrottleKeys = 8192

// blocked reports whether the key is currently refused and for how long.
func (t *failThrottle) blocked(key string) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[key]
	if e == nil {
		return 0, false
	}
	if wait := time.Until(e.blockedUntil); wait > 0 {
		return wait, true
	}
	return 0, false
}

// fail records one failure; at limit failures within window the key is blocked
// for block.
func (t *failThrottle) fail(key string, limit int, window, block time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if t.m == nil {
		t.m = map[string]*failEntry{}
	}
	e := t.m[key]
	if e == nil || (!now.Before(e.windowEnds) && !now.Before(e.blockedUntil)) {
		if e == nil && len(t.m) >= maxThrottleKeys {
			t.evict(now)
		}
		e = &failEntry{windowEnds: now.Add(window)}
		t.m[key] = e
	}
	e.count++
	if e.count >= limit {
		e.blockedUntil = now.Add(block)
		e.count = 0
		e.windowEnds = now.Add(window)
	}
}

func (t *failThrottle) clear(key string) {
	t.mu.Lock()
	delete(t.m, key)
	t.mu.Unlock()
}

// evict drops expired entries, then (if still full) an arbitrary quarter that
// are not currently blocking. The caller holds t.mu.
func (t *failThrottle) evict(now time.Time) {
	for k, e := range t.m {
		if !now.Before(e.windowEnds) && !now.Before(e.blockedUntil) {
			delete(t.m, k)
		}
	}
	if len(t.m) < maxThrottleKeys {
		return
	}
	n := len(t.m) / 4
	for k, e := range t.m {
		if n <= 0 {
			break
		}
		if !now.Before(e.blockedUntil) {
			delete(t.m, k)
			n--
		}
	}
}

// Failure limits for the unauthenticated entry points (in addition to the
// per-address limits in security.go).
const (
	shareUnlockLimit  = 10
	shareUnlockWindow = 10 * time.Minute
	shareUnlockBlock  = 10 * time.Minute
	setupFailLimit    = 10
	setupFailWindow   = time.Minute
	setupFailBlock    = time.Minute
)

// oidcSlotCount bounds concurrent OIDC start/callback requests separately from
// the shared authentication slots, so a slow identity provider cannot starve
// password logins.
const oidcSlotCount = 8

// stepUpLocked refuses a current-password check while the account is locked by
// failed attempts (the counter is shared with the login). The caller returns
// when it reports true.
func (s *Server) stepUpLocked(w http.ResponseWriter, u *User) bool {
	fresh, err := s.userByID(u.ID)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	if fresh.loginLockedUntil <= now {
		return false
	}
	w.Header().Set("Retry-After", strconv.FormatInt(fresh.loginLockedUntil-now+1, 10))
	markAuthFailure(w)
	jerr(w, http.StatusTooManyRequests, "too many failed password attempts; try again later")
	return true
}

// stepUpFailed counts a wrong current password against the account (same
// counter and lockout as the login) and against the client address.
func (s *Server) stepUpFailed(w http.ResponseWriter, u *User) {
	if fresh, err := s.userByID(u.ID); err == nil {
		s.noteAuthFailure(fresh)
	}
	markAuthFailure(w)
}
