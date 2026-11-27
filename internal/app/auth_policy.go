// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/go-chi/chi/v5"
	"github.com/sendora-app/sendora/internal/store"
)

const defaultUserQuotaBytes int64 = store.DefaultQuotaBytes
const maxSafeQuotaBytes int64 = store.MaxSafeQuotaBytes

// Nil fields (including JSON null) preserve an update. Explicit quota always
// selects an override; true without quota resets inheritance.
func quotaChoice(quota *int64, inherits *bool) (*bool, bool) {
	if !validQuotaBytes(quota) || (inherits != nil && ((*inherits && quota != nil) || (!*inherits && quota == nil))) {
		return nil, false
	}
	if quota != nil {
		override := false
		return &override, true
	}
	return inherits, true
}

func validQuotaBytes(q *int64) bool {
	return q == nil || (*q >= 0 && *q <= maxSafeQuotaBytes)
}

// recentSignIn is how long after signing in an account without a local password
// may change its password or email address.
const recentSignIn = 10 * time.Minute

const msgRecentSignIn = "sign in again to change your password or email address"

// dummyHash makes a failed lookup cost as much as a password check, so response
// times do not reveal whether an account exists.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("sendora-timing-equaliser"), bcryptCost)

// usernameOf returns the username for the activity log ("" when unknown).
func (s *Server) usernameOf(id int64) string {
	name, _ := s.St.Repos().Users().Username(context.Background(), id)
	return name
}

// onceUnlock wraps a lock release so it can be called early (before the failure
// delay, so a slow rejection never holds the account lock) and again by defer.
func onceUnlock(unlock func()) func() { return sync.OnceFunc(unlock) }

func rejectLogin(w http.ResponseWriter) {
	time.Sleep(300 * time.Millisecond)
	jerr(w, http.StatusUnauthorized, "invalid credentials")
}

func (s *Server) unlockLogin(w http.ResponseWriter, r *http.Request) {
	if u := s.ctxUser(r); u == nil || !u.Admin {
		jerr(w, http.StatusForbidden, "forbidden")
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		jerr(w, http.StatusBadRequest, "invalid user")
		return
	}
	unlock := s.stripe(&s.loginLocks, strconv.FormatInt(id, 10))
	defer unlock()
	n, err := s.St.Repos().Users().ClearLoginLock(context.Background(), id)
	if err != nil {
		jerr(w, http.StatusInternalServerError, "unlock failed")
		return
	}
	if n != 1 {
		jerr(w, http.StatusNotFound, "not found")
		return
	}
	me := s.ctxUser(r)
	s.logEvent(me.ID, me.Username, "user_unlocked", s.userTarget(id), "")
	jout(w, http.StatusOK, map[string]any{"ok": true})
}
