// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sendora-app/sendora/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// These tests use isolated temporary databases and in-process handlers, not servers.
func lockoutServer(t *testing.T) (*Server, *User) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	legacyTestDefaults(t, st)
	t.Cleanup(func() { st.DB.Close() })
	if err := st.MigratePolicy(); err != nil {
		t.Fatal(err)
	}
	s := &Server{St: st, Secret: []byte("lockout-test-secret")}
	s.passwordScreenOff = true
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	res, err := rawExec(t, st, `INSERT INTO users(username,email,password_hash,email_verified) VALUES('alice','alice@example.org',?,1)`, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	u, err := s.userByID(id)
	if err != nil {
		t.Fatal(err)
	}
	return s, u
}

func lockoutRequest(s *Server, handler http.HandlerFunc, path string, body any, actor *User) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	if actor != nil {
		r.Header.Set("Authorization", "Bearer "+s.accessToken(actor)) // a fresh sign-in (step-up)
		r = withUser(r, actor)
	}
	rctx := chi.NewRouteContext()
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 3 && parts[1] == "users" {
		rctx.URLParams.Add("id", parts[2])
	}
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func lockoutLogin(s *Server, username, password string) *httptest.ResponseRecorder {
	return lockoutRequest(s, s.login, "/api/auth/login", map[string]any{"username": username, "password": password}, nil)
}

func lockoutState(t *testing.T, s *Server, id int64, failures int64, locked bool) int64 {
	t.Helper()
	u, err := s.userByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if u.loginFailures != failures || (u.loginLockedUntil > time.Now().Unix()) != locked {
		t.Fatalf("state: failures=%d locked_until=%d, want failures=%d locked=%v", u.loginFailures, u.loginLockedUntil, failures, locked)
	}
	return u.loginLockedUntil
}

func TestLoginLockoutAliasesRestartExpiryAndSessions(t *testing.T) {
	s, u := lockoutServer(t)
	oldAccess := s.accessToken(u)
	w := httptest.NewRecorder()
	if !s.issueSession(w, httptest.NewRequest("POST", "/api/auth/login", nil), u) {
		t.Fatal("issue session")
	}
	cookie := w.Result().Cookies()[0]
	for i := 0; i < 5; i++ {
		username := "alice"
		if i%2 == 1 {
			username = "ALICE@example.org"
		}
		if r := lockoutLogin(s, username, "wrong"); r.Code != 401 {
			t.Fatal(r.Code, r.Body.String())
		}
	}
	until := lockoutState(t, s, u.ID, 5, true)
	// Reopen the database and recreate the server, retaining only its secret.
	dir, secret := s.St.DataDir, s.Secret
	if err := s.St.DB.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	legacyTestDefaults(t, st)
	t.Cleanup(func() { st.DB.Close() })
	s = &Server{St: st, Secret: secret}
	if r := lockoutLogin(s, "alice", "password123"); r.Code != 401 {
		t.Fatal(r.Code)
	}
	if got := lockoutState(t, s, u.ID, 5, true); got != until {
		t.Fatal("active lock extended")
	}
	request := httptest.NewRequest("GET", "/api/users/me", nil)
	request.Header.Set("Authorization", "Bearer "+oldAccess)
	w = httptest.NewRecorder()
	s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, request)
	if w.Code != 204 {
		t.Fatal("lock revoked access session", w.Code, w.Body.String())
	}
	request = httptest.NewRequest("POST", "/api/auth/refresh", nil)
	request.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.refresh(w, request)
	if w.Code != 200 {
		t.Fatal("lock revoked refresh session", w.Code, w.Body.String())
	}
	if _, err := s.St.DB.Exec(`UPDATE users SET login_locked_until=? WHERE id=?`, time.Now().Unix()-1, u.ID); err != nil {
		t.Fatal(err)
	}
	if r := lockoutLogin(s, "alice", "wrong"); r.Code != 401 {
		t.Fatal(r.Code)
	}
	lockoutState(t, s, u.ID, 1, false)
	if r := lockoutLogin(s, "alice", "password123"); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	lockoutState(t, s, u.ID, 0, false)
}

func TestLoginLockoutConcurrentAttempts(t *testing.T) {
	s, u := lockoutServer(t)
	var wg sync.WaitGroup
	codes := make(chan int, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			username := "alice"
			if i%2 == 1 {
				username = "alice@example.org"
			}
			codes <- lockoutLogin(s, username, "wrong").Code
		}(i)
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 401 {
			t.Fatal(code)
		}
	}
	lockoutState(t, s, u.ID, 5, true)
}

func TestLoginUnlockAdminAndPasswordMutations(t *testing.T) {
	s, u := lockoutServer(t)
	setLocked := func() {
		t.Helper()
		if _, err := s.St.DB.Exec(`UPDATE users SET login_failures=5,login_locked_until=? WHERE id=?`, time.Now().Add(15*time.Minute).Unix(), u.ID); err != nil {
			t.Fatal(err)
		}
	}
	setLocked()
	if r := lockoutRequest(s, s.unlockLogin, "/api/users/1/unlock-login", nil, u); r.Code != 403 {
		t.Fatal("nonadmin unlock", r.Code)
	}
	if r := lockoutRequest(s, s.unlockLogin, "/api/users/1/unlock-login", nil, nil); r.Code != 403 {
		t.Fatal("anonymous unlock", r.Code)
	}
	admin := *u
	admin.Admin = true
	if r := lockoutRequest(s, s.unlockLogin, "/api/users/1/unlock-login", nil, &admin); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	lockoutState(t, s, u.ID, 0, false)
	setLocked()
	if r := lockoutRequest(s, s.forceReset, "/api/users/1/force-reset", nil, &admin); r.Code != 200 {
		t.Fatal(r.Code)
	}
	lockoutState(t, s, u.ID, 5, true)
	if r := lockoutRequest(s, s.updateUser, "/api/users/1", map[string]any{"name": "Alice", "email": u.Email, "admin": true}, &admin); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	lockoutState(t, s, u.ID, 5, true)
	if r := lockoutRequest(s, s.updateUser, "/api/users/1", map[string]any{"name": "Alice", "email": u.Email, "admin": true, "password": "replacement123"}, &admin); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	lockoutState(t, s, u.ID, 0, false)
	setLocked()
	const tok = "reset-token"
	if _, err := s.St.DB.Exec(`INSERT INTO password_resets(hash,user_id,expires_at) VALUES(?,?,?)`, hashToken(tok), u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := lockoutRequest(s, s.resetPassword, "/api/auth/reset-password", map[string]any{"Token": tok, "Password": "resetpassword123"}, nil); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	lockoutState(t, s, u.ID, 0, false)
	if r := lockoutLogin(s, "alice", "resetpassword123"); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	setLocked()
	current, err := s.userByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A locked account cannot be used to guess or confirm the current password.
	if r := lockoutRequest(s, s.updateMe, "/api/users/me", map[string]any{"email": u.Email, "current_password": "resetpassword123", "password": "selfpassword123"}, current); r.Code != 429 {
		t.Fatal(r.Code, r.Body.String())
	}
	lockoutState(t, s, u.ID, 5, true)
	s.clearAuthFailures(u.ID)
	if r := lockoutRequest(s, s.updateMe, "/api/users/me", map[string]any{"email": u.Email, "current_password": "resetpassword123", "password": "selfpassword123"}, current); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	lockoutState(t, s, u.ID, 0, false)
}

func TestLoginUnlockRouteAuthorization(t *testing.T) {
	s, u := lockoutServer(t)
	router := s.Router()
	request := func(token string) int {
		r := httptest.NewRequest("POST", "/api/users/"+strconv.FormatInt(u.ID, 10)+"/unlock-login", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w.Code
	}
	if code := request(""); code != 401 {
		t.Fatal("anonymous route", code)
	}
	token := s.accessToken(u)
	if code := request(token); code != 403 {
		t.Fatal("nonadmin route", code)
	}
	if _, err := s.St.DB.Exec(`UPDATE users SET admin=1,login_failures=5,login_locked_until=? WHERE id=?`, time.Now().Add(15*time.Minute).Unix(), u.ID); err != nil {
		t.Fatal(err)
	}
	if code := request(token); code != 200 {
		t.Fatal("admin route", code)
	}
	lockoutState(t, s, u.ID, 0, false)
	if code := request(token); code != 200 {
		t.Fatal("unlock revoked token", code)
	}
}

func TestLoginLockoutUnverifiedPasswordlessAndUnknown(t *testing.T) {
	s, u := lockoutServer(t)
	if _, err := s.St.DB.Exec(`UPDATE users SET login_failures=3,email_verified=0 WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if r := lockoutLogin(s, "alice", "password123"); r.Code != 403 {
		t.Fatal(r.Code)
	}
	lockoutState(t, s, u.ID, 0, false)
	for _, kind := range []string{"passwordless", "guest"} {
		if _, err := s.St.DB.Exec(`UPDATE users SET password_hash=CASE WHEN ?='passwordless' THEN '' ELSE ? END,is_guest=? WHERE id=?`, kind, u.passwordHash, kind == "guest", u.ID); err != nil {
			t.Fatal(err)
		}
		if r := lockoutLogin(s, "alice", "wrong"); r.Code != 401 {
			t.Fatal(kind, r.Code)
		}
		lockoutState(t, s, u.ID, 0, false)
	}
	if r := lockoutLogin(s, "unknown", "wrong"); r.Code != 401 {
		t.Fatal(r.Code)
	}
}

func TestUserQuotaPolicyAPI(t *testing.T) {
	s, u := lockoutServer(t)
	admin := *u
	admin.Admin = true
	for i, q := range []any{int64(-1), int64(1 << 53), 1.5} {
		r := lockoutRequest(s, s.createUser, "/api/users", map[string]any{"username": fmt.Sprint("bad", i), "password": "password123", "quota_bytes": q}, &admin)
		if r.Code != 400 {
			t.Fatal(q, r.Code, r.Body.String())
		}
	}
	for _, q := range []int64{0, 123} {
		r := lockoutRequest(s, s.updateUser, "/api/users/1", map[string]any{"email": u.Email, "admin": true, "quota_bytes": q}, &admin)
		if r.Code != 200 {
			t.Fatal(r.Code, r.Body.String())
		}
		got, err := s.userByID(u.ID)
		if err != nil || got.QuotaBytes != q {
			t.Fatal(got, err)
		}
	}
	r := lockoutRequest(s, s.updateUser, "/api/users/1", map[string]any{"email": u.Email, "admin": true}, &admin)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	got, _ := s.userByID(u.ID)
	if got.QuotaBytes != 123 {
		t.Fatal("omitted quota not preserved")
	}
	r = lockoutRequest(s, s.updateMe, "/api/users/me", map[string]any{"email": u.Email, "quota_bytes": 0}, got)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	got, _ = s.userByID(u.ID)
	if got.QuotaBytes != 123 {
		t.Fatal("self edited quota")
	}
	r = lockoutRequest(s, s.me, "/api/users/me", nil, got)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var profile map[string]any
	json.Unmarshal(r.Body.Bytes(), &profile)
	if profile["quota_bytes"] != float64(123) || profile["storage_used_bytes"] != float64(0) {
		t.Fatal(profile)
	}
	r = lockoutRequest(s, s.listUsers, "/api/users", nil, &admin)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var users []map[string]any
	json.Unmarshal(r.Body.Bytes(), &users)
	if len(users) != 1 || users[0]["quota_bytes"] != float64(123) || users[0]["login_locked_until"] != float64(0) {
		t.Fatal(users)
	}
	var ordinary map[string]any
	data, _ := json.Marshal(got)
	json.Unmarshal(data, &ordinary)
	if _, ok := ordinary["login_locked_until"]; ok {
		t.Fatal("lock leaked in ordinary user")
	}
	for _, name := range []string{"default", "zero"} {
		body := map[string]any{"username": name, "password": "password123"}
		want := defaultUserQuotaBytes
		if name == "zero" {
			body["quota_bytes"] = 0
			want = 0
		}
		r := lockoutRequest(s, s.createUser, "/api/users", body, &admin)
		if r.Code != 201 {
			t.Fatal(r.Code, r.Body.String())
		}
		var created User
		if err := json.Unmarshal(r.Body.Bytes(), &created); err != nil || created.QuotaBytes != want {
			t.Fatal(created, err)
		}
	}
}

func TestUserDeletionCleansStagedReverseGuestUploads(t *testing.T) {
	s, u := lockoutServer(t)
	res, err := rawExec(t, s.St, `INSERT INTO users(username,is_guest) VALUES('guest',1)`)
	if err != nil {
		t.Fatal(err)
	}
	guestID, _ := res.LastInsertId()
	res, err = s.St.DB.Exec(`INSERT INTO reverse_invites(token,user_id,guest_user_id,expires_at) VALUES('invite',?,?,?)`, u.ID, guestID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inviteID, _ := res.LastInsertId()
	if _, err := s.St.DB.Exec(`INSERT INTO upload_sessions(id,user_id,quota_owner_id,invite_id) VALUES('1111111111111111',?,?,NULL),('2222222222222222',?,?,?)`, u.ID, u.ID, guestID, u.ID, inviteID); err != nil {
		t.Fatal(err)
	}
	if _, err := rawExec(t, s.St, `INSERT INTO shares(user_id,long_id,invite_id) VALUES(?,'aaaaaaaaaaaaaaaa',NULL),(?,'bbbbbbbbbbbbbbbb',?)`, u.ID, guestID, inviteID); err != nil {
		t.Fatal(err)
	}
	dirs := []string{s.uploadDir("1111111111111111"), s.uploadDir("2222222222222222"), filepath.Join(s.St.DataDir, "shares", "aaaaaaaaaaaaaaaa"), filepath.Join(s.St.DataDir, "shares", "bbbbbbbbbbbbbbbb")}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	actor := &User{ID: 999, Admin: true}
	r := lockoutRequest(s, s.deleteUser, "/api/users/"+strconv.FormatInt(u.ID, 10), nil, actor)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	for _, table := range []string{"users", "upload_sessions", "shares", "reverse_invites"} {
		var count int
		if err := s.St.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal(table, count, err)
		}
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("directory retained", dir, err)
		}
	}
}
