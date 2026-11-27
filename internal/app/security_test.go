// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestIdentitySecurity(t *testing.T) {
	e := newEnv(t)
	e.useSMTP(newSMTP(t))
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	e.s.St.SetSetting("allow_self_registration", "true")
	// A taken address gets the same answer as a successful registration (no
	// enumeration), but no account is created.
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "duplicate", "email": "ADMIN@x.io", "password": "password123"}), 201, "duplicate case-insensitive email")
	var dup int
	qByName(e.s.St, `SELECT COUNT(*) FROM users WHERE username='duplicate'`).Scan(&dup)
	if dup != 0 {
		t.Fatal("duplicate case-insensitive email created an account")
	}
	e.want(e.do("PUT", "/api/users/me", bob, map[string]any{"name": "Bob", "email": "admin@x.io", "current_password": "password123"}), 400, "email takeover")
	e.want(e.do("PUT", "/api/users/me", bob, map[string]any{"name": "Bob", "email": "new@x.io"}), 400, "email requires current password")
	updated := e.do("PUT", "/api/users/me", bob, map[string]any{"name": "Bob", "email": "new@x.io", "current_password": "password123"})
	e.want(updated, 200, "change email")
	if updated.J()["user"].(map[string]any)["email_verified"] != false {
		t.Fatal("new address treated as verified")
	}
	e.want(e.do("GET", "/api/users/me", bob, nil), 401, "email change revokes prior access")
	bob = updated.S("access_token")
	e.want(e.do("PUT", "/api/users/me", bob, map[string]any{"name": "Bobby", "email": "new@x.io"}), 200, "name-only update")
	e.want(e.do("GET", "/api/users/me", bob, nil), 200, "name-only update preserves token")
	inv := e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{})
	tok := inv.S("url")[strings.LastIndex(inv.S("url"), "/")+1:]
	acc := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": tok})
	guest := acc.S("access_token")
	e.want(e.do("PUT", "/api/users/me", guest, map[string]any{"password": "password123", "email": "guest@x.io"}), 403, "guest cannot create credentials")
	e.want(e.do("GET", "/api/shares", guest, nil), 403, "guest account APIs blocked")
	meta := map[string]any{"files": []map[string]any{{"name": "a", "size": 0}}}
	e.want(e.do("POST", "/api/uploads", guest, meta), 201, "guest upload")
	e.want(e.do("POST", "/api/uploads", guest, meta), 429, "single guest upload")
}

func TestTokenSecurity(t *testing.T) {
	e := newEnv(t)
	access := e.setup()
	for _, claims := range []jwt.MapClaims{
		{"sub": "1"},
		{"sub": "1", "purpose": "share", "exp": time.Now().Add(time.Hour).Unix()},
		{"sub": "1", "purpose": "access", "credential": "wrong", "exp": time.Now().Add(time.Hour).Unix()},
	} {
		token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(e.s.key(keyAccess))
		e.want(e.do("GET", "/api/users/me", token, nil), 401, "token purpose/expiration/fingerprint")
	}
	e.want(e.do("POST", "/api/auth/logout", access, nil), 200, "logout")
	e.want(e.do("GET", "/api/users/me", access, nil), 401, "logout revokes access")
	fresh := e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"})
	e.want(fresh, 200, "logout permits fresh login")
	if fresh.S("access_token") == access {
		t.Fatal("session access tokens are not unique")
	}
	e.want(e.do("GET", "/api/users/me", fresh.S("access_token"), nil), 200, "distinct session not revoked")
}

func TestResetAtomicAndRevocation(t *testing.T) {
	e := newEnv(t)
	access := e.setup()
	reset := "reset-test"
	e.s.St.DB.Exec(`INSERT INTO password_resets(hash,user_id,expires_at) VALUES(?,?,?)`, hashToken(reset), 1, time.Now().Add(time.Hour))
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": reset, "password": "changed123"}).Code
		}()
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 200 {
			success++
		} else if code != 400 {
			t.Fatalf("unexpected reset status %d", code)
		}
	}
	if success != 1 {
		t.Fatalf("token used %d times", success)
	}
	e.want(e.do("GET", "/api/users/me", access, nil), 401, "reset revokes access")
}

func TestRequestSecurity(t *testing.T) {
	e := newEnv(t)
	e.setup()
	for _, path := range []string{"/api/auth/login", "/api/auth/refresh", "/api/auth/logout", "/api/auth/verify-email", "/api/setup"} {
		e.want(e.do("POST", path, "", map[string]any{}, "Origin", "https://attacker.example"), 403, "cross-origin "+path)
	}
	e.want(e.do("POST", "/api/auth/login", "", []byte(`{"username":"admin","password":"password123"}`), "Content-Type", "text/plain"), 415, "simple form login CSRF")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"}, "Origin", e.ts.URL), 200, "same-origin localhost")
	r := httptest.NewRequest(http.MethodPost, "http://localhost/api/auth/login", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if e.s.secureCookies(r) {
		t.Fatal("trusted spoofed proto")
	}
	e.s.BaseURL = "https://files.example"
	if !e.s.secureCookies(r) {
		t.Fatal("canonical https must secure cookie")
	}
	e.s.BaseURL = ""
	for i := 0; i < 60; i++ {
		r := httptest.NewRequest(http.MethodPost, "http://localhost/api/auth/login", strings.NewReader(`{}`))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i))
		w := httptest.NewRecorder()
		e.s.Router().ServeHTTP(w, r)
	}
	r = httptest.NewRequest(http.MethodPost, "http://localhost/api/auth/login", strings.NewReader(`{}`))
	r.RemoteAddr = "192.0.2.1:4321"
	w := httptest.NewRecorder()
	e.s.Router().ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatalf("spoofable rate budget: %d", w.Code)
	}
}

func TestResourceAndFileSecurity(t *testing.T) {
	e := newEnv(t)
	access := e.setup()
	e.want(e.do("POST", "/api/uploads", access, map[string]any{"files": []map[string]any{{"name": "a", "size": int64(9223372036854775807)}, {"name": "b", "size": int64(1)}}}), 400, "size overflow")
	for _, p := range []string{e.s.St.DataDir, filepath.Join(e.s.St.DataDir, "uploads"), filepath.Join(e.s.St.DataDir, "backups")} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0700 {
			t.Fatalf("directory permissions %s: %v", p, err)
		}
	}
	for _, p := range []string{e.s.St.Path, e.s.St.Path + "-wal", e.s.St.Path + "-shm"} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("database permissions %s: %v", p, err)
		}
	}
	backup, err := e.s.makeBackup()
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(e.s.St.DataDir, "backups", backup))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("backup permissions", err)
	}
	e.s.St.DB.Exec(`UPDATE settings SET grp='system' WHERE key='jwt_secret'`)
	if strings.Contains(string(e.do("GET", "/api/settings", access, nil).Body), "jwt_secret") {
		t.Fatal("legacy secret group leaks signing key")
	}
}

func TestSameOriginLoopbackAliases(t *testing.T) {
	e := newEnv(t)
	r := httptest.NewRequest(http.MethodPost, "http://localhost:9090/api/auth/login", nil)
	cases := []struct {
		base, origin string
		want         bool
	}{
		{"http://localhost:9090", "http://localhost:9090", true},
		{"http://localhost:9090", "http://127.0.0.1:9090", true},
		{"http://localhost:9090", "http://[::1]:9090", true},
		{"http://127.0.0.1:9090", "http://LOCALHOST:9090", true},
		{"http://localhost", "http://127.0.0.1:80", true},
		{"http://localhost:9090", "http://127.0.0.1:9091", false},  // other port
		{"http://localhost:9090", "https://127.0.0.1:9090", false}, // other scheme
		{"http://localhost:9090", "http://localhost.attacker.example:9090", false},
		{"http://localhost:9090", "http://192.168.1.10:9090", false},
		{"https://files.example.com", "https://127.0.0.1", false}, // public APP_URL: no aliasing
		{"https://files.example.com", "https://localhost", false},
	}
	for _, c := range cases {
		e.s.BaseURL = c.base
		if got := e.s.sameOrigin(r, c.origin); got != c.want {
			t.Errorf("base %s origin %s: got %v, want %v", c.base, c.origin, got, c.want)
		}
	}
}
