// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCommonPasswordListIsCuratedAndLoaded(t *testing.T) {
	zr, err := gzip.NewReader(bytes.NewReader(commonPasswordsGz))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) < 1000 {
		t.Fatalf("only %d common passwords", len(lines))
	}
	if !sort.StringsAreSorted(lines) {
		t.Error("list is not sorted (regenerate with gen_common_passwords.go)")
	}
	for i, l := range lines {
		if l != strings.ToLower(strings.TrimSpace(l)) || l == "" || (i > 0 && lines[i-1] == l) {
			t.Fatalf("entry %d %q is not a unique lower-case line", i, l)
		}
	}
	for _, p := range []string{"123456", "password", "Password123", "QWERTY", "qwertyuiop", "1q2w3e4r", "iloveyou", "letmein", "welcome2024", "summer2025", "admin123", "zxcvbnm", "p@ssw0rd"} {
		if !isCommonPassword(p) {
			t.Errorf("%q should be common", p)
		}
	}
	for _, p := range []string{"correct-horse-battery", "Vq8#mL2!pZ", "tulpen-im-regen-17"} {
		if isCommonPassword(p) {
			t.Errorf("%q should not be common", p)
		}
	}
}

func TestTrivialAndPersonalPasswordRules(t *testing.T) {
	for _, p := range []string{"aaaaaaaa", "abababab", "abcabcabc", "12121212", "12345678", "87654321", "abcdefgh", "ZYXWVUTS", "passpass", "aabbaabb"} {
		if !isTrivialPassword(p) {
			t.Errorf("%q should be trivial", p)
		}
	}
	for _, p := range []string{"correct-horse", "a1b2c3d4e5x", "Sommer-im-Park-9", "12345679x"} {
		if isTrivialPassword(p) {
			t.Errorf("%q should not be trivial", p)
		}
	}
	if !containsPersonal("my-JohnDoe-pw", "johndoe") || !containsPersonal("xxSendoraxx", "", "sendora") {
		t.Error("personal parts not found")
	}
	if containsPersonal("abcdefgh-9", "ab", "") {
		t.Error("parts shorter than 3 characters must not count")
	}
}

// screenEnv is a test environment with the password screening switched on.
func screenEnv(t *testing.T) (*env, string) {
	e := newEnv(t)
	admin := e.setup()
	e.s.passwordScreenOff = false
	return e, admin
}

func TestAccountPasswordScreeningOnEveryPath(t *testing.T) {
	e, admin := screenEnv(t)
	create := func(user, pw string) resp {
		return e.do("POST", "/api/users", admin, map[string]any{"username": user, "password": pw, "email": user + "@example.org"})
	}
	for _, c := range []struct{ user, pw, msg string }{
		{"carol", "password123", msgPasswordCommon},
		{"carol", "Welcome2024", msgPasswordCommon},
		{"carol", "my-carol-secret-9", msgPasswordPersonal},
		{"dave77", "xx-DAVE77-yy", msgPasswordPersonal},
		{"erin", "Sendora-files-1", msgPasswordPersonal}, // the application name
		{"frank", "abcabcabcabc", msgPasswordTrivial},
		{"frank", "13579135", ""},
	} {
		r := create(c.user, c.pw)
		if c.msg == "" {
			e.want(r, 201, "acceptable password "+c.pw)
			continue
		}
		if r.Code != 400 || r.S("error") != c.msg {
			t.Errorf("%s/%s: want 400 %q, got %d %s", c.user, c.pw, c.msg, r.Code, r.Body)
		}
	}
	// email local part
	r := e.do("POST", "/api/users", admin, map[string]any{"username": "gina", "password": "Mailbox-jdoe42!", "email": "jdoe42@example.org"})
	if r.Code != 400 || r.S("error") != msgPasswordPersonal {
		t.Errorf("email local part: %d %s", r.Code, r.Body)
	}
	// own profile
	r = e.do("PUT", "/api/users/me", admin, map[string]any{"email": "admin@x.io", "current_password": "password123", "password": "qwerty123"})
	if r.Code != 400 || r.S("error") != msgPasswordCommon {
		t.Errorf("profile change: %d %s", r.Code, r.Body)
	}
	r = e.do("PUT", "/api/users/me", admin, map[string]any{"email": "admin@x.io", "current_password": "password123", "password": "Kiwi-Lantern-58"})
	e.want(r, 200, "strong profile password")
	// self registration
	e.s.St.SetSetting("allow_self_registration", "true")
	r = e.do("POST", "/api/auth/register", "", map[string]any{"username": "ivan", "password": "iloveyou1", "email": "ivan@example.org"})
	if r.Code != 400 || r.S("error") != msgPasswordCommon {
		t.Errorf("registration: %d %s", r.Code, r.Body)
	}
}

func TestPasswordScreeningOnResetAndSetup(t *testing.T) {
	e := newEnv(t)
	e.s.passwordScreenOff = false
	r := e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "root1", "password": "password1", "email": "root@x.io"})
	if r.Code != 400 || r.S("error") != msgPasswordCommon {
		t.Fatalf("setup with a common password: %d %s", r.Code, r.Body)
	}
	r = e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "root1", "password": "Harbour-Lights-77", "email": "root@x.io"})
	e.want(r, 200, "setup")
	var uid int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='root1'`).Scan(&uid)
	tok := "reset-token-for-test"
	if _, err := e.s.St.DB.Exec(`INSERT INTO password_resets(hash,user_id,expires_at,kind) VALUES(?,?,?,'reset')`, hashToken(tok), uid, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	r = e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": tok, "password": "ROOT1-new-pass"})
	if r.Code != 400 || r.S("error") != msgPasswordPersonal {
		t.Fatalf("reset containing the username: %d %s", r.Code, r.Body)
	}
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": tok, "password": "Copper-Valley-31"}), 200, "reset")
}

func TestAccountPasswordMinimumIsEight(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	r := e.do("PUT", "/api/settings", admin, map[string]any{"account_password_min_length": "6"})
	if r.Code != 400 {
		t.Fatalf("min length 6 accepted: %d %s", r.Code, r.Body)
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"account_password_min_length": "8"}), 200, "min 8")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"account_password_min_length": "72"}), 200, "min 72")
	// A stored value below the floor never weakens the check.
	e.s.St.SetSetting("account_password_min_length", "4")
	p, err := e.s.loadAccountPolicy()
	if err != nil || p.MinLength != 8 {
		t.Fatalf("policy %+v %v", p, err)
	}
	// Share password rules are unchanged: 1 is still allowed there.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"share_password_min_length": "1"}), 200, "share rules unchanged")
}

func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// breachServer answers the range API like Have I Been Pwned (with padding).
func breachServer(t *testing.T, breached string) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		hash := sha1Hex(breached)
		fmt.Fprintf(w, "0000000000000000000000000000000000A:0\r\n%s:42\r\n", hash[5:])
	}))
	t.Cleanup(srv.Close)
	oldURL, oldClient := breachRangeURL, breachClient
	breachRangeURL = srv.URL + "/range/"
	breachClient = func() *http.Client { return srv.Client() }
	t.Cleanup(func() { breachRangeURL, breachClient = oldURL, oldClient })
	return srv, &paths
}

func TestOnlineBreachCheckKAnonymityAndFailOpen(t *testing.T) {
	e, admin := screenEnv(t)
	_, paths := breachServer(t, "Unusual-Breached-Phrase-7")
	// Off by default: no request at all.
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "kim", "password": "Unusual-Breached-Phrase-7", "email": "kim@example.org"}), 201, "check off by default")
	if len(*paths) != 0 {
		t.Fatalf("the breach API was called while the check is off: %v", *paths)
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"password_breach_check_online": "true"}), 200, "switch on")
	r := e.do("POST", "/api/users", admin, map[string]any{"username": "lou", "password": "Unusual-Breached-Phrase-7", "email": "lou@example.org"})
	if r.Code != 400 || r.S("error") != msgPasswordBreached {
		t.Fatalf("breached password accepted: %d %s", r.Code, r.Body)
	}
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "mo", "password": "Fresh-Unbreached-88", "email": "mo@example.org"}), 201, "unbreached password")
	re := regexp.MustCompile(`^/range/[0-9A-F]{5}$`)
	for _, p := range *paths {
		if !re.MatchString(p) {
			t.Fatalf("more than the 5-character prefix left the server: %q", p)
		}
	}
	// Unreachable service: fail open.
	breachRangeURL = "http://127.0.0.1:1/range/"
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "ned", "password": "Unusual-Breached-Phrase-7", "email": "ned@example.org"}), 201, "fail open")
}
