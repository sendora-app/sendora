// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"strconv"
	"strings"
	"testing"
)

func (e *env) userCount() int {
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n
}

func (e *env) setSettings(admin string, m map[string]any) {
	e.t.Helper()
	e.want(e.do("PUT", "/api/settings", admin, m), 200, "settings")
}

func (e *env) errMsg(r resp) string { return r.S("error") }

func TestValidateAccountPasswordPure(t *testing.T) {
	multi := strings.Repeat("é", 36) // 72 bytes, 36 runes
	cases := []struct {
		name string
		p    accountPolicy
		pw   string
		want string
	}{
		{"min1 one char", accountPolicy{MinLength: 1}, "a", ""},
		{"empty", accountPolicy{MinLength: 1}, "", "password must be at least 1 characters"},
		{"min8 7", accountPolicy{MinLength: 8}, "1234567", "password must be at least 8 characters"},
		{"min8 8", accountPolicy{MinLength: 8}, "12345678", ""},
		{"72 ok", accountPolicy{MinLength: 8}, strings.Repeat("a", 72), ""},
		{"73 too long", accountPolicy{MinLength: 8}, strings.Repeat("a", 73), "password must not exceed 72 bytes"},
		{"multibyte 72 bytes", accountPolicy{MinLength: 8}, multi, ""},
		{"multibyte 74 bytes", accountPolicy{MinLength: 8}, multi + "é", "password must not exceed 72 bytes"},
		{"runes counted", accountPolicy{MinLength: 4}, "éééé", ""},
		{"runes short", accountPolicy{MinLength: 5}, "éééé", "password must be at least 5 characters"},
		{"bad utf8", accountPolicy{MinLength: 1}, "ab\xff", "password must be valid UTF-8"},
		{"upper", accountPolicy{MinLength: 1, Upper: true}, "abc1!", "password must contain an uppercase letter"},
		{"lower", accountPolicy{MinLength: 1, Lower: true}, "ABC1!", "password must contain a lowercase letter"},
		{"digit", accountPolicy{MinLength: 1, Digit: true}, "abcD!", "password must contain a digit"},
		{"symbol", accountPolicy{MinLength: 1, Symbol: true}, "abcD1", "password must contain a symbol"},
		{"space is symbol", accountPolicy{MinLength: 1, Symbol: true}, "abc d", ""},
		{"all", accountPolicy{MinLength: 5, Upper: true, Lower: true, Digit: true, Symbol: true}, "aB1!x", ""},
	}
	for _, c := range cases {
		err := validateAccountPassword(c.p, c.pw)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestAccountSettingsValidation(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bad := []map[string]any{
		{"account_password_min_length": 0},
		{"account_password_min_length": 73},
		{"account_password_min_length": 1.5},
		{"account_password_min_length": "x"},
		{"account_password_min_length": nil},
		{"account_password_min_length": []any{8}},
		{"account_password_min_length": true},
		{"account_password_require_upper": "yes"},
		{"account_password_require_lower": 1},
		{"account_password_require_digit": nil},
		{"account_password_require_symbol": []any{true}},
		{"account_password_require_symbol": map[string]any{}},
	}
	for i, b := range bad {
		b["application_name"] = "ShouldNotBeWritten"
		e.want(e.do("PUT", "/api/settings", admin, b), 400, "bad batch")
		if e.s.St.Setting("application_name") == "ShouldNotBeWritten" {
			t.Fatalf("case %d wrote part of a rejected batch", i)
		}
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"account_password_min_length": 12, "account_password_require_upper": "true", "account_password_require_lower": false, "account_password_require_digit": "false", "account_password_require_symbol": true}), 200, "valid")
	if e.s.St.Setting("account_password_min_length") != "12" || e.s.St.Setting("account_password_require_upper") != "true" || e.s.St.Setting("account_password_require_symbol") != "true" {
		t.Fatal("not stored")
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"account_password_min_length": "7"}), 400, "below the floor of 8")
	e.setSettings(admin, map[string]any{"account_password_min_length": "8"})
	e.setSettings(admin, map[string]any{"account_password_min_length": 72})
}

func TestAccountPolicyDefaultsAndBootstrap(t *testing.T) {
	e := newEnv(t)
	j := e.do("GET", "/api/bootstrap", "", nil).J()
	if j["account_password_min_length"] != float64(8) || j["account_password_require_upper"] != false || j["account_password_require_lower"] != false ||
		j["account_password_require_digit"] != false || j["account_password_require_symbol"] != false {
		t.Fatal("defaults", j)
	}
	admin := e.setup() // password123 stays valid under defaults
	e.setSettings(admin, map[string]any{"account_password_min_length": 10, "account_password_require_digit": true, "account_password_require_symbol": true})
	j = e.do("GET", "/api/bootstrap", "", nil).J()
	if j["account_password_min_length"] != float64(10) || j["account_password_require_digit"] != true || j["account_password_require_symbol"] != true || j["account_password_require_upper"] != false {
		t.Fatal("bootstrap", j)
	}
	e.s.St.DB.Exec(`UPDATE settings SET value='bogus' WHERE key='account_password_require_lower'`)
	j = e.do("GET", "/api/bootstrap", "", nil).J()
	if j["account_password_min_length"] != float64(72) || j["account_password_require_upper"] != true || j["account_password_require_lower"] != true ||
		j["account_password_require_digit"] != true || j["account_password_require_symbol"] != true {
		t.Fatal("corrupt bootstrap must be strictest", j)
	}
}

func TestAccountPolicySetup(t *testing.T) {
	e := newEnv(t)
	e.s.St.SetSetting("account_password_require_upper", "true")
	r := e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "a", "password": "password123", "email": "a@x.io"})
	e.want(r, 400, "weak")
	if e.errMsg(r) != "password must contain an uppercase letter" {
		t.Fatal(e.errMsg(r))
	}
	e.want(e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "a", "password": strings.Repeat("A", 73)}), 400, "73")
	e.s.St.DB.Exec(`UPDATE settings SET value='bogus' WHERE key='account_password_min_length'`)
	r = e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "a", "password": "Password123", "email": "a@x.io"})
	e.want(r, 500, "corrupt")
	if e.errMsg(r) != "password policy unavailable" || e.userCount() != 0 {
		t.Fatal("corrupt must create nothing", e.errMsg(r))
	}
	e.s.St.SetSetting("account_password_min_length", "8")
	e.want(e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "a", "password": "Password123", "email": "a@x.io"}), 200, "strong")
}

func TestAccountPolicyAdminPaths(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	e.setSettings(admin, map[string]any{"account_password_min_length": 10, "account_password_require_upper": true, "account_password_require_lower": true, "account_password_require_digit": true, "account_password_require_symbol": true})
	create := func(pw string) resp {
		return e.do("POST", "/api/users", admin, map[string]any{"username": "carol", "password": pw, "email": "carol@x.io"})
	}
	for pw, msg := range map[string]string{
		"Aa1!":                  "password must be at least 10 characters",
		"aaaaaaaa1!":            "password must contain an uppercase letter",
		"AAAAAAAA1!":            "password must contain a lowercase letter",
		"Aaaaaaaaa!":            "password must contain a digit",
		"Aaaaaaaaa1":            "password must contain a symbol",
		strings.Repeat("A", 73): "password must not exceed 72 bytes",
	} {
		r := create(pw)
		e.want(r, 400, "create "+pw)
		if e.errMsg(r) != msg {
			t.Fatalf("create %q: %q want %q", pw, e.errMsg(r), msg)
		}
	}
	if e.userCount() != 2 {
		t.Fatal("rejected create made user")
	}
	e.want(create("Aaaaaaaa1!"), 201, "strong create")
	// updateUser: weak rejected, empty password leaves it alone, strong ok
	var bobID int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='bob'`).Scan(&bobID)
	up := "/api/users/" + itoa(bobID)
	body := func(pw string) map[string]any {
		return map[string]any{"name": "Bob", "email": "bob@x.io", "admin": false, "password": pw}
	}
	// An administrator can no longer set another user's password at all (see
	// account_security_test.go), so the policy never gets that far.
	r := e.do("PUT", up, admin, body("weakweak12"))
	e.want(r, 400, "weak update")
	if e.errMsg(r) != msgAdminNoPassword {
		t.Fatal(e.errMsg(r))
	}
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "password123"}), 200, "old pw still works")
	e.want(e.do("PUT", up, admin, body("")), 200, "no password supplied")
	e.want(e.do("PUT", up, admin, body("Aaaaaaaa1!")), 400, "strong update is refused too")
	// corrupt
	e.s.St.DB.Exec(`UPDATE settings SET value='bogus' WHERE key='account_password_require_digit'`)
	e.want(e.do("PUT", up, admin, body("Bbbbbbbb2@")), 400, "corrupt update")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "password123"}), 200, "unchanged")
	e.want(e.do("PUT", up, admin, body("")), 200, "no password under corrupt policy")
	before := e.userCount()
	r = e.do("POST", "/api/users", admin, map[string]any{"username": "dave", "password": "Aaaaaaaa1!", "email": "dave@x.io"})
	e.want(r, 500, "corrupt create")
	if e.userCount() != before {
		t.Fatal("corrupt create made user")
	}
	// login never checks the policy
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"}), 200, "legacy weak login")
	_ = bob
}

func TestAccountPolicyBoundaries(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"account_password_min_length": 1}), 400, "minimum is at least 8")
	mk := func(i int, pw string) resp {
		return e.do("POST", "/api/users", admin, map[string]any{"username": "u" + itoa(int64(i)), "password": pw, "email": "u" + itoa(int64(i)) + "@x.io"})
	}
	e.want(mk(1, "a"), 400, "1 byte")
	e.want(mk(2, strings.Repeat("a", 72)), 201, "72 bytes")
	e.want(mk(3, strings.Repeat("a", 73)), 400, "73 bytes")
	e.want(mk(4, strings.Repeat("é", 36)), 201, "72 bytes multibyte")
	e.want(mk(5, strings.Repeat("é", 37)), 400, "74 bytes multibyte")
	e.want(mk(6, ""), 400, "empty")
	e.setSettings(admin, map[string]any{"account_password_min_length": 8})
	e.want(mk(7, "1234567"), 400, "7 bytes")
	e.want(mk(8, "12345678"), 201, "8 bytes")
	e.want(mk(9, "éééééééé"), 201, "8 runes")
	e.want(mk(10, "ééééééé"), 400, "7 runes")
}

func TestAccountPolicyRegister(t *testing.T) {
	e, admin := regEnv(t)
	e.setSettings(admin, map[string]any{"account_password_require_symbol": true})
	r := e.do("POST", "/api/auth/register", "", regBody("u1", "u1@x.io"))
	e.want(r, 400, "weak")
	if e.errMsg(r) != "password must contain a symbol" {
		t.Fatal(e.errMsg(r))
	}
	b := regBody("u1", "u1@x.io")
	b["password"] = "password123!"
	e.want(e.do("POST", "/api/auth/register", "", b), 201, "strong")
	n := e.userCount()
	e.s.St.DB.Exec(`UPDATE settings SET value='bogus' WHERE key='account_password_min_length'`)
	b2 := regBody("u2", "u2@x.io")
	b2["password"] = "password123!"
	r = e.do("POST", "/api/auth/register", "", b2)
	e.want(r, 500, "corrupt")
	if e.errMsg(r) != "password policy unavailable" || e.userCount() != n {
		t.Fatal("corrupt register")
	}
}

func TestAccountPolicyResetPassword(t *testing.T) {
	e := newEnv(t)
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.BaseURL = "https://files.example.com"
	admin := e.setup()
	e.want(e.do("POST", "/api/auth/forgot-password", "", map[string]any{"email": "admin@x.io"}), 200, "forgot")
	m := sink.wait(t, "https://files.example.com/reset-password/")
	i := strings.Index(m, "/reset-password/")
	rt := strings.TrimSpace(strings.Split(m[i+len("/reset-password/"):], "\r\n")[0])
	e.setSettings(admin, map[string]any{"account_password_require_digit": true})
	reset := func(pw string) resp {
		return e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": rt, "password": pw})
	}
	r := reset("nodigitshere")
	e.want(r, 400, "weak")
	if e.errMsg(r) != "password must contain a digit" {
		t.Fatal(e.errMsg(r))
	}
	e.s.St.DB.Exec(`UPDATE settings SET value='bogus' WHERE key='account_password_require_upper'`)
	r = reset("digits1here")
	e.want(r, 500, "corrupt")
	if e.errMsg(r) != "password policy unavailable" {
		t.Fatal(e.errMsg(r))
	}
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"}), 200, "unchanged")
	e.s.St.SetSetting("account_password_require_upper", "false")
	e.want(reset("digits1here"), 200, "strong reset (token still valid)")
}

func TestAccountPolicyUpdateMe(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setSettings(admin, map[string]any{"account_password_min_length": 12})
	me := func(pw string) resp {
		return e.do("PUT", "/api/users/me", admin, map[string]any{"name": "Admin", "email": "admin@x.io", "current_password": "password123", "password": pw})
	}
	r := me("short1234")
	e.want(r, 400, "weak")
	if e.errMsg(r) != "password must be at least 12 characters" {
		t.Fatal(e.errMsg(r))
	}
	e.s.St.DB.Exec(`UPDATE settings SET value='bogus' WHERE key='account_password_require_lower'`)
	r = me("longenough1234")
	e.want(r, 500, "corrupt")
	if e.errMsg(r) != "password policy unavailable" {
		t.Fatal(e.errMsg(r))
	}
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"}), 200, "unchanged")
	e.s.St.SetSetting("account_password_require_lower", "false")
	e.want(me("longenough1234"), 200, "strong")

	// provider user setting a first local password
	if _, err := rawExec(e.t, e.s.St, `INSERT INTO users(username,name,email,password_hash,admin,language,ui_language) VALUES('prov','Prov','prov@x.io','',0,'en','en')`); err != nil {
		t.Fatal(err)
	}
	var id int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='prov'`).Scan(&id)
	u, err := e.s.userByID(id)
	if err != nil {
		t.Fatal(err)
	}
	tok := e.s.accessToken(u)
	put := func(pw string) resp {
		return e.do("PUT", "/api/users/me", tok, map[string]any{"name": "Prov", "email": "prov@x.io", "password": pw})
	}
	e.want(put("short"), 400, "provider weak")
	e.want(put("firstlocalpassword"), 200, "provider strong")
}

func TestAccountPolicyShareRegression(t *testing.T) {
	// the account policy must not leak into the share policy
	e := newEnv(t)
	admin := e.setup()
	e.setSettings(admin, map[string]any{"account_password_min_length": 30})
	r := e.share(admin, map[string]string{"a.txt": "x"}, map[string]any{"password": "shortpw12"})
	if r.Code >= 400 {
		t.Fatalf("share policy affected by account policy: %d %s", r.Code, r.Body)
	}
	if err := validateSharePassword(sharePolicy{MinLength: 8, Upper: true}, "lower1234"); err == nil || err.Error() != "share password must contain an uppercase letter" {
		t.Fatal(err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
