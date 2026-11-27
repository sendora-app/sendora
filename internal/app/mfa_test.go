// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (e *env) setting(key, val string) {
	e.t.Helper()
	if err := e.s.St.SetSetting(key, val); err != nil {
		e.t.Fatal(err)
	}
}

// enrollTOTP walks begin+confirm and returns the secret, the fresh access token
// and the recovery codes (only present for the first factor).
func (e *env) enrollTOTP(tok, password string) ([]byte, string, []any) {
	e.t.Helper()
	b := e.do("POST", "/api/users/me/mfa/totp/begin", tok, map[string]any{"password": password})
	e.want(b, 200, "totp begin")
	secret, err := decodeTOTPSecret(b.S("secret"))
	if err != nil {
		e.t.Fatal(err)
	}
	c := e.do("POST", "/api/users/me/mfa/totp/confirm", tok, map[string]any{"code": totpCode(secret, time.Now())})
	e.want(c, 200, "totp confirm")
	codes, _ := c.J()["recovery_codes"].([]any)
	return secret, c.S("access_token"), codes
}

func (e *env) login(name, password string) resp {
	return e.do("POST", "/api/auth/login", "", map[string]any{"username": name, "password": password})
}

func refreshCookie(r resp) string {
	for _, line := range r.Hdr.Values("Set-Cookie") {
		if strings.HasPrefix(line, "refresh=") {
			return strings.SplitN(strings.TrimPrefix(line, "refresh="), ";", 2)[0]
		}
	}
	return ""
}

// claimsOf reads a JWT payload without verifying it (tests only).
func claimsOf(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	json.Unmarshal(raw, &m)
	return m
}

func (e *env) userRow(name string) (id int64, failures int64) {
	e.t.Helper()
	if err := qByName(e.s.St, `SELECT id,login_failures FROM users WHERE username=?`, name).Scan(&id, &failures); err != nil {
		e.t.Fatal(err)
	}
	return
}

func TestMFABootstrapAndSettingsValidation(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	boot := e.do("GET", "/api/bootstrap", "", nil).J()
	if boot["mfa_policy"] != "off" || boot["mfa_totp_enabled"] != true || boot["mfa_webauthn_enabled"] != false || boot["webauthn_available"] != false {
		t.Fatal("defaults", boot)
	}
	for _, v := range []any{"", "ON", "required", "admin", nil, 1, true, []string{"off"}} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"mfa_policy": v, "application_name": "must-not-change"}), 400, "invalid policy")
	}
	for _, key := range []string{"mfa_totp_enabled", "mfa_webauthn_enabled"} {
		for _, v := range []any{"yes", "", 3, nil, []int{1}} {
			e.want(e.do("PUT", "/api/settings", admin, map[string]any{key: v, "application_name": "must-not-change"}), 400, "invalid "+key)
		}
	}
	if e.s.St.Setting("application_name") == "must-not-change" || e.s.St.Setting("mfa_policy") != "off" {
		t.Fatal("rejected batch changed state")
	}
	for _, p := range []string{"optional", "off", "optional"} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"mfa_policy": p, "mfa_totp_enabled": true}), 200, "policy "+p)
	}
	if e.do("GET", "/api/bootstrap", "", nil).J()["mfa_policy"] != "optional" {
		t.Fatal("bootstrap must show the stored policy")
	}
	e.setting("mfa_policy", "garbage")
	if e.s.mfaGlobal() != "all" || e.do("GET", "/api/bootstrap", "", nil).J()["mfa_policy"] != "all" {
		t.Fatal("a corrupt policy must fail closed to 'all'")
	}
}

func TestMFAEnrollAndLoginGate(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	tok := e.mkUser(admin, "carol", false)
	// Enrolment needs the account password.
	e.want(e.do("POST", "/api/users/me/mfa/totp/begin", tok, map[string]any{"password": "nope"}), 401, "wrong password")
	e.want(e.do("POST", "/api/users/me/mfa/totp/begin", tok, map[string]any{}), 401, "missing password")
	e.want(e.do("POST", "/api/users/me/mfa/totp/confirm", tok, map[string]any{"code": "123456"}), 409, "confirm before begin")
	b := e.do("POST", "/api/users/me/mfa/totp/begin", tok, map[string]any{"password": "password123"})
	e.want(b, 200, "begin")
	if !strings.HasPrefix(b.S("uri"), "otpauth://totp/") || b.S("secret") == "" || b.S("account") != "carol" {
		t.Fatal("begin response", string(b.Body))
	}
	secret, _ := decodeTOTPSecret(b.S("secret"))
	e.want(e.do("POST", "/api/users/me/mfa/totp/confirm", tok, map[string]any{"code": "000000"}), 400, "wrong confirm code")
	c := e.do("POST", "/api/users/me/mfa/totp/confirm", tok, map[string]any{"code": totpCode(secret, time.Now())})
	e.want(c, 200, "confirm")
	codes, _ := c.J()["recovery_codes"].([]any)
	if len(codes) != 10 || c.S("access_token") == "" || refreshCookie(c) == "" {
		t.Fatal("first factor returns 10 recovery codes and a fresh session", string(c.Body))
	}
	if c.J()["user"].(map[string]any)["mfa_enabled"] != true {
		t.Fatal("user must report mfa_enabled")
	}
	// The pre-enrolment token died with the factor change (epoch).
	e.want(e.do("GET", "/api/users/me", tok, nil), 401, "old token revoked")
	tok = c.S("access_token")
	e.want(e.do("GET", "/api/users/me", tok, nil), 200, "new token works")
	e.want(e.do("POST", "/api/users/me/mfa/totp/begin", tok, map[string]any{"password": "password123"}), 409, "second authenticator")
	// A second confirm does not hand out new recovery codes.
	st := e.do("GET", "/api/users/me/mfa", tok, nil)
	e.want(st, 200, "status")
	if st.J()["recovery_codes_remaining"] != float64(10) || st.J()["totp"].(map[string]any)["enrolled"] != true {
		t.Fatal("status", string(st.Body))
	}
	if strings.Contains(string(st.Body), b.S("secret")) {
		t.Fatal("status must never expose the secret")
	}
	// Login now needs a second step and issues neither session nor refresh token.
	e.s.St.DB.Exec(`UPDATE users SET login_failures=0,login_locked_until=0`) // wrong-password attempts above counted
	e.s.St.DB.Exec(`UPDATE user_totp SET last_counter=0`)
	l := e.login("carol", "password123")
	e.want(l, 200, "password step")
	j := l.J()
	if j["mfa_required"] != true || j["access_token"] != nil || j["user"] != nil || refreshCookie(l) != "" || l.Hdr.Get("Set-Cookie") != "" {
		t.Fatal("no session before MFA", string(l.Body))
	}
	methods, _ := j["methods"].([]any)
	if len(methods) != 2 || methods[0] != "totp" || methods[1] != "recovery" || j["expires_in"] != float64(300) {
		t.Fatal("methods", j)
	}
	mt := j["mfa_token"].(string)
	// Wrong and malformed codes fail.
	for _, code := range []string{"000000", "12345", "abcdef", ""} {
		e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": code}), 401, "bad code "+code)
	}
	if _, f := e.userRow("carol"); f != 4 {
		t.Fatal("each failed code counts towards the shared lock, got", f)
	}
	e.s.St.DB.Exec(`UPDATE users SET login_failures=0,login_locked_until=0`)
	good := totpCode(secret, time.Now())
	ok := e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": good})
	e.want(ok, 200, "mfa login")
	if ok.S("access_token") == "" || refreshCookie(ok) == "" || ok.J()["user"].(map[string]any)["username"] != "carol" {
		t.Fatal("session after MFA", string(ok.Body))
	}
	if _, f := e.userRow("carol"); f != 0 {
		t.Fatal("counter resets only after MFA success, got", f)
	}
	// The pending token is single use, and the used code cannot be replayed.
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": good}), 401, "token reuse")
	mt2 := e.login("carol", "password123").J()["mfa_token"].(string)
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt2, "code": good}), 401, "code replay")
	e.s.St.DB.Exec(`UPDATE users SET login_failures=0,login_locked_until=0`)
	// Recovery codes work once.
	mt3 := e.login("carol", "password123").J()["mfa_token"].(string)
	rc := codes[0].(string)
	e.want(e.do("POST", "/api/auth/mfa/recovery", "", map[string]any{"mfa_token": mt3, "code": strings.ToLower(rc)}), 200, "recovery login")
	mt4 := e.login("carol", "password123").J()["mfa_token"].(string)
	e.want(e.do("POST", "/api/auth/mfa/recovery", "", map[string]any{"mfa_token": mt4, "code": rc}), 401, "recovery reuse")
	e.s.St.DB.Exec(`UPDATE users SET login_failures=0,login_locked_until=0`)
	st = e.do("GET", "/api/users/me/mfa", ok.S("access_token"), nil)
	if st.J()["recovery_codes_remaining"] != float64(9) {
		t.Fatal("one recovery code was consumed", string(st.Body))
	}
	// Regenerating replaces all codes and needs the password.
	at := ok.S("access_token")
	e.want(e.do("POST", "/api/users/me/mfa/recovery/regenerate", at, map[string]any{"password": "x"}), 401, "regenerate wrong password")
	rg := e.do("POST", "/api/users/me/mfa/recovery/regenerate", at, map[string]any{"password": "password123"})
	e.want(rg, 200, "regenerate")
	newCodes, _ := rg.J()["recovery_codes"].([]any)
	if len(newCodes) != 10 || newCodes[0] == codes[1] {
		t.Fatal("regenerate returns 10 new codes")
	}
	mt5 := e.login("carol", "password123").J()["mfa_token"].(string)
	e.want(e.do("POST", "/api/auth/mfa/recovery", "", map[string]any{"mfa_token": mt5, "code": codes[1]}), 401, "old code invalid")
}

func TestMFATokenBoundaries(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	tok := e.mkUser(admin, "dave", false)
	secret, _, _ := e.enrollTOTP(tok, "password123")
	e.s.St.DB.Exec(`UPDATE user_totp SET last_counter=0`)
	mt := e.login("dave", "password123").J()["mfa_token"].(string)
	code := totpCode(secret, time.Now())
	// An MFA token is not an access token, and an access token is not an MFA token.
	e.want(e.do("GET", "/api/users/me", mt, nil), 401, "mfa token as bearer")
	acc := e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": tok, "code": code})
	e.want(acc, 401, "access token as mfa token")
	// Garbage, wrong signature, expired, wrong purpose, missing claims.
	id, _ := e.userRow("dave")
	_ = id
	u, _ := e.s.userByID(id)
	forge := func(claims jwt.MapClaims, key []byte) string {
		s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		return s
	}
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"sub": "2", "purpose": "mfa", "jti": "x1", "credential": e.s.credentialVersion(u), "exp": time.Now().Add(time.Minute).Unix()}
	}
	b1 := base()
	b2 := base()
	b2["exp"] = time.Now().Add(-time.Minute).Unix()
	b3 := base()
	b3["purpose"] = "access"
	b4 := base()
	delete(b4, "jti")
	b5 := base()
	b5["credential"] = "tampered"
	b5["jti"] = "x5"
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, b1).SignedString(jwt.UnsafeAllowNoneSignatureType)
	for name, tk := range map[string]string{
		"garbage": "not.a.token", "empty": "", "wrong key": forge(b1, []byte("wrong")), "expired": forge(b2, e.s.key(keyMFA)),
		"purpose": forge(b3, e.s.key(keyMFA)), "no jti": forge(b4, e.s.key(keyMFA)), "credential": forge(b5, e.s.key(keyMFA)), "alg none": none,
	} {
		if r := e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": tk, "code": code}); r.Code != 401 {
			t.Fatal(name, "accepted:", r.Code, string(r.Body))
		}
	}
	// Token of another account cannot be combined with this account's code.
	other := e.mkUser(admin, "erin", false)
	_ = other
	oid, _ := e.userRow("erin")
	ou, _ := e.s.userByID(oid)
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": e.s.mfaToken(ou), "code": code}), 401, "other account has no authenticator")
	// A credential change after the first step (here: the email address, since an
	// administrator can no longer set a password) invalidates the pending token.
	e.want(e.do("PUT", "/api/users/"+idStr(id), admin, map[string]any{"name": "D", "email": "dave2@x.io"}), 200, "credential change")
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": code}), 401, "credential changed")
	// Expiry is enforced by the 5 minute TTL.
	if ttl := claimsOf(t, mt)["exp"].(float64) - float64(time.Now().Unix()); ttl > 301 || ttl < 290 {
		t.Fatal("mfa token ttl", ttl)
	}
}

func idStr(id int64) string {
	b, _ := json.Marshal(id)
	return string(b)
}

func TestMFASharedLockout(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	tok := e.mkUser(admin, "frank", false)
	secret, _, _ := e.enrollTOTP(tok, "password123")
	e.s.St.DB.Exec(`UPDATE user_totp SET last_counter=0`)
	for i := 0; i < 3; i++ {
		mt := e.login("frank", "password123").J()["mfa_token"].(string)
		e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": "000000"}), 401, "wrong code")
	}
	// A correct password does not reset the counter.
	mt := e.login("frank", "password123").J()["mfa_token"].(string)
	if _, f := e.userRow("frank"); f != 3 {
		t.Fatal("password success must not reset failures, got", f)
	}
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": "000000"}), 401, "4th")
	mt = e.login("frank", "password123").J()["mfa_token"].(string)
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": "000000"}), 401, "5th locks")
	var until int64
	qByName(e.s.St, `SELECT login_locked_until FROM users WHERE username='frank'`).Scan(&until)
	if until <= time.Now().Unix() {
		t.Fatal("five failures must lock the account")
	}
	// Locked: even the correct code is refused, and so is the password step.
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": totpCode(secret, time.Now())}), 401, "locked")
	e.want(e.login("frank", "password123"), 401, "password step locked")
	// Admin unlock restores access; MFA success then resets the counter.
	fid, _ := e.userRow("frank")
	e.want(e.do("POST", "/api/users/"+idStr(fid)+"/unlock-login", admin, nil), 200, "unlock")
	mt = e.login("frank", "password123").J()["mfa_token"].(string)
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": totpCode(secret, time.Now())}), 200, "login after unlock")
}

func TestMFAPolicyMatrix(t *testing.T) {
	e := newEnv(t)
	e.setup()
	cases := []struct {
		global, user string
		admin        bool
		want         bool
	}{
		{"off", "required", true, false}, {"off", "inherit", true, false},
		{"optional", "inherit", true, false}, {"optional", "inherit", false, false}, {"optional", "required", false, true}, {"optional", "exempt", true, false},
		{"admins", "inherit", true, true}, {"admins", "inherit", false, false}, {"admins", "exempt", true, false}, {"admins", "required", false, true},
		{"all", "inherit", true, true}, {"all", "inherit", false, true}, {"all", "exempt", false, false}, {"all", "exempt", true, false}, {"all", "required", false, true},
		{"admins", "weird", false, true}, // unknown per-user value fails closed
	}
	for _, c := range cases {
		e.setting("mfa_policy", c.global)
		u := &User{ID: 99, passwordHash: "x", Admin: c.admin, MFAPolicy: c.user}
		if got := e.s.mfaRequired(u); got != c.want {
			t.Errorf("global=%s user=%s admin=%v: want %v got %v", c.global, c.user, c.admin, c.want, got)
		}
	}
	e.setting("mfa_policy", "all")
	if e.s.mfaRequired(&User{ID: 5, IsGuest: true, passwordHash: "x", MFAPolicy: "required"}) {
		t.Error("guests are outside MFA")
	}
	if e.s.mfaRequired(&User{ID: 6, passwordHash: "", MFAPolicy: "required"}) {
		t.Error("accounts without a local password (external providers) are outside MFA")
	}
	e.setting("mfa_totp_enabled", "false")
	if e.s.mfaRequired(&User{ID: 7, passwordHash: "x", MFAPolicy: "required"}) {
		t.Error("with no method available nobody can be required to enrol")
	}
}

func TestMFAEnrollRestrictionAtNextRefresh(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	// Cannot enforce before the acting admin has a factor of their own.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"mfa_policy": "admins"}), 400, "self lockout guard")
	_, adminTok, _ := e.enrollTOTP(admin, "password123")
	t2 := e.mkUser(adminTok, "admin2", true)
	l2 := e.login("admin2", "password123")
	e.want(l2, 200, "login admin2")
	cookie := refreshCookie(l2)
	t2 = l2.S("access_token")
	e.want(e.do("PUT", "/api/settings", adminTok, map[string]any{"mfa_policy": "admins"}), 200, "enforce")
	// The token issued before the policy keeps working until it is refreshed.
	e.want(e.do("GET", "/api/shares", t2, nil), 200, "existing session unaffected")
	rf := e.do("POST", "/api/auth/refresh", "", nil, "Cookie", "refresh="+cookie)
	e.want(rf, 200, "refresh")
	restricted := rf.S("access_token")
	if claimsOf(t, restricted)["mfa_enroll"] != true || rf.J()["user"].(map[string]any)["mfa_enroll_required"] != true {
		t.Fatal("refresh must hand out an enrolment-only token", string(rf.Body))
	}
	r := e.do("GET", "/api/shares", restricted, nil)
	e.want(r, 403, "restricted token")
	if r.S("error") != "mfa enrollment required" {
		t.Fatal("message", r.S("error"))
	}
	e.want(e.do("GET", "/api/users/me", restricted, nil), 200, "me allowed")
	e.want(e.do("PUT", "/api/users/me", restricted, map[string]any{"name": "Admin Two", "email": "admin2@x.io"}), 200, "profile update allowed")
	e.want(e.do("GET", "/api/users/me/mfa", restricted, nil), 200, "status allowed")
	e.want(e.do("GET", "/api/users", restricted, nil), 403, "admin routes blocked")
	e.want(e.do("POST", "/api/uploads", restricted, map[string]any{"files": []any{}}), 403, "uploads blocked")
	// Login hands out a restricted token too; enrolling lifts the restriction.
	nl := e.login("admin2", "password123")
	if claimsOf(t, nl.S("access_token"))["mfa_enroll"] != true {
		t.Fatal("login of a required, not enrolled user is enrolment-only")
	}
	_, free, _ := e.enrollTOTP(nl.S("access_token"), "password123")
	if _, has := claimsOf(t, free)["mfa_enroll"]; has {
		t.Fatal("enrolled users get ordinary tokens")
	}
	e.want(e.do("GET", "/api/shares", free, nil), 200, "unrestricted after enrolment")
	// Exempt users are never restricted; so are users once the policy is relaxed.
	e.mkUser(adminTok, "svc", false)
	e.want(e.do("PUT", "/api/settings", adminTok, map[string]any{"mfa_policy": "all"}), 200, "all")
	sl := e.login("svc", "password123")
	if claimsOf(t, sl.S("access_token"))["mfa_enroll"] != true {
		t.Fatal("policy all restricts everybody without a factor")
	}
	sid, _ := e.userRow("svc")
	e.want(e.do("PUT", "/api/users/"+idStr(sid), adminTok, map[string]any{"name": "svc", "email": "svc@x.io", "mfa_policy": "exempt"}), 200, "exempt")
	sl = e.login("svc", "password123")
	if _, has := claimsOf(t, sl.S("access_token"))["mfa_enroll"]; has {
		t.Fatal("exempt users are never forced")
	}
	e.want(e.do("PUT", "/api/settings", adminTok, map[string]any{"mfa_policy": "off"}), 200, "off")
	nl = e.login("admin2", "password123")
	if nl.J()["mfa_required"] == true || nl.S("access_token") == "" {
		t.Fatal("policy off is the kill switch: no second step", string(nl.Body))
	}
}

func TestMFASettingsGuardAndUserPolicy(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	for _, p := range []string{"admins", "all"} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"mfa_policy": p}), 400, "guard "+p)
	}
	if e.s.St.Setting("mfa_policy") != "optional" {
		t.Fatal("guard must keep the policy")
	}
	// Explicit exemption of the acting admin satisfies the guard.
	aid, _ := e.userRow("admin")
	e.want(e.do("PUT", "/api/users/"+idStr(aid), admin, map[string]any{"name": "admin", "email": "admin@x.io", "admin": true, "mfa_policy": "exempt"}), 200, "exempt self")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"mfa_policy": "admins"}), 200, "exempt admin may enforce")
	// Per-user policy validation and self-lockout guard.
	for _, v := range []string{"", "ALL", "mandatory", "off"} {
		e.want(e.do("PUT", "/api/users/"+idStr(aid), admin, map[string]any{"name": "admin", "email": "admin@x.io", "admin": true, "mfa_policy": v}), 400, "invalid user policy "+v)
	}
	e.want(e.do("PUT", "/api/users/"+idStr(aid), admin, map[string]any{"name": "admin", "email": "admin@x.io", "admin": true, "mfa_policy": "required"}), 400, "cannot require MFA of yourself without a factor")
	// Omitting the field preserves it.
	e.want(e.do("PUT", "/api/users/"+idStr(aid), admin, map[string]any{"name": "Admin", "email": "admin@x.io", "admin": true}), 200, "update without mfa_policy")
	var pol string
	e.s.St.DB.QueryRow(`SELECT mfa_policy FROM users WHERE id=?`, aid).Scan(&pol)
	if pol != "exempt" {
		t.Fatal("omitted policy must be preserved", pol)
	}
	// Requiring MFA of someone else is allowed and listed.
	e.mkUser(admin, "gina", false)
	gid, _ := e.userRow("gina")
	e.want(e.do("PUT", "/api/users/"+idStr(gid), admin, map[string]any{"name": "gina", "email": "gina@x.io", "mfa_policy": "required"}), 200, "require for gina")
	list := e.do("GET", "/api/users", admin, nil)
	e.want(list, 200, "list")
	var users []map[string]any
	json.Unmarshal(list.Body, &users)
	found := false
	for _, u := range users {
		if u["username"] == "gina" {
			found = u["mfa_policy"] == "required" && u["mfa_enabled"] == false && u["mfa_required"] == true
		}
	}
	if !found {
		t.Fatal("admin list must expose mfa_policy / mfa_enabled / mfa_required", string(list.Body))
	}
}

func TestMFAFactorRemovalAndRequired(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	tok := e.mkUser(admin, "hank", false)
	_, tok, _ = e.enrollTOTP(tok, "password123")
	// Wrong password refused and counted.
	_, before := e.userRow("hank")
	e.want(e.do("POST", "/api/users/me/mfa/totp/remove", tok, map[string]any{"password": "bad"}), 401, "remove wrong password")
	if _, after := e.userRow("hank"); after != before+1 {
		t.Fatal("password failures during MFA management count towards the lock")
	}
	e.s.St.DB.Exec(`UPDATE users SET login_failures=0`)
	// Required: the last factor cannot be removed.
	hid, _ := e.userRow("hank")
	e.want(e.do("PUT", "/api/users/"+idStr(hid), admin, map[string]any{"name": "hank", "email": "hank@x.io", "mfa_policy": "required"}), 200, "require")
	e.want(e.do("POST", "/api/users/me/mfa/totp/remove", tok, map[string]any{"password": "password123"}), 409, "required keeps last factor")
	e.want(e.do("PUT", "/api/users/"+idStr(hid), admin, map[string]any{"name": "hank", "email": "hank@x.io", "mfa_policy": "inherit"}), 200, "relax")
	rm := e.do("POST", "/api/users/me/mfa/totp/remove", tok, map[string]any{"password": "password123"})
	e.want(rm, 200, "remove")
	if rm.S("access_token") == "" || rm.J()["user"].(map[string]any)["mfa_enabled"] != false {
		t.Fatal("removal returns a fresh session", string(rm.Body))
	}
	var codes, totp int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=?`, hid).Scan(&codes)
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM user_totp WHERE user_id=?`, hid).Scan(&totp)
	if codes != 0 || totp != 0 {
		t.Fatal("recovery codes go away with the last factor", codes, totp)
	}
	if l := e.login("hank", "password123"); l.J()["mfa_required"] == true || l.S("access_token") == "" {
		t.Fatal("no second step once the factor is gone")
	}
	e.want(e.do("POST", "/api/users/me/mfa/totp/remove", rm.S("access_token"), map[string]any{"password": "password123"}), 404, "nothing to remove")
	e.want(e.do("POST", "/api/users/me/mfa/recovery/regenerate", rm.S("access_token"), map[string]any{"password": "password123"}), 409, "no recovery codes without a factor")
}

func TestMFAAdminReset(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	tok := e.mkUser(admin, "iris", false)
	_, tok, _ = e.enrollTOTP(tok, "password123")
	e.s.St.DB.Exec(`UPDATE user_totp SET last_counter=0`)
	l := e.login("iris", "password123")
	cookie := ""
	mt := l.J()["mfa_token"].(string)
	secret := func() []byte {
		var enc string
		e.s.St.DB.QueryRow(`SELECT secret FROM user_totp`).Scan(&enc)
		s, _ := decodeTOTPSecret(enc)
		return s
	}()
	ok := e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": totpCode(secret, time.Now())})
	e.want(ok, 200, "login")
	cookie = refreshCookie(ok)
	iid, _ := e.userRow("iris")
	e.want(e.do("POST", "/api/users/"+idStr(iid)+"/mfa/reset", tok, nil), 403, "users cannot reset")
	e.want(e.do("POST", "/api/users/"+idStr(iid)+"/mfa/reset", "", nil), 401, "anonymous cannot reset")
	e.want(e.do("POST", "/api/users/999/mfa/reset", admin, nil), 404, "unknown user")
	e.want(e.do("POST", "/api/users/abc/mfa/reset", admin, nil), 404, "bad id")
	// The reset is a two-step flow now (details in account_security_test.go): the
	// administrator's call only mails the user, whose confirmation removes the factors.
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.BaseURL = "https://files.example.com"
	e.want(e.do("POST", "/api/users/"+idStr(iid)+"/mfa/reset", admin, nil), 200, "reset request")
	e.want(e.do("POST", "/api/auth/mfa-reset/confirm", "", map[string]any{"token": linkToken(t, sink.wait(t, "/mfa-reset/"), "mfa-reset")}), 200, "user confirms")
	var n int
	e.s.St.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM user_totp)+(SELECT COUNT(*) FROM user_recovery_codes)+(SELECT COUNT(*) FROM user_webauthn)+(SELECT COUNT(*) FROM refresh_tokens WHERE user_id=?)`, iid).Scan(&n)
	if n != 0 {
		t.Fatal("reset removes factors and sessions", n)
	}
	e.want(e.do("GET", "/api/users/me", ok.S("access_token"), nil), 401, "access token revoked by the epoch")
	e.want(e.do("POST", "/api/auth/refresh", "", nil, "Cookie", "refresh="+cookie), 401, "refresh token revoked")
	if l := e.login("iris", "password123"); l.J()["mfa_required"] == true || l.S("access_token") == "" {
		t.Fatal("no second step after the reset")
	}
}

func TestMFAKillSwitchAndLocalLoginGate(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	tok := e.mkUser(admin, "jack", false)
	e.enrollTOTP(tok, "password123")
	if e.login("jack", "password123").J()["mfa_required"] != true {
		t.Fatal("enrolled users are gated")
	}
	e.setting("mfa_policy", "off")
	l := e.login("jack", "password123")
	if l.J()["mfa_required"] == true || l.S("access_token") == "" {
		t.Fatal("global off disables the gate for everybody (recovery path)")
	}
	e.want(e.do("POST", "/api/users/me/mfa/totp/begin", l.S("access_token"), map[string]any{"password": "password123"}), 409, "enrolment unavailable when off")
	e.setting("mfa_policy", "optional")
	e.setting("mfa_totp_enabled", "false")
	if e.login("jack", "password123").J()["mfa_required"] == true {
		t.Fatal("a disabled method no longer gates logins")
	}
	e.setting("mfa_totp_enabled", "true")
	mt := e.login("jack", "password123").J()["mfa_token"].(string)
	e.setting("mfa_policy", "off")
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": "123456"}), 409, "pending token after switching off")
	e.setting("mfa_policy", "optional")
	e.s.forceLocalLogin.Store(false)
	e.setting("local_login_enabled", "false")
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": "123456"}), 403, "mfa endpoints follow the local-login gate")
	e.want(e.do("POST", "/api/auth/mfa/recovery", "", map[string]any{"mfa_token": mt, "code": "AAAA-AAAA-AAAA-AAAA"}), 403, "recovery follows the gate")
}

func TestMFAVerifyEmailIsGated(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	tok := e.mkUser(admin, "kate", false)
	e.enrollTOTP(tok, "password123")
	kid, _ := e.userRow("kate")
	e.s.St.DB.Exec(`UPDATE users SET email_verified=0 WHERE id=?`, kid)
	e.s.St.DB.Exec(`INSERT INTO email_verifications(user_id,code,expires_at) VALUES(?,?,?)`, kid, "123456", time.Now().Add(time.Hour))
	// An established account (not a fresh self-registration) gets no session at
	// all from verifying its address: it signs in normally, MFA included.
	r := e.do("POST", "/api/auth/verify-email", "", map[string]any{"email": "kate@x.io", "code": "123456"})
	e.want(r, 200, "verify")
	if r.J()["access_token"] != nil || r.J()["mfa_token"] != nil || refreshCookie(r) != "" {
		t.Fatal("verifying an e-mail address must not bypass MFA", string(r.Body))
	}
	// A fresh self-registration still continues into the MFA step.
	e.s.St.DB.Exec(`UPDATE users SET email_verified=0,pending_registration=1 WHERE id=?`, kid)
	e.s.St.DB.Exec(`INSERT INTO email_verifications(user_id,code,expires_at) VALUES(?,?,?)`, kid, "123456", time.Now().Add(time.Hour))
	r = e.do("POST", "/api/auth/verify-email", "", map[string]any{"email": "kate@x.io", "code": "123456"})
	e.want(r, 200, "verify pending")
	if r.J()["mfa_required"] != true || r.J()["access_token"] != nil || refreshCookie(r) != "" {
		t.Fatal("verifying a registration must not bypass MFA", string(r.Body))
	}
}

func TestMFARouteClass(t *testing.T) {
	for _, c := range []struct {
		method, path, class string
		limit               int
	}{
		{"POST", "/api/auth/mfa/totp", "mfa", 30}, {"POST", "/api/auth/mfa/recovery", "mfa", 30},
		{"POST", "/api/auth/mfa/webauthn/finish", "mfa", 30},
		{"POST", "/api/users/me/mfa/totp/begin", "mfa", 30}, {"POST", "/api/users/me/mfa/recovery/regenerate", "mfa", 30},
		{"POST", "/api/auth/login", "login", 60}, {"POST", "/api/auth/refresh", "refresh", 240},
		{"GET", "/api/users/me/mfa", "", 0},
	} {
		class, limit := routeClass(httptest.NewRequest(c.method, c.path, nil))
		if class != c.class || limit != c.limit {
			t.Errorf("%s %s: got %q/%d want %q/%d", c.method, c.path, class, limit, c.class, c.limit)
		}
	}
}

func TestMFAFloodIsRateLimited(t *testing.T) {
	e := newEnv(t)
	got429 := false
	for i := 0; i < 40 && !got429; i++ {
		r := e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": "x", "code": "1"})
		got429 = r.Code == http.StatusTooManyRequests
	}
	if !got429 {
		t.Fatal("the mfa bucket (30/min) must throttle floods")
	}
	// Its own bucket: logins keep working.
	if r := e.login("nobody", "x"); r.Code == http.StatusTooManyRequests {
		t.Fatal("flooding MFA must not use up the login bucket")
	}
}

func TestMFANoSecretsInLogsOrResponses(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	tok := e.mkUser(admin, "lena", false)
	b := e.do("POST", "/api/users/me/mfa/totp/begin", tok, map[string]any{"password": "password123"})
	secretB32 := b.S("secret")
	secret, _ := decodeTOTPSecret(secretB32)
	c := e.do("POST", "/api/users/me/mfa/totp/confirm", tok, map[string]any{"code": totpCode(secret, time.Now())})
	e.want(c, 200, "confirm")
	codes, _ := c.J()["recovery_codes"].([]any)
	tok = c.S("access_token")
	e.s.St.DB.Exec(`UPDATE user_totp SET last_counter=0`)
	typed := totpCode(secret, time.Now())
	mt := e.login("lena", "password123").J()["mfa_token"].(string)
	e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": "999999"})
	e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": mt, "code": typed})
	e.do("POST", "/api/auth/mfa/recovery", "", map[string]any{"mfa_token": e.login("lena", "password123").J()["mfa_token"].(string), "code": codes[0]})
	e.do("POST", "/api/users/me/mfa/recovery/regenerate", tok, map[string]any{"password": "password123"})
	lid, _ := e.userRow("lena")
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.BaseURL = "https://files.example.com"
	e.want(e.do("POST", "/api/users/"+idStr(lid)+"/mfa/reset", admin, nil), 200, "reset request")
	resetToken := linkToken(t, sink.wait(t, "/mfa-reset/"), "mfa-reset")
	e.want(e.do("POST", "/api/auth/mfa-reset/confirm", "", map[string]any{"token": resetToken}), 200, "user confirms")
	logs := e.do("GET", "/api/logs?limit=100", admin, nil)
	e.want(logs, 200, "logs")
	body := string(logs.Body)
	sensitive := []string{secretB32, typed, "999999", mt, resetToken, hashToken(resetToken)}
	for _, c := range codes {
		sensitive = append(sensitive, c.(string))
	}
	for _, s := range sensitive {
		if s != "" && strings.Contains(body, s) {
			t.Fatalf("event log leaks %q", s)
		}
	}
	for _, want := range []string{"mfa_enrolled", "mfa_login_ok", "mfa_failed", "mfa_reset_requested", "mfa_reset_confirmed"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing audit event %s in %s", want, body)
		}
	}
	// The status and challenge endpoints never contain secrets or codes either.
	st := e.do("GET", "/api/users/me/mfa", tok, nil)
	ch := e.login("lena", "password123")
	for _, r := range []resp{st, ch} {
		for _, s := range sensitive[:1] {
			if strings.Contains(string(r.Body), s) {
				t.Fatal("secret leaked in a read endpoint")
			}
		}
	}
}

func TestMFAUserJSONExposure(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "admins")
	me := e.do("GET", "/api/users/me", admin, nil)
	e.want(me, 200, "me")
	u := me.J()["user"].(map[string]any)
	if u["mfa_policy"] != "inherit" || u["mfa_enabled"] != false || u["mfa_required"] != true || u["mfa_enroll_required"] != true {
		t.Fatal("user json", u)
	}
	for _, leak := range []string{"secret", "code_hash", "mfa_epoch"} {
		if strings.Contains(string(me.Body), leak) {
			t.Fatal("must not expose", leak)
		}
	}
}

// Phase 2 plugs passkeys into the same gate: stored credentials of an enabled and
// available method gate the login and are advertised in `methods`.
func TestMFAWebAuthnCredentialsGateLogin(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	e.mkUser(admin, "mona", false)
	mid, _ := e.userRow("mona")
	if _, err := e.s.St.DB.Exec(`INSERT INTO user_webauthn(user_id,cred_id,public_key,alg,name) VALUES(?,x'0a0b',x'0c',-7,'key')`, mid); err != nil {
		t.Fatal(err)
	}
	if e.login("mona", "password123").J()["mfa_required"] == true {
		t.Fatal("WebAuthn is not available yet: stored credentials must not gate logins")
	}
	old := webauthnAvailable
	webauthnAvailable = func(string) bool { return true }
	defer func() { webauthnAvailable = old }()
	l := e.login("mona", "password123")
	methods, _ := l.J()["methods"].([]any)
	if l.J()["mfa_required"] != true || len(methods) != 1 || methods[0] != "webauthn" {
		t.Fatal("stored credentials gate the login and are advertised", string(l.Body))
	}
	boot := e.do("GET", "/api/bootstrap", "", nil).J()
	if boot["webauthn_available"] != true || boot["mfa_webauthn_enabled"] != true {
		t.Fatal("bootstrap reflects availability", boot)
	}
	e.setting("mfa_webauthn_enabled", "false")
	if e.login("mona", "password123").J()["mfa_required"] == true {
		t.Fatal("a disabled method no longer gates")
	}
}
