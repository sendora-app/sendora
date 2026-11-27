// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sendora-app/sendora/internal/store"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

func (e *env) enableIPBans() { e.t.Setenv("SENDORA_DISABLE_IP_BANS", "") }

func TestVerifyEmailIssuesSessionOnlyForNewRegistrations(t *testing.T) {
	e := newEnv(t)
	e.useSMTP(newSMTP(t))
	admin := e.setup()
	e.mkUser(admin, "mia", false)
	id, _ := e.userRow("mia")
	e.s.St.DB.Exec(`UPDATE users SET email_verified=0,pending_registration=0 WHERE id=?`, id)
	e.s.St.DB.Exec(`INSERT INTO email_verifications(user_id,code,expires_at) VALUES(?,?,?)`, id, "12345678", time.Now().Add(time.Hour))
	r := e.do("POST", "/api/auth/verify-email", "", map[string]any{"email": "mia@x.io", "code": "12345678"})
	e.want(r, 200, "verify")
	if r.J()["access_token"] != nil || refreshCookie(r) != "" {
		t.Fatalf("an established account must not get a session from the code: %s", r.Body)
	}
	var verified bool
	e.s.St.DB.QueryRow(`SELECT email_verified FROM users WHERE id=?`, id).Scan(&verified)
	if !verified {
		t.Fatal("the address should be verified")
	}
	e.want(e.login("mia", "password123"), 200, "normal login afterwards")

	// A fresh self-registration still gets its session.
	e.s.St.SetSetting("allow_self_registration", "true")
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "newbie", "email": "newbie@x.io", "password": "password123"}), 201, "register")
	nid, _ := e.userRow("newbie")
	e.s.St.DB.Exec(`UPDATE email_verifications SET code='87654321' WHERE user_id=?`, nid)
	v := e.do("POST", "/api/auth/verify-email", "", map[string]any{"email": "newbie@x.io", "code": "87654321"})
	e.want(v, 200, "verify registration")
	if v.S("access_token") == "" || v.S("access_token") == "<nil>" {
		t.Fatalf("a new registration should be signed in: %s", v.Body)
	}
}

func TestVerificationCodeHasEightDigits(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "zed", false)
	id, _ := e.userRow("zed")
	e.s.St.DB.Exec(`UPDATE users SET email_verified=0 WHERE id=?`, id)
	u, _ := e.s.userByID(id)
	e.s.sendVerification(u)
	var code string
	if err := e.s.St.DB.QueryRow(`SELECT code FROM email_verifications WHERE user_id=?`, id).Scan(&code); err != nil || len(code) != 8 || strings.Trim(code, "0123456789") != "" {
		t.Fatalf("code %q err %v", code, err)
	}
}

func TestUpdateMeCurrentPasswordLockout(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	tok := e.mkUser(admin, "nina", false)
	change := func(current string) resp {
		return e.do("PUT", "/api/users/me", tok, map[string]any{"name": "Nina", "email": "nina@x.io", "password": "another-pass1", "current_password": current})
	}
	for i := 0; i < 5; i++ {
		e.want(change("wrong-password"), 400, "wrong current password")
	}
	if _, f := e.userRow("nina"); f < 5 {
		t.Fatalf("failures should count against the account: %d", f)
	}
	r := change("password123")
	e.want(r, 429, "locked, even with the right password")
	if r.Hdr.Get("Retry-After") == "" {
		t.Fatal("Retry-After missing")
	}
	// The login is locked by the same counter.
	e.want(e.login("nina", "password123"), 401, "login locked too")
	id, _ := e.userRow("nina")
	e.s.St.DB.Exec(`UPDATE users SET login_failures=0,login_locked_until=0 WHERE id=?`, id)
	e.want(change("password123"), 200, "after the lock expires")
}

func TestMFAStepUpPasswordLockout(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.setting("mfa_policy", "optional")
	tok := e.mkUser(admin, "owen", false)
	for i := 0; i < 5; i++ {
		e.want(e.do("POST", "/api/users/me/mfa/totp/begin", tok, map[string]any{"password": "nope"}), 401, "wrong password")
	}
	r := e.do("POST", "/api/users/me/mfa/totp/begin", tok, map[string]any{"password": "password123"})
	e.want(r, 429, "locked after repeated failures")
	id, _ := e.userRow("owen")
	e.s.St.DB.Exec(`UPDATE users SET login_failures=0,login_locked_until=0 WHERE id=?`, id)
	e.want(e.do("POST", "/api/users/me/mfa/totp/begin", tok, map[string]any{"password": "password123"}), 200, "unlocked")
}

func TestStepUpFailuresCountTowardsIPBan(t *testing.T) {
	for _, tc := range []struct{ name, method, path string }{
		{"profile", "PUT", "/api/users/me"},
		{"mfa", "POST", "/api/users/me/mfa/totp/begin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.enableIPBans()
			admin := e.setup()
			e.setting("mfa_policy", "optional")
			tok := e.mkUser(admin, "pete", false)
			for i := 0; i < ipBanThreshold; i++ {
				body := map[string]any{"password": "nope"}
				if tc.name == "profile" {
					body = map[string]any{"name": "P", "email": "pete@x.io", "password": "another-pass1", "current_password": "nope"}
				}
				if r := e.do(tc.method, tc.path, tok, body); r.Code == 200 {
					t.Fatal("unexpected success")
				}
			}
			if len(e.s.activeIPBans()) != 1 {
				t.Fatalf("expected the address to be banned: %v", e.s.activeIPBans())
			}
			e.want(e.login("admin", "password123"), 429, "banned address")
		})
	}
	// Ordinary signed-in requests (an expired token) are not failures.
	e := newEnv(t)
	e.enableIPBans()
	for i := 0; i < ipBanThreshold+2; i++ {
		e.do("PUT", "/api/users/me", "expired", map[string]any{"name": "x"})
	}
	if len(e.s.activeIPBans()) != 0 {
		t.Fatal("unauthenticated profile requests must not ban the address")
	}
}

func TestRouteClassForProfileUpdate(t *testing.T) {
	class, limit := routeClass(httptest.NewRequest("PUT", "/api/users/me", nil))
	if class != "profile" || limit != 60 {
		t.Fatalf("%q %d", class, limit)
	}
	if class, _ := routeClass(httptest.NewRequest("GET", "/api/users/me", nil)); class != "" {
		t.Fatal("reading the profile is not rate limited here")
	}
}

func TestSetupFailuresAreThrottledGlobally(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < setupFailLimit; i++ {
		e.want(e.do("POST", "/api/setup", "", map[string]any{"username": "admin", "password": "password123", "setup_code": "WRONG-CODE-0000"}), 403, "wrong code")
	}
	r := e.do("POST", "/api/setup", "", map[string]any{"username": "admin", "password": "password123", "setup_code": e.s.setupCode})
	e.want(r, 429, "throttled even with the right code")
	if r.Hdr.Get("Retry-After") == "" {
		t.Fatal("Retry-After missing")
	}
	// The window passes: setup works again.
	e.s.setupThrottle.clear("setup")
	e.want(e.do("POST", "/api/setup", "", map[string]any{"username": "admin", "password": "password123", "setup_code": e.s.setupCode}), 200, "setup after the block")
}

func TestSetupFailuresCountTowardsIPBan(t *testing.T) {
	e := newEnv(t)
	e.enableIPBans()
	for i := 0; i < ipBanThreshold; i++ {
		e.do("POST", "/api/setup", "", map[string]any{"username": "admin", "password": "password123", "setup_code": "WRONG-CODE-0000"})
	}
	if len(e.s.activeIPBans()) != 1 {
		t.Fatalf("wrong setup codes should ban the address: %v", e.s.activeIPBans())
	}
}

func TestWeakSetupCodesAreRefused(t *testing.T) {
	for code, ok := range map[string]bool{
		"": false, "SHORTCODE": false, "AAAAAAAAAAAAAAAAAAAA": false, "11111111111111111111": false,
		"ABCDEFGHIJKLMNOPQRST": false, "0123456789012345": true, // wraps: not a plain run
		"ZYXWVUTSRQPONMLK": false, "ABCDEFGHIJKLMNO": false, // too short
		"QX7M-4TRP-9WLK-2NBH": true, "ABABABABABABABAB": false,
	} {
		if validSetupCode(code) != ok {
			t.Errorf("validSetupCode(%q) != %v", code, ok)
		}
	}
	for _, env := range []string{"AAAAAAAAAAAAAAAAAAAA", "TOO-SHORT-12345", "ABCDEFGHIJKLMNOPQRSTUV"} {
		t.Setenv("SENDORA_SETUP_CODE", env)
		st, err := store.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		s := New(st, fstest.MapFS{"index.html": {Data: []byte("x")}}, "test")
		if s.setupCode == strings.ToUpper(env) || len(s.setupCode) != 14 {
			t.Errorf("weak code %q accepted: %q", env, s.setupCode)
		}
		st.DB.Close()
	}
	t.Setenv("SENDORA_SETUP_CODE", "qx7m-4trp-9wlk-2nbh")
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	if s := New(st, fstest.MapFS{"index.html": {Data: []byte("x")}}, "test"); s.setupCode != "QX7M-4TRP-9WLK-2NBH" {
		t.Fatalf("a strong operator code must be used, got %q", s.setupCode)
	}
}

func TestPasswordHashesUseCostTwelveAndUpgrade(t *testing.T) {
	if c, _ := bcrypt.Cost(dummyHash); c != bcryptCost || bcryptCost != 12 || defaultHashCost != 12 {
		t.Fatalf("dummy hash cost %d, default cost %d", c, defaultHashCost)
	}
	hashCost = bcryptCost
	defer func() { hashCost = bcrypt.MinCost }()
	e := newEnv(t)
	admin := e.setup()
	var h string
	qByName(e.s.St, `SELECT password_hash FROM users WHERE username='admin'`).Scan(&h)
	if c, _ := bcrypt.Cost([]byte(h)); c != 12 {
		t.Fatalf("new account hash cost %d", c)
	}
	e.mkUser(admin, "quinn", false)
	id, _ := e.userRow("quinn")
	old, _ := bcrypt.GenerateFromPassword([]byte("password123"), 10)
	e.s.St.DB.Exec(`UPDATE users SET password_hash=? WHERE id=?`, string(old), id)
	e.want(e.login("quinn", "wrong-password"), 401, "wrong password does not rehash")
	e.s.St.DB.QueryRow(`SELECT password_hash FROM users WHERE id=?`, id).Scan(&h)
	if h != string(old) {
		t.Fatal("hash changed without a successful login")
	}
	r := e.login("quinn", "password123")
	e.want(r, 200, "login with an older hash")
	e.s.St.DB.QueryRow(`SELECT password_hash FROM users WHERE id=?`, id).Scan(&h)
	if c, _ := bcrypt.Cost([]byte(h)); c != 12 || bcrypt.CompareHashAndPassword([]byte(h), []byte("password123")) != nil {
		t.Fatalf("hash not upgraded: cost %d", c)
	}
	// The session issued by that very login is still valid.
	e.want(e.do("GET", "/api/users/me", r.S("access_token"), nil), 200, "session after rehash")

	// Share passwords upgrade on unlock.
	sh := e.share(admin, map[string]string{"a.txt": "x"}, map[string]any{"password": "secret12"})
	lid := sh.S("long_id")
	oldShare, _ := bcrypt.GenerateFromPassword([]byte("secret12"), 10)
	eByName(e.s.St, `UPDATE shares SET password_hash=? WHERE long_id=?`, string(oldShare), lid)
	e.want(e.do("POST", "/api/shares/"+lid+"/unlock", "", map[string]any{"password": "secret12"}), 200, "unlock")
	qByName(e.s.St, `SELECT password_hash FROM shares WHERE long_id=?`, lid).Scan(&h)
	if c, _ := bcrypt.Cost([]byte(h)); c != 12 {
		t.Fatalf("share hash not upgraded: %d", c)
	}
	e.want(e.do("POST", "/api/shares/"+lid+"/unlock", "", map[string]any{"password": "secret12"}), 200, "unlock again")
}

func TestTokenPurposesAreSeparated(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	id, _ := e.userRow("admin")
	u, _ := e.s.userByID(id)
	keys := map[string]bool{string(e.s.Secret): true}
	for _, p := range []string{keyAccess, keyMFA, keyShareUnlock, keyCredential, keySharePasswordVersion} {
		k := string(e.s.key(p))
		if keys[k] || len(k) != 32 {
			t.Fatalf("subkey %s is not distinct", p)
		}
		keys[k] = true
	}
	mfa := e.s.mfaToken(u)
	if _, _, _, _, ok := e.s.parseMFAToken(e.s.accessToken(u)); ok {
		t.Fatal("an access token must not parse as an MFA token")
	}
	if _, _, _, _, ok := e.s.parseMFAToken(mfa); !ok {
		t.Fatal("a real MFA token must parse")
	}
	e.want(e.do("GET", "/api/users/me", mfa, nil), 401, "mfa token as access token")
	e.want(e.do("GET", "/api/users/me", admin, nil), 200, "access token works")

	// Forged purpose claims do not help: the signing key differs per purpose.
	forge := func(key []byte, claims jwt.MapClaims) string {
		s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		return s
	}
	accessClaims := jwt.MapClaims{"sub": "1", "purpose": "access", "credential": e.s.credentialVersion(u), "exp": time.Now().Add(time.Hour).Unix()}
	e.want(e.do("GET", "/api/users/me", forge(e.s.key(keyAccess), accessClaims), nil), 200, "correctly signed access token")
	for name, key := range map[string][]byte{"raw secret": e.s.Secret, "mfa key": e.s.key(keyMFA), "share key": e.s.key(keyShareUnlock)} {
		e.want(e.do("GET", "/api/users/me", forge(key, accessClaims), nil), 401, "access claims signed with the "+name)
	}

	// Share unlock tokens and access tokens do not cross either.
	sh := e.share(admin, map[string]string{"a.txt": "x"}, map[string]any{"password": "secret12"})
	lid := sh.S("long_id")
	share, err := e.s.shareByLongID(lid)
	if err != nil {
		t.Fatal(err)
	}
	unlock := e.s.shareToken(share)
	e.want(e.do("GET", "/api/shares/"+lid, "", nil, "X-Share-Token", unlock), 200, "share token")
	if e.do("GET", "/api/shares/"+lid, "", nil, "X-Share-Token", unlock).J()["files"] == nil {
		t.Fatal("share token should unlock")
	}
	for name, tk := range map[string]string{"access": admin, "mfa": mfa} {
		if e.do("GET", "/api/shares/"+lid, "", nil, "X-Share-Token", tk).J()["files"] != nil {
			t.Fatalf("a %s token must not unlock a share", name)
		}
	}
	e.want(e.do("GET", "/api/users/me", unlock, nil), 401, "share token as access token")
}

func TestShareUnlockIsThrottledPerShare(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	sh := e.share(admin, map[string]string{"a.txt": "x"}, map[string]any{"password": "secret12"})
	lid := sh.S("long_id")
	other := e.share(admin, map[string]string{"b.txt": "y"}, map[string]any{"password": "secret34"}).S("long_id")
	for i := 0; i < shareUnlockLimit; i++ {
		e.want(e.do("POST", "/api/shares/"+lid+"/unlock", "", map[string]any{"password": "wrong"}), 401, "wrong password")
	}
	r := e.do("POST", "/api/shares/"+lid+"/unlock", "", map[string]any{"password": "secret12"})
	e.want(r, 429, "blocked even with the right password")
	if r.Hdr.Get("Retry-After") == "" {
		t.Fatal("Retry-After missing")
	}
	e.want(e.do("POST", "/api/shares/"+other+"/unlock", "", map[string]any{"password": "secret34"}), 200, "other shares are unaffected")
	// The throttle is per share and ends.
	e.s.shareThrottle.mu.Lock()
	for _, f := range e.s.shareThrottle.m {
		f.blockedUntil = time.Now().Add(-time.Second)
		f.windowEnds = f.blockedUntil
	}
	e.s.shareThrottle.mu.Unlock()
	e.want(e.do("POST", "/api/shares/"+lid+"/unlock", "", map[string]any{"password": "secret12"}), 200, "unlock after the block")
}

func TestJWTSecretValidation(t *testing.T) {
	good := "k3J9xQ2vL8mN5pR7sT1uW4yZ6aB0cD3eF"
	for sec, ok := range map[string]bool{
		"": true, good: true,
		strings.Repeat("a", 40): false, strings.Repeat("ab", 20): false, "abcdefgh" + strings.Repeat("a", 30): true,
		"abcdefg" + strings.Repeat("a", 30): false, "short": false,
	} {
		if (ValidateJWTSecret(sec) == nil) != ok {
			t.Errorf("ValidateJWTSecret(%q) ok=%v", sec, !ok)
		}
	}
}

func TestProviderDialGuard(t *testing.T) {
	for addr, blocked := range map[string]bool{
		"127.0.0.1": true, "127.5.5.5": true, "::1": true, "169.254.169.254": true, "169.254.0.1": true, "fe80::1": true,
		"::ffff:127.0.0.1": true, "::ffff:169.254.169.254": true, "0.0.0.0": true, "fd00:ec2::254": true, "100.100.100.200": true,
		"10.1.2.3": false, "192.168.1.5": false, "172.16.0.9": false, "8.8.8.8": false, "2606:4700::1111": false,
	} {
		if got := blockedProviderAddr(netip.MustParseAddr(addr)); got != blocked {
			t.Errorf("blockedProviderAddr(%s)=%v", addr, got)
		}
	}
	if err := providerDialControl("tcp", "10.0.0.5:443", nil); err != nil {
		t.Fatalf("RFC 1918 targets stay reachable: %v", err)
	}
	if err := providerDialControl("tcp", "127.0.0.1:443", nil); err == nil {
		t.Fatal("loopback must be refused")
	}
}

func TestProviderClientRefusesLoopbackAndMetadata(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close() // httptest listens on 127.0.0.1
	c := newProviderHTTPClient()
	if _, err := c.Get(srv.URL); err == nil || !strings.Contains(err.Error(), errBlockedTarget.Error()) {
		t.Fatalf("loopback server reached: %v", err)
	}
	if hit {
		t.Fatal("the request must not leave the guard")
	}
	if _, err := c.Get("http://169.254.169.254/latest/meta-data/"); err == nil || !strings.Contains(err.Error(), errBlockedTarget.Error()) {
		t.Fatalf("metadata address reached: %v", err)
	}
	if c.Timeout > 5*time.Second {
		t.Fatalf("timeout %v", c.Timeout)
	}
	req, _ := http.NewRequest("GET", "http://idp.example/", nil)
	via := make([]*http.Request, oidcMaxRedirects)
	if err := c.CheckRedirect(req, via); err != nil {
		t.Fatalf("%d redirects are allowed: %v", oidcMaxRedirects, err)
	}
	if err := c.CheckRedirect(req, append(via, req)); err == nil {
		t.Fatal("a fourth redirect must stop")
	}
}

func TestProviderContextKeepsAnInjectedClient(t *testing.T) {
	ctx, cancel := providerContext(context.Background())
	defer cancel()
	if c, _ := ctx.Value(oauth2.HTTPClient).(*http.Client); c != providerClient() {
		t.Fatal("the guarded client should be installed by default")
	}
	own := &http.Client{}
	ctx2, cancel2 := providerContext(context.WithValue(context.Background(), oauth2.HTTPClient, own))
	defer cancel2()
	if ctx2.Value(oauth2.HTTPClient) != own {
		t.Fatal("an explicit client must be kept")
	}
	if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > oidcFlowTimeout {
		t.Fatal("the flow needs a bounded deadline")
	}
}

func TestOIDCHasItsOwnSlotPool(t *testing.T) {
	e := newEnv(t)
	e.setup()
	for i := 0; i < cap(e.s.oidcSlots); i++ {
		e.s.oidcSlots <- struct{}{}
	}
	e.want(e.do("GET", "/api/auth/oidc/x/start", "", nil), 429, "oidc pool exhausted")
	e.want(e.login("admin", "password123"), 200, "password logins still have their slots")
	for len(e.s.authSlots) < cap(e.s.authSlots) {
		e.s.authSlots <- struct{}{}
	}
	<-e.s.oidcSlots
	if r := e.do("GET", "/api/auth/oidc/x/start", "", nil); r.Code == 429 {
		t.Fatal("OIDC must not depend on the authentication slots")
	}
}

func TestBrowserErrorsHideInternalDetail(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	// Whatever fails inside, the browser only sees a fixed text.
	r := e.do("POST", "/api/email-templates/preview", admin, map[string]any{"key": "no_such_event"})
	if r.Code != 400 || r.S("error") != "this template could not be rendered" {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
}
