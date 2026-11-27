// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func reqFrom(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func mustProxies(t *testing.T, list string) []*net.IPNet {
	t.Helper()
	nets, err := ParseTrustedProxies(list)
	if err != nil {
		t.Fatal(err)
	}
	return nets
}

func TestParseTrustedProxies(t *testing.T) {
	if nets := mustProxies(t, ""); len(nets) != 0 {
		t.Fatal("empty list must trust nothing")
	}
	if nets := mustProxies(t, "10.0.0.0/8, 127.0.0.1 ::1\n192.168.1.0/24"); len(nets) != 4 {
		t.Fatal(len(nets))
	}
	for _, bad := range []string{"nonsense", "10.0.0.0/33", "300.1.1.1", "10.0.0.1/"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestClientIPOnlyTrustsConfiguredProxies(t *testing.T) {
	e := newEnv(t)
	s := e.s
	// Default: nothing trusted, headers are ignored (spoofing has no effect).
	if got := s.clientIP(reqFrom("203.0.113.9:5555", map[string]string{"X-Forwarded-For": "1.2.3.4"})); got != "203.0.113.9" {
		t.Fatal("untrusted peer's header was believed:", got)
	}
	s.SetTrustedProxies(mustProxies(t, "10.0.0.0/8,127.0.0.1"))
	cases := []struct {
		name, remote, xff, want string
	}{
		{"untrusted peer with header", "203.0.113.9:1", "1.2.3.4", "203.0.113.9"},
		{"trusted peer, single hop", "10.1.1.1:1", "1.2.3.4", "1.2.3.4"},
		{"trusted peer, chain of proxies", "10.1.1.1:1", "1.2.3.4, 10.2.2.2", "1.2.3.4"},
		{"client-supplied spoof on the left is ignored", "10.1.1.1:1", "9.9.9.9, 1.2.3.4", "1.2.3.4"},
		{"all hops trusted falls back to peer", "10.1.1.1:1", "10.2.2.2, 10.3.3.3", "10.1.1.1"},
		{"garbage entry falls back to peer", "10.1.1.1:1", "1.2.3.4, not-an-ip", "10.1.1.1"},
		{"no header", "10.1.1.1:1", "", "10.1.1.1"},
		{"IPv6 client", "10.1.1.1:1", "2001:db8::1", "2001:db8::1"},
	}
	for _, c := range cases {
		h := map[string]string{}
		if c.xff != "" {
			h["X-Forwarded-For"] = c.xff
		}
		if got := s.clientIP(reqFrom(c.remote, h)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if !s.requestHTTPS(reqFrom("10.1.1.1:1", map[string]string{"X-Forwarded-Proto": "https"})) {
		t.Error("trusted proxy https not honoured")
	}
	if s.requestHTTPS(reqFrom("203.0.113.9:1", map[string]string{"X-Forwarded-Proto": "https"})) {
		t.Error("untrusted peer must not be able to claim https")
	}
}

func TestRateLimitBucketsAreSeparatePerRoute(t *testing.T) {
	e := newEnv(t)
	login := func() int {
		return e.do("POST", "/api/auth/login", "", map[string]any{"username": "nobody", "password": "x"}).Code
	}
	limited := false
	for i := 0; i < 70; i++ {
		if login() == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("login must be rate limited")
	}
	// Other sensitive routes still answer (not 429) for the same client.
	for _, route := range []string{"/api/auth/refresh", "/api/auth/forgot-password"} {
		if c := e.do("POST", route, "", map[string]any{"email": "a@b.co"}).Code; c == 429 {
			t.Errorf("%s was blocked by flooding login", route)
		}
	}
	if c := e.do("POST", "/api/shares/anything/unlock", "", map[string]any{"password": "x"}).Code; c == 429 {
		t.Error("unlock was blocked by flooding login")
	}
}

func TestRateLimitHonoursForwardedClientOnlyFromTrustedProxy(t *testing.T) {
	e := newEnv(t)
	post := func(xff string) int {
		return e.do("POST", "/api/auth/login", "", map[string]any{"username": "n", "password": "x"}, "X-Forwarded-For", xff).Code
	}
	// Untrusted peer (default): rotating the header must not reset the budget.
	blocked := false
	for i := 0; i < 70; i++ {
		if post(fmt.Sprintf("198.51.100.%d", i%250)) == 429 {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("spoofed X-Forwarded-For escaped the rate limit")
	}
	// Trusted peer (the test server connects from 127.0.0.1): each real client has its own budget.
	e2 := newEnv(t)
	e2.s.SetTrustedProxies(mustProxies(t, "127.0.0.1"))
	post2 := func(xff string) int {
		return e2.do("POST", "/api/auth/login", "", map[string]any{"username": "n", "password": "x"}, "X-Forwarded-For", xff).Code
	}
	for i := 0; i < 70; i++ {
		post2("198.51.100.1")
	}
	if post2("198.51.100.1") != 429 {
		t.Fatal("client A should be limited")
	}
	if c := post2("198.51.100.2"); c == 429 {
		t.Fatal("client B behind the same proxy must not be limited by client A")
	}
}

func TestRateLimiterMapFullEvictsInsteadOfDenyingEveryone(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < maxSecurityBuckets+500; i++ {
		e.s.allowRequest(fmt.Sprintf("flood:%d", i), 5, time.Hour)
	}
	e.s.securityMu.Lock()
	n := len(e.s.securityBuckets)
	e.s.securityMu.Unlock()
	if n > maxSecurityBuckets {
		t.Fatalf("map grew past its bound: %d", n)
	}
	if !e.s.allowRequest("legit-newcomer", 5, time.Hour) {
		t.Fatal("a new client was refused because the map was full")
	}
}

func TestPublicDownloadRoutesArePerIPLimited(t *testing.T) {
	e := newEnv(t)
	hit429 := false
	for i := 0; i < 130; i++ {
		if e.do("GET", "/api/shares/some-share/preview/x.png", "", nil).Code == 429 {
			hit429 = true
			break
		}
	}
	if !hit429 {
		t.Fatal("anonymous preview/download requests are not rate limited")
	}
}

func TestMailLimitsAndLengthChecks(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_reverse_shares": true}), 200, "reverse shares on")
	for i := 0; i < mailRecipientsPerHour; i++ {
		r := e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{"email": fmt.Sprintf("r%d@example.test", i)})
		if r.Code != 201 {
			t.Fatalf("invite %d: %d %s", i, r.Code, r.Body)
		}
	}
	r := e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{"email": "one-too-many@example.test"})
	e.want(r, 429, "hourly email allowance")
	// Without an email address no mail is sent, so no allowance is used.
	e.want(e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{"name": "link only"}), 201, "invite without email")
	e.want(e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{"name": strings.Repeat("n", 201)}), 400, "invite name too long")
	e.want(e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{"message": strings.Repeat("m", 10001)}), 400, "invite message too long")
	e.want(e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{"name": "x\u202ey"}), 400, "bidi override in invite name")
}

func TestShareCompletionFieldLimits(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	for name, opts := range map[string]map[string]any{
		"name":        {"name": strings.Repeat("n", 201)},
		"bidi name":   {"name": "report\u202egpj.exe"},
		"description": {"description": strings.Repeat("d", 2001)},
		"message":     {"message": strings.Repeat("m", 10001)},
	} {
		r := e.share(admin, map[string]string{"a.txt": "a"}, opts)
		if r.Code != 400 {
			t.Errorf("%s accepted: %d %s", name, r.Code, r.Body)
		}
	}
	e.want(e.share(admin, map[string]string{"a.txt": "a"}, map[string]any{"name": strings.Repeat("n", 200), "description": strings.Repeat("d", 2000)}), 201, "limits are inclusive")
}

func TestRecipientMailAllowanceOnShareCompletion(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.s.takeMail(1, mailRecipientsPerHour-1)
	rcpts := []string{"a@example.test", "b@example.test"}
	r := e.share(admin, map[string]string{"a.txt": "a"}, map[string]any{"recipients": rcpts})
	e.want(r, 429, "recipient allowance")
	e.want(e.share(admin, map[string]string{"a.txt": "a"}, nil), 201, "no recipients is fine")
}

// Usernames are shown to share recipients anyway; email addresses are not. A taken
// email therefore gets the same answer as a successful registration (the old
// combined "username or email" error still revealed addresses: a random
// username plus someone's address failed only when the address existed).
func TestRegistrationHidesTakenEmails(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.useSMTP(newSMTP(t))
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_self_registration": true}), 200, "enable registration")
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "taken", "password": "password123", "email": "taken@example.test"}), 201, "existing user")
	byUser := e.do("POST", "/api/auth/register", "", map[string]any{"username": "taken", "email": "fresh@example.test", "password": "password123"})
	byMail := e.do("POST", "/api/auth/register", "", map[string]any{"username": "freshname", "email": "taken@example.test", "password": "password123"})
	fresh := e.do("POST", "/api/auth/register", "", map[string]any{"username": "brandnew", "email": "brandnew@example.test", "password": "password123"})
	if byUser.Code != 400 || byMail.Code != fresh.Code || byMail.Code != 201 {
		t.Fatalf("unexpected answers: taken username %d, taken email %d, fresh %d", byUser.Code, byMail.Code, fresh.Code)
	}
	var n int
	qByName(e.s.St, `SELECT COUNT(*) FROM users WHERE username='freshname'`).Scan(&n)
	if n != 0 {
		t.Fatal("taken email created an account")
	}
}

func TestUnverifiedAccountsAreRemovedAfter48Hours(t *testing.T) {
	e := newEnv(t)
	e.setup()
	for _, row := range []struct {
		name     string
		verified int
		age      string
	}{{"old-unverified", 0, "2020-01-01 00:00:00"}, {"new-unverified", 0, time.Now().UTC().Format("2006-01-02 15:04:05")}, {"old-verified", 1, "2020-01-01 00:00:00"}} {
		if _, err := rawExec(e.t, e.s.St, `INSERT INTO users(username,email,email_verified,created_at,password_hash,pending_registration) VALUES(?,?,?,?,'registration-hash',1)`, row.name, row.name+"@x.io", row.verified, row.age); err != nil {
			t.Fatal(err)
		}
	}
	e.s.maintain()
	exists := func(name string) bool {
		var n int
		qByName(e.s.St, `SELECT COUNT(*) FROM users WHERE username=?`, name).Scan(&n)
		return n == 1
	}
	if exists("old-unverified") || !exists("new-unverified") || !exists("old-verified") {
		t.Fatal("cleanup must remove only old unverified accounts")
	}
}

func TestSPAHeadersAndDirectoryRequests(t *testing.T) {
	e := newEnv(t)
	e.s.Static = fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}, "assets/app.js": {Data: []byte("x")}}
	r := e.do("GET", "/", "", nil)
	e.want(r, 200, "spa index")
	csp := r.Hdr.Get("Content-Security-Policy")
	for _, must := range []string{"default-src 'self'", "script-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, must) {
			t.Errorf("CSP lacks %q: %s", must, csp)
		}
	}
	for _, dir := range []string{"/assets", "/assets/"} {
		e.want(e.do("GET", dir, "", nil), 404, "directory request "+dir)
	}
	e.want(e.do("GET", "/assets/app.js", "", nil), 200, "real asset")
}

func TestHSTSOnlyWhenHTTPS(t *testing.T) {
	e := newEnv(t)
	if h := e.do("GET", "/api/health", "", nil).Hdr.Get("Strict-Transport-Security"); h != "" {
		t.Fatal("HSTS over plain http:", h)
	}
	e.s.BaseURL = "https://files.example.test"
	if h := e.do("GET", "/api/health", "", nil).Hdr.Get("Strict-Transport-Security"); !strings.Contains(h, "max-age=") {
		t.Fatal("HSTS missing for an https deployment:", h)
	}
}

func TestInviteAcceptIsPostOnly(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_reverse_shares": true}), 200, "reverse shares on")
	inv := e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{})
	tok := inv.S("url")[strings.LastIndex(inv.S("url"), "/")+1:]
	if c := e.do("GET", "/api/reverse-shares/accept?token="+tok, "", nil).Code; c == 200 {
		t.Fatal("GET must not accept an invite (link scanners would consume it)")
	}
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": tok}), 200, "POST accepts")
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": ""}), 404, "empty token")
}

func TestNewUploadNamesAreBoundedAndPlain(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	create := func(path string) int {
		return e.do("POST", "/api/uploads", admin, map[string]any{"files": []map[string]any{{"name": "x", "full_path": path, "size": 1}}}).Code
	}
	for name, p := range map[string]string{
		"segment over 200 bytes": strings.Repeat("a", 201) + ".txt",
		"path over 1024 bytes":   strings.Repeat("d/", 600) + "f.txt",
		"rtl override":           "photo\u202egpj.exe",
		"isolate":                "a\u2066b.txt",
		"left-to-right mark":     "a\u200eb.txt",
		"byte order mark":        "a\ufeffb.txt",
	} {
		if c := create(p); c != 400 {
			t.Errorf("%s accepted (%d)", name, c)
		}
	}
	if c := create(strings.Repeat("a", 196) + ".txt"); c != 201 {
		t.Errorf("a 200-byte segment should be fine: %d", c)
	}
	if c := create("emoji-\U0001F468\u200d\U0001F469.txt"); c != 201 {
		t.Errorf("zero-width joiner (emoji) should stay allowed: %d", c)
	}
}

func TestDownloadNotificationIsThrottledPerShare(t *testing.T) {
	e := newEnv(t)
	if !e.s.downloadMailAllowed(7) {
		t.Fatal("first notification must be allowed")
	}
	if e.s.downloadMailAllowed(7) {
		t.Fatal("second notification within a minute must be suppressed")
	}
	if !e.s.downloadMailAllowed(8) {
		t.Fatal("another share has its own allowance")
	}
}

func TestMailQueueIsBoundedAndDropsWhenFull(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < cap(e.s.mailQueue)+50; i++ {
		e.s.queueMail("", "s", "tpl_x", map[string]any{}) // empty recipient: workers fail fast
	}
	// Reaching this point without blocking proves queueMail never waits for room.
}
