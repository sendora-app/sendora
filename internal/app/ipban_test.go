// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"net/url"
	"testing"
	"time"
)

func failLogins(e *env, n int, user string) (last resp) {
	for i := 0; i < n; i++ {
		// distinct unknown names: the per-account lockout must not interfere
		last = e.login(fmt.Sprintf("ghost-%s-%d", user, i), "definitely-wrong")
	}
	return last
}

func TestIPBanAfterRepeatedFailures(t *testing.T) {
	e := newEnv(t)
	t.Setenv("SENDORA_DISABLE_IP_BANS", "")
	admin := e.setup()
	e.mkUser(admin, "carol", false)

	if r := failLogins(e, ipBanThreshold-1, "carol"); r.Code != 401 {
		t.Fatalf("wrong password must be 401, got %d", r.Code)
	}
	e.want(e.login("carol", "password123"), 200, "still allowed below the threshold")
	// the successful login does not reset the window: one more failure reaches the threshold
	failLogins(e, 1, "carol")
	r := e.login("carol", "password123")
	e.want(r, 429, "banned even with the right password")
	if r.Hdr.Get("Retry-After") == "" {
		t.Fatal("Retry-After missing")
	}
	// other sign-in routes are blocked too, but not downloads or token refresh
	e.want(e.do("POST", "/api/auth/mfa/totp", "", map[string]any{"mfa_token": "x", "code": "123456"}), 429, "mfa blocked")

	list := e.do("GET", "/api/ip-bans", admin, nil)
	e.want(list, 200, "list bans")
	bans, _ := list.J()["bans"].([]any)
	if len(bans) != 1 {
		t.Fatalf("expected one ban, got %v", list.J()["bans"])
	}
	first := bans[0].(map[string]any)
	ip := first["ip"].(string)

	// persisted: survives a reload from the database
	s := e.s
	s.ipBans.mu.Lock()
	s.ipBans.bans = nil
	s.ipBans.mu.Unlock()
	s.loadIPBans()
	e.want(e.login("carol", "password123"), 429, "ban survives restart")

	e.want(e.do("DELETE", "/api/ip-bans?ip="+url.QueryEscape(ip), admin, nil), 200, "unban")
	e.want(e.login("carol", "password123"), 200, "allowed after unban")
	e.want(e.do("DELETE", "/api/ip-bans?ip="+url.QueryEscape(ip), admin, nil), 404, "unban twice")

	// second offence within the memory window doubles the ban
	failLogins(e, ipBanThreshold, "carol")
	b := s.activeIPBans()
	if len(b) != 1 {
		t.Fatalf("expected a ban, got %v", b)
	}
	// unban forgets strikes: duration is the base again
	if d := time.Until(b[0].Until); d > ipBanBase+time.Minute {
		t.Fatalf("strikes must reset on manual unban, got %v", d)
	}
	e.s.ipBans.mu.Lock()
	x := e.s.ipBans.bans[ip]
	x.until = time.Now().Add(-time.Second)
	e.s.ipBans.bans[ip] = x
	e.s.ipBans.mu.Unlock()
	failLogins(e, ipBanThreshold, "carol")
	b = s.activeIPBans()
	if len(b) != 1 || b[0].Strikes != 2 || time.Until(b[0].Until) < 2*ipBanBase-time.Minute {
		t.Fatalf("second ban must double: %+v", b)
	}
}

func TestIPBanAllowlistAndSwitch(t *testing.T) {
	e := newEnv(t)
	t.Setenv("SENDORA_DISABLE_IP_BANS", "")
	admin := e.setup()
	e.mkUser(admin, "dave", false)
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"ip_ban_allowlist": "bogus"}), 400, "invalid allowlist")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"ip_ban_allowlist": "127.0.0.0/8, ::1"}), 200, "set allowlist")
	if got := e.s.St.Setting("ip_ban_allowlist"); got != "127.0.0.0/8\n::1/128" {
		t.Fatalf("allowlist not normalised: %q", got)
	}
	failLogins(e, ipBanThreshold+2, "dave")
	e.want(e.login("dave", "password123"), 200, "allowlisted address is never banned")

	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"ip_ban_allowlist": "", "ip_ban_enabled": "false"}), 200, "disable")
	failLogins(e, ipBanThreshold+2, "dave")
	e.want(e.login("dave", "password123"), 200, "bans switched off")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"ip_ban_enabled": "maybe"}), 400, "invalid switch")

	t.Setenv("SENDORA_DISABLE_IP_BANS", "true")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"ip_ban_enabled": "true"}), 200, "enable")
	failLogins(e, ipBanThreshold+2, "dave")
	e.want(e.login("dave", "password123"), 200, "recovery env var disables bans")
}

func TestIPBanKeyGroupsIPv6Prefix(t *testing.T) {
	if ipBanKey("2001:db8:1:2:aaaa::1") != ipBanKey("2001:db8:1:2:bbbb::9") {
		t.Fatal("same /64 must share a key")
	}
	if ipBanKey("2001:db8:1:3::1") == ipBanKey("2001:db8:1:2::1") {
		t.Fatal("different /64 must differ")
	}
	if ipBanKey("192.0.2.7") != "192.0.2.7" {
		t.Fatal("IPv4 unchanged")
	}
}
