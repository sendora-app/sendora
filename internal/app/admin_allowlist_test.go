// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net"
	"strings"
	"testing"
)

func TestAdminIPAllowlist(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	auditor := e.mkAuditor(admin, "aud1")
	user := e.mkUser(admin, "worker", false)

	// Saving a list without the administrator's own address is refused.
	r := e.do("PUT", "/api/settings", admin, map[string]any{"admin_ip_allowlist": "203.0.113.0/24"})
	if r.Code != 400 || !strings.Contains(r.S("error"), "does not include your own address 127.0.0.1") {
		t.Fatalf("self lock-out not refused: %d %s", r.Code, r.Body)
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"admin_ip_allowlist": "10.0.0.0/8 bogus"}), 400, "invalid entry")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"admin_ip_allowlist": "127.0.0.1, 203.0.113.0/24"}), 200, "list with own address")
	if got := e.s.St.Setting("admin_ip_allowlist"); got != "127.0.0.1/32\n203.0.113.0/24" {
		t.Fatalf("canonical form %q", got)
	}
	e.want(e.do("GET", "/api/users", admin, nil), 200, "allowed address")

	// Another address (stored directly, as a configuration could): refused with an audit record.
	e.s.St.SetSetting("admin_ip_allowlist", "203.0.113.0/24")
	r = e.do("GET", "/api/users", admin, nil)
	if r.Code != 403 || r.S("error") != msgAdminNetworkDenied {
		t.Fatalf("admin route from outside: %d %s", r.Code, r.Body)
	}
	e.want(e.do("GET", "/api/audit", auditor, nil), 403, "audit route from outside")
	e.want(e.do("GET", "/api/shares", user, nil), 200, "ordinary routes are not restricted")
	e.want(e.do("GET", "/api/users/me", admin, nil), 200, "own profile is not restricted")
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='access_denied' AND detail='admin_ip_allowlist'`).Scan(&n)
	if n < 2 {
		t.Fatalf("refusals recorded: %d", n)
	}

	// Recovery switch.
	t.Setenv(envDisableAdminAllowlist, "true")
	e.want(e.do("GET", "/api/users", admin, nil), 200, "recovery switch")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"admin_ip_allowlist": "198.51.100.0/24"}), 200, "switch allows saving any list")
}

func TestAdminIPAllowlistUsesTrustedProxyAddress(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	e.s.SetTrustedProxies([]*net.IPNet{lo})
	e.s.St.SetSetting("admin_ip_allowlist", "198.51.100.10")
	e.want(e.do("GET", "/api/users", admin, nil, "X-Forwarded-For", "198.51.100.10"), 200, "forwarded client inside the list")
	e.want(e.do("GET", "/api/users", admin, nil, "X-Forwarded-For", "192.0.2.1"), 403, "forwarded client outside the list")
}
