// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitBaseDomain(t *testing.T) {
	for in, want := range map[string][2]string{
		"sendora.localhost":      {"sendora.localhost", ""},
		"Sendora.Localhost:9090": {"sendora.localhost", "9090"},
		"files.example.com:443":  {"files.example.com", ""},
		"localhost:9091":         {"localhost", "9091"},
	} {
		h, p, err := SplitBaseDomain(in)
		if err != nil || h != want[0] || p != want[1] {
			t.Errorf("%s: %q %q %v", in, h, p, err)
		}
	}
	for _, bad := range []string{"", "https://x.example", "x.example/path", "x.example:0", "x.example:70000", "x.example:abc", "bad host"} {
		if _, _, err := SplitBaseDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if JoinBaseDomain("x.example", "9090") != "x.example:9090" || JoinBaseDomain("x.example", "443") != "x.example" {
		t.Fatal("join")
	}
}

// Scheduling warns when the base domain's port differs from the port the
// server is reached on (no proxy), and a custom domain keeps only its host.
func TestConversionPortWarning(t *testing.T) {
	c := newConvEnv(t)
	body := map[string]any{}
	for k, v := range convBody {
		body[k] = v
	}
	_, port, _ := strings.Cut(strings.TrimPrefix(c.ts.URL, "http://"), ":")
	body["base_domain"], body["custom_domain"] = "sendora.localhost", "https://files.acme.test:8443/x"
	r := c.schedule(body)
	c.want(r, 200, "schedule")
	if !strings.Contains(r.S("warning"), "has no port") || !strings.Contains(r.S("warning"), port) {
		t.Fatalf("no port warning: %s", r.Body)
	}
	raw, _ := os.ReadFile(filepath.Join(c.dir, ConversionPendingFile))
	if !strings.Contains(string(raw), `"custom_domain": "files.acme.test"`) {
		t.Fatalf("custom domain not reduced to its host: %s", raw)
	}
	body["base_domain"] = "sendora.localhost:" + port
	if r := c.schedule(body); r.S("warning") != "" {
		t.Fatalf("warning with the right port: %s", r.Body)
	}
	body["base_domain"] = "https://sendora.localhost"
	c.want(c.schedule(body), 400, "scheme in the base domain")
}

// The console stores a base domain (host and port) in DATA_DIR for the next
// start, with re-authentication and an audit record.
func TestConsoleBaseDomain(t *testing.T) {
	t.Setenv("SENDORA_BASE_DOMAIN", "")
	m := newMTEnv(t)
	c, cookie, secret := m.consoleLogin()
	g := c.do("GET", "/api/platform/settings", "", nil, "Cookie", cookie)
	if g.J()["base_host"] != mtBase || g.J()["base_domain_managed"] != false {
		t.Fatalf("settings: %s", g.Body)
	}
	c.want(c.do("PUT", "/api/platform/base-domain", "", map[string]any{"host": "sendora.localhost", "port": "9090"}, "Cookie", cookie), 403, "without re-auth")
	c.want(c.do("PUT", "/api/platform/base-domain", "", map[string]any{"host": "https://bad", "port": "", "code": m.nextCode(secret)}, "Cookie", cookie), 400, "invalid host")
	r := c.do("PUT", "/api/platform/base-domain", "", map[string]any{"host": "sendora.localhost", "port": "9090", "code": m.nextCode(secret)}, "Cookie", cookie)
	c.want(r, 200, "base domain")
	if pm, _ := ReadPersistedMode(m.dir); pm == nil || pm.BaseDomain != "sendora.localhost:9090" || r.J()["restart_needed"] != true {
		t.Fatalf("persisted: %+v %s", pm, r.Body)
	}
	au := c.do("GET", "/api/platform/audit", "", nil, "Cookie", cookie)
	if !strings.Contains(string(au.Body), `"action":"platform_base_domain_changed"`) {
		t.Fatal("base domain change not audited")
	}
	t.Setenv("SENDORA_BASE_DOMAIN", "env.example.com")
	c.want(c.do("PUT", "/api/platform/base-domain", "", map[string]any{"host": "x.example", "code": m.nextCode(secret)}, "Cookie", cookie), 409, "set by the environment")
}
