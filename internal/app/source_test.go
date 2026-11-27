// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"strings"
	"testing"
)

func TestResolveSourceURL(t *testing.T) {
	const rev = "0123456789abcdef0123456789abcdef01234567"
	cases := []struct {
		name, version, revision, build, env, want string
		ok                                        bool
	}{
		{"release tag", "0.2.1", rev, "", "", ProjectURL + "/tree/v0.2.1", true},
		{"pre-release tag", "0.3.0-rc.1", "", "", "", ProjectURL + "/tree/v0.3.0-rc.1", true},
		{"dev build: commit", "dev", rev, "", "", ProjectURL + "/tree/" + rev, true},
		{"dev build without commit", "dev", "", "", "", ProjectURL, true},
		{"-dev version: commit, not a tag", "0.3.0-dev", rev, "", "", ProjectURL + "/tree/" + rev, true},
		{"-dev version without commit", "0.3.0-dev", "unknown", "", "", ProjectURL, true},
		{"odd revision ignored", "dev", "unknown", "", "", ProjectURL, true},
		{"build flag", "1.0.0", rev, "https://git.example.com/fork/tree/{revision}", "", "https://git.example.com/fork/tree/" + rev, true},
		{"env wins over build flag", "1.0.0", "", "https://a.example.com/x", "https://b.example.com/src/v{version}", "https://b.example.com/src/v1.0.0", true},
		{"invalid env falls back to build flag", "1.0.0", "", "https://a.example.com/x", "javascript:alert(1)", "https://a.example.com/x", false},
		{"invalid values fall back to the default", "1.0.0", "", "ftp://a.example.com", "not a url", ProjectURL + "/tree/v1.0.0", false},
		{"credentials refused", "1.0.0", "", "", "https://user:pw@example.com/", ProjectURL + "/tree/v1.0.0", false},
		{"markup refused", "1.0.0", "", "", `https://example.com/"><script>`, ProjectURL + "/tree/v1.0.0", false},
		{"blank env ignored (cannot switch the link off)", "1.0.0", "", "", "   ", ProjectURL + "/tree/v1.0.0", true},
	}
	for _, c := range cases {
		got, ok := ResolveSourceURL(c.version, c.revision, c.build, c.env)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

// AGPL-3.0 section 13: public pages carry the source link, signed-out and
// signed-in alike; the plain version stays for signed-in users only.
func TestBootstrapOffersSourceURL(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/api/bootstrap", "", nil)
	e.want(r, 200, "bootstrap")
	if got := r.S("source_url"); got != ProjectURL {
		t.Fatalf("source_url = %q (version %q), want %q", got, e.s.Version, ProjectURL)
	}
	if strings.Contains(string(r.Body), `"version"`) {
		t.Fatalf("bootstrap exposes the version: %s", r.Body)
	}

	SetSourceURL("https://git.example.com/fork/tree/v9.9.9")
	t.Cleanup(func() { SetSourceURL("") })
	r = e.do("GET", "/api/bootstrap", "", nil)
	if got := r.S("source_url"); got != "https://git.example.com/fork/tree/v9.9.9" {
		t.Fatalf("configured source_url = %q", got)
	}
}

// Multi-tenant mode: tenant pages and the platform console carry the link too.
func TestMTSourceURLOnTenantAndConsole(t *testing.T) {
	m := newMTEnv(t)
	m.newTenant("klant1")
	SetSourceURL("https://git.example.com/fork/tree/abc1234")
	t.Cleanup(func() { SetSourceURL("") })
	k := m.host("klant1." + mtBase)
	r := k.do("GET", "/api/bootstrap", "", nil)
	k.want(r, 200, "tenant bootstrap")
	if got := r.S("source_url"); got != "https://git.example.com/fork/tree/abc1234" {
		t.Fatalf("tenant source_url = %q", got)
	}
	c := m.host("admin." + mtBase)
	r = c.do("GET", "/api/platform/bootstrap", "", nil)
	c.want(r, 200, "console bootstrap")
	if got := r.S("source_url"); got != "https://git.example.com/fork/tree/abc1234" {
		t.Fatalf("console source_url = %q", got)
	}
}

// No setting can remove or replace the source link.
func TestSourceURLIsNotASetting(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	for _, key := range []string{"source_url", "show_source_link", "hide_powered_by"} {
		e.do("PUT", "/api/settings", admin, map[string]any{key: "https://evil.example.com"})
		var n int
		e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM settings WHERE key=?`, key).Scan(&n)
		if n != 0 {
			t.Fatalf("setting %s was stored", key)
		}
	}
	if got := e.do("GET", "/api/bootstrap", "", nil).S("source_url"); got != ProjectURL {
		t.Fatalf("source_url = %q", got)
	}
}
