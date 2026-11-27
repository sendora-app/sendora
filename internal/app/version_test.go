// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"strings"
	"testing"
)

// The version label is shown to signed-in users only, never on public endpoints.
// (Public pages do carry the AGPL source link, which names the release; see
// TestBootstrapOffersSourceURL.)
func TestVersionOnlyForSignedInUsers(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	me := e.do("GET", "/api/users/me", admin, nil)
	e.want(me, 200, "me")
	if me.S("version") != "test" {
		t.Fatalf("version = %q", me.S("version"))
	}
	for _, p := range []string{"/api/bootstrap", "/api/health"} {
		r := e.do("GET", p, "", nil)
		e.want(r, 200, p)
		if strings.Contains(string(r.Body), "\"version\"") {
			t.Fatalf("%s exposes the version: %s", p, r.Body)
		}
	}
}
