// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"testing"
)

func TestPrivacyAndTermsSettings(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"privacy_url": "http://example.org/privacy"}), 400, "https only")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"terms_acceptance_required": "true"}), 400, "terms URL and version needed")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"privacy_url": "https://example.org/privacy", "terms_url": "https://example.org/terms"}), 200, "links")
	b := e.do("GET", "/api/bootstrap", "", nil).J()
	if b["privacy_url"] != "https://example.org/privacy" || b["terms_url"] != "https://example.org/terms" || b["terms_acceptance_required"] != false {
		t.Fatalf("bootstrap %v", b)
	}
}

func TestTermsAcceptance(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	user := e.mkUser(admin, "tess", false)
	e.want(e.do("POST", "/api/users/me/terms", user, map[string]any{"version": "1"}), 409, "not required yet")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"terms_url": "https://example.org/terms", "terms_version": "2026-1", "terms_acceptance_required": "true"}), 200, "require terms")
	r := e.do("GET", "/api/shares", user, nil)
	if r.Code != 403 || r.S("code") != "terms_required" {
		t.Fatalf("pending terms: %d %s", r.Code, r.Body)
	}
	me := e.do("GET", "/api/users/me", user, nil)
	if me.J()["terms_pending"] != true {
		t.Fatalf("terms_pending: %s", me.Body)
	}
	e.want(e.do("GET", "/api/users/me/export", user, nil), 200, "export stays possible")
	e.want(e.do("POST", "/api/users/me/terms", user, map[string]any{"version": "2025-9"}), 409, "old version")
	e.want(e.do("POST", "/api/users/me/terms", user, map[string]any{"version": "2026-1"}), 200, "accept")
	e.want(e.do("GET", "/api/shares", user, nil), 200, "after acceptance")
	if countAudit(t, e, "terms_accepted") != 1 {
		t.Fatal("terms_accepted not recorded")
	}
	// A new version asks again.
	e.s.St.SetSetting("terms_version", "2026-2")
	e.want(e.do("GET", "/api/shares", user, nil), 403, "new version")
}
