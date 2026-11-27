// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import "testing"

func TestEmailChangeRespectsRegistrationDomains(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	user := e.mkUser(admin, "mover", false)
	body := func(email string) map[string]any {
		return map[string]any{"name": "Mover", "email": email, "current_password": "password123"}
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"registration_email_domains": "example.com"}), 200, "restrict domains")
	e.want(e.do("PUT", "/api/users/me", user, body("mover@elsewhere.test")), 400, "change to a disallowed domain")
	e.want(e.do("PUT", "/api/users/me", user, map[string]any{"name": "Renamed", "email": "mover@mover.test", "current_password": "password123"}), 400, "unchanged-domain rule applies to any new address")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"registration_email_domains": ""}), 200, "clear restriction")
	e.want(e.do("PUT", "/api/users/me", user, body("mover@elsewhere.test")), 200, "change allowed when unrestricted")
}
