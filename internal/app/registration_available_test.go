// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import "testing"

func TestRegistrationAvailableNeedsEverythingToWork(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	avail := func() any { return e.do("GET", "/api/bootstrap", "", nil).J()["registration_available"] }
	if e.s.St.SettingBool("allow_self_registration") || avail() != false {
		t.Fatal("a fresh install must not offer registration", avail())
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_self_registration": true}), 200, "enable registration")
	if avail() != false {
		t.Fatal("registration must stay hidden while SMTP is not configured", avail())
	}
	e.useSMTP(newSMTP(t))
	if avail() != true {
		t.Fatal("registration should be offered once enabled with working SMTP", avail())
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_self_registration": false}), 200, "disable registration")
	if avail() != false {
		t.Fatal("disabled registration must not be offered", avail())
	}
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "x", "email": "x@x.io", "password": "password123"}), 403, "closed registration")
}
