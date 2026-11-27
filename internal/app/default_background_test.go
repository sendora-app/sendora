// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import "testing"

func TestBundledBackgroundSetting(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	boot := func() any { return e.do("GET", "/api/bootstrap", "", nil).J()["background"] }
	if boot() != "koenigssee" {
		t.Fatal("default bundled background should be the photo", boot())
	}
	e.want(e.do("PUT", "/api/settings", "", map[string]any{"ui_builtin_background": "none"}), 401, "anonymous cannot change")
	for _, id := range []string{"none", "hakkoda", "forest-dawn", "northern-lights"} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"ui_builtin_background": id}), 200, "choose "+id)
		if boot() != id {
			t.Fatal("background not applied", id, boot())
		}
	}
	for _, bad := range []any{"", "../../etc/passwd", "unknown", nil, true, 5, []string{"none"}} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"ui_builtin_background": bad, "application_name": "must-not-change"}), 400, "invalid background")
	}
	if boot() != "northern-lights" || e.s.St.Setting("application_name") == "must-not-change" {
		t.Fatal("rejected batch changed state")
	}
	// A corrupt stored value never leaks through bootstrap.
	if err := e.s.St.SetSetting("ui_builtin_background", "<script>"); err != nil {
		t.Fatal(err)
	}
	if boot() != "none" {
		t.Fatal("unknown stored value must read as none", boot())
	}
}
