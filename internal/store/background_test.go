// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "testing"

func TestLegacyBackgroundOffIsKept(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	if got := st.Setting("ui_builtin_background"); got != "koenigssee" {
		t.Fatal("fresh default should be the photo, got", got)
	}
	if _, err := st.DB.Exec(`DELETE FROM settings WHERE key='ui_builtin_background'`); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("ui_default_background", "false"); err != nil {
		t.Fatal(err)
	}
	st.seed()
	if got := st.Setting("ui_builtin_background"); got != "none" {
		t.Fatal("legacy 'off' must map to none, got", got)
	}
	st.seed() // idempotent: a later explicit choice must survive restarts
	if err := st.SetSetting("ui_builtin_background", "hakkoda"); err != nil {
		t.Fatal(err)
	}
	st.seed()
	if got := st.Setting("ui_builtin_background"); got != "hakkoda" {
		t.Fatal("seed must not overwrite a chosen background, got", got)
	}
}
