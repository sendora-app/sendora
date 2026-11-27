// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import "fmt"

// settingBackground selects the built-in background image ("none" disables it).
// Uploaded custom backgrounds always take precedence in the UI.
const settingBackground = "ui_builtin_background"

// bundledBackgroundIDs must match web/src/backgrounds.js.
var bundledBackgroundIDs = map[string]bool{
	"none": true, "koenigssee": true, "medicine-bow": true, "hakkoda": true,
	"northern-lights": true, "starry-fjord": true, "forest-dawn": true,
}

// validateBackgroundSetting follows the validate*Setting convention: owned is true
// for keys this validator handles, err for an invalid value.
func validateBackgroundSetting(key, val string) (owned bool, err error) {
	if key != settingBackground {
		return false, nil
	}
	if !bundledBackgroundIDs[val] {
		return true, fmt.Errorf("unknown background")
	}
	return true, nil
}

// backgroundID returns the effective bundled background id. An unknown stored
// value falls back to "none" rather than serving an arbitrary string.
func (s *Server) backgroundID() string {
	v := s.St.Setting(settingBackground)
	if !bundledBackgroundIDs[v] {
		return "none"
	}
	return v
}
