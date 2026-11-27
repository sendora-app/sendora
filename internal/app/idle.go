// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"time"
)

// settingIdleLogout is the global inactivity window in minutes; 0 disables it.
const (
	settingIdleLogout = "idle_logout_minutes"
	idleLogoutDefault = 60
	idleLogoutMax     = 10080 // one week
	// Access tokens live 15 minutes, so a browser that is in use refreshes at
	// least that often; the grace also absorbs a slow network or sleeping tab.
	idleRefreshGrace = 20 * time.Minute
)

// validateIdleSetting follows the validate*Setting convention.
func validateIdleSetting(key, val string) (owned bool, err error) {
	if key != settingIdleLogout {
		return false, nil
	}
	if _, ok := parseStrictInt(val, 0, idleLogoutMax); !ok {
		return true, fmt.Errorf("%s must be a whole number of minutes from 0 to %d (0 = never)", settingIdleLogout, idleLogoutMax)
	}
	return true, nil
}

// idleLogoutMinutes returns the effective window. A corrupt stored value falls
// back to the default rather than silently disabling the protection.
func (s *Server) idleLogoutMinutes() int {
	n, ok := parseStrictInt(s.St.Setting(settingIdleLogout), 0, idleLogoutMax)
	if !ok {
		return idleLogoutDefault
	}
	return n
}

// idleExpired reports whether a refresh token issued at `issued` is older than
// the inactivity window plus grace. This is an approximation: the server does not
// track individual requests, only how long ago the token was last rotated. A zero
// time (legacy row) is treated as fresh.
// It takes the window as an argument because it runs inside the refresh
// transaction, which holds the only database connection (settings must be read
// before the transaction begins).
func idleExpired(minutes int, issued time.Time, now time.Time) bool {
	if minutes == 0 || issued.IsZero() {
		return false
	}
	return now.Sub(issued) > time.Duration(minutes)*time.Minute+idleRefreshGrace
}
