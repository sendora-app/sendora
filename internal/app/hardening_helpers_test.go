// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import "testing"

// liftDownloadMailThrottle disables the one-notification-per-share-per-minute
// limit for tests that deliberately download the same share repeatedly.
func liftDownloadMailThrottle(t *testing.T) {
	t.Helper()
	old := downloadMailMinInterval
	downloadMailMinInterval = 0
	t.Cleanup(func() { downloadMailMinInterval = old })
}
