// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"sync"
	"time"
)

const previewLogInterval = 5 * time.Minute

var previewLogSeen = struct {
	sync.Mutex
	at map[int64]time.Time
}{at: map[int64]time.Time{}}

// previewLogAllowed rate-limits audit entries for public previews to one per
// share per interval. The map is bounded and reset when it grows too large.
func previewLogAllowed(shareID int64) bool {
	previewLogSeen.Lock()
	defer previewLogSeen.Unlock()
	now := time.Now()
	if len(previewLogSeen.at) > 4096 {
		previewLogSeen.at = map[int64]time.Time{}
	}
	if last, ok := previewLogSeen.at[shareID]; ok && now.Sub(last) < previewLogInterval {
		return false
	}
	previewLogSeen.at[shareID] = now
	return true
}
