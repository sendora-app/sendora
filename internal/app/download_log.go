// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"strings"
	"time"
)

// downloadLogInterval is how long one download_started record per share
// stands for all downloads of that share.
const downloadLogInterval = 5 * time.Minute

// downloadLogAllowed decides whether a public download gets a download_started
// audit record. Only the first request of a download counts (no Range header,
// or a range from byte 0): a resumed or chunked download (each Range request of
// a player or download manager) is the same download. Like previews, at most
// one record per share is written per interval, so a link that is fetched in a
// loop cannot flood the audit log. The downloads table still counts every
// download. The map is bounded and reset when it grows too large.
func (s *Server) downloadLogAllowed(shareID int64, rangeHeader string) bool {
	if rng := strings.TrimSpace(rangeHeader); rng != "" && !strings.HasPrefix(rng, "bytes=0-") {
		return false
	}
	a := &s.audit
	a.dlMu.Lock()
	defer a.dlMu.Unlock()
	now := time.Now()
	if a.dlAt == nil || len(a.dlAt) > 4096 {
		a.dlAt = map[int64]time.Time{}
	}
	if last, ok := a.dlAt[shareID]; ok && now.Sub(last) < downloadLogInterval {
		return false
	}
	a.dlAt[shareID] = now
	return true
}
