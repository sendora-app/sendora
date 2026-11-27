// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"testing"
	"time"
)

func TestPreviewLogIsThrottledPerShare(t *testing.T) {
	previewLogSeen.Lock()
	previewLogSeen.at = map[int64]time.Time{}
	previewLogSeen.Unlock()
	if !previewLogAllowed(1) || previewLogAllowed(1) || previewLogAllowed(1) {
		t.Fatal("only the first preview of a share within the interval may be logged")
	}
	if !previewLogAllowed(2) {
		t.Fatal("another share has its own allowance")
	}
}
