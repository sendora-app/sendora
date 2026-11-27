// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"testing"
	"time"
)

func TestDownloadLogFirstRequestOnlyAndThrottledPerShare(t *testing.T) {
	s := &Server{}
	// Continuation ranges never count, not even the first time.
	for _, rng := range []string{"bytes=100-", "bytes=500-999", "bytes=-500"} {
		if s.downloadLogAllowed(1, rng) {
			t.Fatalf("range %q is not the start of a download", rng)
		}
	}
	if !s.downloadLogAllowed(1, "") {
		t.Fatal("the first plain request of a share must be recorded")
	}
	if s.downloadLogAllowed(1, "") || s.downloadLogAllowed(1, "bytes=0-") {
		t.Fatal("further downloads of the same share within the interval must not be recorded")
	}
	if !s.downloadLogAllowed(2, "bytes=0-") {
		t.Fatal("a download from byte 0 of another share must be recorded")
	}
	// After the interval the share is recorded again.
	s.audit.dlMu.Lock()
	s.audit.dlAt[1] = time.Now().Add(-downloadLogInterval - time.Second)
	s.audit.dlMu.Unlock()
	if !s.downloadLogAllowed(1, "") {
		t.Fatal("the next download after the interval must be recorded")
	}
	// The map stays bounded.
	for i := int64(10); i < 5000; i++ {
		s.downloadLogAllowed(i, "")
	}
	s.audit.dlMu.Lock()
	n := len(s.audit.dlAt)
	s.audit.dlMu.Unlock()
	if n > 4097 {
		t.Fatalf("map grew to %d entries", n)
	}
}
