// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package app

import "errors"

var errNoDiskSpaceInfo = errors.New("free disk space unavailable on this platform")

// freeDiskSpace is not implemented on this platform; callers treat the error
// as "unknown" and proceed.
func freeDiskSpace(dir string) (uint64, error) { return 0, errNoDiskSpaceInfo }
