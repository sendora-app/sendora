// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package app

import (
	"errors"
	"syscall"
)

// errNoDiskSpaceInfo is returned on platforms without statfs (never here).
var errNoDiskSpaceInfo = errors.New("free disk space unavailable on this platform")

// freeDiskSpace reports the bytes available to unprivileged writers on the
// filesystem holding dir.
func freeDiskSpace(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
