// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package app

import "syscall"

const prSetDumpable = 4

// DisableCoreDumps sets RLIMIT_CORE to 0 and marks the process non-dumpable, so a
// crash or a same-user ptrace cannot write secrets (database key, signing
// secret) to disk or read them from memory.
func DisableCoreDumps() error {
	err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 && err == nil {
		err = errno
	}
	return err
}
