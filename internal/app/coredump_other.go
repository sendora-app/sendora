// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package app

// DisableCoreDumps is a no-op outside Linux.
func DisableCoreDumps() error { return nil }
