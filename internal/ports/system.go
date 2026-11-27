// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import "context"

// SystemRepository covers database health and installation-wide settings
// written outside the settings screen.
type SystemRepository interface {
	// Ping runs a trivial query and reports whether it answered correctly.
	Ping(ctx context.Context) (bool, error)
	// ReadOnly reports whether the connection refuses writes.
	ReadOnly(ctx context.Context) (bool, error)
	// SetAuditKeyFingerprint stores the database key fingerprint as a secret
	// setting (inserting or replacing it).
	SetAuditKeyFingerprint(ctx context.Context, fp string) error
	// ClassifyJWTSecret marks the stored JWT signing secret as a secret
	// setting (hidden from the settings API).
	ClassifyJWTSecret(ctx context.Context) error
	// CopyTo writes a consistent copy of the database to the file path
	// (used only for unencrypted test fixtures). Backends that are not a
	// single file (PostgreSQL) return ErrUnsupported.
	CopyTo(ctx context.Context, path string) error
}
