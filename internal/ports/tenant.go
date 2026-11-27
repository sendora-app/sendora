// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import "context"

// TenantLimitRepository holds the quotas the platform sets for one tenant's
// database (multi-tenant mode). 0 means unlimited. A single-tenant database
// has no limits until Enable is called.
type TenantLimitRepository interface {
	// Enable creates the limits (both unlimited) when absent and makes the
	// database refuse a new non-guest account while MaxUsers > 0 and that
	// many non-guest accounts exist, whichever way the account is added. The
	// refusal error wraps ErrTenantUserLimit (its text mentions "tenant user
	// limit"). Concurrent inserts cannot overshoot the limit. Idempotent;
	// stored limits are kept.
	Enable(ctx context.Context) error
	// Set stores both limits.
	Set(ctx context.Context, maxUsers, maxStorageBytes int64) error
	// MaxUsers returns the stored user limit (an error before Enable).
	MaxUsers(ctx context.Context) (int64, error)
}
