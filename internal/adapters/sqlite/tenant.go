// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import "context"

// tenantLimitRepo implements ports.TenantLimitRepository (table tenant_limits
// and the trigger tenant_user_limit of a tenant database).
type tenantLimitRepo struct{ q querier }

func (r tenantLimitRepo) Enable(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS tenant_limits (
		id INTEGER PRIMARY KEY CHECK (id=1),
		max_users INTEGER NOT NULL DEFAULT 0,
		max_storage_bytes INTEGER NOT NULL DEFAULT 0);
	INSERT OR IGNORE INTO tenant_limits(id,max_users,max_storage_bytes) VALUES(1,0,0);
	CREATE TRIGGER IF NOT EXISTS tenant_user_limit BEFORE INSERT ON users
	WHEN NEW.is_guest=0 AND (SELECT max_users FROM tenant_limits WHERE id=1)>0
	  AND (SELECT COUNT(*) FROM users WHERE is_guest=0)>=(SELECT max_users FROM tenant_limits WHERE id=1)
	BEGIN SELECT RAISE(ABORT,'tenant user limit reached'); END;`)
	return err
}

func (r tenantLimitRepo) Set(ctx context.Context, maxUsers, maxStorageBytes int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE tenant_limits SET max_users=?, max_storage_bytes=? WHERE id=1`, maxUsers, maxStorageBytes)
	return err
}

func (r tenantLimitRepo) MaxUsers(ctx context.Context) (int64, error) {
	var limit int64
	err := r.q.QueryRowContext(ctx, `SELECT max_users FROM tenant_limits WHERE id=1`).Scan(&limit)
	return limit, err
}
