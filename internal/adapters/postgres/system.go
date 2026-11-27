// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

type systemRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r systemRepo) Ping(ctx context.Context) (bool, error) {
	var one int
	if err := r.q.scan(ctx, `SELECT 1`, nil, &one); err != nil {
		return false, err
	}
	return one == 1, nil
}

// ReadOnly reports a session that refuses writes: a hot standby or a
// read-only default (SQLite: PRAGMA query_only).
func (r systemRepo) ReadOnly(ctx context.Context) (bool, error) {
	var ro bool
	err := r.q.scan(ctx, `SELECT current_setting('transaction_read_only')='on'`, nil, &ro)
	return ro, err
}

func (r systemRepo) SetAuditKeyFingerprint(ctx context.Context, fp string) error {
	sealed, err := sealColKey(r.codec, "settings", "value", "audit_key_fingerprint", fp)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `INSERT INTO settings(key,value,grp) VALUES('audit_key_fingerprint',?, 'secret') ON CONFLICT(key) DO UPDATE SET value=excluded.value`, sealed)
	return err
}

func (r systemRepo) ClassifyJWTSecret(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `UPDATE settings SET grp='secret' WHERE key='jwt_secret'`)
	return err
}

func (r userRepo) Roles(ctx context.Context, id int64) (bool, bool, bool, error) {
	var admin, auditor, guest bool
	err := r.q.scan(ctx, `SELECT admin,is_auditor,is_guest FROM users WHERE id=?`, []any{id}, &admin, &auditor, &guest)
	return admin, auditor, guest, err
}

// scanTail scans the user columns followed by extra destinations.
type scanTail struct {
	row  interface{ Scan(...any) error }
	tail []any
}

func (t scanTail) Scan(dest ...any) error { return t.row.Scan(append(dest, t.tail...)...) }

func (r userRepo) ListForAccessReview(ctx context.Context) ([]ports.AccessReviewRecord, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+userCols+`,created_at,created_by,role_changed_at,role_changed_by,email_changed_at,email_changed_by,last_login_at,disabled_at,disabled_by,disabled_reason
		FROM users WHERE is_guest=0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.AccessReviewRecord
	for rows.Next() {
		var x ports.AccessReviewRecord
		var created, roleAt, emailAt, lastLogin, disabledAt sql.NullTime
		u, err := r.scanUser(scanTail{rows, []any{&created, &x.CreatedBy, &roleAt, &x.RoleChangedBy, &emailAt, &x.EmailChangedBy, &lastLogin, &disabledAt, &x.DisabledBy, &x.DisabledReason}})
		if err != nil {
			return nil, err
		}
		x.UserRecord = u
		x.Created, x.RoleChangedAt, x.EmailChangedAt, x.LastLoginAt, x.DisabledAt = nullTime(created), nullTime(roleAt), nullTime(emailAt), nullTime(lastLogin), nullTime(disabledAt)
		out = append(out, x)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Username), strings.ToLower(out[j].Username)
		return a < b || a == b && out[i].ID < out[j].ID
	})
	return out, nil
}

func (r authProviderRepo) ListLinkNames(ctx context.Context) ([]ports.ProviderLinkType, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT upa.user_id, ap.name FROM user_auth_providers upa JOIN auth_providers ap ON ap.id=upa.provider_id ORDER BY ap.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.ProviderLinkType
	for rows.Next() {
		var l ports.ProviderLinkType
		if err := rows.Scan(&l.UserID, &l.Type); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (r uploadRepo) CountAll(ctx context.Context) (int64, error) {
	var n int64
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM upload_sessions`, nil, &n)
	return n, err
}

func (r downloadMailRepo) ReleaseAllReserved(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM download_mail_outbox WHERE status='reserved'`)
	return err
}

func (r shareRepo) CountOwnedOrReceived(ctx context.Context, userID int64) (int64, error) {
	var n int64
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM shares WHERE user_id=? OR invite_id IN (SELECT id FROM reverse_invites WHERE user_id=?)`, []any{userID, userID}, &n)
	return n, err
}

// ---------- tenant limits ----------

// tenantLimitRepo implements ports.TenantLimitRepository. The table and the
// trigger tenant_user_limit are part of the schema (migration 1); Enable adds
// the row that activates them.
type tenantLimitRepo struct{ q pq }

func (r tenantLimitRepo) Enable(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO tenant_limits(id,max_users,max_storage_bytes) VALUES(1,0,0) ON CONFLICT DO NOTHING`)
	return err
}

func (r tenantLimitRepo) Set(ctx context.Context, maxUsers, maxStorageBytes int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE tenant_limits SET max_users=?, max_storage_bytes=? WHERE id=1`, maxUsers, maxStorageBytes)
	return err
}

func (r tenantLimitRepo) MaxUsers(ctx context.Context) (int64, error) {
	var limit int64
	err := r.q.scan(ctx, `SELECT max_users FROM tenant_limits WHERE id=1`, nil, &limit)
	return limit, err
}

// ---------- IP bans ----------

type ipBanRepo struct{ q pq }

func (r ipBanRepo) List(ctx context.Context) ([]ports.IPBan, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT ip,banned_until,strikes,last_strike FROM ip_bans`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.IPBan
	for rows.Next() {
		var ip string
		var until, strikes, last int64
		if rows.Scan(&ip, &until, &strikes, &last) != nil {
			continue // contract: unreadable rows are skipped
		}
		out = append(out, ports.IPBan{Key: ip, Until: time.Unix(until, 0), Strikes: int(strikes), LastStrike: time.Unix(last, 0)})
	}
	return out, rows.Err()
}

func (r ipBanRepo) Put(ctx context.Context, b ports.IPBan) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO ip_bans(ip,banned_until,strikes,last_strike) VALUES(?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET banned_until=excluded.banned_until,strikes=excluded.strikes,last_strike=excluded.last_strike`,
		b.Key, b.Until.Unix(), b.Strikes, b.LastStrike.Unix())
	return err
}

func (r ipBanRepo) Delete(ctx context.Context, key string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM ip_bans WHERE ip=?`, key)
	return err
}

func (r ipBanRepo) Prune(ctx context.Context, endedBefore, strikeBefore time.Time) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM ip_bans WHERE banned_until<? AND last_strike<?`, endedBefore.Unix(), strikeBefore.Unix())
	return err
}
