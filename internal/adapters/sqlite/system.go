// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

type systemRepo struct {
	q     querier
	codec ports.ColumnCodec
}

func (r systemRepo) Ping(ctx context.Context) (bool, error) {
	var one int
	if err := r.q.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		return false, err
	}
	return one == 1, nil
}

func (r systemRepo) ReadOnly(ctx context.Context) (bool, error) {
	var queryOnly int
	if err := r.q.QueryRowContext(ctx, `PRAGMA query_only`).Scan(&queryOnly); err != nil {
		return false, err
	}
	return queryOnly != 0, nil
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
	err := r.q.QueryRowContext(ctx, `SELECT admin,is_auditor,is_guest FROM users WHERE id=?`, id).Scan(&admin, &auditor, &guest)
	return admin, auditor, guest, notFound(err)
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
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM upload_sessions`).Scan(&n)
	return n, err
}

func (r downloadMailRepo) ReleaseAllReserved(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM download_mail_outbox WHERE status='reserved'`)
	return err
}

func (r shareRepo) CountOwnedOrReceived(ctx context.Context, userID int64) (int64, error) {
	var n int64
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM shares WHERE user_id=? OR invite_id IN (SELECT id FROM reverse_invites WHERE user_id=?)`, userID, userID).Scan(&n)
	return n, err
}
