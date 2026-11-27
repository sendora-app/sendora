// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// Account security, deactivation and terms (users), the sign-in history and
// storage accounting.

func (r userRepo) LocalIDByUsername(ctx context.Context, username string) (int64, error) {
	var id int64
	bi, err := blindKey(r.codec, "users", "username", username)
	if err != nil {
		return 0, err
	}
	err = r.q.QueryRowContext(ctx, `SELECT id FROM users WHERE username_bi=? AND is_guest=0`, bi).Scan(&id)
	return id, notFound(err)
}

func (r userRepo) SetLoginFailures(ctx context.Context, id int64, failures, lockedUntil int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET login_failures=?,login_locked_until=? WHERE id=?`, failures, lockedUntil, id)
	return err
}

func (r userRepo) ClearLoginFailures(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET login_failures=0,login_locked_until=0 WHERE id=?`, id)
	return err
}

func (r userRepo) BumpMFAEpoch(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET mfa_epoch=mfa_epoch+1 WHERE id=?`, id)
	return err
}

func (r userRepo) BumpMFAEpochAndClearLock(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET mfa_epoch=mfa_epoch+1,login_failures=0,login_locked_until=0 WHERE id=?`, id)
	return err
}

func (r userRepo) IsDisabled(ctx context.Context, id int64) (bool, error) {
	var stored bool
	err := r.q.QueryRowContext(ctx, `SELECT disabled_at IS NOT NULL FROM users WHERE id=?`, id).Scan(&stored)
	return stored, notFound(err)
}

func (r userRepo) ShareOwnerDisabled(ctx context.Context, shareID int64) (bool, error) {
	n, err := r.count(ctx, `SELECT COUNT(*) FROM shares s
		LEFT JOIN users u ON u.id=s.user_id
		LEFT JOIN reverse_invites ri ON ri.id=s.invite_id
		LEFT JOIN users iu ON iu.id=ri.user_id
		WHERE s.id=? AND (u.disabled_at IS NOT NULL OR iu.disabled_at IS NOT NULL)`, shareID)
	return err == nil && n > 0, err
}

func (r userRepo) CountActiveAdminsExcept(ctx context.Context, id int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM users WHERE admin=1 AND is_guest=0 AND disabled_at IS NULL AND id<>?`, id)
}

func (r userRepo) SetCreatedBy(ctx context.Context, id int64, by string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET created_by=? WHERE id=?`, by, id)
	return err
}

func (r userRepo) NoteRoleChange(ctx context.Context, id int64, at time.Time, by string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET role_changed_at=?,role_changed_by=? WHERE id=?`, at, by, id)
	return err
}

func (r userRepo) NoteEmailChange(ctx context.Context, id int64, at time.Time, by string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET email_changed_at=?,email_changed_by=? WHERE id=?`, at, by, id)
	return err
}

func (r userRepo) Disable(ctx context.Context, id int64, at time.Time, by, reason string) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE users SET disabled_at=?,disabled_by=?,disabled_reason=? WHERE id=? AND is_guest=0 AND disabled_at IS NULL`, at, by, reason, id))
}

func (r userRepo) Enable(ctx context.Context, id int64) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE users SET disabled_at=NULL,disabled_by='',disabled_reason='' WHERE id=? AND is_guest=0 AND disabled_at IS NOT NULL`, id))
}

// uploadsOfAccount selects the pending uploads of an account and of the
// guests it invited (UploadsToRevoke, RevokeAccess).
const uploadsOfAccount = `user_id=? OR quota_owner_id=? OR user_id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=? AND guest_user_id IS NOT NULL)`

func (r userRepo) UploadsToRevoke(ctx context.Context, id int64) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id FROM upload_sessions WHERE `+uploadsOfAccount, id, id, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uploads []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			return nil, err
		}
		uploads = append(uploads, sid)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return uploads, nil
}

func (r userRepo) RevokeAccess(ctx context.Context, id int64, now time.Time) (int64, error) {
	var invites int64
	for _, q := range []struct {
		sql   string
		args  []any
		count *int64
	}{
		{`DELETE FROM upload_sessions WHERE ` + uploadsOfAccount, []any{id, id, id}, nil},
		// Open invitations (and their unused children) stop working now.
		{`UPDATE reverse_invites SET expires_at=? WHERE user_id=? AND completed_at IS NULL AND expires_at>?`, []any{now, id, now}, &invites},
		// Every session of the account and of its guests ends.
		{`DELETE FROM refresh_tokens WHERE user_id=? OR user_id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=? AND guest_user_id IS NOT NULL)`, []any{id, id}, nil},
		{`DELETE FROM password_resets WHERE user_id=?`, []any{id}, nil},
		{`DELETE FROM email_verifications WHERE user_id=?`, []any{id}, nil},
		{`DELETE FROM mfa_reset_requests WHERE user_id=?`, []any{id}, nil},
	} {
		res, err := r.q.ExecContext(ctx, q.sql, q.args...)
		if err != nil {
			return 0, err
		}
		if q.count != nil {
			*q.count, _ = res.RowsAffected()
		}
	}
	return invites, nil
}

func (r userRepo) TermsAcceptedVersion(ctx context.Context, id int64) (string, error) {
	var accepted string
	err := r.q.QueryRowContext(ctx, `SELECT terms_accepted_version FROM users WHERE id=?`, id).Scan(&accepted)
	return accepted, notFound(err)
}

func (r userRepo) AcceptTerms(ctx context.Context, id int64, version string, at time.Time) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET terms_accepted_version=?, terms_accepted_at=? WHERE id=?`, version, at, id)
	return err
}

func (r passwordResetRepo) CreateReset(ctx context.Context, hash string, userID int64, expiresAt time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO password_resets(hash,user_id,expires_at,kind) VALUES(?,?,?,'reset')`, hash, userID, expiresAt)
	return err
}

func (r passwordResetRepo) DeleteResetsForUser(ctx context.Context, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id=? AND kind='reset'`, userID)
	return err
}

func (r passwordResetRepo) CreateWelcome(ctx context.Context, hash string, userID int64, expiresAt time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO password_resets(hash,user_id,expires_at,kind) VALUES(?,?,?,'welcome')`, hash, userID, expiresAt)
	return err
}

func (r passwordResetRepo) DeleteWelcomesForUser(ctx context.Context, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id=? AND kind='welcome'`, userID)
	return err
}

func (r passwordResetRepo) CountWelcomesForUser(ctx context.Context, userID int64) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM password_resets WHERE user_id=? AND kind='welcome'`, userID).Scan(&n)
	return n, err
}

type signInHistoryRepo struct{ q querier }

func (r signInHistoryRepo) PruneBefore(ctx context.Context, userID int64, cutoff time.Time) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM user_signin_seen WHERE user_id=? AND last_seen<?`, userID, cutoff)
	return err
}

func (r signInHistoryRepo) Stats(ctx context.Context, userID int64, fingerprint string) (int, int, error) {
	var history, known int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(fingerprint=?),0) FROM user_signin_seen WHERE user_id=?`, fingerprint, userID).Scan(&history, &known)
	return history, known, err
}

func (r signInHistoryRepo) Touch(ctx context.Context, userID int64, fingerprint string, at time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO user_signin_seen(user_id,fingerprint,last_seen) VALUES(?,?,?)
		ON CONFLICT(user_id,fingerprint) DO UPDATE SET last_seen=excluded.last_seen`, userID, fingerprint, at)
	return err
}

func (r signInHistoryRepo) KeepNewest(ctx context.Context, userID int64, n int) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM user_signin_seen WHERE user_id=? AND fingerprint NOT IN
		(SELECT fingerprint FROM user_signin_seen WHERE user_id=? ORDER BY last_seen DESC LIMIT ?)`, userID, userID, n)
	return err
}

type quotaRepo struct {
	q     querier
	codec ports.ColumnCodec
}

func (r quotaRepo) Policy(ctx context.Context, userID int64) (*string, *string, *string, error) {
	var quota, inheritance, defaultQuota sql.NullString
	if err := r.q.QueryRowContext(ctx, `SELECT quota_bytes,quota_inherits_default FROM users WHERE id=?`, userID).Scan(&quota, &inheritance); err != nil {
		return nil, nil, nil, notFound(err)
	}
	// The default quota is a setting, so its value is sealed: read it apart.
	switch v, err := readSetting(ctx, r.q, r.codec, "default_storage_quota_bytes"); {
	case err == nil:
		defaultQuota = sql.NullString{String: v, Valid: true}
	case !errors.Is(err, sql.ErrNoRows):
		return nil, nil, nil, err
	}
	return nullString(quota), nullString(inheritance), nullString(defaultQuota), nil
}

func (r quotaRepo) CountUnattributedReservations(ctx context.Context) (int, error) {
	var invalid int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM upload_sessions s LEFT JOIN users u ON u.id=s.quota_owner_id
  LEFT JOIN users uploader ON uploader.id=s.user_id WHERE u.id IS NULL OR u.is_guest<>0 OR uploader.id IS NULL`).Scan(&invalid)
	return invalid, err
}

func (r quotaRepo) StoredBytes(ctx context.Context, userID int64) (int64, error) {
	return r.sum(ctx, `SELECT f.size FROM files f JOIN shares s ON s.id=f.share_id WHERE s.user_id=?`, userID)
}

func (r quotaRepo) ReservedBytes(ctx context.Context, userID int64) (int64, error) {
	return r.sum(ctx, `SELECT f.size FROM upload_files f JOIN upload_sessions s ON s.id=f.session_id WHERE s.quota_owner_id=?`, userID)
}

// sum adds up the sizes query returns, refusing negative sizes and overflow.
func (r quotaRepo) sum(ctx context.Context, query string, userID int64) (int64, error) {
	rows, err := r.q.QueryContext(ctx, query, userID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var total int64
	for rows.Next() {
		var size int64
		if err := rows.Scan(&size); err != nil {
			return 0, err
		}
		if size < 0 || size > math.MaxInt64-total {
			return 0, fmt.Errorf("invalid storage accounting")
		}
		total += size
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return total, nil
}

var _ ports.QuotaRepository = quotaRepo{}
