// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

type mfaRepo struct{ q querier }

func (r mfaRepo) count(ctx context.Context, query string, args ...any) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, query, args...).Scan(&n)
	return n, err
}

func (r mfaRepo) CountConfirmedTOTP(ctx context.Context, userID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM user_totp WHERE user_id=? AND confirmed=1`, userID)
}

func (r mfaRepo) CountWebAuthn(ctx context.Context, userID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM user_webauthn WHERE user_id=?`, userID)
}

func (r mfaRepo) CountUnusedRecoveryCodes(ctx context.Context, userID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=? AND used_at IS NULL`, userID)
}

func (r mfaRepo) ConfirmedTOTP(ctx context.Context, userID int64) (string, int64, error) {
	var enc string
	var last int64
	if err := r.q.QueryRowContext(ctx, `SELECT secret,last_counter FROM user_totp WHERE user_id=? AND confirmed=1`, userID).Scan(&enc, &last); err != nil {
		return "", 0, notFound(err)
	}
	return enc, last, nil
}

func (r mfaRepo) TOTP(ctx context.Context, userID int64) (string, bool, error) {
	var enc string
	var confirmed int
	if err := r.q.QueryRowContext(ctx, `SELECT secret,confirmed FROM user_totp WHERE user_id=?`, userID).Scan(&enc, &confirmed); err != nil {
		return "", false, notFound(err)
	}
	return enc, confirmed == 1, nil
}

func (r mfaRepo) StartTOTP(ctx context.Context, userID int64, secret string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO user_totp(user_id,secret,confirmed,last_counter) VALUES(?,?,0,0)
		ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret,confirmed=0,last_counter=0,created_at=CURRENT_TIMESTAMP`, userID, secret)
	return err
}

func (r mfaRepo) ConfirmTOTP(ctx context.Context, userID int64, counter int64) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE user_totp SET confirmed=1,last_counter=? WHERE user_id=? AND confirmed=0`, counter, userID))
}

func (r mfaRepo) AdvanceTOTPCounter(ctx context.Context, userID int64, counter int64) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE user_totp SET last_counter=? WHERE user_id=? AND confirmed=1 AND last_counter<?`, counter, userID, counter))
}

func (r mfaRepo) DeleteTOTP(ctx context.Context, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM user_totp WHERE user_id=?`, userID)
	return err
}

func (r mfaRepo) AddRecoveryCode(ctx context.Context, userID int64, codeHash string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO user_recovery_codes(user_id,code_hash) VALUES(?,?)`, userID, codeHash)
	return err
}

func (r mfaRepo) UseRecoveryCode(ctx context.Context, userID int64, codeHash string) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE user_recovery_codes SET used_at=CURRENT_TIMESTAMP WHERE user_id=? AND code_hash=? AND used_at IS NULL`, userID, codeHash))
}

func (r mfaRepo) DeleteRecoveryCodes(ctx context.Context, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id=?`, userID)
	return err
}

func (r mfaRepo) WebAuthnKeys(ctx context.Context, userID int64) ([]ports.WebAuthnKey, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id,cred_id,public_key,alg,sign_count FROM user_webauthn WHERE user_id=? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.WebAuthnKey
	for rows.Next() {
		var k ports.WebAuthnKey
		if rows.Scan(&k.RowID, &k.CredID, &k.PublicKey, &k.Alg, &k.SignCount) == nil {
			out = append(out, k)
		}
	}
	return out, nil // contract: like the 0.2 loop, an iteration error ends the list without failing it
}

func (r mfaRepo) ListWebAuthn(ctx context.Context, userID int64) ([]ports.WebAuthnInfo, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id,name,created_at,last_used_at FROM user_webauthn WHERE user_id=? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.WebAuthnInfo
	for rows.Next() {
		var c ports.WebAuthnInfo
		if rows.Scan(&c.RowID, &c.Name, &c.CreatedAt, &c.LastUsedAt) == nil {
			out = append(out, c)
		}
	}
	return out, nil // contract: like the 0.2 loop, an iteration error ends the list without failing it
}

func (r mfaRepo) AddWebAuthn(ctx context.Context, userID int64, credID, publicKey []byte, alg int, signCount int64, name string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO user_webauthn(user_id,cred_id,public_key,alg,sign_count,name) VALUES(?,?,?,?,?,?)`,
		userID, credID, publicKey, alg, signCount, name)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return fmt.Errorf("%w: %v", ports.ErrDuplicate, err)
	}
	return err
}

func (r mfaRepo) RenameWebAuthn(ctx context.Context, rowID, userID int64, name string) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE user_webauthn SET name=? WHERE id=? AND user_id=?`, name, rowID, userID))
}

func (r mfaRepo) WebAuthnOwner(ctx context.Context, rowID int64) (int64, error) {
	var owner int64
	err := r.q.QueryRowContext(ctx, `SELECT user_id FROM user_webauthn WHERE id=?`, rowID).Scan(&owner)
	return owner, notFound(err)
}

func (r mfaRepo) DeleteWebAuthn(ctx context.Context, rowID, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM user_webauthn WHERE id=? AND user_id=?`, rowID, userID)
	return err
}

func (r mfaRepo) DeleteAllWebAuthn(ctx context.Context, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM user_webauthn WHERE user_id=?`, userID)
	return err
}

func (r mfaRepo) RecordWebAuthnUse(ctx context.Context, rowID, userID int64, signCount int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE user_webauthn SET sign_count=?,last_used_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?`, signCount, rowID, userID)
	return err
}

func (r mfaRepo) CreateResetRequest(ctx context.Context, hash string, userID, requestedBy int64, expiresAt time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO mfa_reset_requests(hash,user_id,requested_by,expires_at) VALUES(?,?,?,?)`, hash, userID, requestedBy, expiresAt)
	return err
}

func (r mfaRepo) UseResetRequest(ctx context.Context, hash string, now time.Time) (int64, int64, error) {
	var uid, requestedBy int64
	if err := r.q.QueryRowContext(ctx, `UPDATE mfa_reset_requests SET used=1 WHERE hash=? AND used=0 AND expires_at>?
		AND user_id IN (SELECT id FROM users WHERE is_guest=0 AND email_verified=1 AND email<>'')
		RETURNING user_id, requested_by`, hash, now).Scan(&uid, &requestedBy); err != nil {
		return 0, 0, notFound(err)
	}
	return uid, requestedBy, nil
}

func (r mfaRepo) DeleteResetRequest(ctx context.Context, hash string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM mfa_reset_requests WHERE hash=?`, hash)
	return err
}

func (r mfaRepo) DeleteResetRequestsForUser(ctx context.Context, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM mfa_reset_requests WHERE user_id=?`, userID)
	return err
}
