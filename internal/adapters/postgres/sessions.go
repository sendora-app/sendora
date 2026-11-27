// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

type sessionRepo struct {
	q     pq
	codec ports.ColumnCodec
}

// sealed returns the sealed user agent and address of token t: they are bound
// to the token's hash, the row's key.
func (r sessionRepo) sealed(t ports.NewRefreshToken) (ua, ip string, err error) {
	if ua, err = sealColKey(r.codec, "refresh_tokens", "user_agent", t.Hash, t.UserAgent); err != nil {
		return "", "", err
	}
	ip, err = sealColKey(r.codec, "refresh_tokens", "ip", t.Hash, t.IP)
	return ua, ip, err
}

func (r sessionRepo) StartGuarded(ctx context.Context, t ports.NewRefreshToken, g ports.CredentialGuard) (int64, error) {
	ua, ip, err := r.sealed(t)
	if err != nil {
		return 0, err
	}
	cr, found, err := readCreds(ctx, r.q, r.codec, t.UserID)
	if err != nil || !found || cr.hash != g.PasswordHash || cr.email != g.Email || cr.mustChange != g.MustChangePassword {
		return 0, err
	}
	return affected(r.q.ExecContext(ctx, `INSERT INTO refresh_tokens(hash,user_id,expires_at,issued_at,session_started,session_id,user_agent,ip,auth_method)
		SELECT ?::text,id,?::timestamptz,?::timestamptz,?::timestamptz,?::text,?::text,?::text,?::text FROM users WHERE id=? AND password_hash=? AND email=? AND must_change_password=? AND disabled_at IS NULL`,
		t.Hash, t.ExpiresAt, t.IssuedAt, t.Started, t.SessionID, ua, ip, t.Method, t.UserID, cr.storedHash, cr.storedEmail, g.MustChangePassword))
}

func (r sessionRepo) Insert(ctx context.Context, t ports.NewRefreshToken) error {
	ua, ip, err := r.sealed(t)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `INSERT INTO refresh_tokens(hash,user_id,expires_at,issued_at,session_started,session_id,user_agent,ip,auth_method) VALUES(?,?,?,?,?,?,?,?,?)`,
		t.Hash, t.UserID, t.ExpiresAt, t.IssuedAt, t.Started, t.SessionID, ua, ip, t.Method)
	return err
}

func (r sessionRepo) ConsumeLive(ctx context.Context, hash string, now time.Time) (ports.ConsumedRefreshToken, error) {
	var c ports.ConsumedRefreshToken
	var issued, started sql.NullTime
	var sid, method sql.NullString
	if err := r.q.scan(ctx, `DELETE FROM refresh_tokens WHERE hash=? AND expires_at>? RETURNING user_id,issued_at,session_started,session_id,auth_method`, []any{hash, now}, &c.UserID, &issued, &started, &sid, &method); err != nil {
		return ports.ConsumedRefreshToken{}, err
	}
	c.IssuedAt, c.Started, c.SessionID, c.Method = nullTime(issued), nullTime(started), nullString(sid), nullString(method)
	return c, nil
}

func (r sessionRepo) Consume(ctx context.Context, hash string) (int64, error) {
	var uid int64
	err := r.q.scan(ctx, `DELETE FROM refresh_tokens WHERE hash=? RETURNING user_id`, []any{hash}, &uid)
	return uid, err
}

func (r sessionRepo) FindSpent(ctx context.Context, hash string, now time.Time) (int64, time.Time, error) {
	var uid int64
	var spentAt time.Time
	err := r.q.scan(ctx, `SELECT user_id,spent_at FROM refresh_spent WHERE hash=? AND expires_at>?`, []any{hash, now}, &uid, &spentAt)
	return uid, spentAt, err
}

func (r sessionRepo) MarkSpent(ctx context.Context, hash string, userID int64, spentAt, expiresAt time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO refresh_spent(hash,user_id,spent_at,expires_at) VALUES(?,?,?,?) ON CONFLICT DO NOTHING`, hash, userID, spentAt, expiresAt)
	return err
}

func (r sessionRepo) DeleteSpentForUser(ctx context.Context, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM refresh_spent WHERE user_id=?`, userID)
	return err
}

func (r sessionRepo) CountLive(ctx context.Context, sid string, userID int64, now time.Time) (int, error) {
	var n int
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM refresh_tokens WHERE session_id=? AND user_id=? AND expires_at>?`, []any{sid, userID, now}, &n)
	return n, err
}

func (r sessionRepo) ListLive(ctx context.Context, userID int64, now time.Time) ([]ports.RefreshSession, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT hash, session_id, session_started, issued_at, expires_at, user_agent, ip, auth_method
		FROM refresh_tokens WHERE user_id=? AND expires_at>? AND session_id IS NOT NULL`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.RefreshSession
	for rows.Next() {
		var s ports.RefreshSession
		var started, used sql.NullTime
		var hash string
		if err := rows.Scan(&hash, &s.SessionID, &started, &used, &s.ExpiresAt, &s.UserAgent, &s.IP, &s.Method); err != nil {
			return nil, err
		}
		var err error
		if s.UserAgent, err = openColKey(r.codec, "refresh_tokens", "user_agent", hash, s.UserAgent); err != nil {
			return nil, err
		}
		if s.IP, err = openColKey(r.codec, "refresh_tokens", "ip", hash, s.IP); err != nil {
			return nil, err
		}
		s.Started, s.IssuedAt = nullTime(started), nullTime(used)
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r sessionRepo) RevokeAllForUser(ctx context.Context, userID int64) (int64, error) {
	return affected(r.q.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE user_id=?`, userID))
}

func (r sessionRepo) RevokeSession(ctx context.Context, userID int64, sid string) (int64, error) {
	return affected(r.q.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE user_id=? AND session_id=?`, userID, sid))
}

func (r sessionRepo) RevokeOtherSessions(ctx context.Context, userID int64, keepSID string) (int64, error) {
	return affected(r.q.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE user_id=? AND (session_id IS NULL OR session_id<>?)`, userID, keepSID))
}

func (r sessionRepo) RevokeAccessToken(ctx context.Context, hash string, expiresAt time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO revoked_access_tokens(hash,expires_at) VALUES(?,?) ON CONFLICT DO NOTHING`, hash, expiresAt)
	return err
}

func (r sessionRepo) CountRevokedAccess(ctx context.Context, hash string, now time.Time) (int, error) {
	var n int
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM revoked_access_tokens WHERE hash=? AND expires_at>?`, []any{hash, now}, &n)
	return n, err
}

type passwordResetRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r passwordResetRepo) CreateForVerified(ctx context.Context, hash string, userID int64, expiresAt time.Time, email, passwordHash string) (int64, error) {
	cr, found, err := readCreds(ctx, r.q, r.codec, userID)
	if err != nil || !found || cr.email != email || cr.hash != passwordHash || passwordHash == "" {
		return 0, err
	}
	return affected(r.q.ExecContext(ctx, `INSERT INTO password_resets(hash,user_id,expires_at)
		SELECT ?::text,id,?::timestamptz FROM users WHERE id=? AND email=? AND password_hash=? AND email_verified=1`,
		hash, expiresAt, userID, cr.storedEmail, cr.storedHash))
}

func (r passwordResetRepo) UserFor(ctx context.Context, hash string, now time.Time) (int64, error) {
	var uid int64
	err := r.q.scan(ctx, `SELECT user_id FROM password_resets WHERE hash=? AND expires_at>?`, []any{hash, now}, &uid)
	return uid, err
}

func (r passwordResetRepo) Consume(ctx context.Context, hash string, now time.Time, userID int64) (int64, string, error) {
	var uid int64
	var kind string
	err := r.q.scan(ctx, `DELETE FROM password_resets WHERE hash=? AND expires_at>? AND user_id=? RETURNING user_id, kind`, []any{hash, now, userID}, &uid, &kind)
	return uid, kind, err
}

func (r passwordResetRepo) Delete(ctx context.Context, hash string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM password_resets WHERE hash=?`, hash)
	return err
}

func (r passwordResetRepo) DeleteForUser(ctx context.Context, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id=?`, userID)
	return err
}

type emailVerificationRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r emailVerificationRepo) Put(ctx context.Context, userID int64, code string, expiresAt time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO email_verifications(user_id,code,expires_at) VALUES(?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET code=excluded.code, expires_at=excluded.expires_at`, userID, code, expiresAt)
	return err
}

func (r emailVerificationRepo) FindByUniqueEmail(ctx context.Context, email string) (int64, string, time.Time, bool, error) {
	var uid int64
	var code string
	var exp time.Time
	var pending bool
	bi, err := blindKey(r.codec, "users", "email", email)
	if err != nil {
		return 0, "", time.Time{}, false, err
	}
	err = r.q.scan(ctx, `SELECT v.user_id,v.code,v.expires_at,u.pending_registration FROM email_verifications v JOIN users u ON u.id=v.user_id WHERE u.email_bi=? AND u.email_verified=0 AND u.is_guest=0`, []any{bi}, &uid, &code, &exp, &pending)
	return uid, code, exp, pending, err
}

func (r emailVerificationRepo) RecordAttempt(ctx context.Context, userID int64, newExpiry, now time.Time) (int, error) {
	var attempts int
	err := r.q.scan(ctx, `INSERT INTO verification_attempts(user_id,attempts,expires_at) VALUES(?,1,?)
		ON CONFLICT(user_id) DO UPDATE SET
		attempts=CASE WHEN verification_attempts.expires_at<=?::timestamptz THEN 1 ELSE verification_attempts.attempts+1 END,
		expires_at=CASE WHEN verification_attempts.expires_at<=?::timestamptz THEN excluded.expires_at ELSE verification_attempts.expires_at END
		RETURNING attempts`, []any{userID, newExpiry, now, now}, &attempts)
	return attempts, err
}

func (r emailVerificationRepo) DeleteAttempts(ctx context.Context, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM verification_attempts WHERE user_id=?`, userID)
	return err
}

func (r emailVerificationRepo) DeleteForUser(ctx context.Context, userID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM email_verifications WHERE user_id=?`, userID)
	return err
}

type passwordHistoryRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r passwordHistoryRepo) Recent(ctx context.Context, userID int64, n int) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id,hash FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT ?`, userID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id int64
		var h string
		if rows.Scan(&id, &h) == nil {
			if h, err = openCol(r.codec, "password_history", "hash", id, h); err != nil {
				return nil, err
			}
			out = append(out, h)
		}
	}
	return out, rows.Err()
}

func (r passwordHistoryRepo) Remember(ctx context.Context, userID int64, keep int, at time.Time) error {
	if keep > 0 {
		// The users hash is bound to the user's row and the copy to the history
		// row, whose id only exists after the insert: open the hash, insert the
		// row (empty with a codec) and seal the copy in place.
		var stored string
		err := r.q.scan(ctx, `SELECT password_hash FROM users WHERE id=? AND password_hash<>''`, []any{userID}, &stored)
		switch {
		case errors.Is(err, ports.ErrNotFound):
		case err != nil:
			return err
		default:
			plain, err := openCol(r.codec, "users", "password_hash", userID, stored)
			if err != nil {
				return err
			}
			insert := plain
			if r.codec != nil {
				insert = ""
			}
			var rowID int64
			if err := r.q.scan(ctx, `INSERT INTO password_history(user_id,hash,created_at) VALUES(?,?,?::timestamptz) RETURNING id`, []any{userID, insert, at}, &rowID); err != nil {
				return err
			}
			if r.codec != nil {
				sealed, err := sealCol(r.codec, "password_history", "hash", rowID, plain)
				if err != nil {
					return err
				}
				if _, err := r.q.ExecContext(ctx, `UPDATE password_history SET hash=? WHERE id=?`, sealed, rowID); err != nil {
					return err
				}
			}
		}
	}
	_, err := r.q.ExecContext(ctx, `DELETE FROM password_history WHERE user_id=? AND id NOT IN (SELECT id FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT ?)`, userID, userID, keep)
	return err
}
