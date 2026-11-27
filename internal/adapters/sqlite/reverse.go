// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

type reverseInviteRepo struct {
	q     querier
	codec ports.ColumnCodec
}

// seal writes the sealed recipient name, recipient e-mail address and message
// of invite id (they are bound to the row id, which exists after the insert).
func (r reverseInviteRepo) seal(ctx context.Context, id int64, name, email, message string) error {
	vals := make([]string, 3)
	for i, c := range []struct{ col, v string }{{"recipient_name", name}, {"recipient_email", email}, {"message", message}} {
		v, err := sealCol(r.codec, "reverse_invites", c.col, id, c.v)
		if err != nil {
			return err
		}
		vals[i] = v
	}
	_, err := r.q.ExecContext(ctx, `UPDATE reverse_invites SET recipient_name=?,recipient_email=?,message=? WHERE id=?`, vals[0], vals[1], vals[2], id)
	return err
}

func (r reverseInviteRepo) count(ctx context.Context, query string, args ...any) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, query, args...).Scan(&n)
	return n, err
}

func (r reverseInviteRepo) CountOpenForGuest(ctx context.Context, guestUserID int64, now time.Time) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM reverse_invites WHERE guest_user_id=? AND completed_at IS NULL AND expires_at>?`, guestUserID, now).Scan(&n)
	return n, err
}

func (r reverseInviteRepo) Create(ctx context.Context, in ports.NewInvite) (int64, error) {
	name, email, message := in.RecipientName, in.RecipientEmail, in.Message
	if r.codec != nil {
		name, email, message = "", "", "" // sealed below, once the row id exists
	}
	res, err := r.q.ExecContext(ctx, `INSERT INTO reverse_invites(token,user_id,recipient_name,recipient_email,message,expires_at,reusable,max_uploads) VALUES(?,?,?,?,?,?,?,?)`,
		in.Token, in.UserID, name, email, message, in.ExpiresAt, in.Reusable, in.MaxUploads)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId() // contract of the 0.2 caller: the id error was ignored
	if r.codec != nil {
		if err := r.seal(ctx, id, in.RecipientName, in.RecipientEmail, in.Message); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (r reverseInviteRepo) ListOwned(ctx context.Context, userID int64, now time.Time) ([]ports.InviteSummary, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT i.id,i.token,i.recipient_name,i.recipient_email,i.expires_at,i.completed_at,i.reusable,i.max_uploads,
		(SELECT COUNT(*) FROM reverse_invites c WHERE c.parent_id=i.id AND c.completed_at IS NOT NULL),
		(SELECT COUNT(*) FROM reverse_invites c WHERE c.parent_id=i.id AND c.completed_at IS NULL AND c.expires_at>?)
		FROM reverse_invites i WHERE i.user_id=? AND i.parent_id IS NULL ORDER BY i.created_at DESC, i.id DESC`, now, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.InviteSummary
	for rows.Next() {
		var it ports.InviteSummary
		if rows.Scan(&it.ID, &it.Token, &it.RecipientName, &it.RecipientEmail, &it.ExpiresAt, &it.CompletedAt, &it.Reusable, &it.MaxUploads, &it.Used, &it.Pending) != nil {
			continue
		}
		var err error
		if it.RecipientName, err = openCol(r.codec, "reverse_invites", "recipient_name", it.ID, it.RecipientName); err != nil {
			return nil, err
		}
		if it.RecipientEmail, err = openCol(r.codec, "reverse_invites", "recipient_email", it.ID, it.RecipientEmail); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, nil // contract: like the 0.2 loop, an iteration error ends the list without failing it
}

func (r reverseInviteRepo) ExpireOwned(ctx context.Context, id, userID int64, at time.Time) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE reverse_invites SET expires_at=? WHERE id=? AND user_id=? AND parent_id IS NULL`, at, id, userID))
}

func (r reverseInviteRepo) ExpireOpenChildren(ctx context.Context, parentID, userID int64, now time.Time) error {
	_, err := r.q.ExecContext(ctx, `UPDATE reverse_invites SET expires_at=? WHERE parent_id=? AND user_id=? AND completed_at IS NULL AND expires_at>?`, now, parentID, userID, now)
	return err
}

func (r reverseInviteRepo) LockToken(ctx context.Context, token string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE reverse_invites SET used=used WHERE token=?`, token)
	return err
}

func (r reverseInviteRepo) ForAccept(ctx context.Context, token string) (ports.InviteForAccept, error) {
	var i ports.InviteForAccept
	var ownerID int64
	var ownerName, ownerUsername string
	err := r.q.QueryRowContext(ctx, `SELECT i.id,i.guest_user_id,i.expires_at,i.completed_at,i.recipient_name,i.message,i.reusable,i.max_uploads,i.user_id,i.parent_id,u.id,u.name,u.username FROM reverse_invites i JOIN users u ON u.id=i.user_id WHERE i.token=? AND u.is_guest=0`, token).
		Scan(&i.ID, &i.GuestUserID, &i.ExpiresAt, &i.CompletedAt, &i.RecipientName, &i.Message, &i.Reusable, &i.MaxUploads, &i.OwnerID, &i.ParentID, &ownerID, &ownerName, &ownerUsername)
	if err != nil {
		return ports.InviteForAccept{}, notFound(err)
	}
	// The inviter's name is a column of the users row, opened with that row's id.
	if ownerName, err = openCol(r.codec, "users", "name", ownerID, ownerName); err != nil {
		return ports.InviteForAccept{}, err
	}
	if ownerUsername, err = openCol(r.codec, "users", "username", ownerID, ownerUsername); err != nil {
		return ports.InviteForAccept{}, err
	}
	i.InviterName = ownerName
	if i.InviterName == "" {
		i.InviterName = ownerUsername
	}
	if i.RecipientName, err = openCol(r.codec, "reverse_invites", "recipient_name", i.ID, i.RecipientName); err != nil {
		return ports.InviteForAccept{}, err
	}
	if i.Message, err = openCol(r.codec, "reverse_invites", "message", i.ID, i.Message); err != nil {
		return ports.InviteForAccept{}, err
	}
	return i, nil
}

func (r reverseInviteRepo) CountTakenSlots(ctx context.Context, parentID int64, now, recentSince time.Time) (int, error) {
	// created_at is CURRENT_TIMESTAMP text (UTC, one-second precision).
	return r.count(ctx, `SELECT COUNT(*) FROM reverse_invites c WHERE c.parent_id=? AND (c.completed_at IS NOT NULL
			OR (c.expires_at>? AND (c.created_at>? OR EXISTS(SELECT 1 FROM upload_sessions us WHERE us.invite_id=c.id))))`,
		parentID, now, recentSince.UTC().Format("2006-01-02 15:04:05"))
}

func (r reverseInviteRepo) CreateChild(ctx context.Context, c ports.NewChildInvite) error {
	name, message := c.RecipientName, c.Message
	if r.codec != nil {
		name, message = "", "" // sealed below, once the row id exists
	}
	res, err := r.q.ExecContext(ctx, `INSERT INTO reverse_invites(token,user_id,recipient_name,message,guest_user_id,expires_at,parent_id) VALUES(?,?,?,?,?,?,?)`,
		c.Token, c.UserID, name, message, c.GuestUserID, c.ExpiresAt, c.ParentID)
	if err != nil || r.codec == nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	return r.seal(ctx, id, c.RecipientName, "", c.Message)
}

func (r reverseInviteRepo) AssignGuest(ctx context.Context, id, guestUserID int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE reverse_invites SET guest_user_id=? WHERE id=?`, guestUserID, id)
	return err
}
