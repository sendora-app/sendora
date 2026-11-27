// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// opt is the statement argument of an optional id: NULL or the value.
func opt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// nullInt64 turns a nullable scan into a port pointer.
func nullInt64(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

type uploadRepo struct {
	q     querier
	codec ports.ColumnCodec
}

func (r uploadRepo) Create(ctx context.Context, u ports.NewUpload) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO upload_sessions(id,user_id,invite_id,quota_owner_id,share_id) VALUES(?,?,?,?,?)`, u.ID, u.UserID, opt(u.InviteID), u.QuotaOwnerID, opt(u.ShareID))
	return err
}

func (r uploadRepo) AddFile(ctx context.Context, f ports.NewUploadFile) error {
	name, full, sum := f.Name, f.FullPath, f.SHA256
	if r.codec != nil {
		name, full, sum = "", "", "" // bound to the row id: sealed below, once it exists
	}
	res, err := r.q.ExecContext(ctx, `INSERT INTO upload_files(session_id,idx,name,full_path,size,type,sha256) VALUES(?,?,?,?,?,?,?)`, f.SessionID, f.Index, name, full, f.Size, f.Type, sum)
	if err != nil || r.codec == nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	var sealed [3]string
	for i, c := range [][2]string{{"name", f.Name}, {"full_path", f.FullPath}, {"sha256", f.SHA256}} {
		if sealed[i], err = sealCol(r.codec, "upload_files", c[0], id, c[1]); err != nil {
			return err
		}
	}
	_, err = r.q.ExecContext(ctx, `UPDATE upload_files SET name=?,full_path=?,sha256=? WHERE id=?`, sealed[0], sealed[1], sealed[2], id)
	return err
}

func (r uploadRepo) Uploader(ctx context.Context, id string) (int64, error) {
	var uid int64
	err := r.q.QueryRowContext(ctx, `SELECT user_id FROM upload_sessions WHERE id=?`, id).Scan(&uid)
	return uid, notFound(err)
}

func (r uploadRepo) CountByUploader(ctx context.Context, userID int64) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM upload_sessions WHERE user_id=?`, userID).Scan(&n)
	return n, err
}

func (r uploadRepo) AppendTarget(ctx context.Context, id string) (*int64, error) {
	var appendTo sql.NullInt64
	if err := r.q.QueryRowContext(ctx, `SELECT share_id FROM upload_sessions WHERE id=?`, id).Scan(&appendTo); err != nil {
		return nil, notFound(err)
	}
	return nullInt64(appendTo), nil
}

func (r uploadRepo) Reservation(ctx context.Context, id string, userID int64) (int64, *int64, error) {
	var owner int64
	var invite sql.NullInt64
	if err := r.q.QueryRowContext(ctx, `SELECT quota_owner_id,invite_id FROM upload_sessions WHERE id=? AND user_id=?`, id, userID).Scan(&owner, &invite); err != nil {
		return 0, nil, notFound(err)
	}
	return owner, nullInt64(invite), nil
}

func (r uploadRepo) Progress(ctx context.Context, id string) ([]ports.UploadProgress, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT idx,size,received FROM upload_files WHERE session_id=? ORDER BY idx`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.UploadProgress
	for rows.Next() {
		var p ports.UploadProgress
		rows.Scan(&p.Index, &p.Size, &p.Received) // contract: an unreadable row is listed as far as it was read
		out = append(out, p)
	}
	return out, nil // contract: like the 0.2 loop, an iteration error ends the list without failing it
}

func (r uploadRepo) Files(ctx context.Context, id string) ([]ports.UploadFile, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id,idx,name,full_path,type,size,received,sha256 FROM upload_files WHERE session_id=? ORDER BY idx`, id)
	if err != nil {
		return nil, err
	}
	var files []ports.UploadFile
	for rows.Next() {
		var f ports.UploadFile
		var rowID int64
		if err := rows.Scan(&rowID, &f.Index, &f.Name, &f.FullPath, &f.Type, &f.Size, &f.Received, &f.SHA256); err != nil {
			rows.Close()
			return nil, err
		}
		if f.Name, err = openCol(r.codec, "upload_files", "name", rowID, f.Name); err != nil {
			rows.Close()
			return nil, err
		}
		if f.FullPath, err = openCol(r.codec, "upload_files", "full_path", rowID, f.FullPath); err != nil {
			rows.Close()
			return nil, err
		}
		if f.SHA256, err = openCol(r.codec, "upload_files", "sha256", rowID, f.SHA256); err != nil {
			rows.Close()
			return nil, err
		}
		files = append(files, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ports.ErrReadInterrupted, err)
	}
	return files, nil
}

func (r uploadRepo) FileState(ctx context.Context, id string, idx int) (int64, int64, error) {
	var size, rec int64
	if err := r.q.QueryRowContext(ctx, `SELECT size,received FROM upload_files WHERE session_id=? AND idx=?`, id, idx).Scan(&size, &rec); err != nil {
		return 0, 0, notFound(err)
	}
	return size, rec, nil
}

func (r uploadRepo) ReceivedOfUploader(ctx context.Context, id string, idx int, userID int64) (int64, error) {
	var rec int64
	if err := r.q.QueryRowContext(ctx, `SELECT received FROM upload_files uf JOIN upload_sessions us ON us.id=uf.session_id WHERE uf.session_id=? AND uf.idx=? AND us.user_id=?`, id, idx, userID).Scan(&rec); err != nil {
		return 0, notFound(err)
	}
	return rec, nil
}

func (r uploadRepo) SetReceived(ctx context.Context, id string, idx int, received int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE upload_files SET received=? WHERE session_id=? AND idx=?`, received, id, idx)
	return err
}

func (r uploadRepo) LockForCompletion(ctx context.Context, id string, userID, quotaOwnerID int64, uploaderIsGuest bool) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE upload_sessions SET id=id WHERE id=? AND user_id=? AND quota_owner_id=?
		AND EXISTS(SELECT 1 FROM users WHERE id=? AND is_guest=?)
		AND EXISTS(SELECT 1 FROM users WHERE id=? AND is_guest=0)`, id, userID, quotaOwnerID, userID, uploaderIsGuest, quotaOwnerID))
}

func (r uploadRepo) LockForAppend(ctx context.Context, id string, userID, quotaOwnerID, shareID int64) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE upload_sessions SET id=id WHERE id=? AND user_id=? AND quota_owner_id=? AND share_id=?`, id, userID, quotaOwnerID, shareID))
}

func (r uploadRepo) Delete(ctx context.Context, id string) (int64, error) {
	return changed(r.q.ExecContext(ctx, `DELETE FROM upload_sessions WHERE id=?`, id))
}

func (r uploadRepo) IDsOfUploaderOrQuotaOwner(ctx context.Context, userID int64) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id FROM upload_sessions WHERE user_id=? OR quota_owner_id=?`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (r reverseInviteRepo) CountForGuest(ctx context.Context, guestUserID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM reverse_invites WHERE guest_user_id=?`, guestUserID)
}

func (r reverseInviteRepo) OpenForGuest(ctx context.Context, guestUserID int64, now time.Time) (int64, int64, error) {
	var iid, owner int64
	if err := r.q.QueryRowContext(ctx, `SELECT r.id,r.user_id FROM reverse_invites r JOIN users o ON o.id=r.user_id AND o.is_guest=0
			WHERE r.guest_user_id=? AND r.completed_at IS NULL AND r.expires_at>?`, guestUserID, now).Scan(&iid, &owner); err != nil {
		return 0, 0, notFound(err)
	}
	return iid, owner, nil
}

func (r reverseInviteRepo) UploadSlot(ctx context.Context, id int64) (*int64, int, error) {
	var parentID sql.NullInt64
	var maxUploads int
	if err := r.q.QueryRowContext(ctx, `SELECT c.parent_id,COALESCE(p.max_uploads,1) FROM reverse_invites c LEFT JOIN reverse_invites p ON p.id=c.parent_id WHERE c.id=?`, id).Scan(&parentID, &maxUploads); err != nil {
		return nil, 0, notFound(err)
	}
	return nullInt64(parentID), maxUploads, nil
}

func (r reverseInviteRepo) CountUsedSiblings(ctx context.Context, parentID, exceptID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM reverse_invites c WHERE c.parent_id=? AND c.id<>? AND (c.completed_at IS NOT NULL OR EXISTS(SELECT 1 FROM upload_sessions us WHERE us.invite_id=c.id))`, parentID, exceptID)
}

func (r reverseInviteRepo) CountValidForCompletion(ctx context.Context, id, guestUserID, ownerID int64, now time.Time) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM reverse_invites WHERE id=? AND guest_user_id=? AND user_id=? AND completed_at IS NULL AND expires_at>?`, id, guestUserID, ownerID, now)
}

func (r reverseInviteRepo) Complete(ctx context.Context, id int64, at, now time.Time) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE reverse_invites SET completed_at=?, used=1 WHERE id=? AND completed_at IS NULL AND expires_at>?`, at, id, now))
}

func (r shareRepo) OwnedLongIDAndStatus(ctx context.Context, id, userID int64) (string, string, error) {
	var lid, status string
	if err := r.q.QueryRowContext(ctx, `SELECT long_id,status FROM shares WHERE id=? AND user_id=?`, id, userID).Scan(&lid, &status); err != nil {
		return "", "", notFound(err)
	}
	lid, err := openCol(r.codec, "shares", "long_id", id, lid)
	return lid, status, err
}

func (r shareRepo) FilesTotalSize(ctx context.Context, shareID int64) (int64, error) {
	var n int64
	err := r.q.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0) FROM files WHERE share_id=?`, shareID).Scan(&n)
	return n, err
}

func (r userRepo) LockForUpload(ctx context.Context, id int64, isGuest bool) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE users SET quota_bytes=quota_bytes WHERE id=? AND is_guest=?`, id, isGuest))
}

func (r quotaRepo) StorageBackendSetting(ctx context.Context) (string, error) {
	backend, err := readSetting(ctx, r.q, r.codec, "storage_backend")
	return backend, notFound(err)
}

func (r quotaRepo) TenantStorageLimit(ctx context.Context) (int64, error) {
	var limit int64
	err := r.q.QueryRowContext(ctx, `SELECT max_storage_bytes FROM tenant_limits WHERE id=1`).Scan(&limit)
	return limit, err
}

func (r quotaRepo) TotalStoredBytes(ctx context.Context) (int64, error) {
	var n int64
	err := r.q.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0) FROM files`).Scan(&n)
	return n, err
}

func (r quotaRepo) TotalReservedBytes(ctx context.Context) (int64, error) {
	var n int64
	err := r.q.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0) FROM upload_files`).Scan(&n)
	return n, err
}
