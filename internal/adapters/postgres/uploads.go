// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sendora-app/sendora/internal/ports"
)

type uploadRepo struct {
	q     pq
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
	id, err := insertID(ctx, r.q, `INSERT INTO upload_files(session_id,idx,name,full_path,size,type,sha256) VALUES(?,?,?,?,?,?,?) RETURNING id`, f.SessionID, f.Index, name, full, f.Size, f.Type, sum)
	if err != nil || r.codec == nil {
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
	err := r.q.scan(ctx, `SELECT user_id FROM upload_sessions WHERE id=?`, []any{id}, &uid)
	return uid, err
}

func (r uploadRepo) CountByUploader(ctx context.Context, userID int64) (int, error) {
	var n int
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM upload_sessions WHERE user_id=?`, []any{userID}, &n)
	return n, err
}

func (r uploadRepo) AppendTarget(ctx context.Context, id string) (*int64, error) {
	var appendTo sql.NullInt64
	if err := r.q.scan(ctx, `SELECT share_id FROM upload_sessions WHERE id=?`, []any{id}, &appendTo); err != nil {
		return nil, err
	}
	return nullInt64(appendTo), nil
}

func (r uploadRepo) Reservation(ctx context.Context, id string, userID int64) (int64, *int64, error) {
	var owner int64
	var invite sql.NullInt64
	if err := r.q.scan(ctx, `SELECT quota_owner_id,invite_id FROM upload_sessions WHERE id=? AND user_id=?`, []any{id, userID}, &owner, &invite); err != nil {
		return 0, nil, err
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
	return out, nil // contract: an iteration error ends the list without failing it
}

func (r uploadRepo) Files(ctx context.Context, id string) ([]ports.UploadFile, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id,idx,name,full_path,type,size,received,sha256 FROM upload_files WHERE session_id=? ORDER BY idx`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []ports.UploadFile
	for rows.Next() {
		var f ports.UploadFile
		var rowID int64
		if err := rows.Scan(&rowID, &f.Index, &f.Name, &f.FullPath, &f.Type, &f.Size, &f.Received, &f.SHA256); err != nil {
			return nil, err
		}
		if f.Name, err = openCol(r.codec, "upload_files", "name", rowID, f.Name); err != nil {
			return nil, err
		}
		if f.FullPath, err = openCol(r.codec, "upload_files", "full_path", rowID, f.FullPath); err != nil {
			return nil, err
		}
		if f.SHA256, err = openCol(r.codec, "upload_files", "sha256", rowID, f.SHA256); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ports.ErrReadInterrupted, err)
	}
	return files, nil
}

func (r uploadRepo) FileState(ctx context.Context, id string, idx int) (int64, int64, error) {
	var size, rec int64
	if err := r.q.scan(ctx, `SELECT size,received FROM upload_files WHERE session_id=? AND idx=?`, []any{id, idx}, &size, &rec); err != nil {
		return 0, 0, err
	}
	return size, rec, nil
}

func (r uploadRepo) ReceivedOfUploader(ctx context.Context, id string, idx int, userID int64) (int64, error) {
	var rec int64
	if err := r.q.scan(ctx, `SELECT received FROM upload_files uf JOIN upload_sessions us ON us.id=uf.session_id WHERE uf.session_id=? AND uf.idx=? AND us.user_id=?`, []any{id, idx, userID}, &rec); err != nil {
		return 0, err
	}
	return rec, nil
}

func (r uploadRepo) SetReceived(ctx context.Context, id string, idx int, received int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE upload_files SET received=? WHERE session_id=? AND idx=?`, received, id, idx)
	return err
}

func (r uploadRepo) LockForCompletion(ctx context.Context, id string, userID, quotaOwnerID int64, uploaderIsGuest bool) (int64, error) {
	return lockRows(ctx, r.q, `SELECT 1 FROM upload_sessions WHERE id=? AND user_id=? AND quota_owner_id=?
		AND EXISTS(SELECT 1 FROM users WHERE id=? AND is_guest=?)
		AND EXISTS(SELECT 1 FROM users WHERE id=? AND is_guest=0) FOR UPDATE`, id, userID, quotaOwnerID, userID, uploaderIsGuest, quotaOwnerID)
}

func (r uploadRepo) LockForAppend(ctx context.Context, id string, userID, quotaOwnerID, shareID int64) (int64, error) {
	return lockRows(ctx, r.q, `SELECT 1 FROM upload_sessions WHERE id=? AND user_id=? AND quota_owner_id=? AND share_id=? FOR UPDATE`, id, userID, quotaOwnerID, shareID)
}

func (r uploadRepo) Delete(ctx context.Context, id string) (int64, error) {
	return changed(r.q.ExecContext(ctx, `DELETE FROM upload_sessions WHERE id=?`, id))
}

func (r uploadRepo) IDsOfUploaderOrQuotaOwner(ctx context.Context, userID int64) ([]string, error) {
	return queryStrings(ctx, r.q, `SELECT id FROM upload_sessions WHERE user_id=? OR quota_owner_id=?`, userID, userID)
}

func (r uploadRepo) IDsForShare(ctx context.Context, shareID int64) ([]string, error) {
	return queryStrings(ctx, r.q, `SELECT id FROM upload_sessions WHERE share_id=?`, shareID)
}

// LockForUpload is the first statement of quota admission: the write lock
// serialises admissions in this database (as SQLite's write lock did), then
// the account row is locked and checked.
func (r userRepo) LockForUpload(ctx context.Context, id int64, isGuest bool) (int64, error) {
	return lockRows(ctx, r.q, `SELECT 1 FROM users WHERE id=? AND is_guest=? FOR UPDATE`, id, isGuest)
}

func (r quotaRepo) StorageBackendSetting(ctx context.Context) (string, error) {
	return readSetting(ctx, r.q, r.codec, "storage_backend")
}

func (r quotaRepo) TenantStorageLimit(ctx context.Context) (int64, error) {
	var limit int64
	err := r.q.scan(ctx, `SELECT max_storage_bytes FROM tenant_limits WHERE id=1`, nil, &limit)
	return limit, err
}

func (r quotaRepo) TotalStoredBytes(ctx context.Context) (int64, error) {
	var n int64
	err := r.q.scan(ctx, `SELECT COALESCE(SUM(size),0)::bigint FROM files`, nil, &n)
	return n, err
}

func (r quotaRepo) TotalReservedBytes(ctx context.Context) (int64, error) {
	var n int64
	err := r.q.scan(ctx, `SELECT COALESCE(SUM(size),0)::bigint FROM upload_files`, nil, &n)
	return n, err
}
