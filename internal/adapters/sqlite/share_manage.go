// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// shareCols is the column list behind ports.ShareRecord (scanShareRecord).
const shareCols = `s.id,s.long_id,s.name,s.description,COALESCE(u.username,''),s.password_hash,s.status,s.download_limit,s.download_count,s.expires_at,s.created_at,s.user_id,
	(SELECT COALESCE(SUM(size),0) FROM files WHERE share_id=s.id),(SELECT COUNT(*) FROM files WHERE share_id=s.id)`

func (r shareRepo) scanShareRecord(row interface{ Scan(...any) error }) (ports.ShareRecord, error) {
	sh, err := scanShareRecordRaw(row)
	if err != nil {
		return sh, err
	}
	if sh.Name, err = openCol(r.codec, "shares", "name", sh.ID, sh.Name); err != nil {
		return sh, err
	}
	if sh.Description, err = openCol(r.codec, "shares", "description", sh.ID, sh.Description); err != nil {
		return sh, err
	}
	if sh.LongID, err = openCol(r.codec, "shares", "long_id", sh.ID, sh.LongID); err != nil {
		return sh, err
	}
	if sh.PasswordHash, err = openCol(r.codec, "shares", "password_hash", sh.ID, sh.PasswordHash); err != nil {
		return sh, err
	}
	if sh.UserID != nil {
		// the owner's name is a column of the users row, not of the share
		sh.Owner, err = openCol(r.codec, "users", "username", *sh.UserID, sh.Owner)
	}
	return sh, err
}

func scanShareRecordRaw(row interface{ Scan(...any) error }) (ports.ShareRecord, error) {
	var sh ports.ShareRecord
	var lim, uid sql.NullInt64
	var exp sql.NullTime
	if err := row.Scan(&sh.ID, &sh.LongID, &sh.Name, &sh.Description, &sh.Owner, &sh.PasswordHash, &sh.Status, &lim, &sh.DownloadCount, &exp, &sh.CreatedAt, &uid, &sh.Size, &sh.FileCount); err != nil {
		return ports.ShareRecord{}, notFound(err)
	}
	sh.DownloadLimit, sh.UserID, sh.ExpiresAt = nullInt64(lim), nullInt64(uid), nullTime(exp)
	return sh, nil
}

// optTime is the statement argument of an optional time: NULL or the value.
func optTime(p *time.Time) any {
	if p == nil {
		return nil
	}
	return *p
}

func (r shareRepo) ByID(ctx context.Context, id int64) (ports.ShareRecord, error) {
	return r.scanShareRecord(r.q.QueryRowContext(ctx, `SELECT `+shareCols+` FROM shares s LEFT JOIN users u ON u.id=s.user_id WHERE s.id=?`, id))
}

func (r shareRepo) ByLongID(ctx context.Context, longID string) (ports.ShareRecord, error) {
	bi, err := blindKey(r.codec, "shares", "long_id", longID)
	if err != nil {
		return ports.ShareRecord{}, err
	}
	return r.scanShareRecord(r.q.QueryRowContext(ctx, `SELECT `+shareCols+` FROM shares s LEFT JOIN users u ON u.id=s.user_id WHERE s.long_id_bi=?`, bi))
}

func (r shareRepo) ListOwned(ctx context.Context, userID int64) ([]ports.ShareRecord, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+shareCols+` FROM shares s LEFT JOIN users u ON u.id=s.user_id `+`WHERE s.user_id=? AND s.status<>'deleted'`+` ORDER BY s.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.ShareRecord
	for rows.Next() {
		if sh, err := r.scanShareRecord(rows); err == nil {
			out = append(out, sh)
		}
	}
	return out, nil // contract: like the 0.2 loop, an iteration error ends the list without failing it
}

func (r shareRepo) Files(ctx context.Context, shareID int64) ([]ports.ShareFile, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT f.id,f.name,f.full_path,f.size,f.type,f.disk_path,f.sha256,f.integrity,f.enc,f.enc_id,s.long_id,f.storage_id,f.object_key FROM files f JOIN shares s ON s.id=f.share_id WHERE f.share_id=? ORDER BY f.id`, shareID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.ShareFile
	for rows.Next() {
		var f ports.ShareFile
		if err := rows.Scan(&f.ID, &f.Name, &f.FullPath, &f.Size, &f.Type, &f.DiskPath, &f.SHA256, &f.Integrity, &f.Encrypted, &f.EncID, &f.LongID, &f.StorageID, &f.ObjectKey); err != nil {
			return nil, fmt.Errorf("%w: %v", ports.ErrReadInterrupted, err)
		}
		if err := r.openFile(&f, shareID); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ports.ErrReadInterrupted, err)
	}
	// The path is sealed, so the order by path happens here (ties by id).
	sort.SliceStable(out, func(i, j int) bool { return out[i].FullPath < out[j].FullPath })
	return out, nil
}

func (r shareRepo) summaries(ctx context.Context, withID bool, query string, args ...any) ([]ports.ShareFileSummary, error) {
	rows, err := r.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.ShareFileSummary
	for rows.Next() {
		var f ports.ShareFileSummary
		dest := []any{&f.ID, &f.FullPath, &f.Size}
		if withID {
			dest = []any{&f.ID, &f.Name, &f.FullPath, &f.Size}
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		if withID {
			if f.Name, err = openCol(r.codec, "files", "name", f.ID, f.Name); err != nil {
				return nil, err
			}
		}
		if f.FullPath, err = openCol(r.codec, "files", "full_path", f.ID, f.FullPath); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r shareRepo) ListFiles(ctx context.Context, shareID int64) ([]ports.ShareFileSummary, error) {
	list, err := r.summaries(ctx, true, `SELECT id,name,full_path,size FROM files WHERE share_id=? ORDER BY id`, shareID)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].FullPath < list[j].FullPath })
	return list, nil
}

func (r shareRepo) FilePathsAndSizes(ctx context.Context, shareID int64) ([]ports.ShareFileSummary, error) {
	return r.summaries(ctx, false, `SELECT id,full_path,size FROM files WHERE share_id=?`, shareID)
}

func (r shareRepo) FileLocation(ctx context.Context, fileID, shareID int64) (string, string, int64, error) {
	var disk, lid string
	var loc int64
	if err := r.q.QueryRowContext(ctx, `SELECT f.disk_path,s.long_id,f.storage_id FROM files f JOIN shares s ON s.id=f.share_id WHERE f.id=? AND f.share_id=?`, fileID, shareID).Scan(&disk, &lid, &loc); err != nil {
		return "", "", 0, notFound(err)
	}
	lid, err := openCol(r.codec, "shares", "long_id", shareID, lid)
	if err != nil {
		return "", "", 0, err
	}
	return disk, lid, loc, nil
}

func (r shareRepo) CountFiles(ctx context.Context, shareID int64) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM files WHERE share_id=?`, shareID).Scan(&n)
	return n, err
}

func (r shareRepo) DeleteFile(ctx context.Context, fileID, shareID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM files WHERE id=? AND share_id=?`, fileID, shareID)
	return err
}

func (r shareRepo) OwnedActiveLongID(ctx context.Context, id, userID int64) (string, error) {
	var lid string
	if err := r.q.QueryRowContext(ctx, `SELECT long_id FROM shares WHERE id=? AND user_id=? AND status<>'deleted'`, id, userID).Scan(&lid); err != nil {
		return "", notFound(err)
	}
	return openCol(r.codec, "shares", "long_id", id, lid)
}

func (r shareRepo) ReplacePasswordHash(ctx context.Context, id int64, newHash, oldHash string) (int64, error) {
	var stored string
	if err := r.q.QueryRowContext(ctx, `SELECT password_hash FROM shares WHERE id=?`, id).Scan(&stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	current, err := openCol(r.codec, "shares", "password_hash", id, stored)
	if err != nil || current != oldHash {
		return 0, err
	}
	sealed, err := sealCol(r.codec, "shares", "password_hash", id, newHash)
	if err != nil {
		return 0, err
	}
	// Bound to the stored (sealed) value, so a concurrent change fails the swap.
	return changed(r.q.ExecContext(ctx, `UPDATE shares SET password_hash=? WHERE id=? AND password_hash=?`, sealed, id, stored))
}

func (r shareRepo) CountDownload(ctx context.Context, id int64, now time.Time) (int64, error) {
	var count int64
	if err := r.q.QueryRowContext(ctx, `UPDATE shares SET download_count=download_count+1
		WHERE id=? AND status='active' AND (expires_at IS NULL OR expires_at>?)
		AND (download_limit IS NULL OR download_count<download_limit)
		RETURNING download_count`, id, now).Scan(&count); err != nil {
		return 0, notFound(err)
	}
	return count, nil
}

func (r shareRepo) Expire(ctx context.Context, id int64, at time.Time) error {
	_, err := r.q.ExecContext(ctx, `UPDATE shares SET status='expired', expires_at=? WHERE id=?`, at, id)
	return err
}

func (r shareRepo) Extend(ctx context.Context, id int64, until time.Time) error {
	_, err := r.q.ExecContext(ctx, `UPDATE shares SET expires_at=?, status='active', expiry_warned=0 WHERE id=?`, until, id)
	return err
}

func (r shareRepo) SetExpiry(ctx context.Context, id, userID int64, expiresAt *time.Time) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE shares SET expires_at=?, status='active', expiry_warned=0
		WHERE id=? AND status<>'deleted' AND user_id=?`, optTime(expiresAt), id, userID))
}

func (r shareRepo) SetDownloadLimit(ctx context.Context, id int64, limit *int64, now time.Time) error {
	// Maintenance marks limit-exhausted shares expired without changing their future expiry.
	// Revive only that case, not manually or time-expired shares.
	_, err := r.q.ExecContext(ctx, `UPDATE shares SET download_limit=?, status=CASE
		WHEN status='expired' AND download_limit IS NOT NULL AND download_count>=download_limit
		AND (expires_at IS NULL OR expires_at>?) AND (? IS NULL OR download_count<?)
		THEN 'active' ELSE status END WHERE id=?`, opt(limit), now, opt(limit), opt(limit), id)
	return err
}

func (r shareRepo) Edit(ctx context.Context, id, userID int64, e ports.ShareEdit) (int64, error) {
	sets := []string{}
	args := []any{}
	if e.Name != nil {
		sealed, err := sealCol(r.codec, "shares", "name", id, *e.Name)
		if err != nil {
			return 0, err
		}
		sets = append(sets, "name=?")
		args = append(args, sealed)
	}
	if e.Description != nil {
		sealed, err := sealCol(r.codec, "shares", "description", id, *e.Description)
		if err != nil {
			return 0, err
		}
		sets = append(sets, "description=?")
		args = append(args, sealed)
	}
	if e.SetDownloadLimit {
		lim := opt(e.DownloadLimit)
		// Same revive rule as SetDownloadLimit: only a share that maintenance
		// expired because its limit was exhausted is reactivated.
		sets = append(sets, `download_limit=?`, `status=CASE
			WHEN status='expired' AND download_limit IS NOT NULL AND download_count>=download_limit
			AND (expires_at IS NULL OR expires_at>?) AND (? IS NULL OR download_count<?)
			THEN 'active' ELSE status END`)
		args = append(args, lim, e.Now, lim, lim)
	}
	if e.PasswordHash != nil {
		sealed, err := sealCol(r.codec, "shares", "password_hash", id, *e.PasswordHash)
		if err != nil {
			return 0, err
		}
		sets = append(sets, "password_hash=?")
		args = append(args, sealed)
	}
	args = append(args, id, userID)
	return changed(r.q.ExecContext(ctx, `UPDATE shares SET `+strings.Join(sets, ", ")+` WHERE id=? AND status<>'deleted' AND user_id=?`, args...))
}

func (r shareRepo) PrunableIDs(ctx context.Context, userID int64, now time.Time) ([]int64, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id FROM shares WHERE user_id=? AND (status<>'active' OR (expires_at IS NOT NULL AND expires_at<?))`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id) // contract: an unreadable row is listed as 0
		ids = append(ids, id)
	}
	return ids, nil // contract: like the 0.2 loop, an iteration error ends the list without failing it
}

func (r shareRepo) Lock(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE shares SET id=id WHERE id=?`, id)
	return err
}

func (r shareRepo) LockOwnedForAppend(ctx context.Context, id, userID int64) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE shares SET id=id WHERE id=? AND user_id=? AND status<>'deleted'`, id, userID))
}

func (r shareRepo) LockOwnedForFileRemoval(ctx context.Context, id, userID int64) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE shares SET id=id WHERE id=? AND status<>'deleted' AND user_id=?`, id, userID))
}

func (r shareRepo) LongIDIf(ctx context.Context, id int64, f ports.ShareFilter) (string, error) {
	condition, args := "1=1", []any(nil)
	switch f.Kind {
	case ports.AnyShare:
	case ports.SharePrunableByOwner:
		condition, args = `user_id=? AND (status<>'active' OR (expires_at IS NOT NULL AND expires_at<?))`, []any{f.UserID, f.At}
	case ports.ShareRetiredBefore:
		condition, args = `status<>'active' AND COALESCE(expires_at,created_at)<?`, []any{f.At}
	default:
		return "", fmt.Errorf("unknown share filter %d", f.Kind)
	}
	var lid string
	queryArgs := append([]any{id}, args...)
	if err := r.q.QueryRowContext(ctx, `SELECT long_id FROM shares WHERE id=? AND (`+condition+`)`, queryArgs...).Scan(&lid); err != nil {
		return "", notFound(err)
	}
	return openCol(r.codec, "shares", "long_id", id, lid)
}

func (r shareRepo) Delete(ctx context.Context, id int64) (int64, error) {
	return affected(r.q.ExecContext(ctx, `DELETE FROM shares WHERE id=?`, id))
}

func (r uploadRepo) IDsForShare(ctx context.Context, shareID int64) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id FROM upload_sessions WHERE share_id=?`, shareID)
	if err != nil {
		return nil, err
	}
	var sessions []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			rows.Close()
			return nil, err
		}
		sessions = append(sessions, sid)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

func (r downloadRepo) Record(ctx context.Context, shareID int64, fileID *int64, ip string, at time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO downloads(share_id,file_id,ip,created_at) VALUES(?,?,?,?)`, shareID, opt(fileID), ip, at)
	return err
}

func (r downloadRepo) Count(ctx context.Context, shareID int64) (int64, error) {
	var total int64
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM downloads WHERE share_id=?`, shareID).Scan(&total)
	return total, err
}

func (r downloadRepo) List(ctx context.Context, shareID int64, limit, offset int) ([]ports.DownloadRecord, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT d.id,d.file_id,COALESCE(f.name,''),d.created_at
		FROM downloads d LEFT JOIN files f ON f.id=d.file_id AND f.share_id=d.share_id
		WHERE d.share_id=? ORDER BY d.created_at DESC,d.id DESC LIMIT ? OFFSET ?`, shareID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.DownloadRecord
	for rows.Next() {
		var d ports.DownloadRecord
		var fileID sql.NullInt64
		if err := rows.Scan(&d.ID, &fileID, &d.FileName, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.FileID = nullInt64(fileID)
		if d.FileID != nil {
			// the name is a column of the files row, not of the download
			if d.FileName, err = openCol(r.codec, "files", "name", *d.FileID, d.FileName); err != nil {
				return nil, err
			}
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type downloadMailRepo struct{ q querier }

func (r downloadMailRepo) CountQueued(ctx context.Context) (int, error) {
	var pending int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM download_mail_outbox WHERE status IN ('reserved','pending')`).Scan(&pending)
	return pending, err
}

func (r downloadMailRepo) Reserve(ctx context.Context, shareID int64, recipient, language, data string, nextAttempt time.Time) (int64, error) {
	res, err := r.q.ExecContext(ctx, `INSERT INTO download_mail_outbox(share_id,recipient,language,data,next_attempt) VALUES(?,?,?,?,?)`, shareID, recipient, language, data, nextAttempt)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId() // contract of the 0.2 caller: the id error was ignored
	return id, nil
}

func (r downloadMailRepo) Activate(ctx context.Context, id int64, startedAt time.Time) error {
	_, err := r.q.ExecContext(ctx, `UPDATE download_mail_outbox SET status='pending',data=json_set(data,'$.StartedAt',?),next_attempt=? WHERE id=? AND status='reserved'`, startedAt.Format(time.RFC3339), startedAt, id)
	return err
}

func (r downloadMailRepo) Release(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM download_mail_outbox WHERE id=? AND status='reserved'`, id)
	return err
}

func (r userRepo) EmailAndLanguage(ctx context.Context, id int64) (string, string, error) {
	var email, language string
	if err := r.q.QueryRowContext(ctx, `SELECT email,language FROM users WHERE id=?`, id).Scan(&email, &language); err != nil {
		return "", "", notFound(err)
	}
	email, err := openCol(r.codec, "users", "email", id, email)
	return email, language, err
}
