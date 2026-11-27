// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

type shareRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r shareRepo) Create(ctx context.Context, s ports.NewShare) (int64, error) {
	// The encrypted columns are bound to the row id, which only exists after
	// the insert: with a codec the row is inserted with the hex of the link
	// ID's blind index (a unique placeholder for the NOT NULL UNIQUE column)
	// and empty name, description and password hash, and the sealed values are
	// written next. The blind index is final from the start.
	bi, err := blindIdx(r.codec, "shares", "long_id", s.LongID)
	if err != nil {
		return 0, err
	}
	longID, desc, name, hash := s.LongID, s.Description, s.Name, s.PasswordHash
	if r.codec != nil {
		desc, name, hash = "", "", ""
		if b, ok := bi.([]byte); ok {
			longID = hex.EncodeToString(b)
		}
	}
	id, err := insertID(ctx, r.q, `INSERT INTO shares(user_id,invite_id,long_id,long_id_bi,name,description,password_hash,download_limit,expires_at) VALUES(?,?,?,?,?,?,?,?,?) RETURNING id`,
		s.UserID, opt(s.InviteID), longID, bi, name, desc, hash, opt(s.DownloadLimit), s.ExpiresAt)
	if err != nil {
		return 0, err
	}
	if r.codec != nil {
		var v [4]string
		for n, c := range []struct{ col, val string }{{"long_id", s.LongID}, {"description", s.Description}, {"name", s.Name}, {"password_hash", s.PasswordHash}} {
			if v[n], err = sealCol(r.codec, "shares", c.col, id, c.val); err != nil {
				return 0, err
			}
		}
		if _, err := r.q.ExecContext(ctx, `UPDATE shares SET long_id=?,description=?,name=?,password_hash=? WHERE id=?`, v[0], v[1], v[2], v[3], id); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (r shareRepo) LongIDExists(ctx context.Context, longID string) (bool, error) {
	bi, err := blindKey(r.codec, "shares", "long_id", longID)
	if err != nil {
		return false, err
	}
	var exists bool
	err = r.q.scan(ctx, `SELECT EXISTS(SELECT 1 FROM shares WHERE long_id_bi=?)`, []any{bi}, &exists)
	return exists, err
}

func (r shareRepo) AddFile(ctx context.Context, f ports.NewShareFile) (int64, error) {
	name, sum, full := f.Name, f.SHA256, f.FullPath
	if r.codec != nil {
		name, sum, full = "", "", "" // bound to the row id: sealed below, once it exists
	}
	id, err := insertID(ctx, r.q, `INSERT INTO files(share_id,name,full_path,size,type,disk_path,sha256,integrity,enc,enc_id,storage_id,object_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`,
		f.ShareID, name, full, f.Size, f.Type, f.DiskPath, sum, f.Integrity, f.Encrypted, f.EncID, f.StorageID, f.ObjectKey)
	if err != nil {
		return 0, err
	}
	if r.codec != nil && (f.Name != "" || f.SHA256 != "" || f.FullPath != "") {
		sealedName, err := sealCol(r.codec, "files", "name", id, f.Name)
		if err != nil {
			return 0, err
		}
		sealedSum, err := sealCol(r.codec, "files", "sha256", id, f.SHA256)
		if err != nil {
			return 0, err
		}
		sealedPath, err := sealCol(r.codec, "files", "full_path", id, f.FullPath)
		if err != nil {
			return 0, err
		}
		if _, err := r.q.ExecContext(ctx, `UPDATE files SET name=?,sha256=?,full_path=? WHERE id=?`, sealedName, sealedSum, sealedPath, id); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (r shareRepo) BaselineFileChecksum(ctx context.Context, fileID int64, sum string) error {
	sealed, err := sealCol(r.codec, "files", "sha256", fileID, sum)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `UPDATE files SET sha256=? WHERE id=? AND sha256=''`, sealed, fileID)
	return err
}

func (r shareRepo) FileChecksum(ctx context.Context, fileID int64) (string, error) {
	var sum string
	if err := r.q.scan(ctx, `SELECT sha256 FROM files WHERE id=?`, []any{fileID}, &sum); err != nil {
		return sum, err
	}
	return openCol(r.codec, "files", "sha256", fileID, sum)
}

func (r shareRepo) CountFilesByEncryption(ctx context.Context) (int64, int64, error) {
	var enc, plain int64
	err := r.q.scan(ctx, `SELECT COUNT(*) FILTER (WHERE enc=1), COUNT(*) FILTER (WHERE enc=0) FROM files`, nil, &enc, &plain)
	return enc, plain, err
}

// VerificationFiles: the PostgreSQL schema always has the storage columns.
func (r shareRepo) VerificationFiles(ctx context.Context) ([]ports.ShareFile, bool, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT f.id,f.name,f.full_path,f.size,f.disk_path,f.sha256,f.enc,f.enc_id,s.long_id,s.name,f.storage_id,f.object_key,s.id FROM files f JOIN shares s ON s.id=f.share_id ORDER BY f.id`)
	if err != nil {
		return nil, true, err
	}
	defer rows.Close()
	var list []ports.ShareFile
	for rows.Next() {
		var f ports.ShareFile
		var enc int
		var shareID int64
		if err := rows.Scan(&f.ID, &f.Name, &f.FullPath, &f.Size, &f.DiskPath, &f.SHA256, &enc, &f.EncID, &f.LongID, &f.ShareName, &f.StorageID, &f.ObjectKey, &shareID); err != nil {
			return nil, true, err
		}
		if err := r.openFile(&f, shareID); err != nil {
			return nil, true, err
		}
		f.Encrypted = enc == 1
		list = append(list, f)
	}
	if err := rows.Err(); err != nil {
		return nil, true, err
	}
	return list, true, nil
}

// openFile opens the encrypted columns of a scanned file row (f.Name and
// f.SHA256 of file f.ID) and, when shareID is not 0, the link ID and name of
// its share (f.LongID, f.ShareName, columns of the shares row shareID).
func (r shareRepo) openFile(f *ports.ShareFile, shareID int64) error {
	var err error
	if f.Name, err = openCol(r.codec, "files", "name", f.ID, f.Name); err != nil {
		return err
	}
	if f.SHA256, err = openCol(r.codec, "files", "sha256", f.ID, f.SHA256); err != nil {
		return err
	}
	if f.FullPath, err = openCol(r.codec, "files", "full_path", f.ID, f.FullPath); err != nil {
		return err
	}
	if shareID != 0 {
		if f.LongID, err = openCol(r.codec, "shares", "long_id", shareID, f.LongID); err != nil {
			return err
		}
		f.ShareName, err = openCol(r.codec, "shares", "name", shareID, f.ShareName)
	}
	return err
}

type downloadRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r downloadRepo) BlankAddressesUnlessLogged(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `UPDATE downloads SET ip='' WHERE ip<>''
		AND NOT EXISTS(SELECT 1 FROM settings WHERE key='audit_log_ip' AND lower(value)='true')`)
	return err
}

func (r downloadRepo) Record(ctx context.Context, shareID int64, fileID *int64, ip string, at time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO downloads(share_id,file_id,ip,created_at) VALUES(?,?,?,?)`, shareID, opt(fileID), ip, at)
	return err
}

func (r downloadRepo) Count(ctx context.Context, shareID int64) (int64, error) {
	var total int64
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM downloads WHERE share_id=?`, []any{shareID}, &total)
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

type storageLocationRepo struct{ q pq }

func (r storageLocationRepo) IDs(ctx context.Context) ([]int64, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id FROM storage_locations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var locs []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			locs = append(locs, id)
		}
	}
	return locs, nil // contract: an iteration error ends the list without failing it
}

// ---------- share records and management ----------

// shareCols is the column list behind ports.ShareRecord (scanShareRecord).
const shareCols = `s.id,s.long_id,s.name,s.description,COALESCE(u.username,''),s.password_hash,s.status,s.download_limit,s.download_count,s.expires_at,s.created_at,s.user_id,
	(SELECT COALESCE(SUM(size),0)::bigint FROM files WHERE share_id=s.id),(SELECT COUNT(*) FROM files WHERE share_id=s.id)`

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
	rows, err := r.q.QueryContext(ctx, `SELECT `+shareCols+` FROM shares s LEFT JOIN users u ON u.id=s.user_id WHERE s.user_id=? AND s.status<>'deleted' ORDER BY s.created_at DESC`, userID)
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
	return out, nil // contract: an iteration error ends the list without failing it
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
	return r.summaries(ctx, false, `SELECT id,full_path,size FROM files WHERE share_id=? ORDER BY id`, shareID)
}

func (r shareRepo) FileLocation(ctx context.Context, fileID, shareID int64) (string, string, int64, error) {
	var disk, lid string
	var loc int64
	if err := r.q.scan(ctx, `SELECT f.disk_path,s.long_id,f.storage_id FROM files f JOIN shares s ON s.id=f.share_id WHERE f.id=? AND f.share_id=?`, []any{fileID, shareID}, &disk, &lid, &loc); err != nil {
		return "", "", 0, err
	}
	lid, err := openCol(r.codec, "shares", "long_id", shareID, lid)
	if err != nil {
		return "", "", 0, err
	}
	return disk, lid, loc, nil
}

func (r shareRepo) CountFiles(ctx context.Context, shareID int64) (int, error) {
	var n int
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM files WHERE share_id=?`, []any{shareID}, &n)
	return n, err
}

func (r shareRepo) DeleteFile(ctx context.Context, fileID, shareID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM files WHERE id=? AND share_id=?`, fileID, shareID)
	return err
}

func (r shareRepo) OwnedActiveLongID(ctx context.Context, id, userID int64) (string, error) {
	var lid string
	if err := r.q.scan(ctx, `SELECT long_id FROM shares WHERE id=? AND user_id=? AND status<>'deleted'`, []any{id, userID}, &lid); err != nil {
		return "", err
	}
	return openCol(r.codec, "shares", "long_id", id, lid)
}

func (r shareRepo) ReplacePasswordHash(ctx context.Context, id int64, newHash, oldHash string) (int64, error) {
	var stored string
	if err := r.q.scan(ctx, `SELECT password_hash FROM shares WHERE id=?`, []any{id}, &stored); err != nil {
		if errors.Is(err, ports.ErrNotFound) {
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

// CountDownload is one atomic UPDATE ... RETURNING: concurrent downloads
// queue on the share's row lock and re-check the limit (download counter).
func (r shareRepo) CountDownload(ctx context.Context, id int64, now time.Time) (int64, error) {
	var count int64
	if err := r.q.scan(ctx, `UPDATE shares SET download_count=download_count+1
		WHERE id=? AND status='active' AND (expires_at IS NULL OR expires_at>?)
		AND (download_limit IS NULL OR download_count<download_limit)
		RETURNING download_count`, []any{id, now}, &count); err != nil {
		return 0, err
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
	return changed(r.q.ExecContext(ctx, `UPDATE shares SET expires_at=?::timestamptz, status='active', expiry_warned=0
		WHERE id=? AND status<>'deleted' AND user_id=?`, optTime(expiresAt), id, userID))
}

// reviveLimit is the status rule of SetDownloadLimit and Edit: only a share
// that maintenance expired because its limit was exhausted is reactivated.
const reviveLimit = `status=CASE
		WHEN status='expired' AND download_limit IS NOT NULL AND download_count>=download_limit
		AND (expires_at IS NULL OR expires_at>?::timestamptz) AND (?::bigint IS NULL OR download_count<?::bigint)
		THEN 'active' ELSE status END`

func (r shareRepo) SetDownloadLimit(ctx context.Context, id int64, limit *int64, now time.Time) error {
	_, err := r.q.ExecContext(ctx, `UPDATE shares SET download_limit=?::bigint, `+reviveLimit+` WHERE id=?`, opt(limit), now, opt(limit), opt(limit), id)
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
		sets = append(sets, `download_limit=?::bigint`, reviveLimit)
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
	return ids, nil // contract: an iteration error ends the list without failing it
}

func (r shareRepo) Lock(ctx context.Context, id int64) error {
	_, err := lockRows(ctx, r.q, `SELECT 1 FROM shares WHERE id=? FOR UPDATE`, id)
	return err
}

func (r shareRepo) LockOwnedForAppend(ctx context.Context, id, userID int64) (int64, error) {
	return lockRows(ctx, r.q, `SELECT 1 FROM shares WHERE id=? AND user_id=? AND status<>'deleted' FOR UPDATE`, id, userID)
}

func (r shareRepo) LockOwnedForFileRemoval(ctx context.Context, id, userID int64) (int64, error) {
	return lockRows(ctx, r.q, `SELECT 1 FROM shares WHERE id=? AND status<>'deleted' AND user_id=? FOR UPDATE`, id, userID)
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
	if err := r.q.scan(ctx, `SELECT long_id FROM shares WHERE id=? AND (`+condition+`)`, append([]any{id}, args...), &lid); err != nil {
		return "", err
	}
	return openCol(r.codec, "shares", "long_id", id, lid)
}

func (r shareRepo) Delete(ctx context.Context, id int64) (int64, error) {
	return affected(r.q.ExecContext(ctx, `DELETE FROM shares WHERE id=?`, id))
}

func (r shareRepo) OwnedLongIDAndStatus(ctx context.Context, id, userID int64) (string, string, error) {
	var lid, status string
	if err := r.q.scan(ctx, `SELECT long_id,status FROM shares WHERE id=? AND user_id=?`, []any{id, userID}, &lid, &status); err != nil {
		return "", "", err
	}
	lid, err := openCol(r.codec, "shares", "long_id", id, lid)
	return lid, status, err
}

func (r shareRepo) FilesTotalSize(ctx context.Context, shareID int64) (int64, error) {
	var n int64
	err := r.q.scan(ctx, `SELECT COALESCE(SUM(size),0)::bigint FROM files WHERE share_id=?`, []any{shareID}, &n)
	return n, err
}

// ---------- download notification outbox ----------

type downloadMailRepo struct{ q pq }

func (r downloadMailRepo) CountQueued(ctx context.Context) (int, error) {
	var pending int
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM download_mail_outbox WHERE status IN ('reserved','pending')`, nil, &pending)
	return pending, err
}

func (r downloadMailRepo) Reserve(ctx context.Context, shareID int64, recipient, language, data string, nextAttempt time.Time) (int64, error) {
	return insertID(ctx, r.q, `INSERT INTO download_mail_outbox(share_id,recipient,language,data,next_attempt) VALUES(?,?,?,?,?) RETURNING id`, shareID, recipient, language, data, nextAttempt)
}

// Activate sets data.StartedAt like SQLite's json_set: the JSON keeps its
// other members (jsonb normalises spacing and member order; readers decode
// the object, they do not compare its text).
func (r downloadMailRepo) Activate(ctx context.Context, id int64, startedAt time.Time) error {
	_, err := r.q.ExecContext(ctx, `UPDATE download_mail_outbox SET status='pending',data=jsonb_set(data::jsonb,'{StartedAt}',to_jsonb(?::text))::text,next_attempt=? WHERE id=? AND status='reserved'`, startedAt.Format(time.RFC3339), startedAt, id)
	return err
}

func (r downloadMailRepo) Release(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM download_mail_outbox WHERE id=? AND status='reserved'`, id)
	return err
}

func (r userRepo) EmailAndLanguage(ctx context.Context, id int64) (string, string, error) {
	var email, language string
	if err := r.q.scan(ctx, `SELECT email,language FROM users WHERE id=?`, []any{id}, &email, &language); err != nil {
		return "", "", err
	}
	email, err := openCol(r.codec, "users", "email", id, email)
	return email, language, err
}
