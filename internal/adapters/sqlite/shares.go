// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/sendora-app/sendora/internal/ports"
)

type shareRepo struct {
	q     querier
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
	res, err := r.q.ExecContext(ctx, `INSERT INTO shares(user_id,invite_id,long_id,long_id_bi,name,description,password_hash,download_limit,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		s.UserID, opt(s.InviteID), longID, bi, name, desc, hash, opt(s.DownloadLimit), s.ExpiresAt)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId() // contract of the 0.2 caller: the id error was ignored
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
	err = r.q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM shares WHERE long_id_bi=?)`, bi).Scan(&exists)
	return exists, err
}

func (r shareRepo) AddFile(ctx context.Context, f ports.NewShareFile) (int64, error) {
	name, sum, full := f.Name, f.SHA256, f.FullPath
	if r.codec != nil {
		name, sum, full = "", "", "" // bound to the row id: sealed below, once it exists
	}
	res, err := r.q.ExecContext(ctx, `INSERT INTO files(share_id,name,full_path,size,type,disk_path,sha256,integrity,enc,enc_id,storage_id,object_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, f.ShareID, name, full, f.Size, f.Type, f.DiskPath, sum, f.Integrity, f.Encrypted, f.EncID, f.StorageID, f.ObjectKey)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId() // contract of the 0.2 callers: the id error was ignored
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
	err := r.q.QueryRowContext(ctx, `SELECT sha256 FROM files WHERE id=?`, fileID).Scan(&sum)
	if err != nil {
		return sum, notFound(err)
	}
	return openCol(r.codec, "files", "sha256", fileID, sum)
}

func (r shareRepo) CountFilesByEncryption(ctx context.Context) (int64, int64, error) {
	var enc, plain int64
	err := r.q.QueryRowContext(ctx, `SELECT COALESCE(SUM(enc=1),0), COALESCE(SUM(enc=0),0) FROM files`).Scan(&enc, &plain)
	return enc, plain, err
}

func (r shareRepo) VerificationFiles(ctx context.Context) ([]ports.ShareFile, bool, error) {
	// A database from before 0.2.0 that this binary has not opened yet has no
	// storage columns: every file is local then.
	var probe int64
	perr := r.q.QueryRowContext(ctx, `SELECT storage_id FROM files LIMIT 1`).Scan(&probe)
	hasLoc := perr == nil || errors.Is(perr, sql.ErrNoRows)
	q := `SELECT f.id,f.name,f.full_path,f.size,f.disk_path,f.sha256,f.enc,f.enc_id,s.long_id,s.name,0,'',s.id FROM files f JOIN shares s ON s.id=f.share_id ORDER BY f.id`
	if hasLoc {
		q = `SELECT f.id,f.name,f.full_path,f.size,f.disk_path,f.sha256,f.enc,f.enc_id,s.long_id,s.name,f.storage_id,f.object_key,s.id FROM files f JOIN shares s ON s.id=f.share_id ORDER BY f.id`
	}
	rows, err := r.q.QueryContext(ctx, q)
	if err != nil {
		return nil, hasLoc, err
	}
	var list []ports.ShareFile
	for rows.Next() {
		var f ports.ShareFile
		var enc int
		var shareID int64
		if err := rows.Scan(&f.ID, &f.Name, &f.FullPath, &f.Size, &f.DiskPath, &f.SHA256, &enc, &f.EncID, &f.LongID, &f.ShareName, &f.StorageID, &f.ObjectKey, &shareID); err != nil {
			rows.Close()
			return nil, hasLoc, err
		}
		if err := r.openFile(&f, shareID); err != nil {
			rows.Close()
			return nil, hasLoc, err
		}
		f.Encrypted = enc == 1
		list = append(list, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, hasLoc, err
	}
	return list, hasLoc, nil
}

// openFile opens the encrypted columns of a scanned file row (f.Name, f.SHA256
// and f.FullPath of file f.ID) and, when shareID is not 0, the link ID and name of
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
	q     querier
	codec ports.ColumnCodec
}

func (r downloadRepo) BlankAddressesUnlessLogged(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `UPDATE downloads SET ip='' WHERE ip<>''
		AND NOT EXISTS(SELECT 1 FROM settings WHERE key='audit_log_ip' AND lower(value)='true')`)
	return err
}

type storageLocationRepo struct{ q querier }

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
	return locs, nil // contract: like the 0.2 loop, an iteration error ends the list without failing it
}
