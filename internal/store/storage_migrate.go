// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/storage"
)

// MigrateOptions controls MigrateFiles.
type MigrateOptions struct {
	// DeleteDelay > 0 queues each source object for deletion after this delay
	// (downloads that opened the old copy can finish); 0 deletes it at once.
	// Local source files are always removed at once.
	DeleteDelay time.Duration
	// Progress is called after every file.
	Progress func(MigrateStats)
	// Limit stops after this many files (0 = all; tests).
	Limit int
}

// MigrateStats counts a migration run.
type MigrateStats struct {
	Total   int   `json:"total"`
	Done    int   `json:"done"`
	Failed  int   `json:"failed"`
	Skipped int   `json:"skipped"` // removed or changed while being copied
	Bytes   int64 `json:"bytes"`
}

// ErrMigrateNoKey refuses to copy a plain legacy file to an object store
// without the key that would encrypt it first.
var ErrMigrateNoKey = errors.New("file encryption key unavailable: plain files are never copied to an object store")

// FileKeys gives the keys of stored files: the one new files are written
// under and the one a stored file (its files.enc_id value) was written under.
// *Store implements it.
type FileKeys interface {
	NewFileKey() (master []byte, version int, err error)
	FileMaster(encRef string) (master []byte, id string, err error)
}

type migrateRow struct {
	id, size, loc         int64
	sha, encID, key, disk string
	name, lid             string
	enc                   bool
}

// MigrateFiles copies every share file that does not live in target to
// target, verifies the copy (size, every GCM chunk tag, file id and the
// plaintext SHA-256), switches the files row and then deletes the source.
// Legacy plain files are encrypted on the way. A file that fails stays where
// it is (its copy is removed) and is counted; the run continues. It returns
// when every file was tried or ctx ends.
func MigrateFiles(ctx context.Context, db ports.Store, dataDir string, keys FileKeys, backends *Backends, target int64, opt MigrateOptions) (MigrateStats, error) {
	var st MigrateStats
	dst, err := backends.Get(ctx, target)
	if err != nil {
		return st, err
	}
	ids, err := migrateCandidates(db, target)
	if err != nil {
		return st, err
	}
	if opt.Limit > 0 && len(ids) > opt.Limit {
		ids = ids[:opt.Limit]
	}
	st.Total = len(ids)
	if opt.Progress != nil {
		opt.Progress(st)
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return st, ctx.Err()
		}
		f, err := db.ObjectStorage().MigrationFile(context.Background(), id)
		r := migrateRow{id: f.ID, size: f.Size, loc: f.LocationID, sha: f.SHA256, encID: f.EncID, key: f.ObjectKey, disk: f.DiskPath, name: f.Name, enc: f.Encrypted, lid: f.ShareLongID}
		if err != nil || r.loc == target {
			st.Skipped++
		} else {
			n, skipped, err := migrateOne(ctx, db, dataDir, keys, backends, dst, target, r, opt)
			switch {
			case err != nil:
				if ctx.Err() != nil {
					return st, ctx.Err()
				}
				st.Failed++
			case skipped:
				st.Skipped++
			default:
				st.Done++
				st.Bytes += n
			}
		}
		if opt.Progress != nil {
			opt.Progress(st)
		}
	}
	return st, nil
}

func migrateCandidates(db ports.Store, target int64) ([]int64, error) {
	return db.ObjectStorage().FilesOutside(context.Background(), target)
}

// MigrateRemaining is the number of files outside target.
func MigrateRemaining(db ports.Store, target int64) int64 {
	n, _ := db.ObjectStorage().CountFilesOutside(context.Background(), target)
	return n
}

func migrateOne(ctx context.Context, db ports.Store, dataDir string, keys FileKeys, backends *Backends, dst storage.Backend, target int64, r migrateRow, opt MigrateOptions) (int64, bool, error) {
	srcKey, err := FileObjectKey(r.loc, r.lid, r.disk, r.key)
	if err != nil {
		return 0, false, err
	}
	src, err := backends.Get(ctx, r.loc)
	if err != nil {
		return 0, false, err
	}
	in, err := src.Open(ctx, srcKey)
	if err != nil {
		return 0, false, err
	}
	defer in.Close()

	newKey, newDisk, gone, err := newFileTarget(dataDir, target, r)
	if err != nil {
		return 0, false, err
	}
	if gone {
		return 0, true, nil // share removed meanwhile
	}

	enc, encID, sha := r.enc, r.encID, r.sha
	if !r.enc {
		// A plain legacy file (uploaded before 0.1.2) is encrypted on the way;
		// without a key it may only move between local directories.
		master, ver, kerr := keys.NewFileKey()
		if kerr != nil {
			return 0, false, kerr
		}
		if len(master) != 32 {
			if target != LocalLocation {
				return 0, false, ErrMigrateNoKey
			}
		} else {
			pr, pw := io.Pipe()
			h := sha256.New()
			var id string
			go func() {
				n, fid, err := filecrypt.Encrypt(pw, io.NewSectionReader(in, 0, in.Size()), master, h)
				if err == nil && n != r.size {
					err = errors.New("plain file size differs from its record")
				}
				id = fid
				pw.CloseWithError(err)
			}()
			err := dst.Put(ctx, newKey, pr, filecrypt.CipherSize(r.size))
			pr.CloseWithError(errors.New("upload ended"))
			if err != nil {
				dst.Delete(context.WithoutCancel(ctx), newKey)
				return 0, false, err
			}
			got := hex.EncodeToString(h.Sum(nil))
			if r.sha != "" && got != r.sha {
				dst.Delete(context.WithoutCancel(ctx), newKey)
				return 0, false, errors.New("plain source does not match its checksum")
			}
			enc, encID, sha = true, EncRef(id, ver), got
		}
	}
	if enc == r.enc {
		if err := dst.Put(ctx, newKey, io.NewSectionReader(in, 0, in.Size()), in.Size()); err != nil {
			dst.Delete(context.WithoutCancel(ctx), newKey)
			return 0, false, err
		}
	}
	if err := verifyCopy(ctx, dst, newKey, r.size, enc, encID, sha, keys); err != nil {
		dst.Delete(context.WithoutCancel(ctx), newKey)
		return 0, false, err
	}

	objectKey, diskPath := newKey, ""
	if target == LocalLocation {
		objectKey, diskPath = "", newDisk
	}
	n, err := db.ObjectStorage().MoveFile(context.Background(),
		ports.MigrationFile{ID: r.id, LocationID: r.loc, ObjectKey: r.key, DiskPath: r.disk, EncID: r.encID},
		ports.MovedFile{LocationID: target, ObjectKey: objectKey, DiskPath: diskPath, Encrypted: enc, EncID: encID, SHA256: sha})
	if err != nil {
		dst.Delete(context.WithoutCancel(ctx), newKey)
		return 0, false, err
	}
	if n != 1 {
		dst.Delete(context.WithoutCancel(ctx), newKey)
		return 0, true, nil // the file was removed or moved meanwhile
	}
	in.Close()
	if r.loc == LocalLocation || opt.DeleteDelay <= 0 {
		if err := src.Delete(ctx, srcKey); err != nil && r.loc != LocalLocation {
			QueueDelete(db, r.loc, srcKey, time.Now().Add(10*time.Minute))
		}
	} else {
		QueueDelete(db, r.loc, srcKey, time.Now().Add(opt.DeleteDelay))
	}
	return r.size, false, nil
}

// newFileTarget allocates where a copy of file r goes in location target: a
// random key in an object store; in the local data directory the layout of
// every earlier release (the share directory must still exist, else gone).
func newFileTarget(dataDir string, target int64, r migrateRow) (newKey, newDisk string, gone bool, err error) {
	if target != LocalLocation {
		newKey, err = storage.NewFileKey()
		return newKey, "", false, err
	}
	dir, err := ShareDir(dataDir, r.lid)
	if err != nil {
		return "", "", false, err
	}
	if _, serr := os.Stat(dir); serr != nil {
		return "", "", true, nil
	}
	base := randomHex(8) + "_" + filepath.Base(r.name)
	newKey, newDisk = "shares/"+r.lid+"/"+base, filepath.Join(dir, base)
	if _, err := FileObjectKey(LocalLocation, r.lid, newDisk, ""); err != nil {
		base = randomHex(8) + "_file"
		newKey, newDisk = "shares/"+r.lid+"/"+base, filepath.Join(dir, base)
	}
	return newKey, newDisk, false, nil
}

// verifyCopy reads the stored copy back completely: the encrypted format's
// header, file id and every chunk tag, the plaintext length and SHA-256.
func verifyCopy(ctx context.Context, b storage.Backend, key string, size int64, enc bool, encID, sha string, keys FileKeys) error {
	obj, err := b.Open(ctx, key)
	if err != nil {
		return err
	}
	defer obj.Close()
	var rd io.Reader = io.NewSectionReader(obj, 0, obj.Size())
	if enc {
		master, headerID, kerr := keys.FileMaster(encID)
		if kerr != nil {
			return fmt.Errorf("copy cannot be verified: %w", kerr)
		}
		fr, err := filecrypt.NewReader(nopCloser{obj}, obj.Size(), size, master, headerID)
		if err != nil {
			return fmt.Errorf("copy fails authentication: %w", err)
		}
		rd = fr
	} else if obj.Size() != size {
		return errors.New("copy has the wrong size")
	}
	h := sha256.New()
	n, err := io.Copy(h, rd)
	if err != nil {
		return fmt.Errorf("copy fails authentication: %w", err)
	}
	if n != size || (sha != "" && hex.EncodeToString(h.Sum(nil)) != sha) {
		return errors.New("copy does not match the recorded checksum")
	}
	return nil
}

type nopCloser struct{ io.ReaderAt }

func (nopCloser) Close() error { return nil }
