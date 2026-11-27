// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/ports"
)

// Re-encryption of stored files (docs/cluster/DESIGN.md D45). A stored file is
// encrypted under one version of the tenant's "files" DEK, recorded in
// files.enc_id ("<file id>.<version>"). RekeyFiles rewrites every encrypted file
// that is not under the active version, which is what converts a store written
// before files moved under the keyring (root-derived key, no version) and what
// finishes a rotation of the files key.

// rekeyBatch is how many file rows are read per step; the walk is by file id
// so a restarted job simply continues (files already on the active version
// are skipped).
const rekeyBatch = 50

// RekeyStats counts a RekeyFiles run.
type RekeyStats struct {
	Rewritten int   `json:"rewritten"`
	Failed    int   `json:"failed"`
	Skipped   int   `json:"skipped"` // removed or changed while being rewritten
	Bytes     int64 `json:"bytes"`
}

// RekeyOptions controls RekeyFiles.
type RekeyOptions struct {
	// Pause between batches (online runs leave room for normal traffic).
	Pause time.Duration
	// DeleteDelay queues the old object of an object store for deletion after
	// this delay (readers that opened it can finish); 0 deletes at once.
	DeleteDelay time.Duration
	// Progress is called after every file.
	Progress func(RekeyStats)
}

// FileKeyCounts counts the encrypted files by the key version they are under
// (0 is the legacy root-derived key). Plain legacy files (enc = 0) are not
// counted.
func (s *Store) FileKeyCounts(ctx context.Context) (map[int]int64, error) {
	counts := map[int]int64{}
	var after int64
	for {
		files, err := s.Repos().ObjectStorage().ListMigrationFiles(ctx, after, 500)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			after = f.ID
			if f.Encrypted {
				_, v := ParseEncRef(f.EncID)
				counts[v]++
			}
		}
		if len(files) < 500 {
			return counts, nil
		}
	}
}

// RekeyFiles streams every encrypted file that is not under the active files
// key into a new object (new key in an object store, new name in the local
// directory) encrypted under the active version, verifies it completely,
// switches the files row with a compare-and-swap on its previous state and
// deletes the old copy. A file that fails stays as it is and is counted; the
// run goes on. It is safe to run while the application serves traffic, to
// repeat and to resume.
func (s *Store) RekeyFiles(ctx context.Context, opt RekeyOptions) (RekeyStats, error) {
	var st RekeyStats
	if s.codec == nil {
		return st, errors.New("file encryption keys unavailable")
	}
	newMaster, newVer, err := s.codec.FileMaster(0)
	if err != nil {
		return st, err
	}
	repo := s.Repos().ObjectStorage()
	var after int64
	for {
		files, err := repo.ListMigrationFiles(ctx, after, rekeyBatch)
		if err != nil {
			return st, err
		}
		for _, f := range files {
			after = f.ID
			if !f.Encrypted {
				continue
			}
			if _, v := ParseEncRef(f.EncID); v == newVer {
				continue
			}
			if err := ctx.Err(); err != nil {
				return st, err
			}
			n, skipped, err := s.rekeyOne(ctx, f, newMaster, newVer, opt)
			switch {
			case err != nil:
				if ctx.Err() != nil {
					return st, ctx.Err()
				}
				st.Failed++
			case skipped:
				st.Skipped++
			default:
				st.Rewritten++
				st.Bytes += n
			}
			if opt.Progress != nil {
				opt.Progress(st)
			}
		}
		if len(files) < rekeyBatch {
			return st, nil
		}
		if opt.Pause > 0 {
			select {
			case <-ctx.Done():
				return st, ctx.Err()
			case <-time.After(opt.Pause):
			}
		}
	}
}

// oldFileMaster is the key f is encrypted under: its version of the files key,
// or the legacy root-derived key (only this conversion may use that).
func (s *Store) oldFileMaster(encRef string) (master []byte, id string, err error) {
	id, v := ParseEncRef(encRef)
	if v == 0 {
		m, err := s.legacyFileMaster()
		return m, id, err
	}
	m, _, err := s.codec.FileMaster(v)
	return m, id, err
}

func (s *Store) rekeyOne(ctx context.Context, f ports.MigrationFile, newMaster []byte, newVer int, opt RekeyOptions) (int64, bool, error) {
	oldMaster, oldID, err := s.oldFileMaster(f.EncID)
	if err != nil {
		return 0, false, err
	}
	defer func() {
		if _, v := ParseEncRef(f.EncID); v == 0 {
			clear(oldMaster)
		}
	}()
	r := migrateRow{id: f.ID, size: f.Size, loc: f.LocationID, sha: f.SHA256, encID: f.EncID, key: f.ObjectKey, disk: f.DiskPath, name: f.Name, enc: f.Encrypted, lid: f.ShareLongID}
	srcKey, err := FileObjectKey(r.loc, r.lid, r.disk, r.key)
	if err != nil {
		return 0, false, err
	}
	backends := s.Backends()
	src, err := backends.Get(ctx, r.loc)
	if err != nil {
		return 0, false, err
	}
	in, err := src.Open(ctx, srcKey)
	if err != nil {
		return 0, false, err
	}
	defer in.Close()
	newKey, newDisk, gone, err := newFileTarget(s.DataDir, r.loc, r)
	if err != nil {
		return 0, false, err
	}
	if gone {
		return 0, true, nil
	}
	plain, err := filecrypt.NewReader(nopCloser{in}, in.Size(), r.size, oldMaster, oldID)
	if err != nil {
		return 0, false, fmt.Errorf("the file does not open under its recorded key: %w", err)
	}
	pr, pw := io.Pipe()
	h := sha256.New()
	var fid string
	go func() {
		n, id, err := filecrypt.Encrypt(pw, plain, newMaster, h)
		if err == nil && n != r.size {
			err = errors.New("file size differs from its record")
		}
		fid = id
		pw.CloseWithError(err)
	}()
	dst := src
	err = dst.Put(ctx, newKey, pr, filecrypt.CipherSize(r.size))
	pr.CloseWithError(errors.New("rewrite ended"))
	if err != nil {
		dst.Delete(context.WithoutCancel(ctx), newKey)
		return 0, false, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if r.sha != "" && sum != r.sha {
		dst.Delete(context.WithoutCancel(ctx), newKey)
		return 0, false, errors.New("file does not match its checksum")
	}
	newRef := EncRef(fid, newVer)
	if err := verifyCopy(ctx, dst, newKey, r.size, true, newRef, sum, s); err != nil {
		dst.Delete(context.WithoutCancel(ctx), newKey)
		return 0, false, err
	}
	objectKey, diskPath := newKey, ""
	if r.loc == LocalLocation {
		objectKey, diskPath = "", newDisk
	}
	n, err := s.Repos().ObjectStorage().MoveFile(context.Background(),
		ports.MigrationFile{ID: r.id, LocationID: r.loc, ObjectKey: r.key, DiskPath: r.disk, EncID: r.encID},
		ports.MovedFile{LocationID: r.loc, ObjectKey: objectKey, DiskPath: diskPath, Encrypted: true, EncID: newRef, SHA256: sum})
	if err != nil {
		dst.Delete(context.WithoutCancel(ctx), newKey)
		return 0, false, err
	}
	if n != 1 {
		dst.Delete(context.WithoutCancel(ctx), newKey)
		return 0, true, nil // removed or changed meanwhile
	}
	in.Close()
	if r.loc == LocalLocation || opt.DeleteDelay <= 0 {
		if err := src.Delete(ctx, srcKey); err != nil && r.loc != LocalLocation {
			QueueDelete(s.Repos(), r.loc, srcKey, time.Now().Add(10*time.Minute))
		}
	} else {
		QueueDelete(s.Repos(), r.loc, srcKey, time.Now().Add(opt.DeleteDelay))
	}
	return r.size, false, nil
}

// RewriteFiles runs RekeyFiles with pause between batches and returns how many
// files it rewrote and how many failed (the keyops file-rewriter interface).
func (s *Store) RewriteFiles(ctx context.Context, pause time.Duration) (rewritten, failed int, err error) {
	st, err := s.RekeyFiles(ctx, RekeyOptions{Pause: pause, DeleteDelay: time.Minute})
	return st.Rewritten, st.Failed, err
}
