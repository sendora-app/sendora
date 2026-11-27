// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/storage"
	"github.com/sendora-app/sendora/internal/store"
)

type shareFileOut struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullPath string `json:"full_path"`
	Size     int64  `json:"size"`
}

func shareDirExists(dataDir, longID string) bool {
	dir, err := store.ShareDir(dataDir, longID)
	if err != nil {
		return false
	}
	st, err := os.Stat(dir)
	return err == nil && st.IsDir()
}

// shareTotalProblem returns a user-facing message when adding add bytes to a
// share already holding existing bytes would break the configured share size
// (maxBytes <= 0 means unlimited) or the verified-download snapshot limit.
func shareTotalProblem(existing, add, maxBytes int64) string {
	if existing < 0 || add < 0 || add > math.MaxInt64-existing {
		return "share size exceeds limit"
	}
	sum := existing + add
	if maxBytes > 0 && sum > maxBytes {
		return fmt.Sprintf("total share size would exceed limit of %d MB", maxBytes/1024/1024)
	}
	if lim := snapshotLimit(); sum > lim {
		return fmt.Sprintf("share would exceed the maximum downloadable size of %d MB", lim/1024/1024)
	}
	return ""
}

var errNoUniquePath = errors.New("no unique file path available")

// uniqueSharePath returns p, or "name (2).ext", "name (3).ext", ... in the same
// directory, such that its lower-cased form is not in existing. The chosen
// path is NOT added to existing; callers do that. Pure and bounded.
func uniqueSharePath(existing map[string]bool, p string) (string, error) {
	if !existing[strings.ToLower(p)] {
		return p, nil
	}
	dir, base := path.Split(p)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem == "" {
		stem, ext = base, ""
	}
	for n := 2; n <= 10000; n++ {
		cand := fmt.Sprintf("%s%s (%d)%s", dir, stem, n, ext)
		if !existing[strings.ToLower(cand)] {
			return cand, nil
		}
	}
	return "", errNoUniquePath
}

// addParentDirs records every parent folder of the (lower-cased) file path p.
func addParentDirs(dirs map[string]bool, p string) {
	for dir := path.Dir(p); dir != "." && dir != "/" && dir != ""; dir = path.Dir(dir) {
		dirs[dir] = true
	}
}

// pathKindConflict reports whether file path p (lower-cased) is already a folder,
// or one of its parent folders is already a file.
func pathKindConflict(files, dirs map[string]bool, p string) bool {
	if dirs[p] {
		return true
	}
	for dir := path.Dir(p); dir != "." && dir != "/" && dir != ""; dir = path.Dir(dir) {
		if files[dir] {
			return true
		}
	}
	return false
}

// completeAppend finishes an upload session that targets an existing share.
// It never claims or removes the share directory: on failure only the files
// staged by this call are removed.
func (s *Server) completeAppend(w http.ResponseWriter, r *http.Request, id string, shareID int64) {
	u := s.ctxUser(r)
	if u.IsGuest {
		jerr(w, 404, "share not found")
		return
	}
	var junk completeReq
	if err := decode(r, &junk); err != nil && !errors.Is(err, io.EOF) {
		jerr(w, 400, "bad request")
		return
	}
	type uf struct {
		idx                           int
		name, fp, typ                 string
		expected, checksum, integrity string
		size, rec                     int64
		disk                          string
		enc                           bool
		encID, objKey                 string
	}
	declared, err := s.St.Repos().Uploads().Files(context.Background(), id)
	if err != nil && !errors.Is(err, ports.ErrReadInterrupted) {
		jerr(w, 500, "database error")
		return
	}
	var files []uf
	for _, d := range declared {
		files = append(files, uf{idx: d.Index, name: d.Name, fp: d.FullPath, typ: d.Type, size: d.Size, rec: d.Received, expected: d.SHA256})
	}
	if err != nil || len(files) == 0 {
		jerr(w, 500, "upload metadata unavailable")
		return
	}
	for _, f := range files {
		if f.rec != f.size {
			jerr(w, 400, fmt.Sprintf("file %q incomplete", f.name))
			return
		}
	}
	owner, invite, err := s.St.Repos().Uploads().Reservation(context.Background(), id, u.ID)
	if err != nil {
		jerr(w, 409, "upload reservation unavailable")
		return
	}
	if invite != nil || owner != u.ID {
		jerr(w, 409, "upload reservation invalid")
		return
	}
	longID, err := s.St.Repos().Shares().OwnedActiveLongID(context.Background(), shareID, u.ID)
	if err != nil {
		jerr(w, 404, "share not found")
		return
	}
	if !shareDirExists(s.St.DataDir, longID) {
		jerr(w, 409, "share is no longer available")
		return
	}
	dest := filepath.Join(s.St.DataDir, "shares", longID)
	loc, backend, err := s.currentStorage(r.Context())
	if err != nil {
		log.Printf("storage unavailable: %v", err)
		jerr(w, 503, "file storage unavailable")
		return
	}
	committed := false
	defer func() {
		if !committed {
			for _, f := range files {
				if f.disk != "" {
					os.Remove(f.disk)
				}
				if f.objKey != "" {
					backend.Delete(context.WithoutCancel(r.Context()), f.objKey)
				}
			}
		}
	}()
	for i := range files {
		f := &files[i]
		part := filepath.Join(s.uploadDir(id), strconv.Itoa(f.idx)+".part")
		var checksum, encID string
		fk, fv, err := s.St.NewFileKey()
		switch {
		case err != nil:
			log.Printf("files: no file key: %v", err)
			err = errNoFileKey
		case loc != store.LocalLocation:
			if f.objKey, err = storage.NewFileKey(); err == nil {
				checksum, encID, err = putUploadRemote(r.Context(), backend, part, f.objKey, f.size, fk)
			}
		default:
			disk := filepath.Join(dest, randHex(8)+"_"+f.name)
			checksum, encID, err = stageUploadFile(r.Context(), part, disk, f.size, fk, s.St.IsEncrypted())
			f.disk = disk
			if err != nil {
				os.Remove(disk) // partial copy under our own fresh random name
			}
		}
		if err != nil {
			if errors.Is(err, errIntegrity) {
				jerr(w, 409, "uploaded file integrity check failed")
			} else if loc != store.LocalLocation && !errors.Is(err, errNoFileKey) {
				// The object store failed; the parts are kept, so completing again works.
				jerr(w, 503, "file storage unavailable")
			} else {
				jerr(w, 500, "storage error")
			}
			return
		}
		encID = store.EncRef(encID, fv)
		f.enc, f.encID = encID != "", encID
		if f.expected != "" && checksum != f.expected {
			jerr(w, 409, "upload checksum mismatch")
			return
		}
		f.checksum, f.integrity = checksum, "server_baseline"
		if f.expected != "" {
			f.integrity = "expected_checksum_verified"
		}
	}
	maxShare := int64(s.St.SettingInt("max_share_size", 2048)) * 1024 * 1024
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	// Write lock first, then recheck everything against the current state.
	n, err := tx.Shares().LockOwnedForAppend(ctx, shareID, u.ID)
	if err != nil {
		jerr(w, 500, "upload finalization failed")
		return
	}
	if n != 1 {
		jerr(w, 404, "share not found")
		return
	}
	if !shareDirExists(s.St.DataDir, longID) {
		jerr(w, 409, "share is no longer available")
		return
	}
	n, err = tx.Uploads().LockForAppend(ctx, id, u.ID, owner, shareID)
	if err != nil {
		jerr(w, 500, "upload finalization failed")
		return
	}
	if n != 1 {
		jerr(w, 409, "upload no longer exists")
		return
	}
	used := map[string]bool{}
	dirs := map[string]bool{}
	var existing int64
	stored, err := tx.Shares().FilePathsAndSizes(ctx, shareID)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	for _, sf := range stored {
		fp, sz := sf.FullPath, sf.Size
		used[strings.ToLower(fp)] = true
		addParentDirs(dirs, strings.ToLower(fp))
		existing += sz
	}
	var add int64
	for _, f := range files {
		add += f.size
	}
	if msg := shareTotalProblem(existing, add, maxShare); msg != "" {
		jerr(w, 413, msg)
		return
	}
	added := make([]shareFileOut, 0, len(files))
	for _, f := range files {
		np, err := uniqueSharePath(used, f.fp)
		if err != nil {
			jerr(w, 409, "could not choose a unique file name")
			return
		}
		// A path may not be both a file and a folder, over existing plus new files.
		if pathKindConflict(used, dirs, strings.ToLower(np)) {
			jerr(w, 409, "a file and a folder would have the same name in this share")
			return
		}
		used[strings.ToLower(np)] = true
		addParentDirs(dirs, strings.ToLower(np))
		name := path.Base(np)
		fid, err := tx.Shares().AddFile(ctx, ports.NewShareFile{ShareID: shareID, Name: name, FullPath: np, Size: f.size, Type: f.typ, DiskPath: f.disk,
			SHA256: f.checksum, Integrity: f.integrity, Encrypted: f.enc, EncID: f.encID, StorageID: loc, ObjectKey: f.objKey})
		if err != nil {
			jerr(w, 500, "file metadata write failed")
			return
		}
		added = append(added, shareFileOut{fid, name, np, f.size})
	}
	n, err = tx.Uploads().Delete(ctx, id)
	if err != nil {
		jerr(w, 500, "upload finalization failed")
		return
	}
	if n != 1 {
		jerr(w, 409, "upload no longer exists")
		return
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "file metadata write failed")
		return
	}
	committed = true
	// Only generated hex session ids ever name a staging directory.
	if uploadIDRe.MatchString(id) {
		os.RemoveAll(s.uploadDir(id))
	}
	s.logEvent(u.ID, u.Username, "share_files_added", "share#"+strconv.FormatInt(shareID, 10), fmt.Sprintf("%d files", len(added)))
	jout(w, 201, map[string]any{"ok": true, "added": added})
}

func (s *Server) listShareFiles(w http.ResponseWriter, r *http.Request) {
	sh := s.ownedShare(w, r)
	if sh == nil {
		return
	}
	files, err := s.St.Repos().Shares().ListFiles(context.Background(), sh.ID)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	out := []shareFileOut{}
	for _, f := range files {
		out = append(out, shareFileOut{f.ID, f.Name, f.FullPath, f.Size})
	}
	jout(w, 200, out)
}

// removeFileCommitHook lets tests force a commit failure.
var removeFileCommitHook func() error

func (s *Server) deleteShareFile(w http.ResponseWriter, r *http.Request) {
	sh := s.ownedShare(w, r)
	if sh == nil {
		return
	}
	u := s.ctxUser(r)
	fileID, err := strconv.ParseInt(chi.URLParam(r, "fileId"), 10, 64)
	if err != nil {
		jerr(w, 404, "file not found")
		return
	}
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	n, err := tx.Shares().LockOwnedForFileRemoval(ctx, sh.ID, u.ID)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if n != 1 {
		jerr(w, 404, "share not found")
		return
	}
	disk, lid, loc, err := tx.Shares().FileLocation(ctx, fileID, sh.ID)
	if err != nil {
		if errors.Is(err, ports.ErrNotFound) {
			jerr(w, 404, "file not found")
		} else {
			jerr(w, 500, "database error")
		}
		return
	}
	count, err := tx.Shares().CountFiles(ctx, sh.ID)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if count <= 1 {
		jerr(w, 409, "a share needs at least one file")
		return
	}
	if loc != store.LocalLocation {
		// In an object store: deleting the row queues the object for deletion
		// in the same transaction (files_remote_deleted trigger).
		if err := tx.Shares().DeleteFile(ctx, fileID, sh.ID); err != nil {
			jerr(w, 500, "database error")
			return
		}
		if removeFileCommitHook != nil {
			if err := removeFileCommitHook(); err != nil {
				jerr(w, 500, "database error")
				return
			}
		}
		if err := tx.Commit(); err != nil {
			jerr(w, 500, "database error")
			return
		}
		s.kickDeletes()
		s.logEvent(u.ID, u.Username, "share_file_removed", "share#"+strconv.FormatInt(sh.ID, 10), "file#"+strconv.FormatInt(fileID, 10))
		jout(w, 200, map[string]any{"ok": true})
		return
	}
	// Only ever touch a file directly inside this share's own directory: the path
	// is derived from the validated long ID and the recorded base name only.
	safe, perr := store.SharePath(s.St.DataDir, lid, disk)
	if perr != nil {
		jerr(w, 500, "file storage metadata invalid")
		return
	}
	disk = safe
	removing := disk + ".removing"
	renamed := false
	if err := os.Rename(disk, removing); err == nil {
		renamed = true
	} else if !os.IsNotExist(err) {
		jerr(w, 503, "file removal failed")
		return
	}
	undo := func() {
		if renamed {
			os.Rename(removing, disk)
		}
	}
	if err := tx.Shares().DeleteFile(ctx, fileID, sh.ID); err != nil {
		undo()
		jerr(w, 500, "database error")
		return
	}
	if removeFileCommitHook != nil {
		if err := removeFileCommitHook(); err != nil {
			undo()
			jerr(w, 500, "database error")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		undo()
		jerr(w, 500, "database error")
		return
	}
	if renamed {
		os.Remove(removing)
	}
	s.logEvent(u.ID, u.Username, "share_file_removed", "share#"+strconv.FormatInt(sh.ID, 10), "file#"+strconv.FormatInt(fileID, 10))
	jout(w, 200, map[string]any{"ok": true})
}
