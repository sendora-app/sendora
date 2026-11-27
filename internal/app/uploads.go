// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/storage"
	"github.com/sendora-app/sendora/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type uploadFileReq struct {
	Name     string `json:"name"`
	FullPath string `json:"full_path"`
	Size     int64  `json:"size"`
	Type     string `json:"type"`
	SHA256   string `json:"sha256"`
}

func cleanRel(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(path.Clean("/"+p), "/")
	return p
}

// validateUploadPath checks portable filename hazards before cleanRel can hide
// them. Historical POSIX absolute/dot-path normalization remains supported;
// backslash-relative folder paths are also accepted and normalized by cleanRel.
func validateUploadPath(p string) error {
	if strings.HasPrefix(p, "\\") {
		return fmt.Errorf("unsafe file path")
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "//") || strings.ContainsAny(p, ":\"*?<>|") {
		return fmt.Errorf("unsafe file path")
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return fmt.Errorf("unsafe file path")
		}
	}
	for _, component := range strings.Split(p, "/") {
		if component == "" || component == "." || component == ".." {
			continue
		}
		if strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return fmt.Errorf("unsafe file path")
		}
		// Windows reserves device names even with an extension, in any folder.
		base, _, _ := strings.Cut(component, ".")
		base = strings.ToUpper(strings.TrimRight(base, " "))
		switch base {
		case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
			return fmt.Errorf("unsafe file path")
		}
		if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
			suffix := base[3:]
			if len(suffix) == 1 && suffix[0] >= '1' && suffix[0] <= '9' || suffix == "¹" || suffix == "²" || suffix == "³" {
				return fmt.Errorf("unsafe file path")
			}
		}
	}
	return nil
}

// Persisted archive names must already be safe, canonical relative paths. Never
// silently rewrite legacy metadata: a ZIP must preserve exactly the safe name.
func validateArchivePath(p string) error {
	if p == "" || p != cleanRel(p) || validateUploadPath(p) != nil {
		return fmt.Errorf("%w: unsafe archive path", errIntegrity)
	}
	return nil
}

var uploadIDRe = regexp.MustCompile(`^[a-f0-9]{16,64}$`)

// uploadDir maps a session id to its staging directory. Ids are always generated
// hex strings; anything else (e.g. from a tampered database) maps to a fixed
// directory that is never created, so path tricks cannot reach other places.
// The id only reaches the path behind the early-return regexp guard.
func (s *Server) uploadDir(id string) string {
	if !uploadIDRe.MatchString(id) {
		return filepath.Join(s.St.DataDir, "uploads", ".invalid-session")
	}
	return filepath.Join(s.St.DataDir, "uploads", id)
}

func (s *Server) ownUpload(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := chi.URLParam(r, "id")
	uid, err := s.St.Repos().Uploads().Uploader(context.Background(), id)
	if err != nil || uid != s.ctxUser(r).ID {
		jerr(w, 404, "upload not found")
		return "", false
	}
	return id, true
}

func (s *Server) createUpload(w http.ResponseWriter, r *http.Request) {
	if !s.storageAdmits(w) {
		return
	}
	u := s.ctxUser(r)
	var b struct {
		Files   []uploadFileReq
		ShareID *int64 `json:"share_id"`
	}
	if decode(r, &b) != nil || len(b.Files) == 0 || len(b.Files) > 5000 {
		jerr(w, 400, "files required (max 5000)")
		return
	}
	if b.ShareID != nil && u.IsGuest {
		jerr(w, 404, "share not found")
		return
	}
	// Switching uploads by invitation off also stops invitations already sent.
	if u.IsGuest && !s.St.SettingBool("allow_reverse_shares") {
		jerr(w, 403, msgReverseOff)
		return
	}
	var total int64
	for _, f := range b.Files {
		if f.SHA256 != "" && !validSHA256(f.SHA256) {
			jerr(w, 400, "invalid SHA-256 checksum")
			return
		}
		if f.Size < 0 || f.Size > math.MaxInt64-total {
			jerr(w, 400, "bad size")
			return
		}
		total += f.Size
	}
	if max := int64(s.St.SettingInt("max_share_size", 2048)) * 1024 * 1024; max > 0 && total > max {
		jerr(w, 413, fmt.Sprintf("total size exceeds limit of %d MB", max/1024/1024))
		return
	}
	maxShare := int64(s.St.SettingInt("max_share_size", 2048)) * 1024 * 1024
	// A share larger than the verified-download limit could never be downloaded.
	if limit := snapshotLimit(); total > limit {
		jerr(w, 413, fmt.Sprintf("total size exceeds the download limit of %d MB", limit/1024/1024))
		return
	}
	id := randHex(16)
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	// The first statement obtains SQLite's write lock before the snapshot. Both
	// attribution and capacity are revalidated here, including different guests
	// spending the same inviter's quota. Never call Store.DB while tx is open.
	n, err := tx.Users().LockForUpload(ctx, u.ID, u.IsGuest)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if n != 1 {
		jerr(w, 403, "user no longer valid")
		return
	}
	pending, err := tx.Uploads().CountByUploader(ctx, u.ID)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if pending >= 16 || (u.IsGuest && pending > 0) {
		jerr(w, 429, "too many active uploads")
		return
	}
	owner := u.ID
	var inviteID *int64
	if u.IsGuest {
		if count, err := tx.ReverseInvites().CountForGuest(ctx, u.ID); err != nil || count != 1 {
			jerr(w, 403, "invite no longer valid")
			return
		}
		iid, invOwner, err := tx.ReverseInvites().OpenForGuest(ctx, u.ID, time.Now())
		if err != nil {
			jerr(w, 403, "invite no longer valid")
			return
		}
		owner = invOwner
		inviteID = &iid
		// For an open link, the upload limit is checked again when uploading
		// starts: an accept may have released its slot after an hour.
		parentID, maxUploads, err := tx.ReverseInvites().UploadSlot(ctx, iid)
		if err != nil {
			jerr(w, 403, "invite no longer valid")
			return
		}
		if parentID != nil {
			used, err := tx.ReverseInvites().CountUsedSiblings(ctx, *parentID, iid)
			if err != nil {
				jerr(w, 500, "database error")
				return
			}
			if used >= maxUploads {
				jerr(w, 410, "invite upload limit reached")
				return
			}
		}
	}
	var shareID *int64
	if b.ShareID != nil {
		// Appending: the write lock is already held, so the share cannot be
		// removed or resized between this check and the session insert.
		lid, status, err := tx.Shares().OwnedLongIDAndStatus(ctx, *b.ShareID, u.ID)
		if err != nil {
			jerr(w, 404, "share not found")
			return
		}
		if status == "deleted" || !shareDirExists(s.St.DataDir, lid) {
			jerr(w, 409, "share is no longer available")
			return
		}
		existing, err := tx.Shares().FilesTotalSize(ctx, *b.ShareID)
		if err != nil {
			jerr(w, 500, "database error")
			return
		}
		if msg := shareTotalProblem(existing, total, maxShare); msg != "" {
			jerr(w, 413, msg)
			return
		}
		sid := *b.ShareID
		shareID = &sid
	}
	usage, err := s.St.StorageUsageTx(tx, owner)
	if err != nil {
		jerr(w, 503, "storage accounting unavailable")
		return
	}
	if usage.StoredBytes+usage.ReservedBytes > usage.QuotaBytes || total > usage.AvailableBytes {
		jerr(w, 413, "storage quota exceeded")
		return
	}
	if !s.tenantStorageAdmits(w, tx, total) {
		return
	}
	if err = tx.Uploads().Create(ctx, ports.NewUpload{ID: id, UserID: u.ID, InviteID: inviteID, QuotaOwnerID: owner, ShareID: shareID}); err != nil {
		jerr(w, 500, "upload metadata write failed")
		return
	}
	// Within one new share every path must be unique (case-insensitively), or
	// the ZIP and single-file downloads would be ambiguous: repeated names get a
	// " (2)" suffix, as when appending to a share, and a file that is also used
	// as a folder is refused. Append sessions are renamed on completion instead.
	seenFiles, seenDirs := map[string]bool{}, map[string]bool{}
	for i, f := range b.Files {
		if validateUploadPath(f.FullPath) != nil {
			jerr(w, 400, "unsafe file path")
			return
		}
		fp := cleanRel(f.FullPath)
		if fp == "" {
			if validateUploadPath(f.Name) != nil {
				jerr(w, 400, "unsafe file path")
				return
			}
			fp = cleanRel(f.Name)
		}
		if validateArchivePath(fp) != nil {
			jerr(w, 400, "unsafe file path")
			return
		}
		if err := validateNewPath(f.FullPath); err != nil {
			jerr(w, 400, err.Error())
			return
		}
		if err := validateNewPath(fp); err != nil {
			jerr(w, 400, err.Error())
			return
		}
		name := safeName(path.Base(fp))
		if name == "" {
			tx.Rollback()
			jerr(w, 400, "invalid file name")
			return
		}
		if shareID == nil {
			if seenFiles[strings.ToLower(fp)] {
				renamed, err := uniqueSharePath(seenFiles, fp)
				if err != nil {
					jerr(w, 400, "duplicate file path in upload")
					return
				}
				fp, name = renamed, safeName(path.Base(renamed))
			}
			key := strings.ToLower(fp)
			if seenDirs[key] {
				jerr(w, 400, "duplicate file path in upload")
				return
			}
			for dir := path.Dir(key); dir != "." && dir != "/"; dir = path.Dir(dir) {
				if seenFiles[dir] {
					jerr(w, 400, "duplicate file path in upload")
					return
				}
				seenDirs[dir] = true
			}
			seenFiles[key] = true
		}
		typ := f.Type
		if typ == "" {
			typ = mime.TypeByExtension(filepath.Ext(name))
		}
		if err := tx.Uploads().AddFile(ctx, ports.NewUploadFile{SessionID: id, Index: i, Name: name, FullPath: fp, Size: f.Size, Type: typ, SHA256: f.SHA256}); err != nil {
			tx.Rollback()
			jerr(w, 500, "upload metadata write failed")
			return
		}
	}
	if err := os.MkdirAll(s.uploadDir(id), 0o700); err != nil {
		jerr(w, 503, "upload storage unavailable")
		return
	}
	if err := tx.Commit(); err != nil {
		os.Remove(s.uploadDir(id))
		jerr(w, 500, "upload metadata write failed")
		return
	}
	jout(w, 201, map[string]any{"id": id})
}

func (s *Server) uploadStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := s.ownUpload(w, r)
	if !ok {
		return
	}
	progress, err := s.St.Repos().Uploads().Progress(context.Background(), id)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	out := []map[string]any{}
	for _, p := range progress {
		out = append(out, map[string]any{"idx": p.Index, "size": p.Size, "received": p.Received})
	}
	jout(w, 200, map[string]any{"id": id, "files": out})
}

// chunkBusy marks upload sessions that are currently receiving a chunk. It is a
// per-session try-lock: a slow body only delays that one session, never the other
// users that share its stripe mutex.
var chunkBusy sync.Map

const maxChunkBytes = 64 << 20

// uploadChunk appends request body at Upload-Offset. Resumable: client asks status then continues from received.
//
// The body is first spooled to a bounded temporary file inside the session
// directory without holding any stripe lock; the stripe lock is taken only for the
// short offset re-check, copy into the part file and database update. A second
// chunk for the same session while one is in flight gets 409 with busy=true and
// the current offset, so the client retries after a pause.
func (s *Server) uploadChunk(w http.ResponseWriter, r *http.Request) {
	id, ok := s.ownUpload(w, r)
	if !ok {
		return
	}
	// Session ids are generated hex; anything else never names a staging directory.
	if !uploadIDRe.MatchString(id) {
		jerr(w, 404, "upload not found")
		return
	}
	idx, _ := strconv.Atoi(chi.URLParam(r, "idx"))
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil {
		jerr(w, 400, "Upload-Offset required")
		return
	}
	size, rec, err := s.St.Repos().Uploads().FileState(context.Background(), id, idx)
	if err != nil {
		jerr(w, 404, "file not found")
		return
	}
	if _, busy := chunkBusy.LoadOrStore(id, struct{}{}); busy {
		w.Header().Set("Retry-After", "1")
		jout(w, 409, map[string]any{"error": "another chunk of this upload is still being received", "busy": true, "received": rec})
		return
	}
	defer chunkBusy.Delete(id)
	// Re-read under the busy marker: the previous chunk may have just finished.
	if size, rec, err = s.St.Repos().Uploads().FileState(context.Background(), id, idx); err != nil {
		jerr(w, 404, "file not found")
		return
	}
	if offset != rec {
		jout(w, 409, map[string]any{"error": "offset mismatch", "received": rec})
		return
	}
	if rec >= size && size > 0 {
		jout(w, 200, map[string]any{"received": rec})
		return
	}
	tmp, err := os.OpenFile(filepath.Join(s.uploadDir(id), strconv.Itoa(idx)+".chunk"), os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		jerr(w, 404, "upload not found")
		return
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()
	n, copyErr := io.Copy(tmp, io.LimitReader(r.Body, min(size-offset, int64(maxChunkBytes))+1))
	if offset+n > size || n > maxChunkBytes {
		jerr(w, 413, "chunk exceeds declared size")
		return
	}
	unlock := s.stripe(&s.uploadLocks, id)
	defer unlock()
	// The session may have been aborted, completed or cleaned up meanwhile.
	if rec, err = s.St.Repos().Uploads().ReceivedOfUploader(context.Background(), id, idx, s.ctxUser(r).ID); err != nil {
		jerr(w, 404, "upload not found")
		return
	}
	if rec != offset {
		jout(w, 409, map[string]any{"error": "offset mismatch", "received": rec})
		return
	}
	if n > 0 {
		f, err := os.OpenFile(filepath.Join(s.uploadDir(id), strconv.Itoa(idx)+".part"), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			jerr(w, 500, "storage error")
			return
		}
		defer f.Close()
		if _, err = tmp.Seek(0, io.SeekStart); err == nil {
			_, err = f.Seek(offset, io.SeekStart)
		}
		var m int64
		if err == nil {
			m, err = io.Copy(f, tmp)
		}
		if err != nil || m != n {
			f.Truncate(offset)
			jerr(w, 500, "write failed")
			return
		}
		f.Truncate(offset + n)
		if err := s.St.Repos().Uploads().SetReceived(context.Background(), id, idx, offset+n); err != nil {
			jerr(w, 500, "write failed")
			return
		}
	}
	if copyErr != nil {
		jerr(w, 500, "write failed")
		return
	}
	jout(w, 200, map[string]any{"received": offset + n})
}

func (s *Server) abortUpload(w http.ResponseWriter, r *http.Request) {
	unlock := s.stripe(&s.uploadLocks, chi.URLParam(r, "id"))
	defer unlock()
	id, ok := s.ownUpload(w, r)
	if !ok {
		return
	}
	if err := s.removeUploadSession(id); err != nil {
		jerr(w, 503, "upload cleanup failed")
		return
	}
	jout(w, 200, map[string]any{"ok": true})
}

type completeReq struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Password      string   `json:"password"`
	ExpiresInDays int      `json:"expires_in_days"`
	DownloadLimit int64    `json:"download_limit"`
	Recipients    []string `json:"recipients"`
	Message       string   `json:"message"`
	EmailLanguage string   `json:"email_language"`
}

func (s *Server) completeUpload(w http.ResponseWriter, r *http.Request) {
	s.completeUploadWithShareID(w, r, newShareID)
}

func (s *Server) completeUploadWithShareID(w http.ResponseWriter, r *http.Request, generate func() (string, error)) {
	if !s.storageAdmits(w) {
		return
	}
	unlock := s.stripe(&s.uploadLocks, chi.URLParam(r, "id"))
	defer unlock()
	id, ok := s.ownUpload(w, r)
	if !ok {
		return
	}
	// Session ids are generated hex; anything else never names a staging directory.
	if !uploadIDRe.MatchString(id) {
		jerr(w, 404, "upload not found")
		return
	}
	u := s.ctxUser(r)
	if u.IsGuest && !s.St.SettingBool("allow_reverse_shares") {
		jerr(w, 403, msgReverseOff)
		return
	}
	appendTo, err := s.St.Repos().Uploads().AppendTarget(context.Background(), id)
	if err != nil {
		jerr(w, 409, "upload no longer exists")
		return
	}
	if appendTo != nil {
		s.completeAppend(w, r, id, *appendTo)
		return
	}
	var b completeReq
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	if b.EmailLanguage == "" {
		b.EmailLanguage = "en"
	}
	if !s.St.ValidMailLanguage(b.EmailLanguage) {
		jerr(w, 400, "unsupported email language")
		return
	}
	if len(b.Recipients) > 20 {
		jerr(w, 400, "max 20 recipients")
		return
	}
	if validateText(b.Name, maxShareNameRunes, true) != nil || validateText(b.Description, maxDescriptionRunes, false) != nil || validateText(b.Message, maxMessageRunes, false) != nil {
		jerr(w, 400, "name, description or message too long or contains invalid characters")
		return
	}
	type uf struct {
		idx                           int
		name, fp, typ                 string
		expected, checksum, integrity string
		size, rec                     int64
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
	max := s.St.SettingInt("max_expiry_time", 30)
	days := b.ExpiresInDays
	if days <= 0 {
		days = s.St.SettingInt("default_expiry_time", 7)
	}
	if max > 0 && days > max {
		days = max
	}
	owner, reservationInvite, err := s.St.Repos().Uploads().Reservation(context.Background(), id, u.ID)
	if err != nil {
		jerr(w, 409, "upload reservation unavailable")
		return
	}
	var inviteID *int64
	var inviteOwner int64
	if u.IsGuest {
		if reservationInvite == nil {
			jerr(w, 403, "invite no longer valid")
			return
		}
		inviteID, inviteOwner = reservationInvite, owner
		b.Password, b.Recipients = "", nil
	} else if reservationInvite != nil || owner != u.ID {
		jerr(w, 409, "upload reservation invalid")
		return
	}
	if !u.IsGuest {
		if n := countRecipients(b.Recipients); n > 0 && !s.takeMail(u.ID, n) {
			w.Header().Set("Retry-After", "3600")
			jerr(w, 429, "too many emails sent recently; try again later")
			return
		}
		policy, err := s.loadSharePolicy()
		if err != nil {
			jerr(w, 500, "share password policy unavailable")
			return
		}
		if err := validateSharePassword(policy, b.Password); err != nil {
			jerr(w, 400, err.Error())
			return
		}
	}
	var hash string
	if b.Password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(b.Password), hashCost)
		if err != nil {
			jerr(w, 400, "share password must not exceed 72 bytes")
			return
		}
		hash = string(h)
	}
	name := strings.TrimSpace(b.Name)
	if name == "" {
		name = "Shared files"
	}
	var lim *int64
	if b.DownloadLimit > 0 {
		lim = &b.DownloadLimit
	}
	// New files go to the selected storage location; files are encrypted
	// before they leave this server.
	loc, backend, err := s.currentStorage(r.Context())
	if err != nil {
		log.Printf("storage unavailable: %v", err)
		jerr(w, 503, "file storage unavailable")
		return
	}
	// The local share directory is also the claim of the share ID for files in
	// an object store (it then stays empty).
	longID, dest, err := claimShareDir(s.St.Repos().Shares(), filepath.Join(s.St.DataDir, "shares"), generate)
	if err != nil {
		jerr(w, 500, "share storage unavailable")
		return
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(dest)
			for _, f := range files {
				if f.objKey != "" {
					backend.Delete(context.WithoutCancel(r.Context()), f.objKey)
				}
			}
		}
	}()
	// Keep the original parts until the database commit succeeds, so every failure is retryable.
	for i := range files {
		f := &files[i]
		disk := filepath.Join(dest, fmt.Sprintf("%d_%s", f.idx, f.name))
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
			checksum, encID, err = stageUploadFile(r.Context(), part, disk, f.size, fk, s.St.IsEncrypted())
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
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	// An admitted reservation may finish after the quota is lowered. Only its
	// original owner may receive the share; never reattribute it at completion.
	n, err := tx.Uploads().LockForCompletion(ctx, id, u.ID, owner, u.IsGuest)
	if err != nil {
		jerr(w, 500, "upload finalization failed")
		return
	}
	if n != 1 {
		jerr(w, 409, "upload no longer exists")
		return
	}
	if inviteID != nil {
		if valid, err := tx.ReverseInvites().CountValidForCompletion(ctx, *inviteID, u.ID, owner, time.Now()); err != nil || valid != 1 {
			jerr(w, 403, "invite no longer valid")
			return
		}
	}
	sid, err := tx.Shares().Create(ctx, ports.NewShare{UserID: owner, InviteID: inviteID, LongID: longID, Name: name, Description: b.Description,
		PasswordHash: hash, DownloadLimit: lim, ExpiresAt: time.Now().AddDate(0, 0, days)})
	if err != nil {
		tx.Rollback()
		jerr(w, 500, "share metadata write failed")
		return
	}
	for _, f := range files {
		disk := filepath.Join(dest, fmt.Sprintf("%d_%s", f.idx, f.name))
		if f.objKey != "" {
			disk = ""
		}
		if _, err := tx.Shares().AddFile(ctx, ports.NewShareFile{ShareID: sid, Name: f.name, FullPath: f.fp, Size: f.size, Type: f.typ, DiskPath: disk,
			SHA256: f.checksum, Integrity: f.integrity, Encrypted: f.enc, EncID: f.encID, StorageID: loc, ObjectKey: f.objKey}); err != nil {
			jerr(w, 500, "file metadata write failed")
			return
		}
	}
	if inviteID != nil {
		n, err := tx.ReverseInvites().Complete(ctx, *inviteID, time.Now(), time.Now())
		if err != nil {
			jerr(w, 500, "invite update failed")
			return
		}
		if n == 0 {
			jerr(w, 403, "invite no longer valid")
			return
		}
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
		jerr(w, 500, "share metadata write failed")
		return
	}
	committed = true
	// Only generated hex session ids ever name a staging directory.
	if uploadIDRe.MatchString(id) {
		os.RemoveAll(s.uploadDir(id))
	}
	s.logEvent(u.ID, u.Username, "share_created", "share#"+strconv.FormatInt(sid, 10), fmt.Sprintf("%d files", len(files)))
	url := s.baseURL(r) + "/share/" + longID
	emailBase, emailOK := s.emailBaseURL(r)
	emailURL := emailBase + "/share/" + longID
	sh, _ := s.shareByID(sid)
	for _, rcpt := range b.Recipients {
		rcpt = strings.TrimSpace(rcpt)
		if rcpt != "" && emailOK {
			s.queueMail(rcpt, u.Name+" shared files with you", "tpl_share_created", map[string]any{
				"EmailLanguage": b.EmailLanguage, "RecipientName": rcpt, "SenderName": nameOf(u), "URL": emailURL, "Message": b.Message,
				"Expires": sh.ExpiresAt.Format("2006-01-02"), "ShareName": name,
			})
		}
	}
	if inviteID != nil && emailOK {
		go s.notifyInviteCompleted(inviteOwner, u, emailURL, name)
	}
	if u.IsGuest {
		// The share belongs to the inviter. The guest never gets its link, so an
		// invitation cannot be used to publish files on this domain.
		jout(w, 201, map[string]any{"ok": true})
		return
	}
	jout(w, 201, map[string]any{"id": sid, "long_id": longID, "url": url})
}

// LockUserUploads blocks chunks, completion, abort and stale cleanup while a
// user (including their invited guests) is deleted. Lock all stripes: discovering
// a subset first would miss sessions admitted immediately before deletion.
func (s *Server) LockUserUploads(_ int64) func() {
	for i := range s.uploadLocks {
		s.uploadLocks[i].Lock()
	}
	return func() {
		for i := len(s.uploadLocks) - 1; i >= 0; i-- {
			s.uploadLocks[i].Unlock()
		}
	}
}

// UserUploadSessions is a convenience snapshot. Deletion must collect the same
// predicate inside its transaction before deleting the user, then clean disk.
func (s *Server) UserUploadSessions(userID int64) ([]string, error) {
	return s.St.Repos().Uploads().IDsOfUploaderOrQuotaOwner(context.Background(), userID)
}

// Caller holds the upload stripe. Keep the reservation until disk cleanup
// succeeds; failed cleanup must not grant storage for another upload.
func (s *Server) removeUploadSession(id string) error {
	// A non-hex id (tampered row) has no staging directory; only its row goes.
	if uploadIDRe.MatchString(id) {
		if err := os.RemoveAll(s.uploadDir(id)); err != nil {
			return err
		}
	}
	_, err := s.St.Repos().Uploads().Delete(context.Background(), id)
	return err
}

// errNoFileKey is returned when an encrypted store has no file key: storing the
// upload unencrypted would be a silent downgrade, so nothing is written.
var errNoFileKey = errors.New("file encryption key unavailable")

// stageUploadFile moves one finished upload part into its final place. With a
// file key it encrypts on the way (one streaming pass, no extra read) and always
// returns the SHA-256 of the plaintext computed during that same pass, plus the
// file id (hex) of the encrypted file for the database row. Only the plaintext
// fixture store (encryptedStore false, no key) stores plain files; an encrypted
// store without a usable key is refused. A partially written dest is removed.
func stageUploadFile(ctx context.Context, src, dest string, size int64, key []byte, encryptedStore bool) (checksum, encID string, err error) {
	if len(key) != 32 && (encryptedStore || len(key) != 0) {
		return "", "", errNoFileKey
	}
	in, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) && size == 0 {
			in = nil
		} else {
			return "", "", err
		}
	}
	var reader io.Reader = bytes.NewReader(nil)
	if in != nil {
		defer in.Close()
		st, err := in.Stat()
		if err != nil {
			return "", "", err
		}
		if !st.Mode().IsRegular() || st.Size() != size {
			return "", "", errIntegrity
		}
		reader = contextReader{ctx, io.LimitReader(in, size+1)}
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", err
	}
	// dest was created by this call (O_EXCL), so it is ours to remove on failure.
	ok := false
	defer func() {
		if !ok {
			out.Close()
			os.Remove(dest)
		}
	}()
	h := sha256.New()
	var n int64
	var copyErr error
	if len(key) == 32 {
		w := bufio.NewWriterSize(out, 256<<10)
		n, encID, copyErr = filecrypt.Encrypt(w, reader, key, h)
		if copyErr == nil {
			copyErr = w.Flush()
		}
	} else {
		n, copyErr = io.Copy(io.MultiWriter(out, h), reader)
	}
	if copyErr != nil {
		return "", "", copyErr
	}
	if n != size {
		return "", "", errIntegrity
	}
	if err := out.Close(); err != nil {
		return "", "", err
	}
	ok = true
	return hex.EncodeToString(h.Sum(nil)), encID, nil
}

func nameOf(u *User) string {
	if u.Name != "" {
		return u.Name
	}
	return u.Username
}
