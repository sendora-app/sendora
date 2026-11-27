// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type FileInfo struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	FullPath  string `json:"full_path"`
	Size      int64  `json:"size"`
	Type      string `json:"type"`
	SHA256    string `json:"sha256"`
	Integrity string `json:"integrity"`
	diskPath  string
	enc       bool
	encID     string // hex file id (format v2); empty for plain and v1 files
	storageID int64  // storage location (0 = local data directory)
	objectKey string // key in a remote location
	longID    string
}

type Share struct {
	ID            int64      `json:"id"`
	LongID        string     `json:"long_id"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Owner         string     `json:"owner,omitempty"`
	Protected     bool       `json:"password_protected"`
	Status        string     `json:"status"`
	DownloadLimit *int64     `json:"download_limit"`
	DownloadCount int64      `json:"download_count"`
	ExpiresAt     *time.Time `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
	Expired       bool       `json:"expired"`
	Size          int64      `json:"size"`
	FileCount     int        `json:"file_count"`
	Files         []FileInfo `json:"files,omitempty"`
	userID        sql.NullInt64
	hash          string
}

// shareFromRecord turns a repository record (or its lookup error) into a
// Share.
func shareFromRecord(rec ports.ShareRecord, err error) (*Share, error) {
	if err != nil {
		return nil, err
	}
	sh := &Share{ID: rec.ID, LongID: rec.LongID, Name: rec.Name, Description: rec.Description, Owner: rec.Owner, hash: rec.PasswordHash,
		Status: rec.Status, DownloadCount: rec.DownloadCount, CreatedAt: rec.CreatedAt, Size: rec.Size, FileCount: rec.FileCount,
		DownloadLimit: rec.DownloadLimit, ExpiresAt: rec.ExpiresAt}
	if rec.UserID != nil {
		sh.userID = sql.NullInt64{Int64: *rec.UserID, Valid: true}
	}
	sh.Protected = sh.hash != ""
	sh.Expired = sh.Status != "active" ||
		(sh.ExpiresAt != nil && time.Now().After(*sh.ExpiresAt)) ||
		(sh.DownloadLimit != nil && sh.DownloadCount >= *sh.DownloadLimit)
	return sh, nil
}

// shareByLongID loads a share for the public link routes. While its owner's
// account is disabled the link answers like an expired share (deactivate.go).
func (s *Server) shareByLongID(id string) (*Share, error) {
	sh, err := shareFromRecord(s.St.Repos().Shares().ByLongID(context.Background(), id))
	if err == nil && s.shareOwnerDisabled(sh.ID) {
		sh.Expired = true
	}
	return sh, err
}

func (s *Server) shareByID(id int64) (*Share, error) {
	return shareFromRecord(s.St.Repos().Shares().ByID(context.Background(), id))
}

func (s *Server) shareFiles(shareID int64) []FileInfo {
	recs, err := s.St.Repos().Shares().Files(context.Background(), shareID)
	out := []FileInfo{}
	if err != nil {
		if errors.Is(err, ports.ErrReadInterrupted) {
			return nil
		}
		return out
	}
	for _, rec := range recs {
		f := FileInfo{ID: rec.ID, Name: rec.Name, FullPath: rec.FullPath, Size: rec.Size, Type: rec.Type, diskPath: rec.DiskPath, SHA256: rec.SHA256,
			Integrity: rec.Integrity, enc: rec.Encrypted, encID: rec.EncID, storageID: rec.StorageID, objectKey: rec.ObjectKey}
		lid := rec.LongID
		f.longID = lid
		if f.storageID != store.LocalLocation {
			f.diskPath = "" // in an object store (openRemoteFile)
			out = append(out, f)
			continue
		}
		// The recorded directory is never trusted: only the base name is used, under
		// this server's DataDir/shares/<validated long id>. An unsafe record leaves
		// diskPath empty, which cannot be opened.
		if safe, err := store.SharePath(s.St.DataDir, lid, f.diskPath); err == nil {
			f.diskPath = safe
		} else {
			f.diskPath = ""
		}
		out = append(out, f)
	}
	return out
}

// share download tokens: short-lived JWT proving password was supplied.
func (s *Server) shareToken(sh *Share) string {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"purpose": "share", "share": sh.LongID, "pv": s.sharePasswordVersion(sh), "exp": time.Now().Add(2 * time.Hour).Unix()})
	str, _ := t.SignedString(s.key(keyShareUnlock))
	return str
}

// sharePasswordVersion binds unlock tokens to the current password hash, so a
// changed or removed password invalidates every earlier token.
func (s *Server) sharePasswordVersion(sh *Share) string {
	h := hmac.New(sha256.New, s.key(keySharePasswordVersion))
	fmt.Fprintf(h, "share-password:%s:%s", sh.LongID, sh.hash)
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) shareUnlocked(r *http.Request, sh *Share) bool {
	if !sh.Protected {
		return true
	}
	tok := r.Header.Get("X-Share-Token")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	if tok == "" {
		return false
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return s.key(keyShareUnlock), nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	return err == nil && claims["purpose"] == "share" && claims["share"] == sh.LongID && s.validSharePV(claims["pv"], sh)
}

func (s *Server) validSharePV(v any, sh *Share) bool {
	pv, ok := v.(string)
	return ok && hmac.Equal([]byte(pv), []byte(s.sharePasswordVersion(sh)))
}

func (s *Server) readShare(w http.ResponseWriter, r *http.Request) {
	sh, err := s.shareByLongID(chi.URLParam(r, "id"))
	if err != nil {
		jerr(w, 404, "share not found")
		return
	}
	if sh.Expired {
		jout(w, 410, map[string]any{"error": "share expired"})
		return
	}
	if !s.shareUnlocked(r, sh) {
		// Nothing about the share (owner, name, description) before the password is given.
		jout(w, 200, map[string]any{"password_protected": true})
		return
	}
	sh.Files = s.shareFiles(sh.ID)
	jout(w, 200, sh)
}

func (s *Server) unlockShare(w http.ResponseWriter, r *http.Request) {
	sh, err := s.shareByLongID(chi.URLParam(r, "id"))
	if err != nil || sh.Expired {
		jerr(w, 404, "share not found")
		return
	}
	// Budgets on top of the per-address limits: one per client (address, IPv6
	// /64) and share, and a higher one per share for guesses from many
	// addresses. An attempt is reserved before bcrypt, so parallel guesses
	// cannot overrun either budget.
	keys := shareUnlockKeys(sh.ID, ipBanKey(s.clientIP(r)))
	if wait, ok := s.unlockReserve(keys, time.Now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		jerr(w, 429, "too many failed attempts for this share; try again later")
		return
	}
	var b struct{ Password string }
	decode(r, &b)
	if bcrypt.CompareHashAndPassword([]byte(sh.hash), []byte(b.Password)) != nil {
		s.unlockFail(keys, time.Now())
		time.Sleep(300 * time.Millisecond)
		jerr(w, 401, "wrong password")
		return
	}
	s.unlockSucceeded(keys)
	s.rehashShare(sh, b.Password)
	jout(w, 200, map[string]any{"token": s.shareToken(sh)})
}

// shareUnlockShareLimit is the failure budget of a whole share within
// shareUnlockWindow. A single client (address, IPv6 /64) is blocked for one
// share after shareUnlockLimit failures; the share itself only at this higher
// threshold, which takes guesses from several addresses, so one client
// guessing cannot lock out every real recipient.
const shareUnlockShareLimit = 50

// unlockKey is one throttle budget an unlock attempt counts against.
type unlockKey struct {
	key   string
	limit int
}

// shareUnlockKeys returns the client budget first, then the share budget.
func shareUnlockKeys(shareID int64, client string) []unlockKey {
	id := strconv.FormatInt(shareID, 10)
	return []unlockKey{{"c:" + id + ":" + client, shareUnlockLimit}, {"s:" + id, shareUnlockShareLimit}}
}

// reserveAttempt atomically counts one attempt against every key before the
// password is checked. It refuses (with the time to wait) when a key is
// blocked or its budget is already used up by failures and attempts still in
// progress, so parallel guesses cannot exceed the budget. A reserved attempt
// ends with failAttempt or releaseAttempt.
func (t *failThrottle) reserveAttempt(keys []unlockKey, now time.Time) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]*failEntry{}
	}
	if len(t.m)+len(keys) > maxThrottleKeys {
		t.evict(now)
	}
	entries := make([]*failEntry, len(keys))
	for i, k := range keys {
		e := t.m[k.key]
		if e != nil && !now.Before(e.windowEnds) && !now.Before(e.blockedUntil) {
			e = nil // window and block are over: start afresh
		}
		if e != nil {
			if wait := e.blockedUntil.Sub(now); wait > 0 {
				return wait, false
			}
			if e.count >= k.limit {
				return e.windowEnds.Sub(now), false
			}
		}
		entries[i] = e
	}
	for i, k := range keys {
		e := entries[i]
		if e == nil {
			e = &failEntry{windowEnds: now.Add(shareUnlockWindow)}
			t.m[k.key] = e
		}
		e.count++
	}
	return 0, true
}

// failAttempt keeps a reserved attempt counted as a failure and blocks every
// key whose budget is now used up.
func (t *failThrottle) failAttempt(keys []unlockKey, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		e := t.m[k.key]
		if e == nil || e.count < k.limit {
			continue
		}
		e.blockedUntil = now.Add(shareUnlockBlock)
		if e.windowEnds.Before(e.blockedUntil) {
			e.windowEnds = e.blockedUntil
		}
	}
}

// releaseAttempt gives back a reserved attempt that succeeded.
func (t *failThrottle) releaseAttempt(keys []unlockKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		if e := t.m[k.key]; e != nil && e.count > 0 {
			e.count--
		}
	}
}

// rehashShare upgrades a share password hash made with a lower bcrypt cost.
func (s *Server) rehashShare(sh *Share, password string) {
	if !passwordHashIsWeak(sh.hash) {
		return
	}
	h, err := hashPassword(password)
	if err != nil {
		return
	}
	n, err := s.St.Repos().Shares().ReplacePasswordHash(context.Background(), sh.ID, string(h), sh.hash)
	if err != nil {
		return
	}
	if n == 1 {
		sh.hash = string(h)
	}
}

// reserveDownload snapshots the atomic count; Range requests keep their existing
// per-request slot semantics, even if ServeContent rejects the requested range.
func (s *Server) reserveDownload(w http.ResponseWriter, sh *Share, files []FileInfo) (int64, bool) {
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		jerr(w, 503, "download temporarily unavailable")
		return 0, false
	}
	defer tx.Rollback()
	var email, language string
	if sh.userID.Valid {
		if email, language, err = tx.Users().EmailAndLanguage(ctx, sh.userID.Int64); err != nil {
			jerr(w, 503, "download temporarily unavailable")
			return 0, false
		}
	}
	var jobID int64
	if email != "" && !s.downloadMailAllowed(sh.ID) {
		email = "" // notified recently: count the download, skip another email
	}
	if email != "" {
		if pending, err := tx.DownloadMails().CountQueued(ctx); err != nil || pending >= downloadMailCapacity {
			w.Header().Set("Retry-After", "30")
			jerr(w, 503, "download notification queue full; try again later")
			return 0, false
		}
	}
	count, err := tx.Shares().CountDownload(ctx, sh.ID, time.Now())
	if err != nil {
		jerr(w, 410, "share expired")
		return 0, false
	}
	sh.DownloadCount = count
	if email != "" {
		names := make([]string, 0, len(files))
		for _, f := range files {
			names = append(names, f.FullPath)
		}
		data, err := json.Marshal(map[string]any{"ShareName": sh.Name, "DownloadCount": sh.DownloadCount, "FileName": strings.Join(names, ", "), "FileNames": strings.Join(names, ", ")})
		if err != nil {
			jerr(w, 503, "download temporarily unavailable")
			return 0, false
		}
		jobID, err = tx.DownloadMails().Reserve(ctx, sh.ID, email, language, string(data), time.Now())
		if err != nil {
			jerr(w, 503, "download temporarily unavailable")
			return 0, false
		}
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 503, "download temporarily unavailable")
		return 0, false
	}
	return jobID, true
}

// downloadWriter records a start only when a successful file response begins.
// Neither a successful status nor bytes written proves transfer completion.
type downloadWriter struct {
	http.ResponseWriter
	started  func() error
	status   int
	rejected bool
}

func (w *downloadWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *downloadWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	if status == http.StatusOK || status == http.StatusPartialContent {
		if err := w.started(); err != nil {
			w.rejected = true
			w.Header().Del("Content-Length")
			w.Header().Del("Content-Disposition")
			jerr(w.ResponseWriter, 503, "download temporarily unavailable")
			return
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *downloadWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.rejected {
		return 0, fmt.Errorf("download start recording failed")
	}
	return w.ResponseWriter.Write(p)
}

func (s *Server) downloadResponse(w http.ResponseWriter, r *http.Request, sh *Share, fileID *int64, jobID int64) http.ResponseWriter {
	// downloads.ip is the recipient's address. It is personal data that nothing
	// reads back (the owner's download history shows times and files only), so
	// it is stored only while audit_log_ip is on and left empty otherwise.
	shareID, ip := sh.ID, ""
	if s.auditLogIP() {
		ip = s.clientIP(r)
	}
	rangeHeader := r.Header.Get("Range")
	recorded := &downloadWriter{ResponseWriter: w, started: func() error {
		startedAt := time.Now().UTC()
		ctx := context.Background()
		tx, err := s.St.Repos().Begin(ctx)
		if err == nil {
			defer tx.Rollback()
			err = tx.Downloads().Record(ctx, shareID, fileID, ip, startedAt)
			if err == nil && jobID != 0 {
				err = tx.DownloadMails().Activate(ctx, jobID, startedAt)
			}
			if err == nil {
				err = tx.Commit()
			}
		}
		if err != nil {
			log.Printf("record download start: %v", err)
			return err
		}
		select {
		case s.downloadMailWake <- struct{}{}:
		default:
		}
		if jobID != 0 {
			s.signalWork(WorkDownloadMail)
		}
		detail := "all files"
		if fileID != nil {
			detail = "file#" + strconv.FormatInt(*fileID, 10)
		}
		// The downloads table keeps every start; the audit log only the first
		// request of a download, so range requests cannot flood it.
		if s.downloadLogAllowed(shareID, rangeHeader) {
			s.logEvent(0, "public", "download_started", "share#"+strconv.FormatInt(shareID, 10), detail)
		}
		return nil
	}}
	return &idleResponseWriter{ResponseWriter: recorded, controller: http.NewResponseController(recorded), timeout: s.transferTimeout()}
}

func (s *Server) releaseDownloadMail(jobID int64) {
	if jobID != 0 {
		s.St.Repos().DownloadMails().Release(context.Background(), jobID)
	}
}

// reserve a download slot atomically w.r.t. limit
func (s *Server) openShare(w http.ResponseWriter, r *http.Request) *Share {
	sh, err := s.shareByLongID(chi.URLParam(r, "id"))
	if err != nil {
		jerr(w, 404, "share not found")
		return nil
	}
	if sh.Expired {
		jerr(w, 410, "share expired")
		return nil
	}
	if !s.shareUnlocked(r, sh) {
		jerr(w, 401, "password required")
		return nil
	}
	return sh
}

func (s *Server) downloadShare(w http.ResponseWriter, r *http.Request) {
	sh := s.openShare(w, r)
	if sh == nil {
		return
	}
	files := s.shareFiles(sh.ID)
	if len(files) == 0 {
		jerr(w, 404, "no files")
		return
	}
	rangeSize := int64(-1)
	if len(files) == 1 {
		rangeSize = files[0].Size
	}
	if rangeNeverSatisfiable(r, rangeSize) {
		rejectRange(w, rangeSize)
		return
	}
	client := ipBanKey(s.clientIP(r))
	snapshot, checksum, release, err := s.prepareClientDownload(r.Context(), client, sh.ID, files)
	if err != nil {
		integrityError(w, err)
		return
	}
	defer release()
	jobID, ok := s.reserveDownload(w, sh, files)
	if !ok {
		return
	}
	defer s.releaseDownloadMail(jobID)
	w = s.downloadResponse(w, r, sh, nil, jobID)
	setDownloadChecksum(w, checksum)
	if len(files) == 1 {
		serveSnapshot(w, r, snapshot, files[0].Name)
		return
	}
	name := safeName(sh.Name)
	if name == "" {
		name = "share"
	}
	serveSnapshot(w, r, snapshot, name+".zip")

}

func (s *Server) downloadShareFile(w http.ResponseWriter, r *http.Request) {
	sh := s.openShare(w, r)
	if sh == nil {
		return
	}
	fp := strings.TrimPrefix(path.Clean("/"+wildcardPath(r)), "/")
	for _, f := range s.shareFiles(sh.ID) {
		if f.FullPath == fp {
			if rangeNeverSatisfiable(r, f.Size) {
				rejectRange(w, f.Size)
				return
			}
			client := ipBanKey(s.clientIP(r))
			in, checksum, release, err := s.prepareClientDownload(r.Context(), client, sh.ID, []FileInfo{f})
			if err != nil {
				integrityError(w, err)
				return
			}
			defer release()
			setDownloadChecksum(w, checksum)
			id := f.ID
			jobID, ok := s.reserveDownload(w, sh, []FileInfo{f})
			if !ok {
				return
			}
			defer s.releaseDownloadMail(jobID)
			serveSnapshot(s.downloadResponse(w, r, sh, &id, jobID), r, in, f.Name)
			return
		}
	}
	jerr(w, 404, "file not found")
}

// previewTypes is the only set of types ever served inline. Never add SVG,
// HTML, PDF or anything scriptable.
var previewTypes = map[string]string{
	".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif",
	".mp4": "video/mp4", ".webm": "video/webm",
	".mp3": "audio/mpeg", ".ogg": "audio/ogg", ".wav": "audio/wav",
}

func previewSniffOK(mime string, b []byte) bool {
	has := func(off int, sig string) bool { return len(b) >= off+len(sig) && string(b[off:off+len(sig)]) == sig }
	switch mime {
	case "image/png":
		return has(0, "\x89PNG\r\n\x1a\n")
	case "image/jpeg":
		return has(0, "\xff\xd8\xff")
	case "image/webp":
		return has(0, "RIFF") && has(8, "WEBP")
	case "image/gif":
		return has(0, "GIF87a") || has(0, "GIF89a")
	case "video/mp4":
		return has(4, "ftyp")
	case "video/webm":
		return has(0, "\x1a\x45\xdf\xa3")
	case "audio/mpeg":
		return has(0, "ID3") || (len(b) >= 2 && b[0] == 0xff && b[1]&0xe0 == 0xe0)
	case "audio/ogg":
		return has(0, "OggS")
	case "audio/wav":
		return has(0, "RIFF") && has(8, "WAVE")
	}
	return false
}

// previewShareFile serves an allowlisted media file inline. It is not a
// download: no counter, no outbox mail, no checksum snapshot.
func (s *Server) previewShareFile(w http.ResponseWriter, r *http.Request) {
	sh := s.openShare(w, r)
	if sh == nil {
		return
	}
	if !s.St.SettingBool("allow_preview") {
		jerr(w, 403, "preview disabled")
		return
	}
	if sh.DownloadLimit != nil {
		jerr(w, 403, "preview unavailable for shares with a download limit")
		return
	}
	fp := strings.TrimPrefix(path.Clean("/"+wildcardPath(r)), "/")
	for _, f := range s.shareFiles(sh.ID) {
		if f.FullPath != fp {
			continue
		}
		mime, ok := previewTypes[strings.ToLower(path.Ext(f.Name))]
		if !ok {
			jerr(w, 415, "preview not supported for this file type")
			return
		}
		in, modTime, err := s.openStoredFile(r.Context(), f)
		if err != nil {
			if f.storageID != store.LocalLocation && errors.Is(err, errIntegrity) {
				integrityError(w, err)
				return
			}
			if !os.IsNotExist(err) && f.storageID != store.LocalLocation {
				jerr(w, 503, "file storage temporarily unavailable")
				return
			}
			jerr(w, 404, "file missing")
			return
		}
		defer in.Close()
		// A chunk that fails authentication ends the response mid-stream (the
		// headers are already sent); record it, rate-limited per file.
		fileID := f.ID
		content := corruptWatch{ReadSeeker: in, onCorrupt: func() { s.noteDecryptFailure(fileID) }}
		head := make([]byte, 512)
		n, err := io.ReadFull(content, head)
		if errors.Is(err, filecrypt.ErrCorrupt) {
			integrityError(w, errIntegrity)
			return
		}
		if !previewSniffOK(mime, head[:n]) {
			jerr(w, 415, "preview not supported for this file type")
			return
		}
		// Log only the first request of a media session, not every Range chunk, so a
		// player cannot flood the audit log.
		// A gallery loads every thumbnail at once, so also log at most one preview
		// entry per share every few minutes instead of one per image.
		if rng := r.Header.Get("Range"); (rng == "" || strings.HasPrefix(rng, "bytes=0-")) && previewLogAllowed(sh.ID) {
			s.logEvent(0, "public", "share_preview", "share#"+strconv.FormatInt(sh.ID, 10), "")
		}
		var rw http.ResponseWriter = &idleResponseWriter{ResponseWriter: w, controller: http.NewResponseController(w), timeout: s.transferTimeout()}
		h := rw.Header()
		h.Set("Content-Type", mime)
		h.Set("Content-Disposition", "inline")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
		h.Set("Cache-Control", "no-store")
		defer func() { _ = http.NewResponseController(rw).Flush() }()
		http.ServeContent(rw, r, "", modTime, content)
		return
	}
	jerr(w, 404, "file not found")
}

// openStoredFile opens a share file for reading plaintext: encrypted files are
// decrypted on the fly and stay seekable, so Range requests keep working.
func (s *Server) openStoredFile(ctx context.Context, f FileInfo) (io.ReadSeekCloser, time.Time, error) {
	if f.storageID != store.LocalLocation {
		return s.openRemoteFile(ctx, f)
	}
	file, err := openDownloadFile(f.diskPath)
	if err != nil {
		return nil, time.Time{}, err
	}
	st, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, time.Time{}, err
	}
	if !f.enc {
		return file, st.ModTime(), nil
	}
	master, headerID, err := s.St.FileMaster(f.encID)
	if err != nil {
		file.Close()
		return nil, time.Time{}, s.fileKeyError(f.ID, err)
	}
	r, err := filecrypt.NewReader(file, st.Size(), f.Size, master, headerID)
	if err != nil {
		file.Close()
		s.noteDecryptFailure(f.ID)
		return nil, time.Time{}, errIntegrity
	}
	return r, st.ModTime(), nil
}

func openDownloadFile(p string) (*os.File, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("file unavailable")
	}
	return f, nil
}

func serveDisk(w http.ResponseWriter, r *http.Request, p, name string) {
	f, err := openDownloadFile(p)
	if err != nil {
		jerr(w, 404, "file missing")
		return
	}
	defer f.Close()
	serveOpenDisk(w, r, f, name)
}

func serveOpenDisk(w http.ResponseWriter, r *http.Request, f *os.File, name string) {
	st, err := f.Stat()
	if err != nil {
		jerr(w, 404, "file missing")
		return
	}
	serveAttachment(w, r, f, st.ModTime(), name)
}

// serveSnapshot serves one reader of a verified snapshot as an attachment.
func serveSnapshot(w http.ResponseWriter, r *http.Request, snap *snapshotReader, name string) {
	serveAttachment(w, r, snap, snap.ModTime(), name)
}

func serveAttachment(w http.ResponseWriter, r *http.Request, content io.ReadSeeker, modTime time.Time, name string) {
	if _, ok := w.(*idleResponseWriter); !ok {
		w = &idleResponseWriter{ResponseWriter: w, controller: http.NewResponseController(w), timeout: 60 * time.Second}
	}
	controller := http.NewResponseController(w)
	defer func() {
		// Flush pending buffered bytes under the final deadline before releasing
		// the snapshot slot. net/http resets deadlines for the next request.
		_ = controller.Flush()
	}()
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename*=UTF-8''%s`, urlEscape(name)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, modTime, content)
}

func urlEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func safeName(n string) string {
	n = filepath.Base(strings.TrimSpace(n))
	n = strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`"/\:*?<>|`, r) {
			return '_'
		}
		return r
	}, n)
	if n == "." || n == ".." || n == string(filepath.Separator) {
		return ""
	}
	return n
}

// ---------- owner management ----------

func (s *Server) listShares(w http.ResponseWriter, userID int64) {
	recs, err := s.St.Repos().Shares().ListOwned(context.Background(), userID)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	out := []*Share{}
	for _, rec := range recs {
		sh, err := shareFromRecord(rec, nil)
		if err == nil {
			out = append(out, sh)
		}
	}
	jout(w, 200, out)
}

func (s *Server) myShares(w http.ResponseWriter, r *http.Request) {
	s.listShares(w, s.ctxUser(r).ID)
}

// ownedShare returns the share only to its uploader. Administrators have no
// access to other users' shares, files or download history.
func (s *Server) ownedShare(w http.ResponseWriter, r *http.Request) *Share {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	sh, err := s.shareByID(id)
	u := s.ctxUser(r)
	if err != nil || !sh.userID.Valid || sh.userID.Int64 != u.ID {
		if err == nil {
			s.auditAccessDenied(r, catShare, "share#"+strconv.FormatInt(id, 10), "share belongs to another account")
		}
		jerr(w, 404, "share not found")
		return nil
	}
	return sh
}

func (s *Server) shareDownloads(w http.ResponseWriter, r *http.Request) {
	sh := s.ownedShare(w, r)
	if sh == nil {
		return
	}
	limit, offset := 50, 0
	for key, dest := range map[string]*int{"limit": &limit, "offset": &offset} {
		if value := r.URL.Query().Get(key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || (key == "limit" && n == 0) {
				jerr(w, 400, "invalid pagination")
				return
			}
			*dest = n
		}
	}
	if limit > 100 {
		limit = 100
	}
	total, err := s.St.Repos().Downloads().Count(context.Background(), sh.ID)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	files := s.shareFiles(sh.ID)
	downloads, err := s.St.Repos().Downloads().List(context.Background(), sh.ID, limit, offset)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	out := []map[string]any{}
	wholeName := safeName(sh.Name)
	if wholeName == "" {
		wholeName = "share"
	}
	wholeName += ".zip"
	if len(files) == 1 {
		wholeName = files[0].Name
	}
	for _, d := range downloads {
		id, name, at := d.ID, d.FileName, d.CreatedAt
		var fid any
		if d.FileID != nil {
			fid = *d.FileID
		} else {
			name = wholeName
		}
		out = append(out, map[string]any{"id": id, "file_id": fid, "file_name": name, "created_at": at})
	}
	jout(w, 200, map[string]any{"downloads": out, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) expireShare(w http.ResponseWriter, r *http.Request) {
	sh := s.ownedShare(w, r)
	if sh == nil {
		return
	}
	s.St.Repos().Shares().Expire(context.Background(), sh.ID, time.Now())
	s.logShare(r, "share_expired_manual", sh.ID, "")
	jout(w, 200, map[string]any{"ok": true})
}

func (s *Server) extendShare(w http.ResponseWriter, r *http.Request) {
	sh := s.ownedShare(w, r)
	if sh == nil {
		return
	}
	var b struct{ Days int }
	decode(r, &b)
	if b.Days <= 0 {
		jerr(w, 400, "days required")
		return
	}
	max := s.St.SettingInt("max_expiry_time", 30)
	if !s.ctxUser(r).Admin && max > 0 && b.Days > max {
		jerr(w, 400, fmt.Sprintf("max %d days", max))
		return
	}
	base := time.Now()
	if sh.ExpiresAt != nil && sh.ExpiresAt.After(base) {
		base = *sh.ExpiresAt
	}
	s.St.Repos().Shares().Extend(context.Background(), sh.ID, base.AddDate(0, 0, b.Days))
	s.logShare(r, "share_extended", sh.ID, strconv.Itoa(b.Days)+" days")
	jout(w, 200, map[string]any{"ok": true})
}

// setShareExpiry sets an absolute expiry (or none) after creation. Shortening
// and extending are both allowed; an expired share is reactivated only while
// its files still exist.
func (s *Server) setShareExpiry(w http.ResponseWriter, r *http.Request) {
	sh := s.ownedShare(w, r)
	if sh == nil {
		return
	}
	var b struct {
		ExpiresAt *time.Time `json:"expires_at"`
		Never     bool       `json:"never"`
	}
	if err := decode(r, &b); err != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if b.Never == (b.ExpiresAt != nil) {
		jerr(w, 400, "provide either expires_at or never")
		return
	}
	admin := s.ctxUser(r).Admin // exemption from the maximum expiry applies to own shares only
	max := s.St.SettingInt("max_expiry_time", 30)
	now := time.Now()
	var exp any
	var expAt *time.Time
	if b.Never {
		if !admin && max > 0 {
			jerr(w, 400, fmt.Sprintf("max %d days", max))
			return
		}
	} else {
		if !b.ExpiresAt.After(now) {
			jerr(w, 400, "expiry must be in the future")
			return
		}
		if !admin && max > 0 && b.ExpiresAt.After(now.AddDate(0, 0, max)) {
			jerr(w, 400, fmt.Sprintf("max %d days", max))
			return
		}
		at := b.ExpiresAt.UTC()
		exp, expAt = at, &at
	}
	if sh.Expired {
		if !shareDirExists(s.St.DataDir, sh.LongID) {
			jerr(w, 409, "share files were already cleaned up")
			return
		}
	}
	n, err := s.St.Repos().Shares().SetExpiry(context.Background(), sh.ID, s.ctxUser(r).ID, expAt)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if n != 1 {
		jerr(w, 404, "share not found")
		return
	}
	s.logShare(r, "share_expiry_changed", sh.ID, "")
	jout(w, 200, map[string]any{"ok": true, "expires_at": exp})
}

func (s *Server) setDownloadLimit(w http.ResponseWriter, r *http.Request) {
	sh := s.ownedShare(w, r)
	if sh == nil {
		return
	}
	var b struct{ Limit *int64 }
	decode(r, &b)
	if b.Limit != nil && *b.Limit <= 0 {
		b.Limit = nil
	}
	// Maintenance marks limit-exhausted shares expired without changing their future expiry.
	// Revive only that case, not manually or time-expired shares.
	s.St.Repos().Shares().SetDownloadLimit(context.Background(), sh.ID, b.Limit, time.Now())
	s.logShare(r, "share_limit_changed", sh.ID, "")
	jout(w, 200, map[string]any{"ok": true})
}

// editShare applies a partial update. Absent fields stay unchanged; wrong
// types, unknown fields and conflicting options are rejected with 400.
func (s *Server) editShare(w http.ResponseWriter, r *http.Request) {
	sh := s.ownedShare(w, r)
	if sh == nil {
		return
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&raw); err != nil || raw == nil {
		jerr(w, 400, "invalid request")
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		jerr(w, 400, "invalid request")
		return
	}
	bad := func(msg string) { jerr(w, 400, msg) }
	for k := range raw {
		switch k {
		case "name", "description", "download_limit", "password", "remove_password":
		default:
			bad("unknown field: " + k)
			return
		}
	}
	// field parses a present, non-null value strictly into dst.
	field := func(k string, dst any) (present, ok bool) {
		v, has := raw[k]
		if !has {
			return false, true
		}
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			bad(k + " must not be null")
			return true, false
		}
		if err := json.Unmarshal(v, dst); err != nil {
			bad(k + " has an invalid type")
			return true, false
		}
		return true, true
	}
	var name, desc, pw string
	var limit float64
	var removePW bool
	hasName, ok := field("name", &name)
	if !ok {
		return
	}
	hasDesc, ok := field("description", &desc)
	if !ok {
		return
	}
	hasLimit, ok := field("download_limit", &limit)
	if !ok {
		return
	}
	hasPW, ok := field("password", &pw)
	if !ok {
		return
	}
	_, ok = field("remove_password", &removePW)
	if !ok {
		return
	}
	var edit ports.ShareEdit
	if hasName {
		name = strings.TrimSpace(name)
		if hasFormatRune(name) {
			bad("name contains invalid characters")
			return
		}
		if n := utf8.RuneCountInString(name); n < 1 || n > 120 {
			bad("name must be 1 to 120 characters")
			return
		}
		edit.Name = &name
	}
	if hasDesc {
		if utf8.RuneCountInString(desc) > 2000 {
			bad("description must not exceed 2000 characters")
			return
		}
		edit.Description = &desc
	}
	if hasLimit {
		if limit < 0 || limit != float64(int64(limit)) || limit > 1<<53 {
			bad("download_limit must be a whole number, 0 or greater")
			return
		}
		var lim *int64
		if limit > 0 {
			l := int64(limit)
			lim = &l
		}
		// Same revive rule as setDownloadLimit: only a share that maintenance
		// expired because its limit was exhausted is reactivated.
		edit.SetDownloadLimit, edit.DownloadLimit, edit.Now = true, lim, time.Now()
	}
	if hasPW && removePW {
		bad("password and remove_password are mutually exclusive")
		return
	}
	if hasPW || removePW {
		policy, err := s.loadSharePolicy()
		if err != nil {
			jerr(w, 500, "share password policy unavailable")
			return
		}
		if removePW {
			if policy.Required {
				bad("a share password is required")
				return
			}
			none := ""
			edit.PasswordHash = &none
		} else {
			if pw == "" {
				bad("password must not be empty; use remove_password to remove it")
				return
			}
			if err := validateSharePassword(policy, pw); err != nil {
				bad(err.Error())
				return
			}
			h, err := bcrypt.GenerateFromPassword([]byte(pw), hashCost)
			if err != nil {
				bad("share password must not exceed 72 bytes")
				return
			}
			hash := string(h)
			edit.PasswordHash = &hash
		}
	}
	if !edit.Empty() {
		u := s.ctxUser(r)
		n, err := s.St.Repos().Shares().Edit(context.Background(), sh.ID, u.ID, edit)
		if err != nil {
			jerr(w, 500, "database error")
			return
		}
		if n != 1 {
			jerr(w, 404, "share not found")
			return
		}
		// Field names only, never values.
		var changed []string
		if hasName {
			changed = append(changed, "name")
		}
		if hasDesc {
			changed = append(changed, "description")
		}
		if hasLimit {
			changed = append(changed, "download_limit")
		}
		if hasPW {
			changed = append(changed, "password_set")
		}
		if removePW {
			changed = append(changed, "password_removed")
		}
		s.logShare(r, "share_edited", sh.ID, strings.Join(changed, ","))
	}
	jout(w, 200, map[string]any{"ok": true})
}

func (s *Server) deleteShare(w http.ResponseWriter, r *http.Request) {
	sh := s.ownedShare(w, r)
	if sh == nil {
		return
	}
	if _, err := s.removeShare(sh.ID); err != nil {
		jerr(w, 503, "share cleanup failed")
		return
	}
	s.logShare(r, "share_deleted", sh.ID, "")
	jout(w, 200, map[string]any{"ok": true})
}

func (s *Server) pruneMine(w http.ResponseWriter, r *http.Request) {
	ids, _ := s.St.Repos().Shares().PrunableIDs(context.Background(), s.ctxUser(r).ID, time.Now())
	removed := 0
	for _, id := range ids {
		ok, err := s.removeShareIf(id, ports.ShareFilter{Kind: ports.SharePrunableByOwner, UserID: s.ctxUser(r).ID, At: time.Now()})
		if err != nil {
			jerr(w, 503, "share cleanup failed")
			return
		}
		if ok {
			removed++
			s.logShare(r, "share_deleted", id, "prune")
		}
	}
	jout(w, 200, map[string]any{"removed": removed})
}

// removeShare serializes removal with quota admission and other removals in the
// database. Storage stays charged until filesystem cleanup has succeeded.
func (s *Server) removeShare(id int64) (bool, error) {
	return s.removeShareIf(id, ports.ShareFilter{Kind: ports.AnyShare})
}

// Recheck discovery predicates under the write lock so an extended share is
// not removed from a stale cleanup snapshot.
func (s *Server) removeShareIf(id int64, cond ports.ShareFilter) (bool, error) {
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err := tx.Shares().Lock(ctx, id); err != nil {
		return false, err
	}
	lid, err := tx.Shares().LongIDIf(ctx, id, cond)
	if err != nil {
		if errors.Is(err, ports.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if lid == "" {
		return false, fmt.Errorf("share storage metadata unavailable")
	}
	// Pending append sessions go away with the share (ON DELETE CASCADE); remember
	// their staging dirs and remove them after the commit.
	sessions, err := tx.Uploads().IDsForShare(ctx, id)
	if err != nil {
		return false, err
	}
	// Only ever remove a validated share directory; a share record with a malformed
	// long ID (e.g. from a tampered import) is deleted without touching the disk.
	// The directory is moved aside inside the transaction (fast) and deleted
	// after the commit, so a share with thousands of files never holds the only
	// database connection while the disk works.
	var tomb, dir string
	if d, derr := store.ShareDir(s.St.DataDir, lid); derr == nil {
		dir = d
		tomb = filepath.Join(filepath.Dir(dir), ".deleting-"+randHex(8)) // same directory, so same mount
		if err := os.Rename(dir, tomb); err != nil {
			if !os.IsNotExist(err) {
				return false, err
			}
			tomb = ""
		}
	}
	restore := func() {
		if tomb != "" {
			os.Rename(tomb, dir)
		}
	}
	n, err := tx.Shares().Delete(ctx, id)
	if err != nil {
		restore()
		return false, err
	}
	if err := tx.Commit(); err != nil {
		restore()
		return false, err
	}
	if tomb != "" {
		os.RemoveAll(tomb)
	}
	for _, sid := range sessions {
		os.RemoveAll(s.uploadDir(sid))
	}
	s.kickDeletes() // remote objects of the share's files (queued by the delete)
	return n == 1, nil
}

// wildcardPath returns the decoded `*` route segment. chi serves the raw
// (still percent-encoded) path whenever the client's encoding differs from Go's
// canonical form, e.g. literal parentheses as produced by encodeURIComponent,
// so such names ("photo (1).jpg") would otherwise never match.
func wildcardPath(r *http.Request) string {
	p := chi.URLParam(r, "*")
	if r.URL.RawPath != "" {
		if decoded, err := url.PathUnescape(p); err == nil {
			p = decoded
		}
	}
	return p
}
