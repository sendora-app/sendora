// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sendora-app/sendora/internal/store"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultImportMaxBytes  = int64(4) << 30
	defaultImportTTL       = 15 * time.Minute
	importFilePrefix       = ".import-"
	importConfirmWord      = "IMPORT"
	msgImportNeedsPassword = "applying an import requires your current password; set a local password under your profile first"
	// Slack for multipart framing and the small key parts around the file.
	importBodySlack = int64(64) << 10
)

// preparedImport is a validated, re-keyed copy waiting for confirmation.
type preparedImport struct {
	token   string
	path    string
	expires time.Time
	summary importSummary
}

type importSummary struct {
	Users         int64    `json:"users"`
	Admins        int64    `json:"admins"`
	Shares        int64    `json:"shares"`
	Files         int64    `json:"files"`
	MissingFiles  int64    `json:"missing_files"`
	MissingShares int64    `json:"missing_shares"`
	Warnings      []string `json:"warnings"`
}

func (s *Server) importLimit() int64 {
	if s.importMaxBytes > 0 {
		return s.importMaxBytes
	}
	return defaultImportMaxBytes
}

func (s *Server) importLifetime() time.Duration {
	if s.importTTL > 0 {
		return s.importTTL
	}
	return defaultImportTTL
}

func (s *Server) backupsDir() string { return filepath.Join(s.St.DataDir, "backups") }

// maintenanceMode answers 503 for the API while a database import is being
// applied. /api/health and everything outside /api (static assets) stay up.
func (s *Server) maintenanceMode(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/backups/import/apply" && s.importApplying.Load() {
			jerr(w, 409, "an import is already being applied")
			return
		}
		if s.maintenance.Load() && strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/health" {
			w.Header().Set("Retry-After", "5")
			jerr(w, 503, "the server is applying a database import and will restart shortly")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// discardPreparedLocked removes the prepared copy. Caller holds importMu.
func (s *Server) discardPreparedLocked() {
	if s.imp != nil {
		store.RemoveImportFiles(s.imp.path)
		s.imp = nil
	}
}

// cleanImportFiles expires an outdated preparation and removes stray
// .import-* files (crashes, failed uploads). It never touches a running prepare
// or apply, nor the currently prepared copy.
func (s *Server) cleanImportFiles() {
	s.importMu.Lock()
	defer s.importMu.Unlock()
	if s.imp != nil && !time.Now().Before(s.imp.expires) {
		s.discardPreparedLocked()
	}
	if s.importPreparing.Load() || s.importApplying.Load() {
		return
	}
	keep := ""
	if s.imp != nil {
		keep = filepath.Base(s.imp.path)
	}
	ents, err := os.ReadDir(s.backupsDir())
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, importFilePrefix) || e.IsDir() || (keep != "" && strings.HasPrefix(n, keep)) {
			continue
		}
		os.Remove(filepath.Join(s.backupsDir(), n))
	}
}

func importSafeCounts(sum *store.ImportSummary) string {
	return fmt.Sprintf("users=%d admins=%d shares=%d files=%d", sum.Users, sum.Admins, sum.Shares, sum.Files)
}

// readSmallPart reads a short form field; longer values are rejected.
func readSmallPart(p *multipart.Part, max int64) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(p, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, false
	}
	return b, true
}

// prepareImport streams an uploaded database, validates and re-keys it, and
// reports what applying it would do. Nothing live is touched.
// msgImportMultiTenant: database import is not available to tenants.
const msgImportMultiTenant = "database import is not available in multi-tenant mode; ask the platform operator to restore a backup"

func (s *Server) prepareImport(w http.ResponseWriter, r *http.Request) {
	me := s.ctxUser(r)
	if s.tenant != nil {
		// The swap restarts the whole process; a tenant is restored by the
		// platform operator instead (docs/MULTI-TENANT.md).
		jerr(w, 409, msgImportMultiTenant)
		return
	}
	if !s.St.IsEncrypted() {
		jerr(w, 409, "database import requires an encrypted database")
		return
	}
	limit := s.importLimit()
	if r.ContentLength > limit+importBodySlack {
		jerr(w, 413, "file too large")
		return
	}
	// Claim the single preparation slot and discard any earlier preparation.
	s.importMu.Lock()
	if s.importApplying.Load() || s.maintenance.Load() {
		s.importMu.Unlock()
		jerr(w, 409, "an import is being applied")
		return
	}
	if !s.importPreparing.CompareAndSwap(false, true) {
		s.importMu.Unlock()
		jerr(w, 409, "another import is already being prepared")
		return
	}
	s.discardPreparedLocked()
	s.importMu.Unlock()
	defer s.importPreparing.Store(false)

	token := randHex(32)
	src := filepath.Join(s.backupsDir(), importFilePrefix+randHex(8)+".src")
	dest := filepath.Join(s.backupsDir(), importFilePrefix+token+".new")
	// Only a successfully registered copy survives; every other path cleans up.
	keepDest := false
	defer func() {
		store.RemoveImportFiles(src)
		if !keepDest {
			store.RemoveImportFiles(dest)
		}
	}()

	r.Body = http.MaxBytesReader(w, r.Body, limit+importBodySlack)
	mr, err := r.MultipartReader()
	if err != nil {
		jerr(w, 400, "multipart/form-data upload required")
		return
	}
	var key []byte
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	haveKey, gotFile := false, false
	for !gotFile {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.importBodyError(w, err)
			return
		}
		switch part.FormName() {
		case "key_hex", "key_file":
			if haveKey {
				jerr(w, 400, "provide either key_hex or key_file, once")
				return
			}
			haveKey = true
			if part.FormName() == "key_hex" {
				raw, ok := readSmallPart(part, 256)
				v := strings.TrimSpace(string(raw))
				b, derr := hex.DecodeString(v)
				if !ok || len(v) != 64 || derr != nil {
					jerr(w, 400, "key_hex must be exactly 64 hexadecimal characters")
					return
				}
				key = b
			} else {
				raw, ok := readSmallPart(part, 32)
				if !ok || len(raw) != 32 {
					jerr(w, 400, "key_file must contain exactly 32 raw bytes")
					return
				}
				key = raw
			}
		case "file":
			gotFile = true
			if !s.receiveImportFile(w, part, src, limit) {
				return
			}
		default:
			jerr(w, 400, "unexpected form field")
			return
		}
	}
	if !gotFile {
		jerr(w, 400, "database file required")
		return
	}
	// Anything after the file (e.g. a key sent too late) is refused explicitly.
	if extra, err := mr.NextPart(); err == nil {
		extra.Close()
		jerr(w, 400, "key fields must be sent before the file")
		return
	} else if err != io.EOF {
		s.importBodyError(w, err)
		return
	}

	hdr := make([]byte, 16)
	f, err := os.Open(src)
	if err != nil {
		jerr(w, 500, "import preparation failed")
		return
	}
	n, _ := io.ReadFull(f, hdr)
	f.Close()
	if n == 0 {
		jerr(w, 400, "the uploaded file is empty")
		return
	}
	if n == 16 && string(hdr) == "SQLite format 3\x00" {
		jerr(w, 400, "unencrypted SQLite files are not accepted; upload an encrypted Sendora backup")
		return
	}

	err = s.St.ImportDatabase(src, dest, key)
	store.RemoveImportFiles(src)
	if err != nil {
		s.importFail(w, err)
		return
	}
	sum, err := s.St.PrepareImportedCopy(dest)
	if err != nil {
		s.importFail(w, err)
		return
	}
	out := importSummary{Users: sum.Users, Admins: sum.Admins, Shares: sum.Shares, Files: sum.Files}
	missingShares := map[int64]bool{}
	scanErr := s.St.ScanImportedCopy(dest, func(shareID int64, disk string) {
		if !filepath.IsAbs(disk) {
			out.MissingFiles++
			missingShares[shareID] = true
			return
		}
		if _, err := os.Stat(disk); err != nil {
			out.MissingFiles++
			missingShares[shareID] = true
		}
	})
	if scanErr != nil {
		s.importFail(w, scanErr)
		return
	}
	out.MissingShares = int64(len(missingShares))
	out.Warnings = []string{
		"Uploaded files are not part of a database backup; files on disk are not touched or restored.",
		"All users must sign in again after the import: sessions, reset codes and the signing secret are cleared.",
		"Accounts, shares and settings from the import replace the current ones.",
	}
	if out.Files > 0 {
		out.Warnings = append(out.Warnings, "File locations are rebased to this server's data directory: copy each share folder to DATA_DIR/shares/<share id>/ for downloads to work.")
	}
	if out.MissingFiles > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d file(s) in %d share(s) are missing on disk and cannot be downloaded after the import.", out.MissingFiles, out.MissingShares))
	}
	if sum.DroppedUploads > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d unfinished upload session(s) in the import are discarded.", sum.DroppedUploads))
	}
	ttl := s.importLifetime()
	s.importMu.Lock()
	s.imp = &preparedImport{token: token, path: dest, expires: time.Now().Add(ttl), summary: out}
	s.importMu.Unlock()
	keepDest = true
	s.logEvent(me.ID, me.Username, "db_import_prepared", "", importSafeCounts(sum))
	jout(w, 200, map[string]any{"token": token, "expires_in": int(ttl.Seconds()), "summary": out})
}

func (s *Server) importBodyError(w http.ResponseWriter, err error) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		jerr(w, 413, "file too large")
		return
	}
	jerr(w, 400, "the upload was invalid or interrupted")
}

func (s *Server) importFail(w http.ResponseWriter, err error) {
	var ie *store.ImportError
	if errors.As(err, &ie) {
		jerr(w, 400, ie.Msg)
		return
	}
	log.Printf("database import preparation failed: %v", err)
	jerr(w, 500, "import preparation failed")
}

// receiveImportFile streams the file part to a 0600 temp file, enforcing the limit.
func (s *Server) receiveImportFile(w http.ResponseWriter, part *multipart.Part, dst string, limit int64) bool {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		jerr(w, 500, "import preparation failed")
		return false
	}
	n, err := io.Copy(f, io.LimitReader(part, limit+1))
	cerr := f.Close()
	if err != nil {
		s.importBodyError(w, err)
		return false
	}
	if n > limit {
		jerr(w, 413, "file too large")
		return false
	}
	if cerr != nil {
		jerr(w, 500, "import preparation failed")
		return false
	}
	return true
}

// applyImport confirms a prepared import: maintenance mode, pre-import backup,
// 202, then the process swaps the database and re-executes itself.
func (s *Server) applyImport(w http.ResponseWriter, r *http.Request) {
	me := s.ctxUser(r)
	if s.tenant != nil {
		jerr(w, 409, msgImportMultiTenant)
		return
	}
	var b struct {
		Token    string `json:"token"`
		Confirm  string `json:"confirm"`
		Password string `json:"password"`
	}
	if err := decode(r, &b); err != nil {
		jerr(w, 400, "invalid request")
		return
	}
	if !s.St.IsEncrypted() {
		jerr(w, 409, "database import requires an encrypted database")
		return
	}
	s.importMu.Lock()
	if s.importApplying.Load() {
		s.importMu.Unlock()
		jerr(w, 409, "an import is already being applied")
		return
	}
	if s.importPreparing.Load() {
		s.importMu.Unlock()
		jerr(w, 409, "an import is being prepared")
		return
	}
	p := s.imp
	if p != nil && !time.Now().Before(p.expires) {
		s.discardPreparedLocked()
		p = nil
	}
	if p == nil || subtle.ConstantTimeCompare([]byte(b.Token), []byte(p.token)) != 1 {
		s.importMu.Unlock()
		jerr(w, 404, "import not found or expired; prepare it again")
		return
	}
	if b.Confirm != importConfirmWord {
		s.importMu.Unlock()
		jerr(w, 400, `type "IMPORT" to confirm`)
		return
	}
	if me.passwordHash == "" {
		// Replacing the whole database needs fresh proof of identity, and an
		// account that only signs in through an external provider has none to give.
		s.importMu.Unlock()
		jerr(w, 403, msgImportNeedsPassword)
		return
	}
	if me.passwordHash != "" {
		if b.Password == "" {
			s.importMu.Unlock()
			jerr(w, 400, "your current password is required")
			return
		}
		if !s.allowRequest(fmt.Sprintf("import-password:%d", me.ID), 10, 15*time.Minute) {
			s.importMu.Unlock()
			w.Header().Set("Retry-After", "60")
			jerr(w, 429, "too many attempts")
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(me.passwordHash), []byte(b.Password)) != nil {
			s.importMu.Unlock()
			jerr(w, 401, "incorrect password")
			return
		}
	}
	s.importApplying.Store(true)
	s.maintenance.Store(true)
	s.importMu.Unlock()

	name, err := s.makeBackupAs("sendora-preimport-")
	if err != nil {
		log.Printf("pre-import backup failed: %v", err)
		s.maintenance.Store(false)
		s.importApplying.Store(false)
		jerr(w, 500, "the pre-import backup failed; nothing was changed")
		return
	}
	s.importMu.Lock()
	s.imp = nil // single use
	s.importMu.Unlock()
	s.logEvent(me.ID, me.Username, "db_import_applied", name, fmt.Sprintf("users=%d admins=%d shares=%d files=%d", p.summary.Users, p.summary.Admins, p.summary.Shares, p.summary.Files))
	jout(w, 202, map[string]any{"ok": true, "backup": name, "restarting": true})
	_ = http.NewResponseController(w).Flush()
	go s.runImportSwap(p)
}

// runImportSwap performs the controlled stop: servers and jobs are stopped, the
// database is closed, files are swapped and the process re-executes itself. It
// never returns normally in production (exec replaces the process; failure exits).
func (s *Server) runImportSwap(p *preparedImport) {
	defer close(s.importDone)
	if s.importStop != nil {
		s.importStop() // GracefulStop in production: also records system_stop
	}
	// The stop is recorded before the log is carried, so the record is part of
	// the carried trail (a no-op when the stopper already wrote it).
	s.recordStop()
	// The audit trail of this instance survives the import: it replaces the
	// imported file's own, so a backup can neither erase nor roll back records.
	if err := s.St.CarryAuditLog(p.path); err != nil {
		log.Printf("audit log could not be carried into the import, previous database kept: %v", err)
		s.importExit(1)
		return
	}
	if err := s.St.Close(); err != nil {
		log.Printf("database close before import swap: %v", err)
	}
	if err := store.SwapImportedDatabase(s.St.DataDir, p.path); err != nil {
		log.Printf("database import swap failed, previous database kept: %v", err)
		s.importExit(1)
		return
	}
	log.Printf("database import applied; restarting")
	if err := s.importExec(); err != nil {
		log.Printf("restart after database import failed: %v", err)
		s.importExit(1)
	}
}

// SetImportStopper registers how main stops the HTTP server and background jobs
// before the database is swapped.
func (s *Server) SetImportStopper(stop func()) { s.importStop = stop }

// AwaitImport blocks main while an applied import is swapping and re-executing,
// so the process is not terminated by the HTTP server having been shut down. It
// reports whether an import was being applied (the import owns the store then).
func (s *Server) AwaitImport() bool {
	if !s.importApplying.Load() {
		return false
	}
	select {
	case <-s.importDone:
	case <-time.After(5 * time.Minute):
	}
	return true
}

// execSelf replaces the process image; sockets are close-on-exec and the key is
// read again from SENDORA_DB_KEY_FILE at start.
func execSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
