// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Personal data: a self-service export (GDPR art. 15/20) and erasure of an
// account (art. 17), by the user or by an administrator.
//
// Erasure deletes the account's shares and files, upload sessions, invites
// (and their guest accounts), sessions, reset and verification codes, second
// factors, linked sign-ins and sign-in fingerprints, and pseudonymises the
// account row: username "erased-<id>", name and email cleared, no password, no
// roles. The row stays so that references (ids) keep resolving; it can never
// sign in again.
//
// Legitimate-interest exception: audit records written while the account
// existed keep their actor_name (the former username) and are not rewritten.
// The audit log is tamper-evident (hash chain) and serves the security of the
// service and the accountability of administrators (GDPR art. 6(1)(f), and
// art. 17(3)(e) for the establishment or defence of legal claims). Those
// records disappear with the normal retention (audit_retention_days, at most
// 365 days). See docs/THREAT-MODEL.md.

const (
	msgEraseLastAdmin  = "the last administrator cannot be erased; make another account administrator first"
	msgEraseSelfAdmin  = "you cannot erase your own account here; use Profile -> Delete my account"
	msgEraseRecent     = "sign in again to delete your account"
	msgAlreadyErased   = "this account was erased"
	exportAuditMaxRows = 100000
)

// ---------- export ----------

// exportMyData: GET /api/users/me/export. JSON with the caller's own data. No
// secrets (password hashes, TOTP secrets, recovery codes, key material, tokens)
// and no file contents. Recorded as personal_data_exported before it is served.
func (s *Server) exportMyData(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	if u.IsGuest {
		jerr(w, 403, "guest session is upload-only")
		return
	}
	s.fillMFA(u)
	usage, _ := s.St.UserStorageUsage(u.ID)
	termsVersion, termsAtPtr, _ := s.St.Repos().PersonalData().Terms(context.Background(), u.ID)
	termsAt := nullTimeOf(termsAtPtr)
	out := map[string]any{
		"format":      "sendora-personal-data-1",
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"application": s.St.Setting("application_name"),
		"profile": map[string]any{
			"id": u.ID, "username": u.Username, "name": u.Name, "email": u.Email, "email_verified": u.EmailVerified,
			"created_at": u.CreatedAt, "administrator": u.Admin, "auditor": u.Auditor, "has_password": u.passwordHash != "",
			"must_change_password": u.MustChangePassword, "password_changed_at": u.PasswordChangedAt,
			"password_rotation_exempt": u.PasswordRotationExempt,
		},
		"settings": map[string]any{
			"email_language": u.Language, "ui_language": u.UILanguage, "mfa_policy": u.MFAPolicy,
			"quota_bytes": u.QuotaBytes, "quota_inherits_default": u.QuotaInheritsDefault, "storage": usage,
			"terms_accepted_version": termsVersion, "terms_accepted_at": nullTime(termsAt),
		},
	}
	f := s.loadFactors(u.ID)
	mfa := map[string]any{"enabled": u.MFAEnabled, "recovery_codes_remaining": f.Recovery, "security_keys": s.webauthnCredentials(u.ID)}
	if totpCreated, err := s.St.Repos().PersonalData().TOTPCreated(context.Background(), u.ID); err == nil {
		mfa["authenticator_app"] = map[string]any{"set_up": true, "created_at": nullTime(nullTimeOf(totpCreated))}
	} else {
		mfa["authenticator_app"] = map[string]any{"set_up": false}
	}
	out["mfa"] = mfa
	pd := s.St.Repos().PersonalData()
	for _, sec := range []ports.ExportSection{ports.ExportLinkedLogins, ports.ExportShares, ports.ExportShareFiles,
		// Downloads of the caller's shares, as the owner sees them (no recipient addresses).
		ports.ExportDownloadHistory, ports.ExportInvites, ports.ExportSessions, ports.ExportAuditRecords} {
		out[string(sec)] = pd.Section(context.Background(), sec, u.ID, exportAuditMaxRows)
	}
	w.Header().Set("Content-Disposition", `attachment; filename="sendora-my-data-`+time.Now().UTC().Format("20060102")+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	jout(w, 200, out)
}

func nullTime(t sql.NullTime) any {
	if !t.Valid {
		return nil
	}
	return t.Time.UTC().Format(time.RFC3339)
}

// ---------- erasure ----------

// refuseErased answers 409 for an account that was erased. It has answered
// when it returns true.
func (s *Server) refuseErased(w http.ResponseWriter, id int64) bool {
	if erased, err := s.St.Repos().Users().ErasedAt(context.Background(), id); err == nil && erased != nil {
		jerr(w, 409, msgAlreadyErased)
		return true
	}
	return false
}

// lastAdmin reports whether id is the only remaining administrator.
func (s *Server) lastAdmin(id int64) bool {
	if admin, err := s.St.Repos().Users().IsAdmin(context.Background(), id); err != nil || !admin {
		return false
	}
	others, _ := s.St.Repos().Users().CountOtherUnerasedAdmins(context.Background(), id)
	return others == 0
}

// eraseAccount deletes the account's content and pseudonymises the row. It
// writes the error response and returns false on failure.
func (s *Server) eraseAccount(w http.ResponseWriter, id int64) bool {
	unlock := s.stripe(&s.loginLocks, strconv.FormatInt(id, 10))
	defer unlock()
	unlockUploads := s.LockUserUploads(id)
	defer unlockUploads()
	tx, err := s.St.Repos().Begin(context.Background())
	if err != nil {
		jerr(w, 500, "erasure failed")
		return false
	}
	defer tx.Rollback()
	n, err := tx.Users().LockForErasure(context.Background(), id)
	if err != nil {
		jerr(w, 500, "erasure failed")
		return false
	}
	if n != 1 {
		jerr(w, 404, "not found")
		return false
	}
	var dirs []string
	uploads, err := tx.Users().OwnedUploadIDs(context.Background(), id)
	if err != nil {
		jerr(w, 500, "erasure failed")
		return false
	}
	for _, name := range uploads {
		dirs = append(dirs, s.uploadDir(name))
	}
	shares, err := tx.Users().OwnedShareLongIDs(context.Background(), id)
	if err != nil {
		jerr(w, 500, "erasure failed")
		return false
	}
	for _, name := range shares {
		if dir, derr := store.ShareDir(s.St.DataDir, name); derr == nil {
			dirs = append(dirs, dir)
		}
	}
	if err := tx.Users().EraseWithOwnedData(context.Background(), id); err != nil {
		jerr(w, 500, "erasure failed")
		return false
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "erasure failed")
		return false
	}
	s.kickDeletes() // remote objects of the erased shares (queued by the delete)
	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			jerr(w, 500, "account erased but file cleanup failed")
			return false
		}
	}
	return true
}

// eraseUser: POST /api/users/{id}/erase (administrators; critical audited
// user_erased, needs a step-up).
func (s *Server) eraseUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		jerr(w, 404, "not found")
		return
	}
	me := s.ctxUser(r)
	if id == me.ID {
		jerr(w, 400, msgEraseSelfAdmin)
		return
	}
	target, err := s.userByID(id)
	if err != nil || target.IsGuest {
		jerr(w, 404, "not found")
		return
	}
	if s.refuseErased(w, id) {
		return
	}
	if s.lastAdmin(id) {
		jerr(w, 409, msgEraseLastAdmin)
		return
	}
	if s.refuseLastExternalAdmin(w, id, 0) {
		return
	}
	label := s.userTarget(id) // the former name, before it is replaced
	if !s.eraseAccount(w, id) {
		return
	}
	s.logEvent(me.ID, me.Username, "user_erased", label, "by administrator")
	jout(w, 200, map[string]any{"ok": true})
}

// eraseMe: POST /api/users/me/erase {password}. Accounts with a password
// confirm with it; accounts that sign in only through a provider need a recent
// sign-in. The last administrator cannot erase itself.
func (s *Server) eraseMe(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	if u.IsGuest {
		jerr(w, 403, "guest session is upload-only")
		return
	}
	var b struct {
		Password string `json:"password"`
	}
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	if u.passwordHash != "" {
		if s.stepUpLocked(w, u) {
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(u.passwordHash), []byte(b.Password)) != nil {
			s.stepUpFailed(w, u)
			jerr(w, 400, "current password incorrect")
			return
		}
	} else if time.Since(s.requestAuthTime(r)) > recentSignIn {
		jerr(w, 403, msgEraseRecent)
		return
	}
	if s.lastAdmin(u.ID) {
		jerr(w, 409, msgEraseLastAdmin)
		return
	}
	if s.refuseLastExternalAdmin(w, u.ID, 0) {
		return
	}
	label := s.userTarget(u.ID)
	if !s.eraseAccount(w, u.ID) {
		return
	}
	s.logEvent(u.ID, u.Username, "user_erased", label, "self-service")
	s.clearRefreshCookie(w, r)
	jout(w, 200, map[string]any{"ok": true})
}

// resetTokenIdentity returns the username and email of the account a valid
// password reset token belongs to (nothing for an unknown token), so the new
// password can be compared with them.
func (s *Server) resetTokenIdentity(token string) []string {
	name, email, err := s.St.Repos().PasswordResets().Identity(context.Background(), hashToken(token), time.Now())
	if err != nil {
		return nil
	}
	return []string{name, email}
}
