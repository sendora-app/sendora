// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Account deactivation: a reversible alternative to deleting an account. While
// an account is disabled it cannot sign in (password, second factor, provider),
// its sessions are gone and its access tokens are refused, its share links
// answer 410 like expired shares (nothing is deleted), and its pending upload
// sessions and invitations are revoked. Deleting stays a separate action.

const (
	msgAccountDisabled      = "account disabled"
	msgDisableSelf          = "you cannot disable your own account"
	msgDisableLastAdmin     = "cannot disable the last active administrator"
	msgAlreadyDisabled      = "account already disabled"
	msgNotDisabled          = "account is not disabled"
	msgDisableReasonInvalid = "the reason must be at most 200 characters without control characters"
	disableReasonMax        = 200
)

// refuseDisabledSignIn answers 403 for a sign-in by a disabled account and
// records the attempt. The current state is read from the database, so an
// account disabled during a sign-in (between password and second factor) is
// refused as well.
func (s *Server) refuseDisabledSignIn(w http.ResponseWriter, u *User, method string) bool {
	disabled := u.Disabled
	if stored, err := s.St.Repos().Users().IsDisabled(context.Background(), u.ID); err == nil {
		disabled = disabled || stored
	}
	if !disabled {
		return false
	}
	detail := msgAccountDisabled
	if method != "" {
		detail += "; " + method
	}
	s.logEvent(u.ID, u.Username, "login_failed", "", detail)
	jerr(w, http.StatusForbidden, msgAccountDisabled)
	return true
}

// shareOwnerDisabled reports whether the owner of a share is disabled. Files
// received through an invitation belong to the inviter, so a disabled inviter
// counts too.
func (s *Server) shareOwnerDisabled(shareID int64) bool {
	disabled, err := s.St.Repos().Users().ShareOwnerDisabled(context.Background(), shareID)
	return err == nil && disabled
}

// noteCreatedBy records who created an account ("setup", "self-registration",
// "provider <name>" or the administrator's label).
func (s *Server) noteCreatedBy(id int64, by string) {
	s.St.Repos().Users().SetCreatedBy(context.Background(), id, clip(by, 160))
}

// noteRoleChange and noteEmailChange keep the last change of role and email
// address on the account, so the access review does not depend on the audit
// log's retention.
func (s *Server) noteRoleChange(id int64, actor *User) {
	s.St.Repos().Users().NoteRoleChange(context.Background(), id, time.Now().UTC(), s.userTarget(actor.ID))
}

func (s *Server) noteEmailChange(id int64, actor *User) {
	s.St.Repos().Users().NoteEmailChange(context.Background(), id, time.Now().UTC(), s.userTarget(actor.ID))
}

// activeAdminsExcept counts the administrators that are not disabled, without
// the given account.
func (s *Server) activeAdminsExcept(id int64) int {
	n, err := s.St.Repos().Users().CountActiveAdminsExcept(context.Background(), id)
	if err != nil {
		return 0
	}
	return n
}

// disableUser: POST /api/users/{id}/disable {"reason": "..."} (administrators).
func (s *Server) disableUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		jerr(w, 404, "not found")
		return
	}
	me := s.ctxUser(r)
	if id == me.ID {
		jerr(w, 400, msgDisableSelf)
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &b); err != nil && !errors.Is(err, io.EOF) {
		jerr(w, 400, "bad request")
		return
	}
	reason := strings.TrimSpace(b.Reason)
	if !plainText(reason, disableReasonMax) {
		jerr(w, 400, msgDisableReasonInvalid)
		return
	}
	unlock := s.stripe(&s.loginLocks, strconv.FormatInt(id, 10))
	defer unlock()
	target, err := s.userByID(id)
	if err != nil || target.IsGuest {
		jerr(w, 404, "not found")
		return
	}
	if target.Disabled {
		jerr(w, 409, msgAlreadyDisabled)
		return
	}
	if target.Admin && s.activeAdminsExcept(id) == 0 {
		jerr(w, 409, msgDisableLastAdmin)
		return
	}
	if target.Admin && s.refuseLastExternalAdmin(w, id, 0) {
		return
	}
	by := s.userTarget(me.ID) // before the transaction takes the only connection
	unlockUploads := s.LockUserUploads(id)
	defer unlockUploads()
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	n, err := tx.Users().Disable(ctx, id, now, by, reason)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if n != 1 {
		jerr(w, 409, msgAlreadyDisabled)
		return
	}
	// Pending uploads of the account and of the guests it invited.
	uploads, err := tx.Users().UploadsToRevoke(ctx, id)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	// Then the uploads, open invitations, sessions (also of its guests),
	// reset links, verification code and MFA reset requests.
	invites, err := tx.Users().RevokeAccess(ctx, id, now)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "database error")
		return
	}
	cleanupFailed := false
	for _, sid := range uploads {
		if err := os.RemoveAll(s.uploadDir(sid)); err != nil {
			log.Printf("disable user %d: upload cleanup: %v", id, err)
			cleanupFailed = true
		}
	}
	detail := "uploads revoked: " + strconv.Itoa(len(uploads)) + ", invites revoked: " + strconv.FormatInt(invites, 10)
	if reason != "" {
		detail += ", reason: " + reason
	}
	s.logEvent(me.ID, me.Username, "user_disabled", s.userTarget(id), detail)
	out := map[string]any{"ok": true, "uploads_revoked": len(uploads), "invites_revoked": invites}
	if cleanupFailed {
		out["cleanup_failed"] = true
	}
	jout(w, 200, out)
}

// enableUser: POST /api/users/{id}/enable (administrators). Revoked invitations
// and uploads stay revoked; share links work again (unless expired meanwhile).
func (s *Server) enableUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		jerr(w, 404, "not found")
		return
	}
	unlock := s.stripe(&s.loginLocks, strconv.FormatInt(id, 10))
	defer unlock()
	target, err := s.userByID(id)
	if err != nil || target.IsGuest {
		jerr(w, 404, "not found")
		return
	}
	n, err := s.St.Repos().Users().Enable(context.Background(), id)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if n != 1 {
		jerr(w, 409, msgNotDisabled)
		return
	}
	me := s.ctxUser(r)
	s.logEvent(me.ID, me.Username, "user_enabled", s.userTarget(id), "")
	jout(w, 200, map[string]any{"ok": true})
}
