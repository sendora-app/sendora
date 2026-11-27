// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// welcomeTokenTTL is how long the one-time "choose your password" link in the
// welcome email stays valid.
const welcomeTokenTTL = 7 * 24 * time.Hour

const msgWelcomeUnverified = "this user's email address is not verified; ask them to use 'Forgot password' or confirm the address first"

// Outcomes reported to the administrator.
const (
	welcomeSent    = "sent"
	welcomeSkipped = "skipped"
	welcomeFailed  = "failed"
)

// sendWelcome mails a user their username, the sign-in link and a one-time link
// for choosing their own password. It never includes a password and never logs
// the token or the message. It returns an outcome plus a short admin-facing note
// when nothing was sent. It must not be called while rows or a transaction hold
// the single database connection.
func (s *Server) sendWelcome(r *http.Request, actor, u *User) (string, string) {
	switch {
	case u == nil || u.IsGuest:
		return welcomeSkipped, "this account cannot receive a welcome email"
	case strings.TrimSpace(u.Email) == "":
		return welcomeSkipped, "this user has no email address"
	case !s.localLoginEnabled():
		return welcomeSkipped, "local sign-in is disabled, so there is no password to choose"
	case s.smtpConfigured() != nil:
		return welcomeSkipped, "outgoing email (SMTP) is not configured"
	}
	base, ok := s.emailBaseURL(r)
	if !ok {
		return welcomeSkipped, "set the public application URL (APP_URL) first, so the links in the email are trustworthy"
	}
	if !s.takeMail(actor.ID, 1) {
		return welcomeSkipped, "the hourly limit for outgoing emails was reached; try again later"
	}
	tok := randHex(24)
	hash := hashToken(tok)
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		return welcomeFailed, "the welcome email could not be prepared"
	}
	// A fresh link replaces older unused welcome links of this user.
	if err := tx.PasswordResets().DeleteWelcomesForUser(ctx, u.ID); err != nil {
		tx.Rollback()
		return welcomeFailed, "the welcome email could not be prepared"
	}
	if err := tx.PasswordResets().CreateWelcome(ctx, hash, u.ID, time.Now().Add(welcomeTokenTTL)); err != nil {
		tx.Rollback()
		return welcomeFailed, "the welcome email could not be prepared"
	}
	if err := tx.Commit(); err != nil {
		return welcomeFailed, "the welcome email could not be prepared"
	}
	name := strings.TrimSpace(u.Name)
	if name == "" {
		name = u.Username
	}
	err = s.deliverTemplate(u.Email, "tpl_welcome", map[string]any{
		"RecipientName":  name,
		"Username":       u.Username,
		"LoginURL":       base + "/login",
		"SetPasswordURL": base + "/reset-password/" + tok,
		"ExpiresDays":    strconv.Itoa(int(welcomeTokenTTL / (24 * time.Hour))),
		"EmailLanguage":  u.Language,
	})
	if err != nil {
		// The link was never delivered, so it must not stay redeemable.
		s.St.Repos().PasswordResets().Delete(ctx, hash)
		return welcomeFailed, "the email could not be delivered; check the SMTP settings (Settings → Send test email to me)"
	}
	return welcomeSent, ""
}

// resendWelcome: POST /api/users/{id}/welcome (admin only).
func (s *Server) resendWelcome(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		jerr(w, 404, "not found")
		return
	}
	u, err := s.userByID(id)
	if err != nil || u.IsGuest {
		jerr(w, 404, "not found")
		return
	}
	me := s.ctxUser(r)
	// The link lets its holder set the password, so it may only go to an address
	// the user proved is theirs, or to an account that never finished its welcome
	// (an address changed by an administrator drops those links, see updateUser).
	pending, _ := s.St.Repos().PasswordResets().CountWelcomesForUser(context.Background(), u.ID)
	if !u.EmailVerified && pending == 0 {
		s.logEvent(me.ID, me.Username, "user_welcome", s.userTarget(id), "welcome="+welcomeSkipped)
		jerr(w, 409, msgWelcomeUnverified)
		return
	}
	outcome, note := s.sendWelcome(r, me, u)
	s.logEvent(me.ID, me.Username, "user_welcome", s.userTarget(id), "welcome="+outcome)
	switch outcome {
	case welcomeSent:
		jout(w, 200, map[string]any{"ok": true, "welcome_email": outcome})
	case welcomeSkipped:
		jerr(w, 409, note)
	default:
		jerr(w, 502, note)
	}
}
