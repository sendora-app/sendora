// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Password maximum age and password history for local accounts.
//
//   - account_password_max_age_days (0..365, 0 = off; 365 for new installations,
//     0 for installations that already had accounts at the upgrade): a local
//     password older than this must be changed before anything else. It applies
//     only to accounts with a local password (password_hash<>''), never to guests
//     or accounts that sign in only through a provider, and not to accounts an
//     administrator exempted (users.password_rotation_exempt). An expired password
//     sets must_change_password, so the existing forced-change flow takes over.
//     It is detected at every sign-in (issueSession) and in the auth middleware,
//     so a long-lived session is caught within one access-token lifetime: there
//     the sessions end and the user signs in again, because a session token alone
//     must never choose a new password without the current one.
//   - account_password_history (0..24, default 5, 0 = no check): a new password
//     must differ from the current one and from the last N earlier passwords,
//     kept as bcrypt hashes in password_history (newest N per account).

const (
	msgPasswordReused       = "you used this password recently; choose a password you have not used before"
	msgPasswordExpired      = "your password has expired; sign in again and choose a new one"
	passwordMaxAgeLimit     = 365
	passwordHistoryLimit    = 24
	passwordHistoryFallback = 5
	// passwordWarnMailDays: the reminder mail is sent once, this many days before expiry.
	passwordWarnMailDays = 7
)

// validatePasswordRotationSetting checks the two keys; owned is false for other keys.
func validatePasswordRotationSetting(key, val string) (owned bool, err error) {
	switch key {
	case store.SettingPasswordMaxAgeDays:
		if _, ok := parseStrictInt(val, 0, passwordMaxAgeLimit); !ok {
			return true, fmt.Errorf("account_password_max_age_days must be an integer from %d to %d", 0, passwordMaxAgeLimit)
		}
		return true, nil
	case store.SettingPasswordHistory:
		if _, ok := parseStrictInt(val, 0, passwordHistoryLimit); !ok {
			return true, fmt.Errorf("account_password_history must be an integer from %d to %d", 0, passwordHistoryLimit)
		}
		return true, nil
	}
	return false, nil
}

// passwordMaxAgeDays is the configured maximum age; 0 (off) for a value that
// does not validate (it cannot be stored through the screen or the configuration).
func (s *Server) passwordMaxAgeDays() int {
	v := s.St.Setting(store.SettingPasswordMaxAgeDays)
	if v == "" {
		return 0
	}
	n, ok := parseStrictInt(v, 0, passwordMaxAgeLimit)
	if !ok {
		log.Printf("%s has an invalid value; password maximum age is not applied", store.SettingPasswordMaxAgeDays)
		return 0
	}
	return n
}

// passwordHistoryDepth is the number of earlier passwords that cannot be reused;
// an invalid stored value counts as the default rather than switching the check off.
func (s *Server) passwordHistoryDepth() int {
	v := s.St.Setting(store.SettingPasswordHistory)
	if v == "" {
		return 0
	}
	n, ok := parseStrictInt(v, 0, passwordHistoryLimit)
	if !ok {
		return passwordHistoryFallback
	}
	return n
}

// passwordExpiry returns when u's local password expires and whether the maximum
// age applies to the account at all.
func (s *Server) passwordExpiry(u *User) (time.Time, bool) {
	if u == nil || u.IsGuest || u.passwordHash == "" || u.PasswordRotationExempt || !u.passwordChangedAt.Valid {
		return time.Time{}, false
	}
	days := s.passwordMaxAgeDays()
	if days == 0 {
		return time.Time{}, false
	}
	return u.passwordChangedAt.Time.AddDate(0, 0, days), true
}

// flagExpiredPassword sets must_change_password when u's password is past its
// maximum age and records password_expired once (only the call that flips the
// flag records it). It reports whether it flagged the account now.
func (s *Server) flagExpiredPassword(u *User) bool {
	if u == nil || u.MustChangePassword {
		return false
	}
	exp, ok := s.passwordExpiry(u)
	if !ok || time.Now().Before(exp) {
		return false
	}
	n, err := s.St.Repos().Users().FlagPasswordExpired(context.Background(), u.ID, u.passwordHash)
	if err != nil {
		return false
	}
	if n != 1 {
		return false
	}
	u.MustChangePassword = true
	s.logEvent(u.ID, u.Username, "password_expired", s.userTarget(u.ID), "max age "+strconv.Itoa(s.passwordMaxAgeDays())+" days")
	return true
}

// expiredPasswordBlocked is the auth middleware's check: a session whose
// account's password expired since it signed in ends here (all sessions are
// signed out) and the user signs in again, which leads to the forced change.
func (s *Server) expiredPasswordBlocked(w http.ResponseWriter, u *User) bool {
	if !s.flagExpiredPassword(u) {
		return false
	}
	s.St.Repos().Sessions().RevokeAllForUser(context.Background(), u.ID)
	jerr(w, 401, msgPasswordExpired)
	return true
}

// passwordExpiryFields adds password_expires_at (RFC 3339) and
// password_expires_in_days (never negative) to out when the maximum age applies.
func (s *Server) passwordExpiryFields(u *User, out map[string]any) {
	exp, ok := s.passwordExpiry(u)
	if !ok {
		return
	}
	days := int(math.Ceil(time.Until(exp).Hours() / 24))
	out["password_expires_at"] = exp.UTC().Format(time.RFC3339)
	out["password_expires_in_days"] = max(days, 0)
}

// refusePasswordReuse answers 400 and returns true when pw is the account's
// current password or one of its last account_password_history passwords.
// Every comparison is a full bcrypt verification (about 250 ms at cost 12, so
// up to 25 of them), which is why callers run it only after all other password
// checks have passed. current is the account's current hash (may be empty).
func (s *Server) refusePasswordReuse(w http.ResponseWriter, uid int64, current, pw string) bool {
	n := s.passwordHistoryDepth()
	if n == 0 {
		return false
	}
	hashes := []string{}
	if current != "" {
		hashes = append(hashes, current)
	}
	history, err := s.St.Repos().PasswordHistory().Recent(context.Background(), uid, n)
	if err != nil {
		jerr(w, 500, "password history unavailable")
		return true
	}
	for _, h := range history {
		if h != "" {
			hashes = append(hashes, h)
		}
	}
	for _, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(pw)) == nil {
			jerr(w, 400, msgPasswordReused)
			return true
		}
	}
	return false
}

// rememberPasswordTx keeps the account's current hash (about to be replaced) in
// password_history and prunes it to the newest n; n=0 empties the account's
// history. It must run inside the transaction that changes the password, before
// the UPDATE; n is read by the caller before the transaction (single connection).
func rememberPasswordTx(tx ports.Tx, uid int64, n int) error {
	return tx.PasswordHistory().Remember(context.Background(), uid, n, time.Now().UTC())
}

// warnExpiringPasswords (maintenance) mails the owner of each account whose
// password expires within passwordWarnMailDays, once per password: the time is
// kept in password_expiry_warned_at, which every password change clears. Only
// verified addresses get it, only with SMTP and a public URL configured; the
// mail is queued, so a failing mail server never blocks anything.
func (s *Server) warnExpiringPasswords(now time.Time) {
	if s.passwordMaxAgeDays() == 0 || s.smtpConfigured() != nil {
		return
	}
	base, ok := s.emailBaseURL(&http.Request{Host: "invalid.invalid"})
	if !ok {
		return
	}
	recs, err := s.St.Repos().Users().ListPasswordExpiryCandidates(context.Background())
	if err != nil {
		log.Printf("password expiry reminders: %v", err)
		return
	}
	var users []*User
	for _, rec := range recs {
		if u, err := userFromRecord(rec, nil); err == nil {
			users = append(users, u)
		}
	}
	for _, u := range users {
		exp, ok := s.passwordExpiry(u)
		left := exp.Sub(now)
		if !ok || left <= 0 || left > passwordWarnMailDays*24*time.Hour {
			continue
		}
		n, err := s.St.Repos().Users().MarkPasswordExpiryWarned(context.Background(), u.ID, u.passwordHash, now.UTC())
		if err != nil {
			continue
		}
		if n != 1 {
			continue
		}
		days := strconv.Itoa(int(math.Ceil(left.Hours() / 24)))
		date := exp.UTC().Format("2006-01-02")
		s.queueMail(u.Email, "", "tpl_password_expiry_warning", map[string]any{
			"RecipientName": recipientName(u),
			"Username":      u.Username,
			"ExpiresDays":   days,
			"Expires":       date,
			"URL":           base + "/profile",
			"EmailLanguage": u.Language,
		})
		s.logEvent(0, "system", "password_expiry_warning_sent", s.userTarget(u.ID), "expires "+date+" ("+days+" days)")
	}
}
