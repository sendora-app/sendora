// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Security notifications to the account owner: password changed (by the user
// or through a reset link), a second factor added or removed, recovery codes
// regenerated, and a sign-in from a browser family and network not seen for the
// account in the last 30 days (setting notify_new_signin, default on).
//
// Mail goes only to a verified address and only when SMTP is configured; it is
// queued, so a failing mail server never blocks or fails the action. Messages
// carry the approximate time and the browser family, never a secret, a link or
// an address.
//
// For the sign-in check a short list of keyed hashes of (browser family,
// address class) is kept per account: /16 for IPv4, /48 for IPv6. Raw addresses
// are never stored for this.

const (
	keySigninFingerprint = "signin-fingerprint"
	signinMemory         = 30 * 24 * time.Hour
	signinMaxPerUser     = 20
	settingNotifySignin  = "notify_new_signin"
)

// browserFamily names the browser (and platform) from a User-Agent, coarsely.
func browserFamily(ua string) string {
	family := "Unknown browser"
	switch {
	case strings.Contains(ua, "Edg/") || strings.Contains(ua, "EdgA/") || strings.Contains(ua, "EdgiOS/"):
		family = "Edge"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera"):
		family = "Opera"
	case strings.Contains(ua, "SamsungBrowser/"):
		family = "Samsung Internet"
	case strings.Contains(ua, "Firefox/") || strings.Contains(ua, "FxiOS/"):
		family = "Firefox"
	case strings.Contains(ua, "Chrome/") || strings.Contains(ua, "CriOS/") || strings.Contains(ua, "Chromium/"):
		family = "Chrome"
	case strings.Contains(ua, "Safari/"):
		family = "Safari"
	case strings.HasPrefix(ua, "curl/") || strings.Contains(ua, "Go-http-client") || strings.Contains(ua, "python"):
		family = "Script or command-line tool"
	}
	platform := ""
	switch {
	case strings.Contains(ua, "Android"):
		platform = "Android"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		platform = "iOS"
	case strings.Contains(ua, "Windows"):
		platform = "Windows"
	case strings.Contains(ua, "Mac OS X") || strings.Contains(ua, "Macintosh"):
		platform = "macOS"
	case strings.Contains(ua, "CrOS"):
		platform = "ChromeOS"
	case strings.Contains(ua, "Linux"):
		platform = "Linux"
	}
	if platform != "" {
		return family + " (" + platform + ")"
	}
	return family
}

// addressClass is the network an address belongs to: /16 (IPv4) or /48 (IPv6).
func addressClass(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return "unknown"
	}
	if v4 := p.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(16, 32)), Mask: net.CIDRMask(16, 32)}).String()
	}
	return (&net.IPNet{IP: p.Mask(net.CIDRMask(48, 128)), Mask: net.CIDRMask(48, 128)}).String()
}

// signinFingerprint is a keyed hash of account, browser family and address
// class; it cannot be turned back into an address.
func (s *Server) signinFingerprint(uid int64, r *http.Request) string {
	m := hmac.New(sha256.New, s.key(keySigninFingerprint))
	m.Write([]byte(strconv.FormatInt(uid, 10) + "\x00" + browserFamily(r.UserAgent()) + "\x00" + addressClass(s.clientIP(r))))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// approximateTime is "now", rounded down to five minutes, in UTC.
func approximateTime(t time.Time) string {
	return t.UTC().Truncate(5*time.Minute).Format("2006-01-02 15:04") + " UTC"
}

// notifySecurity queues a security notification to the account owner. It never
// blocks and never fails the caller.
func (s *Server) notifySecurity(r *http.Request, u *User, event string) {
	if u == nil || u.IsGuest || !u.EmailVerified || strings.TrimSpace(u.Email) == "" || s.smtpConfigured() != nil {
		return
	}
	browser := "Unknown browser"
	if r != nil {
		browser = browserFamily(r.UserAgent())
	}
	s.queueMail(u.Email, "", "tpl_"+event, map[string]any{
		"RecipientName": recipientName(u),
		"Username":      u.Username,
		"Time":          approximateTime(time.Now()),
		"Browser":       browser,
		"EmailLanguage": u.Language,
	})
}

// notifyUserID reloads the account (for its current address and language) and notifies.
func (s *Server) notifyUserID(r *http.Request, uid int64, event string) {
	if u, err := s.userByID(uid); err == nil {
		s.notifySecurity(r, u, event)
	}
}

// noteSignIn remembers the sign-in's fingerprint and, when the account has a
// sign-in history and this browser/network combination is not in it, sends the
// new_signin notification. The first sign-in of an account only starts the
// history. It must not be called with a transaction open.
func (s *Server) noteSignIn(r *http.Request, u *User) {
	if u == nil || u.IsGuest || r == nil {
		return
	}
	fp := s.signinFingerprint(u.ID, r)
	now := time.Now().UTC()
	cutoff := now.Add(-signinMemory)
	ctx, h := context.Background(), s.St.Repos().SignInHistory()
	h.PruneBefore(ctx, u.ID, cutoff)
	history, known, err := h.Stats(ctx, u.ID, fp)
	if err != nil {
		return
	}
	if err := h.Touch(ctx, u.ID, fp, now); err != nil {
		return
	}
	// Keep the list short: only the most recent combinations.
	h.KeepNewest(ctx, u.ID, signinMaxPerUser)
	if history == 0 || known > 0 {
		return
	}
	if on, ok := parseStrictBool(s.St.Setting(settingNotifySignin)); ok && !on {
		return
	}
	s.notifySecurity(r, u, "new_signin")
}
