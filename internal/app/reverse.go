// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sendora-app/sendora/internal/ports"
)

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	if !s.storageAdmits(w) {
		return
	}
	u := s.ctxUser(r)
	if u.IsGuest || !s.St.SettingBool("allow_reverse_shares") {
		jerr(w, 403, "reverse shares disabled")
		return
	}
	var b struct {
		Name          string `json:"name"`
		Email         string `json:"email"`
		Message       string `json:"message"`
		Days          int    `json:"days"`
		EmailLanguage string `json:"email_language"`
		Open          bool   `json:"open"`
		MaxUploads    int    `json:"max_uploads"`
	}
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
	if b.Email != "" {
		if _, err := mail.ParseAddress(b.Email); err != nil {
			jerr(w, 400, "invalid email")
			return
		}
	}
	if validateText(b.Name, maxShareNameRunes, true) != nil || validateText(b.Message, maxMessageRunes, false) != nil {
		jerr(w, 400, "name or message too long or contains invalid characters")
		return
	}
	if b.Days <= 0 || b.Days > 30 {
		b.Days = 7
	}
	if b.Open {
		if b.Email != "" {
			jerr(w, 400, "open links do not take an email address")
			return
		}
		if b.MaxUploads < 1 || b.MaxUploads > 100 {
			jerr(w, 400, "max_uploads must be between 1 and 100")
			return
		}
	} else {
		b.MaxUploads = 0
	}
	if b.Email != "" && !s.takeMail(u.ID, 1) {
		w.Header().Set("Retry-After", "3600")
		jerr(w, 429, "too many emails sent recently; try again later")
		return
	}
	tok := randHex(24)
	exp := time.Now().AddDate(0, 0, b.Days)
	inviteID, err := s.St.Repos().ReverseInvites().Create(context.Background(), ports.NewInvite{Token: tok, UserID: u.ID, RecipientName: b.Name,
		RecipientEmail: b.Email, Message: b.Message, ExpiresAt: exp, Reusable: b.Open, MaxUploads: b.MaxUploads})
	if err != nil {
		jerr(w, 500, "invite unavailable")
		return
	}
	kind := "email"
	if b.Open {
		kind = "open"
	}
	s.logEvent(u.ID, u.Username, "invite_created", "invite#"+strconv.FormatInt(inviteID, 10), kind)
	link := s.baseURL(r) + "/invite/" + tok
	if b.Open {
		jout(w, 201, map[string]any{"id": inviteID, "kind": "open", "url": link, "expires_at": exp, "max_uploads": b.MaxUploads, "used": 0})
		return
	}
	if base, ok := s.emailBaseURL(r); b.Email != "" && ok {
		s.queueMail(b.Email, nameOf(u)+" invites you to upload files", "tpl_reverse_invite", map[string]any{
			"EmailLanguage": b.EmailLanguage, "RecipientName": b.Name, "SenderName": nameOf(u), "URL": base + "/invite/" + tok, "Message": b.Message})
	}
	jout(w, 201, map[string]any{"kind": "email", "url": link, "expires_at": exp})
}

// listInvites shows the caller's own invites. Child rows (one per accepted open
// link) are internal and folded into the parent's used count. The URL is only
// ever returned for open links, to their owner.
func (s *Server) listInvites(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	base := s.baseURL(r) // may query settings: must run before rows hold the sole connection
	invites, err := s.St.Repos().ReverseInvites().ListOwned(context.Background(), s.ctxUser(r).ID, now)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	out := []map[string]any{}
	for _, iv := range invites {
		id, tok, n, e, exp, done := iv.ID, iv.Token, iv.RecipientName, iv.RecipientEmail, iv.ExpiresAt, iv.CompletedAt
		open, max, used, pending := iv.Reusable, iv.MaxUploads, iv.Used, iv.Pending
		it := map[string]any{"id": id, "name": n, "email": e, "expires_at": exp, "completed_at": done, "kind": "email"}
		if open {
			it["kind"] = "open"
			it["max_uploads"] = max
			it["used"] = used
			it["pending"] = pending
			it["active"] = now.Before(exp)
			it["url"] = base + "/invite/" + tok
		} else {
			it["used"] = 0
			if done != nil {
				it["used"] = 1
			}
			it["max_uploads"] = 1
			it["active"] = done == nil && now.Before(exp)
		}
		out = append(out, it)
	}
	jout(w, 200, out)
}

// revokeInvite expires one of the caller's invites now, and for open links also
// every outstanding (incomplete) child. Completed uploads are untouched.
func (s *Server) revokeInvite(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		jerr(w, 404, "invite not found")
		return
	}
	u := s.ctxUser(r)
	now := time.Now()
	n, err := s.St.Repos().ReverseInvites().ExpireOwned(context.Background(), id, u.ID, now)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if n != 1 {
		jerr(w, 404, "invite not found")
		return
	}
	if err := s.St.Repos().ReverseInvites().ExpireOpenChildren(context.Background(), id, u.ID, now); err != nil {
		jerr(w, 500, "database error")
		return
	}
	s.logEvent(u.ID, u.Username, "invite_revoked", "invite#"+strconv.FormatInt(id, 10), "")
	jout(w, 200, map[string]any{"revoked": true})
}

// acceptInvite turns an invite token into a guest session limited to one upload.
const msgReverseOff = "uploads by invitation are turned off"

func (s *Server) acceptInvite(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		jerr(w, 403, "cross-origin request refused")
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if decode(r, &in) != nil || in.Token == "" || len(in.Token) > 256 {
		jerr(w, 404, "invite not found")
		return
	}
	if !s.St.SettingBool("allow_reverse_shares") {
		jerr(w, 403, msgReverseOff)
		return
	}
	tok := in.Token
	unlock := s.stripe(&s.identityLocks, "invite:"+tok)
	defer unlock()
	// Serialize owner deletion with invitation validation and guest creation.
	// No DB helpers may run while this transaction owns the sole connection.
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		jerr(w, 500, "invite unavailable")
		return
	}
	defer tx.Rollback()
	if err := tx.ReverseInvites().LockToken(ctx, tok); err != nil {
		jerr(w, 500, "invite unavailable")
		return
	}
	inv, err := tx.ReverseInvites().ForAccept(ctx, tok)
	id, guest, exp, done := inv.ID, inv.GuestUserID, inv.ExpiresAt, inv.CompletedAt
	name, msg, inviter := inv.RecipientName, inv.Message, inv.InviterName
	reusable, maxUploads, ownerID, parent := inv.Reusable, inv.MaxUploads, inv.OwnerID, inv.ParentID
	now := time.Now()
	if err != nil || !now.Before(exp) || done != nil {
		jerr(w, 404, "invite invalid, expired or already used")
		return
	}
	var gu *User
	if reusable && parent == nil {
		// Open link: the link itself never uploads. Each accept mints a fresh
		// guest plus a single-use child invite with its own unreturned token.
		// A slot is taken by a finished upload, an upload in progress, or an
		// accept from the last hour. Accepts that never start uploading release
		// their slot after an hour, so the link cannot be exhausted by clicking.
		taken, err := tx.ReverseInvites().CountTakenSlots(ctx, id, now, now.Add(-time.Hour))
		if err != nil {
			jerr(w, 500, "invite unavailable")
			return
		}
		if taken >= maxUploads {
			jerr(w, 410, "invite upload limit reached")
			return
		}
		childExp := now.Add(24 * time.Hour)
		if exp.Before(childExp) {
			childExp = exp
		}
		display := strings.TrimSpace(name)
		if display == "" {
			display = "Guest"
		}
		gid, err := tx.Users().CreateGuest(ctx, "guest-"+randHex(6), display)
		if err == nil {
			err = tx.ReverseInvites().CreateChild(ctx, ports.NewChildInvite{Token: randHex(24), UserID: ownerID, RecipientName: name,
				Message: msg, GuestUserID: gid, ExpiresAt: childExp, ParentID: id})
		}
		if err == nil {
			gu, err = userFromRecord(tx.Users().ByID(ctx, gid))
		}
		if err != nil {
			jerr(w, 500, "invite unavailable")
			return
		}
	} else if guest != nil {
		gu, err = userFromRecord(tx.Users().GuestByID(ctx, *guest))
		if err != nil {
			jerr(w, 404, "invite invalid, expired or already used")
			return
		}
	} else {
		uname := "guest-" + randHex(6)
		display := strings.TrimSpace(name)
		if display == "" {
			display = "Guest"
		}
		gid, err := tx.Users().CreateGuest(ctx, uname, display)
		if err != nil {
			jerr(w, 500, "invite unavailable")
			return
		}
		err = tx.ReverseInvites().AssignGuest(ctx, id, gid)
		if err == nil {
			gu, err = userFromRecord(tx.Users().ByID(ctx, gid))
		}
		if err != nil {
			jerr(w, 500, "invite unavailable")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "invite unavailable")
		return
	}
	s.logEvent(gu.ID, gu.Username, "invite_accepted", "invite#"+strconv.FormatInt(id, 10), "")
	s.issueSession(w, r, gu)
	jout(w, 200, map[string]any{"access_token": s.accessToken(gu), "user": gu, "inviter": inviter, "message": msg})
}
