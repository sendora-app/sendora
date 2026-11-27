// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"net/http"
	"time"
)

// Privacy statement and terms of use: privacy_url and terms_url (https,
// optional) are links shown in the footer, on the sign-in page and on public
// share pages. With terms_acceptance_required and a terms_version, every
// signed-in account (not reverse-share guests) accepts the current version once;
// until then only its profile, the acceptance, the personal data export and the
// erasure of the account are reachable. A new version asks again.

const (
	msgTermsRequired    = "terms acceptance required"
	msgTermsNotRequired = "accepting terms is not required"
	msgTermsOutdated    = "the terms have changed; reload the page and read the current version"
)

// currentTerms returns the version to accept, or "" when acceptance is off.
func (s *Server) currentTerms() string {
	if req, ok := parseStrictBool(s.St.Setting("terms_acceptance_required")); !ok || !req {
		return ""
	}
	if s.St.Setting("terms_url") == "" {
		return ""
	}
	return s.St.Setting("terms_version")
}

// termsPending reports whether u still has to accept the current terms.
func (s *Server) termsPending(u *User) bool {
	if u == nil || u.IsGuest {
		return false
	}
	version := s.currentTerms()
	if version == "" {
		return false
	}
	accepted, err := s.St.Repos().Users().TermsAcceptedVersion(context.Background(), u.ID)
	if err != nil {
		return true
	}
	return accepted != version
}

// termsAllowed lists what an account that has not accepted yet may still do.
func termsAllowed(r *http.Request) bool {
	switch r.URL.Path {
	case "/api/users/me", "/api/users/me/export", "/api/users/me/mfa":
		return r.Method == http.MethodGet
	case "/api/users/me/terms", "/api/users/me/erase":
		return r.Method == http.MethodPost
	}
	return false
}

// termsBlocked answers 403 {code: terms_required} for a request of an account
// that has not accepted the current terms. It has answered when it returns true.
func (s *Server) termsBlocked(w http.ResponseWriter, r *http.Request, u *User) bool {
	if termsAllowed(r) || !s.termsPending(u) {
		return false
	}
	jout(w, http.StatusForbidden, map[string]any{"error": msgTermsRequired, "code": "terms_required",
		"terms_version": s.St.Setting("terms_version"), "terms_url": s.St.Setting("terms_url")})
	return true
}

// acceptTerms: POST /api/users/me/terms {version}. The version must be the
// current one, so nobody accepts a text they were not shown.
func (s *Server) acceptTerms(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	if u.IsGuest {
		jerr(w, 403, "guest session is upload-only")
		return
	}
	var b struct {
		Version string `json:"version"`
	}
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	version := s.currentTerms()
	if version == "" {
		jerr(w, 409, msgTermsNotRequired)
		return
	}
	if b.Version != version {
		jerr(w, 409, msgTermsOutdated)
		return
	}
	if err := s.St.Repos().Users().AcceptTerms(context.Background(), u.ID, version, time.Now().UTC()); err != nil {
		jerr(w, 500, "database error")
		return
	}
	s.logEvent(u.ID, u.Username, "terms_accepted", s.userTarget(u.ID), "version="+clip(version, 40))
	jout(w, 200, map[string]any{"ok": true, "terms_accepted_version": version})
}
