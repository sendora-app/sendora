// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sendora-app/sendora/internal/ports"
	"golang.org/x/oauth2"
	githubep "golang.org/x/oauth2/github"
)

type Provider struct {
	ID                int64  `json:"id"`
	UUID              string `json:"uuid"`
	Name              string `json:"name"`
	Type              string `json:"type"`                // oidc | google | github | entra
	TenantID          string `json:"tenant_id,omitempty"` // Entra tenant, stored in canonical issuer_url
	Enabled           bool   `json:"enabled"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret,omitempty"`
	SecretSet         bool   `json:"client_secret_set"`
	IssuerURL         string `json:"issuer_url"`
	Icon              string `json:"icon"`
	TrustEmail        bool   `json:"trust_email"`
	AllowRegistration bool   `json:"allow_registration"`
	CallbackURL       string `json:"callback_url,omitempty"`
	Managed           bool   `json:"managed"` // set by the server configuration; read-only here
}

// providerFrom turns a stored provider (and its lookup error) into a Provider;
// like a scan, it returns the provider even with an error.
func providerFrom(rec ports.ProviderRecord, err error) (*Provider, error) {
	p := &Provider{ID: rec.ID, UUID: rec.UUID, Name: rec.Name, Type: rec.Type, Enabled: rec.Enabled, ClientID: rec.ClientID, ClientSecret: rec.ClientSecret,
		IssuerURL: rec.IssuerURL, Icon: rec.Icon, TrustEmail: rec.TrustEmail, AllowRegistration: rec.AllowRegistration, Managed: rec.Managed}
	p.SecretSet = p.ClientSecret != ""
	if p.Type == "entra" {
		p.TenantID, _ = entraTenant(p.IssuerURL)
	}
	return p, err
}

func (s *Server) providerByUUID(id string) (*Provider, error) {
	return providerFrom(s.St.Repos().AuthProviders().ByUUID(context.Background(), id))
}

func (s *Server) listPublicProviders(w http.ResponseWriter, r *http.Request) {
	recs, _ := s.St.Repos().AuthProviders().List(context.Background(), true)
	out := []map[string]any{}
	for _, rec := range recs {
		p, _ := providerFrom(rec, nil)
		out = append(out, map[string]any{"uuid": p.UUID, "name": p.Name, "type": p.Type, "icon": p.Icon})
	}
	jout(w, 200, out)
}

func (s *Server) adminProviders(w http.ResponseWriter, r *http.Request) {
	recs, _ := s.St.Repos().AuthProviders().List(context.Background(), false)
	out := []*Provider{}
	for _, rec := range recs {
		p, _ := providerFrom(rec, nil)
		p.ClientSecret = ""
		out = append(out, p)
	}
	base := s.baseURL(r)
	for _, p := range out {
		p.CallbackURL = base + "/api/auth/oidc/" + p.UUID + "/callback"
	}
	jout(w, 200, out)
}

func validProvider(p *Provider) string {
	switch p.Type {
	case "oidc":
		if u, err := url.Parse(p.IssuerURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "valid issuer URL required"
		}
	case "entra":
		if msg := normalizeEntra(p); msg != "" {
			return msg
		}
	case "google", "github":
	default:
		return "type must be oidc, google, github or entra"
	}
	if strings.TrimSpace(p.Name) == "" || p.ClientID == "" {
		return "name and client id required"
	}
	return ""
}

func (s *Server) createProvider(w http.ResponseWriter, r *http.Request) {
	var p Provider
	if decode(r, &p) != nil {
		jerr(w, 400, "bad request")
		return
	}
	if m := validProvider(&p); m != "" {
		jerr(w, 400, m)
		return
	}
	if p.Type == "oidc" {
		if err := s.checkTarget(r.Context(), p.IssuerURL); err != nil {
			jerr(w, 400, "issuer URL: "+err.Error())
			return
		}
	}
	p.UUID = uuid.NewString()
	id, err := s.St.Repos().AuthProviders().Create(context.Background(), p.UUID, providerSettings(&p))
	if err != nil {
		log.Printf("create login provider failed: %v", err)
		jerr(w, 500, "could not create the login provider")
		return
	}
	jout(w, 201, map[string]any{"id": id, "uuid": p.UUID, "callback_url": s.baseURL(r) + "/api/auth/oidc/" + p.UUID + "/callback"})
}

// providerManaged reports whether a provider comes from the server configuration.
func (s *Server) providerManaged(id int64) bool {
	m, _ := s.St.Repos().AuthProviders().IsManaged(context.Background(), id)
	return m
}

const msgProviderManaged = "this login provider is managed by the server configuration and cannot be changed here"

func (s *Server) updateProvider(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if s.providerManaged(id) {
		jerr(w, 409, msgProviderManaged)
		return
	}
	var p Provider
	if decode(r, &p) != nil {
		jerr(w, 400, "bad request")
		return
	}
	if m := validProvider(&p); m != "" {
		jerr(w, 400, m)
		return
	}
	if p.Type == "oidc" {
		if err := s.checkTarget(r.Context(), p.IssuerURL); err != nil {
			jerr(w, 400, "issuer URL: "+err.Error())
			return
		}
	}
	if !p.Enabled && s.refuseLastExternalAdmin(w, 0, id) {
		return
	}
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	oldType, oldClient, oldIssuer, err := tx.AuthProviders().Identity(ctx, id)
	if err != nil {
		jerr(w, 404, "provider not found")
		return
	}
	linked, err := tx.AuthProviders().CountProviderLinks(ctx, id)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if linked > 0 && (oldType != p.Type || oldClient != p.ClientID || oldIssuer != p.IssuerURL) {
		jerr(w, 409, "linked provider identity cannot change; create a new provider")
		return
	}
	// The stored client secret is only sent to the issuer it was entered for.
	if p.ClientSecret == "" && (oldType != p.Type || oldClient != p.ClientID || oldIssuer != p.IssuerURL) {
		jerr(w, 400, "enter the client secret again when changing the provider type, client ID or issuer")
		return
	}
	err = tx.AuthProviders().Update(ctx, id, providerSettings(&p))
	if err == nil && p.ClientSecret != "" {
		err = tx.AuthProviders().SetClientSecret(ctx, id, p.ClientSecret)
	}
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if err = tx.Commit(); err != nil {
		jerr(w, 500, "database error")
		return
	}
	jout(w, 200, map[string]any{"ok": true})
}

func (s *Server) deleteProvider(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if s.providerManaged(id) {
		jerr(w, 409, msgProviderManaged)
		return
	}
	if s.refuseLastExternalAdmin(w, 0, id) {
		return
	}
	s.St.Repos().AuthProviders().Delete(context.Background(), id)
	jout(w, 200, map[string]any{"ok": true})
}

// ---------- OAuth / OIDC flow ----------

func (s *Server) oauthConfig(ctx context.Context, p *Provider, r *http.Request) (*oauth2.Config, *oidc.Provider, error) {
	cfg := &oauth2.Config{ClientID: p.ClientID, ClientSecret: p.ClientSecret,
		RedirectURL: ""}
	base, ok := s.emailBaseURL(r)
	if !ok {
		return nil, nil, fmt.Errorf("configure a trusted application URL")
	}
	cfg.RedirectURL = base + "/api/auth/oidc/" + p.UUID + "/callback"
	switch p.Type {
	case "github":
		cfg.Endpoint = githubep.Endpoint
		cfg.Scopes = []string{"read:user", "user:email"}
		return cfg, nil, nil
	}
	issuer := p.IssuerURL
	if p.Type == "google" {
		issuer = "https://accounts.google.com"
	}
	op, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, nil, err
	}
	cfg.Endpoint = op.Endpoint()
	cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	return cfg, op, nil
}

func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	p, err := s.providerByUUID(chi.URLParam(r, "uuid"))
	if err != nil || !p.Enabled {
		jerr(w, 404, "provider not found")
		return
	}
	ctx, cancel := s.providerContextFor(r.Context(), p)
	defer cancel()
	cfg, _, err := s.oauthConfig(ctx, p, r)
	if err != nil {
		jerr(w, 502, "provider unreachable")
		return
	}
	state, nonce := p.UUID+":"+randHex(16), randHex(16)
	verifier := oauth2.GenerateVerifier()
	secure := s.secureCookies(r)
	for k, v := range map[string]string{"oidc_state": state, "oidc_nonce": nonce, "oidc_pkce": verifier} {
		http.SetCookie(w, &http.Cookie{Name: k, Value: v, Path: "/api/auth/oidc", MaxAge: 600, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if p.Type != "github" {
		opts = append(opts, oidc.Nonce(nonce))
	}
	http.Redirect(w, r, cfg.AuthCodeURL(state, opts...), http.StatusFound)
}

type extIdentity struct {
	Sub, Email, Name, Username string
	EmailVerified              bool
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) { http.Redirect(w, r, "/?auth_error="+url.QueryEscape(msg), http.StatusFound) }
	p, err := s.providerByUUID(chi.URLParam(r, "uuid"))
	if err != nil || !p.Enabled {
		fail("provider not found")
		return
	}
	sc, err1 := r.Cookie("oidc_state")
	nc, err2 := r.Cookie("oidc_nonce")
	pc, err3 := r.Cookie("oidc_pkce")
	if err1 != nil || err2 != nil || err3 != nil || len(pc.Value) < 43 || len(pc.Value) > 128 || nc.Value == "" || sc.Value == "" || sc.Value != r.URL.Query().Get("state") || !strings.HasPrefix(sc.Value, p.UUID+":") {
		fail("invalid state")
		return
	}
	for _, name := range []string{"oidc_state", "oidc_nonce", "oidc_pkce"} {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/api/auth/oidc", MaxAge: -1, HttpOnly: true, Secure: s.secureCookies(r), SameSite: http.SameSiteLaxMode})
	}
	ctx, cancel := s.providerContextFor(r.Context(), p)
	defer cancel()
	cfg, op, err := s.oauthConfig(ctx, p, r)
	if err != nil {
		fail("provider unreachable")
		return
	}
	tok, err := cfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pc.Value))
	if err != nil {
		s.logEvent(0, "unknown", "login_failed", "", "provider "+p.Name)
		fail("login failed")
		return
	}
	var id extIdentity
	if p.Type == "github" {
		id, err = githubIdentity(ctx, cfg, tok)
	} else {
		raw, _ := tok.Extra("id_token").(string)
		var idt *oidc.IDToken
		idt, err = op.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, raw)
		if err == nil && idt.Nonce != nc.Value {
			err = fmt.Errorf("nonce mismatch")
		}
		if err == nil {
			id, err = oidcIdentity(p, idt)
		}
	}
	if err != nil || id.Sub == "" {
		s.logEvent(0, "unknown", "login_failed", "", "provider "+p.Name)
		fail("login failed")
		return
	}
	u, msg := s.resolveExternalUser(p, id)
	if u == nil {
		s.logEvent(0, "unknown", "login_failed", "", "provider "+p.Name)
		fail(msg)
		return
	}
	if u.Disabled {
		s.logEvent(u.ID, u.Username, "login_failed", "", "account disabled; provider "+p.Name)
		fail(msgAccountDisabled)
		return
	}
	u.authMethod = authMethodProvider
	if !s.issueSession(w, r, u) {
		fail("session changed; log in again")
		return
	}
	s.noteSignIn(r, u)
	s.logEvent(u.ID, u.Username, "login_ok", "", "provider "+p.Name)
	http.Redirect(w, r, "/?oidc=1", http.StatusFound)
}

func githubIdentity(ctx context.Context, cfg *oauth2.Config, tok *oauth2.Token) (extIdentity, error) {
	c := cfg.Client(ctx, tok)
	var me struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	resp, err := c.Get("https://api.github.com/user")
	if err != nil {
		return extIdentity{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return extIdentity{}, fmt.Errorf("identity request failed")
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&me); err != nil || me.ID <= 0 {
		return extIdentity{}, fmt.Errorf("invalid identity")
	}
	id := extIdentity{Sub: strconv.FormatInt(me.ID, 10), Name: me.Name, Username: me.Login}
	resp, err = c.Get("https://api.github.com/user/emails")
	if err == nil {
		var emails []struct {
			Email    string
			Primary  bool
			Verified bool
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return id, nil
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&emails); err != nil {
			return id, nil
		}
		for _, e := range emails {
			if e.Primary {
				id.Email, id.EmailVerified = e.Email, e.Verified
			}
		}
	}
	return id, nil
}

var nonUser = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

func (s *Server) resolveExternalUser(p *Provider, id extIdentity) (*User, string) {
	unlock := s.stripe(&s.identityLocks, "external-identities")
	defer unlock()
	uid, err := s.St.Repos().AuthProviders().LinkedUser(context.Background(), p.ID, id.Sub)
	if err == nil {
		u, err := s.userByID(uid)
		if err != nil || u.IsGuest {
			return nil, "account unavailable"
		}
		// Fill an empty email from the Entra user name once; never overwrite.
		if u.Email == "" {
			if upn := s.entraUPNEmail(p, id, u.ID); upn != "" {
				if n, e := s.St.Repos().Users().FillEmptyEmail(context.Background(), u.ID, upn); e == nil {
					if n == 1 {
						u.Email = upn
					}
				}
			}
		}
		return u, ""
	}
	if !errors.Is(err, ports.ErrNotFound) {
		return nil, "account unavailable"
	}
	// Provider subject links are explicit identities. Email alone must never create
	// a link: locally supplied emails are not proof of ownership.
	email := ""
	if p.Type != "entra" && p.TrustEmail && id.EmailVerified {
		var err error
		email, err = canonicalEmail(id.Email)
		if err != nil {
			return nil, "invalid provider email"
		}
	}
	if email != "" && !s.emailAvailable(email, 0) {
		return nil, "email already has an account; use its existing login"
	}
	verified := 1
	if email == "" {
		if email = s.entraUPNEmail(p, id, 0); email != "" {
			verified = 0 // the user name is not proof of a mailbox
		}
	}
	if !p.AllowRegistration {
		return nil, "no account linked to this login"
	}
	base := nonUser.ReplaceAllString(firstNonEmpty(id.Username, strings.Split(id.Email, "@")[0], "user"), "")
	if len(base) > 58 { // leave room for a numeric suffix within the 64-character limit
		base = base[:58]
	}
	if base == "" {
		base = "user"
	}
	uname := base
	for i := 2; ; i++ {
		n, _ := s.St.Repos().Users().CountByUsernameFold(context.Background(), uname)
		if n == 0 {
			break
		}
		uname = base + strconv.Itoa(i)
	}
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		return nil, "could not create account"
	}
	defer tx.Rollback()
	nid, err := tx.Users().CreateExternal(ctx, uname, id.Name, email, verified)
	if err != nil {
		return nil, "could not create account"
	}
	if err := tx.Users().SetCreatedBy(ctx, nid, clip("provider "+p.Name, 160)); err != nil {
		return nil, "could not create account"
	}
	if err := tx.AuthProviders().Link(ctx, nid, p.ID, id.Sub); err != nil {
		return nil, "could not link account"
	}
	u, err := userFromRecord(tx.Users().ByID(ctx, nid))
	if err != nil {
		return nil, "account unavailable"
	}
	if err := tx.Commit(); err != nil {
		return nil, "could not create account"
	}
	return u, ""
}

// entraUPNEmail returns the Entra user name (preferred_username, normally the
// user principal name) when it is an email address nobody else uses. It is stored
// on the account as an unverified address for display and notifications only: it
// is never used to link accounts, and unverified addresses cannot reset passwords.
// The email claim of the token is deliberately still ignored.
func (s *Server) entraUPNEmail(p *Provider, id extIdentity, except int64) string {
	if p.Type != "entra" || !strings.Contains(id.Username, "@") {
		return ""
	}
	// Guest (B2B) accounts have a user principal name such as
	// name_example.com#EXT#@tenant.onmicrosoft.com, which is not a mailbox.
	if strings.Contains(strings.ToLower(id.Username), "#ext#") {
		return ""
	}
	email, err := canonicalEmail(id.Username)
	if err != nil || email == "" || !s.emailAvailable(email, except) {
		return ""
	}
	return email
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// providerSettings is the editable part of p.
func providerSettings(p *Provider) ports.ProviderSettings {
	return ports.ProviderSettings{Name: p.Name, Type: p.Type, Enabled: p.Enabled, ClientID: p.ClientID, ClientSecret: p.ClientSecret,
		IssuerURL: p.IssuerURL, Icon: p.Icon, TrustEmail: p.TrustEmail, AllowRegistration: p.AllowRegistration}
}
