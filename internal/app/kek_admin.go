// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/keyclient"
	"github.com/sendora-app/sendora/internal/keyops"
	"github.com/sendora-app/sendora/internal/keyserver"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/store"
)

// Tenant-supplied key (KEK) administration, Cluster flavour (docs/cluster/
// DESIGN.md D41, D44). A tenant administrator moves the tenant from
// platform-managed to tenant-managed by uploading its own 32-byte key,
// replaces the key, or hands it back. The request reaches one web replica; it
// forwards the key over the controller key endpoint (TLS 1.3) and never stores
// or logs it. The audit log records the fingerprint, never the key.

// KEKService is what the web tier needs from the controllers (keyclient.Client
// implements it). Keys travel as the base64 text the administrator entered.
type KEKService interface {
	Switch(ctx context.Context, tenant, kek, actor string) (keyserver.Response, error)
	Replace(ctx context.Context, tenant, oldKEK, newKEK, actor string) (keyserver.Response, error)
	Release(ctx context.Context, tenant, kek, actor string) (keyserver.Response, error)
	Unlock(ctx context.Context, tenant, kek string) (keyserver.Response, error)
	Status(ctx context.Context, tenant string) (mode, fingerprint string, unlocked, total int, err error)
}

var _ KEKService = (*keyclient.Client)(nil)

// kekWarning is part of every answer of the KEK API.
const kekWarning = "With your own key the platform operator cannot read your data, and nobody can recover it for you: if you lose the key (and its Shamir shares) your data is lost for good, backups included."

// kekBinding ties a tenant server to the KEK service and to the platform's
// record of the tenant.
type kekBinding struct {
	svc      KEKService
	tenantID string
	slug     string
	// state returns the platform record's KEK mode and fingerprint now.
	state func() (mode, fingerprint string)
}

// AttachKEK enables the KEK administration of this tenant server.
func (s *Server) AttachKEK(svc KEKService, tenantID, slug string, state func() (mode, fingerprint string)) {
	s.kek = &kekBinding{svc: svc, tenantID: tenantID, slug: slug, state: state}
}

func (s *Server) kekReady(w http.ResponseWriter) bool {
	if s.kek == nil || s.kek.svc == nil {
		jerr(w, http.StatusNotImplemented, "a tenant-supplied key is only available in the Cluster flavour")
		return false
	}
	return true
}

// kekStatus: GET /api/admin/kek. slug is what the administrator types to confirm an upload.
func (s *Server) kekStatus(w http.ResponseWriter, r *http.Request) {
	if s.kek == nil {
		jout(w, http.StatusOK, map[string]any{"supported": false, "mode": platform.KEKPlatform, "locked": false})
		return
	}
	mode, fp := s.kek.state()
	out := map[string]any{"supported": true, "mode": mode, "fingerprint": fp, "locked": false, "slug": s.kek.slug, "warning": kekWarning}
	// This tenant is open, so at least this replica's controller answered; the
	// controllers' own state shows whether every replica holds the key.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, _, unlocked, total, err := s.kek.svc.Status(ctx, s.kek.tenantID); err == nil {
		out["controllers_unlocked"], out["controllers_total"] = unlocked, total
		out["locked"] = mode == platform.KEKTenant && unlocked == 0
	}
	jout(w, http.StatusOK, out)
}

// kekPrecheck refuses a KEK operation while a key rotation job is open.
func (s *Server) kekPrecheck(w http.ResponseWriter, r *http.Request) bool {
	if !s.allowRequest("kek", keyOpsPerHour(), time.Hour) {
		jerr(w, http.StatusTooManyRequests, "too many key operations; try again later")
		return false
	}
	if s.keysEnabled() {
		if jobs, err := s.St.Repos().ColumnKeys().KeyJobs(r.Context(), keyJobLimit); err == nil {
			for _, p := range keyops.Purposes {
				if keyops.OpenJob(jobs, p) {
					jerr(w, http.StatusConflict, "a key rotation is still running; wait until it has finished")
					return false
				}
			}
		}
	}
	return true
}

// kekFail maps a KEK call's error to the API answer (no key material).
func (s *Server) kekFail(w http.ResponseWriter, err error, res keyserver.Response) {
	body := map[string]any{"ok": false, "steps": res.Steps}
	var ce *keyclient.CallError
	var ae *keyclient.AckError
	switch {
	case errors.Is(err, keyclient.ErrKEKRefused):
		body["error"] = "the key was refused: it does not match this organisation's key"
		jout(w, http.StatusForbidden, body)
	case errors.As(err, &ae):
		body["error"] = fmt.Sprintf("the operation succeeded, but only %d of %d controller replicas hold the key; present the key again on the unlock page of this organisation", ae.Acked, ae.Total)
		body["code"] = "partial_unlock"
		jout(w, http.StatusBadGateway, body)
	case errors.As(err, &ce) && ce.Status == http.StatusConflict:
		body["error"] = ce.Message
		jout(w, http.StatusConflict, body)
	case errors.As(err, &ce) && (ce.Status == http.StatusTooManyRequests || ce.Status == http.StatusUnprocessableEntity):
		body["error"] = ce.Message
		jout(w, ce.Status, body)
	case errors.As(err, &ce) && ce.Status == http.StatusBadRequest:
		body["error"] = ce.Message
		jout(w, http.StatusBadRequest, body)
	default:
		log.Printf("kek: %v", err)
		body["error"] = "the operation did not complete; it is safe to repeat it with the same key"
		jout(w, http.StatusBadGateway, body)
	}
}

// kekAudit records the steps and the outcome in the tenant's audit log.
func (s *Server) kekAudit(r *http.Request, action, failed string, res keyserver.Response, err error, detail string) {
	u := s.ctxUser(r)
	id, name := int64(0), "system"
	if u != nil {
		id, name = u.ID, u.Username
	}
	for _, step := range res.Steps {
		s.logEvent(id, name, "kek_step", "kek", step)
	}
	if err != nil {
		s.logEvent(id, name, failed, "kek", detail+": "+auditErr(err))
		return
	}
	s.logEvent(id, name, action, "kek", detail)
}

// auditErr is an error text for the audit log; it never holds a key, because
// no error of the key calls does.
func auditErr(err error) string {
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

func (s *Server) kekDone(w http.ResponseWriter, mode string, res keyserver.Response) {
	jout(w, http.StatusOK, map[string]any{"ok": true, "mode": mode, "fingerprint": res.Fingerprint, "steps": res.Steps, "warning": kekWarning})
}

// kekUpload: POST /api/admin/kek/upload {kek, confirm} (administrators,
// step-up). Switches the tenant from platform-managed to tenant-managed.
func (s *Server) kekUpload(w http.ResponseWriter, r *http.Request) {
	if !s.kekReady(w) {
		return
	}
	var b struct {
		KEK     string `json:"kek"`
		Confirm string `json:"confirm"`
	}
	if decode(r, &b) != nil {
		jerr(w, http.StatusBadRequest, "kek and confirm are required")
		return
	}
	if strings.TrimSpace(b.Confirm) != s.kek.slug {
		jerr(w, http.StatusBadRequest, "confirm must be the slug of this organisation ("+s.kek.slug+"): you acknowledge that losing the key loses the data")
		return
	}
	k, err := store.ParseTenantKEK(b.KEK)
	if err != nil {
		jerr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer clear(k)
	if mode, _ := s.kek.state(); mode == platform.KEKTenant {
		jerr(w, http.StatusConflict, "this organisation already uses its own key; use replace")
		return
	}
	if !s.kekPrecheck(w, r) {
		return
	}
	fp := store.TenantKEKFingerprint(k)
	actor := s.ctxUser(r).Username
	res, err := s.kek.svc.Switch(r.Context(), s.kek.tenantID, b.KEK, actor)
	s.kekAudit(r, "kek_switched", "kek_switch_failed", res, err, "key fingerprint "+fp)
	if err != nil {
		s.kekFail(w, err, res)
		return
	}
	s.kekDone(w, platform.KEKTenant, res)
}

// kekReplace: POST /api/admin/kek/replace {old_kek, new_kek} (administrators,
// step-up).
func (s *Server) kekReplace(w http.ResponseWriter, r *http.Request) {
	if !s.kekReady(w) {
		return
	}
	var b struct {
		Old string `json:"old_kek"`
		New string `json:"new_kek"`
	}
	if decode(r, &b) != nil {
		jerr(w, http.StatusBadRequest, "old_kek and new_kek are required")
		return
	}
	oldK, err := store.ParseTenantKEK(b.Old)
	if err != nil {
		jerr(w, http.StatusBadRequest, "old_kek: "+err.Error())
		return
	}
	defer clear(oldK)
	newK, err := store.ParseTenantKEK(b.New)
	if err != nil {
		jerr(w, http.StatusBadRequest, "new_kek: "+err.Error())
		return
	}
	defer clear(newK)
	if mode, _ := s.kek.state(); mode != platform.KEKTenant {
		jerr(w, http.StatusConflict, "this organisation does not use its own key; use upload")
		return
	}
	if !s.kekPrecheck(w, r) {
		return
	}
	detail := "old " + store.TenantKEKFingerprint(oldK) + " new " + store.TenantKEKFingerprint(newK)
	res, err := s.kek.svc.Replace(r.Context(), s.kek.tenantID, b.Old, b.New, s.ctxUser(r).Username)
	s.kekAudit(r, "kek_replaced", "kek_replace_failed", res, err, detail)
	if err != nil {
		s.kekFail(w, err, res)
		return
	}
	s.kekDone(w, platform.KEKTenant, res)
}

// kekRelease: POST /api/admin/kek/release {kek} (administrators, step-up).
// Back to platform-managed.
func (s *Server) kekRelease(w http.ResponseWriter, r *http.Request) {
	if !s.kekReady(w) {
		return
	}
	var b struct {
		KEK string `json:"kek"`
	}
	if decode(r, &b) != nil {
		jerr(w, http.StatusBadRequest, "kek is required")
		return
	}
	k, err := store.ParseTenantKEK(b.KEK)
	if err != nil {
		jerr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer clear(k)
	if mode, _ := s.kek.state(); mode != platform.KEKTenant {
		jerr(w, http.StatusConflict, "this organisation does not use its own key")
		return
	}
	if !s.kekPrecheck(w, r) {
		return
	}
	res, err := s.kek.svc.Release(r.Context(), s.kek.tenantID, b.KEK, s.ctxUser(r).Username)
	s.kekAudit(r, "kek_released", "kek_release_failed", res, err, "key fingerprint "+store.TenantKEKFingerprint(k))
	if err != nil {
		s.kekFail(w, err, res)
		return
	}
	s.kekDone(w, platform.KEKPlatform, res)
}
