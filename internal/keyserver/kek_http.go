// SPDX-License-Identifier: AGPL-3.0-or-later

package keyserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/store"
)

// The key-presenting endpoints. A request body holds a KEK for a moment: it is
// decoded into a buffer that is cleared when the handler returns, never
// logged, never echoed. Responses carry fingerprints and step names only.

// MsgKeyRefused is the error text of a refused key (403).
const MsgKeyRefused = "the key was refused"

// Request is the body of the /v1/kek/* calls (JSON; fields not used by a call
// are ignored by it but unknown fields are refused).
type Request struct {
	TenantID string `json:"tenant_id"`
	KEK      string `json:"kek,omitempty"`
	OldKEK   string `json:"old_kek,omitempty"`
	NewKEK   string `json:"new_kek,omitempty"`
	Actor    string `json:"actor,omitempty"`
}

// Response is the answer of a /v1/kek/* call.
type Response struct {
	Fingerprint string   `json:"fingerprint,omitempty"`
	Steps       []string `json:"steps,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Unlocked    bool     `json:"unlocked,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// kekCall authenticates, rate-limits and decodes a /v1/kek/* request. On
// failure it has replied.
func (h *handler) kekCall(w http.ResponseWriter, r *http.Request) (Request, bool) {
	id, ok := h.auth(w, r)
	if !ok {
		return Request{}, false
	}
	if !h.allow("kek|"+id.Pod, h.cfg.TenantRate) {
		reply(w, http.StatusTooManyRequests, nil)
		return Request{}, false
	}
	var req Request
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || !store.TenantIDPattern.MatchString(req.TenantID) {
		reply(w, http.StatusBadRequest, nil)
		return Request{}, false
	}
	return req, true
}

// kekReply maps an operation's error to a status code and a message that
// holds no key material.
func (h *handler) kekReply(w http.ResponseWriter, what, tenant string, res Result, err error) {
	switch {
	case err == nil:
		reply(w, http.StatusOK, Response{Fingerprint: res.Fingerprint, Steps: res.Steps})
	case errors.Is(err, ErrWrongKEK):
		h.cfg.Logf("keys: %s of tenant %s: the key was refused", what, tenant)
		reply(w, http.StatusForbidden, Response{Error: MsgKeyRefused, Steps: res.Steps})
	case errors.Is(err, ErrTooManyAttempts):
		reply(w, http.StatusTooManyRequests, Response{Error: err.Error()})
	case errors.Is(err, ErrNotTenantManaged), errors.Is(err, ErrTenantManaged), errors.Is(err, ErrBusy):
		reply(w, http.StatusConflict, Response{Error: err.Error()})
	case errors.Is(err, ErrUnknownTenant), errors.Is(err, platform.ErrNotFound):
		reply(w, http.StatusNotFound, nil)
	case errors.Is(err, keyring.ErrBroken), errors.Is(err, keyring.ErrNoLog):
		h.cfg.Logf("keys: %s of tenant %s: the keyring does not verify: %v", what, tenant, err)
		reply(w, http.StatusUnprocessableEntity, Response{Error: "the tenant's control log does not verify", Steps: res.Steps})
	default:
		h.cfg.Logf("keys: %s of tenant %s failed: %v", what, tenant, err)
		reply(w, http.StatusInternalServerError, Response{Error: "the operation failed; it is safe to repeat", Steps: res.Steps})
	}
}

func (h *handler) kekCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 2*time.Minute)
}

// parse decodes one presented key and reports a bad one with a 400.
func parseKEK(w http.ResponseWriter, s string) ([]byte, bool) {
	k, err := store.ParseTenantKEK(s)
	if err != nil {
		reply(w, http.StatusBadRequest, Response{Error: err.Error()})
		return nil, false
	}
	return k, true
}

func (h *handler) kekUnlock(w http.ResponseWriter, r *http.Request) {
	req, ok := h.kekCall(w, r)
	if !ok {
		return
	}
	k, ok := parseKEK(w, req.KEK)
	if !ok {
		return
	}
	defer clear(k)
	ctx, cancel := h.kekCtx(r)
	defer cancel()
	fp, err := h.cfg.KEK.Unlock(ctx, req.TenantID, k)
	if err == nil {
		h.cfg.Logf("keys: tenant %s unlocked on this controller (KEK %s)", req.TenantID, fp)
	}
	h.kekReply(w, "unlock", req.TenantID, Result{Fingerprint: fp}, err)
}

func (h *handler) kekLock(w http.ResponseWriter, r *http.Request) {
	req, ok := h.kekCall(w, r)
	if !ok {
		return
	}
	h.cfg.KEK.Lock(req.TenantID)
	h.cfg.Logf("keys: tenant %s locked on this controller", req.TenantID)
	reply(w, http.StatusOK, Response{})
}

func (h *handler) kekStatus(w http.ResponseWriter, r *http.Request) {
	req, ok := h.kekCall(w, r)
	if !ok {
		return
	}
	t, err := h.cfg.KEK.P.Tenant(req.TenantID)
	if err != nil {
		h.kekReply(w, "status", req.TenantID, Result{}, err)
		return
	}
	reply(w, http.StatusOK, Response{Mode: t.KEKMode, Fingerprint: t.KEKFingerprint, Unlocked: t.KEKMode != platform.KEKTenant || h.cfg.KEK.Unlocked(t.ID)})
}

func (h *handler) kekSwitch(w http.ResponseWriter, r *http.Request) {
	req, ok := h.kekCall(w, r)
	if !ok {
		return
	}
	k, ok := parseKEK(w, req.KEK)
	if !ok {
		return
	}
	defer clear(k)
	ctx, cancel := h.kekCtx(r)
	defer cancel()
	res, err := h.cfg.KEK.Switch(ctx, req.TenantID, k, req.Actor)
	h.kekReply(w, "switch", req.TenantID, res, err)
}

func (h *handler) kekReplace(w http.ResponseWriter, r *http.Request) {
	req, ok := h.kekCall(w, r)
	if !ok {
		return
	}
	oldK, ok := parseKEK(w, req.OldKEK)
	if !ok {
		return
	}
	defer clear(oldK)
	newK, ok := parseKEK(w, req.NewKEK)
	if !ok {
		return
	}
	defer clear(newK)
	ctx, cancel := h.kekCtx(r)
	defer cancel()
	res, err := h.cfg.KEK.Replace(ctx, req.TenantID, oldK, newK, req.Actor)
	h.kekReply(w, "replace", req.TenantID, res, err)
}

func (h *handler) kekRelease(w http.ResponseWriter, r *http.Request) {
	req, ok := h.kekCall(w, r)
	if !ok {
		return
	}
	k, ok := parseKEK(w, req.KEK)
	if !ok {
		return
	}
	defer clear(k)
	ctx, cancel := h.kekCtx(r)
	defer cancel()
	res, err := h.cfg.KEK.Release(ctx, req.TenantID, k, req.Actor)
	h.kekReply(w, "release", req.TenantID, res, err)
}
