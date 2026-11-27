// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/keyclient"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// A tenant-managed tenant is "locked" while the controllers do not hold its
// KEK: after a controller restart, after a restore, or when a controller has
// not been given the key. A locked tenant's database cannot be opened, so no
// session can be checked: the tenant's pages answer 423 and the only thing
// that works is presenting the key itself. The controller verifies it against
// the tenant's keyring (fingerprint and a successful unwrap of every key); only
// the right key unlocks. The endpoint is public, rate limited per address and
// per tenant, and audited in the platform audit log (D44).

const unlockPath = "/api/unlock"

type unlockBudget struct {
	count   int
	expires time.Time
}

const (
	unlockPerIP     = 10
	unlockPerTenant = 30
	unlockWindow    = 10 * time.Minute
)

// unlockAllow charges one attempt to (kind, key); false when the budget is spent.
func (h *TenantHost) unlockAllow(ctx context.Context, kind, key string, limit int) bool {
	if cl := h.cfg.Cluster; cl != nil && cl.Limiter != nil {
		n, err := cl.Limiter.Hit(ctx, "kek-unlock:"+kind, key, unlockWindow)
		if err == nil {
			return n <= limit
		}
		log.Printf("kek: unlock limiter: %v", err)
	}
	h.unlockMu.Lock()
	defer h.unlockMu.Unlock()
	if h.unlockHits == nil {
		h.unlockHits = map[string]*unlockBudget{}
	}
	now := time.Now()
	k := kind + "|" + key
	b := h.unlockHits[k]
	if b == nil || !now.Before(b.expires) {
		if len(h.unlockHits) > 8192 {
			clear(h.unlockHits)
		}
		b = &unlockBudget{expires: now.Add(unlockWindow)}
		h.unlockHits[k] = b
	}
	b.count++
	return b.count <= limit
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// serveUnlock handles GET (state) and POST {kek} on /api/unlock of a tenant.
func (h *TenantHost) serveUnlock(w http.ResponseWriter, r *http.Request, id string, route platform.Route) {
	noStore(w)
	t, err := h.P.Tenant(id)
	if err != nil || t.KEKMode != platform.KEKTenant {
		jerr(w, http.StatusNotFound, "this organisation does not use its own key")
		return
	}
	ip := h.console.clientIP(r)
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		_, _, unlocked, total, serr := h.cfg.KEK.Status(ctx, id)
		out := map[string]any{"tenant_managed": true, "fingerprint": t.KEKFingerprint, "locked": serr != nil || total == 0 || unlocked < total}
		if serr == nil {
			out["controllers_unlocked"], out["controllers_total"] = unlocked, total
		}
		jout(w, http.StatusOK, out)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, POST")
		jerr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		jerr(w, http.StatusUnsupportedMediaType, "send application/json")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if !h.unlockAllow(ctx, "ip", ip, unlockPerIP) || !h.unlockAllow(ctx, "tenant", id, unlockPerTenant) {
		w.Header().Set("Retry-After", "600")
		h.auditUnlock(route, "denied", "rate limited", ip)
		jerr(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return
	}
	var b struct {
		KEK string `json:"kek"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&b); err != nil {
		jerr(w, http.StatusBadRequest, "kek is required")
		return
	}
	k, err := store.ParseTenantKEK(b.KEK)
	if err != nil {
		jerr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer clear(k)
	fp := store.TenantKEKFingerprint(k)
	res, err := h.cfg.KEK.Unlock(ctx, id, b.KEK)
	var ae *keyclient.AckError
	switch {
	case err == nil:
		h.auditUnlock(route, "ok", "key fingerprint "+fp, ip)
		h.tenantUnlockedEvent(id, fp, ip)
		jout(w, http.StatusOK, map[string]any{"ok": true, "fingerprint": res.Fingerprint})
	case errors.Is(err, keyclient.ErrKEKRefused):
		h.auditUnlock(route, "failed", "wrong key (fingerprint "+fp+")", ip)
		jerr(w, http.StatusForbidden, "the key was refused")
	case errors.As(err, &ae):
		h.auditUnlock(route, "failed", fmt.Sprintf("only %d of %d controllers acknowledged", ae.Acked, ae.Total), ip)
		jout(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "not every controller replica accepted the key; present it again", "controllers_unlocked": ae.Acked, "controllers_total": ae.Total})
	default:
		log.Printf("kek: unlock of tenant %s: %v", route.Slug, err)
		h.auditUnlock(route, "failed", "controller error", ip)
		jerr(w, http.StatusBadGateway, "the key could not be checked; try again shortly")
	}
}

// auditUnlock records an unlock attempt in the platform audit log (the tenant's
// own cannot be written while it is locked). Never the key.
func (h *TenantHost) auditUnlock(route platform.Route, outcome, detail, ip string) {
	if err := h.P.Audit(0, "unlock", "tenant_unlock", "tenant#"+route.Slug, outcome, detail, ip); err != nil {
		log.Printf("kek: platform audit: %v", err)
	}
}

// tenantUnlockedEvent writes the unlock into the tenant's own audit log once it
// can be opened (best effort; the platform log has the record either way).
func (h *TenantHost) tenantUnlockedEvent(id, fp, ip string) {
	go func() {
		h.reloadOnMiss()
		_ = h.withTenant(id, func(s *Server) error {
			s.logEvent(0, "unlock", "kek_unlocked", "kek", "key fingerprint "+fp+" presented from "+ip)
			return nil
		})
	}()
}

// closeLocked closes the open tenant-managed tenants whose keys the
// controllers no longer hand out (a controller restarted: locked), so a locked
// tenant stops being served from this replica's memory. A web replica notices
// within the key client's cache lifetime.
func (h *TenantHost) closeLocked() {
	cl := h.cfg.Cluster
	if cl == nil || cl.KeyCheck == nil {
		return
	}
	for _, id := range h.OpenTenants() {
		t, err := h.P.Tenant(id)
		if err != nil || t.KEKMode != platform.KEKTenant {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = cl.KeyCheck(ctx, id)
		cancel()
		if errors.Is(err, ports.ErrLocked) {
			log.Printf("tenant %s: locked by the controllers; closing it here", t.Slug)
			h.reopen(id)
		}
	}
}

// lockedScript is the unlock page's only script; its hash is in the CSP.
const lockedScript = `document.getElementById('f').addEventListener('submit',async function(e){e.preventDefault();var m=document.getElementById('m');m.textContent='...';` +
	`try{var r=await fetch('/api/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kek:document.getElementById('k').value.trim()})});` +
	`var j=await r.json().catch(function(){return{}});if(r.ok){m.textContent='Unlocked. Reloading...';location.href='/';}else{m.textContent=j.error||('Error '+r.status);}}` +
	`catch(x){m.textContent='Network error';}});`

func lockedPageHTML() (page string, scriptHash string) {
	sum := sha256.Sum256([]byte(lockedScript))
	scriptHash = "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Locked</title>` +
		`<style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f8fafc;color:#0f172a}main{max-width:34rem;padding:2rem}input,button{font:inherit;padding:.5rem;width:100%;box-sizing:border-box;margin-top:.5rem}</style></head>` +
		`<body><main><h1>This organisation is locked</h1><p>Its data is protected with a key that only your organisation holds. Present that key to unlock it.</p>` +
		`<form id="f"><label for="k">Key (base64)</label><input id="k" type="password" autocomplete="off" required><button type="submit">Unlock</button></form><p id="m" role="status"></p>` +
		`<p lang="nl">Deze organisatie is vergrendeld. Voer de sleutel van uw organisatie in om te ontgrendelen.</p></main><script>` + lockedScript + `</script></body></html>`
	return
}

// serveLocked answers any request for a locked tenant with 423.
func (h *TenantHost) serveLocked(w http.ResponseWriter, r *http.Request, id string, route platform.Route) {
	noStore(w)
	w.Header().Set("Retry-After", "60")
	fp := ""
	if t, err := h.P.Tenant(id); err == nil {
		fp = t.KEKFingerprint
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		jout(w, http.StatusLocked, map[string]any{"error": "this organisation is locked: its key must be presented (POST /api/unlock)", "code": "tenant_locked", "fingerprint": fp})
		return
	}
	page, hash := lockedPageHTML()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src "+hash+"; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	w.WriteHeader(http.StatusLocked)
	io.WriteString(w, page)
}
