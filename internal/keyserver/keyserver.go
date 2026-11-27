// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keyserver is the controller's key endpoint of the Cluster flavour
// (docs/cluster/DESIGN.md D42). The master key exists only in controller
// pods; web replicas fetch exactly the derived material they need, over TLS
// 1.3, authenticated with a projected ServiceAccount token that the
// Kubernetes TokenReview API validates.
package keyserver

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// Labels of the secrets derived from the master key (store.DeriveKey).
const (
	LabelPlatformPassword = "sendora/v1/cluster/pg-password/platform"
	LabelTenantPassword   = "sendora/v1/cluster/pg-password/tenant/"
	LabelRateLimitKey     = "sendora/v1/cluster/rate-limit-key"
)

// Audience of the web replicas' projected tokens.
const Audience = "sendora-keys"

// ErrUnknownTenant is returned for a tenant that does not exist or is not
// active or suspended.
var ErrUnknownTenant = errors.New("unknown tenant")

// DerivedHex derives label from master as a hex string.
func DerivedHex(master []byte, label string) (string, error) {
	k, err := store.DeriveKey(master, label)
	if err != nil {
		return "", err
	}
	defer clear(k)
	return hex.EncodeToString(k), nil
}

// Local derives key material from the master key (controller replicas). It
// implements ports.ClusterKeys. Master is the key of masterkey.InfraVersion
// (platform material and database role passwords); a tenant's own keys come
// from P, which derives them from the master key version its record names
// (Platform.UseMasters, D46).
type Local struct {
	Master []byte
	// P supplies the tenants (legacy roots); set once the platform is open.
	P *platform.Platform
	// KEK holds the tenant-supplied KEKs unlocked on this controller (D44);
	// nil when none can be.
	KEK *KEKManager
}

// Platform implements ports.ClusterKeys.
func (l *Local) Platform(context.Context) (ports.PlatformKeys, error) {
	pw, err := DerivedHex(l.Master, LabelPlatformPassword)
	if err != nil {
		return ports.PlatformKeys{}, err
	}
	dk, err := store.PlatformDBKey(l.Master)
	if err != nil {
		return ports.PlatformKeys{}, err
	}
	defer clear(dk)
	rk, err := DerivedHex(l.Master, LabelRateLimitKey)
	if err != nil {
		return ports.PlatformKeys{}, err
	}
	return ports.PlatformKeys{DBPassword: pw, DBKey: hex.EncodeToString(dk), RateKey: rk}, nil
}

// Tenant implements ports.ClusterKeys. It serves any registered tenant; the
// HTTP handler restricts which ones web replicas may fetch.
func (l *Local) Tenant(_ context.Context, id string) (ports.TenantKeys, error) {
	if l.P == nil {
		return ports.TenantKeys{}, errors.New("platform not open")
	}
	t, err := l.P.Tenant(id)
	if errors.Is(err, platform.ErrNotFound) {
		return ports.TenantKeys{}, ErrUnknownTenant
	}
	if err != nil {
		return ports.TenantKeys{}, err
	}
	kek, err := l.kekFor(t)
	if err != nil {
		return ports.TenantKeys{}, err
	}
	pw, err := DerivedHex(l.Master, LabelTenantPassword+id)
	if err != nil {
		return ports.TenantKeys{}, err
	}
	dbKey, root, err := l.P.TenantKeys(t)
	if err != nil {
		return ports.TenantKeys{}, err
	}
	defer clear(dbKey)
	defer clear(root)
	out := ports.TenantKeys{DBPassword: pw, DBKey: hex.EncodeToString(dbKey), KEK: kek, MasterVersion: t.MasterVersion}
	if root != nil {
		out.Root = hex.EncodeToString(root)
	}
	return out, nil
}

// Config configures Handler.
type Config struct {
	Source ports.ClusterKeys
	Review ports.TokenReviewer
	// AllowedUser is the only user that may fetch keys, for example
	// system:serviceaccount:sendora-cluster:sendora-web.
	AllowedUser string
	// Status returns the tenant's status; platform.ErrNotFound (or
	// ErrUnknownTenant) for an unknown tenant.
	Status func(id string) (string, error)
	// Logf receives the audit log (default log.Printf); never key material.
	Logf func(string, ...any)
	// KEK runs the tenant-supplied KEK operations (D44); nil disables
	// /v1/kek/*.
	KEK *KEKManager
	// TenantRate is the sustained tenant requests per second allowed per
	// calling identity (default 20, burst 5x).
	TenantRate float64
	Now        func() time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

type handler struct {
	cfg Config
	mu  sync.Mutex
	b   map[string]*bucket
}

// Handler returns the endpoint's http.Handler: POST /v1/platform and
// POST /v1/tenant.
func Handler(cfg Config) http.Handler {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.TenantRate <= 0 {
		cfg.TenantRate = 20
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	h := &handler{cfg: cfg, b: map[string]*bucket{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/platform", h.platform)
	mux.HandleFunc("POST /v1/tenant", h.tenant)
	if cfg.KEK != nil {
		mux.HandleFunc("POST /v1/kek/unlock", h.kekUnlock)
		mux.HandleFunc("POST /v1/kek/lock", h.kekLock)
		mux.HandleFunc("POST /v1/kek/status", h.kekStatus)
		mux.HandleFunc("POST /v1/kek/switch", h.kekSwitch)
		mux.HandleFunc("POST /v1/kek/replace", h.kekReplace)
		mux.HandleFunc("POST /v1/kek/release", h.kekRelease)
	}
	return mux
}

// allow is a token bucket per key (identity, or "" for everything).
func (h *handler) allow(key string, rate float64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.cfg.Now()
	b := h.b[key]
	if b == nil {
		if len(h.b) > 4096 {
			clear(h.b)
		}
		b = &bucket{tokens: rate * 5, at: now}
		h.b[key] = b
	}
	b.tokens = min(b.tokens+now.Sub(b.at).Seconds()*rate, rate*5)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	} else {
		json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(code)})
	}
}

// auth authenticates the caller; on failure it has replied.
func (h *handler) auth(w http.ResponseWriter, r *http.Request) (ports.Identity, bool) {
	// Global limit first: it protects the API server from unauthenticated floods.
	if !h.allow("", 200) {
		reply(w, http.StatusTooManyRequests, nil)
		return ports.Identity{}, false
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	tok = strings.TrimSpace(tok)
	if !ok || tok == "" {
		reply(w, http.StatusUnauthorized, nil)
		return ports.Identity{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	id, err := h.cfg.Review.Review(ctx, tok, Audience)
	if err != nil {
		h.cfg.Logf("keys: %s %s: token rejected: %v", r.Method, r.URL.Path, err)
		reply(w, http.StatusUnauthorized, nil)
		return ports.Identity{}, false
	}
	if h.cfg.AllowedUser == "" || id.User != h.cfg.AllowedUser {
		h.cfg.Logf("keys: %s %s: user %q is not allowed (pod %q)", r.Method, r.URL.Path, id.User, id.Pod)
		reply(w, http.StatusForbidden, nil)
		return ports.Identity{}, false
	}
	return id, true
}

func (h *handler) platform(w http.ResponseWriter, r *http.Request) {
	id, ok := h.auth(w, r)
	if !ok {
		return
	}
	if !h.allow("platform|"+id.Pod, h.cfg.TenantRate) {
		reply(w, http.StatusTooManyRequests, nil)
		return
	}
	k, err := h.cfg.Source.Platform(r.Context())
	if err != nil {
		h.cfg.Logf("keys: platform keys for pod %q: %v", id.Pod, err)
		reply(w, http.StatusInternalServerError, nil)
		return
	}
	h.cfg.Logf("keys: platform keys served to pod %q", id.Pod)
	reply(w, http.StatusOK, k)
}

func (h *handler) tenant(w http.ResponseWriter, r *http.Request) {
	id, ok := h.auth(w, r)
	if !ok {
		return
	}
	if !h.allow("tenant|"+id.Pod, h.cfg.TenantRate) {
		h.cfg.Logf("keys: tenant request from pod %q rate limited", id.Pod)
		reply(w, http.StatusTooManyRequests, nil)
		return
	}
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || !store.TenantIDPattern.MatchString(req.TenantID) {
		reply(w, http.StatusBadRequest, nil)
		return
	}
	st, err := h.cfg.Status(req.TenantID)
	if err != nil || (st != platform.StatusActive && st != platform.StatusSuspended) {
		if err != nil && !errors.Is(err, platform.ErrNotFound) && !errors.Is(err, ErrUnknownTenant) {
			h.cfg.Logf("keys: tenant %s for pod %q: status: %v", req.TenantID, id.Pod, err)
			reply(w, http.StatusInternalServerError, nil)
			return
		}
		h.cfg.Logf("keys: tenant %s refused to pod %q (unknown or not active)", req.TenantID, id.Pod)
		reply(w, http.StatusNotFound, nil)
		return
	}
	k, err := h.cfg.Source.Tenant(r.Context(), req.TenantID)
	if errors.Is(err, ports.ErrLocked) {
		h.cfg.Logf("keys: tenant %s is locked on this controller (pod %q asked)", req.TenantID, id.Pod)
		reply(w, http.StatusLocked, nil)
		return
	}
	if err != nil {
		h.cfg.Logf("keys: tenant %s for pod %q: %v", req.TenantID, id.Pod, err)
		reply(w, http.StatusInternalServerError, nil)
		return
	}
	h.cfg.Logf("keys: tenant %s keys served to pod %q (%s)", req.TenantID, id.Pod, id.User)
	reply(w, http.StatusOK, k)
}

// TLSConfig serves the certificate in certFile/keyFile (re-read when the
// files change: cert-manager rotates them) with TLS 1.3 only.
func TLSConfig(certFile, keyFile string) (*tls.Config, error) {
	c := &certLoader{cert: certFile, key: keyFile}
	if _, err := c.get(nil); err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: c.get}, nil
}

type certLoader struct {
	cert, key string
	mu        sync.Mutex
	mod       time.Time
	cur       *tls.Certificate
}

func (c *certLoader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, err := os.Stat(c.cert)
	if err == nil && c.cur != nil && fi.ModTime().Equal(c.mod) {
		return c.cur, nil
	}
	pair, lerr := tls.LoadX509KeyPair(c.cert, c.key)
	if lerr != nil {
		if c.cur != nil {
			return c.cur, nil // keep serving the last good certificate
		}
		return nil, lerr
	}
	c.cur = &pair
	if fi != nil {
		c.mod = fi.ModTime()
	}
	return c.cur, nil
}
