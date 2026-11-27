// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keyclient is the web replicas' client of the controller's key
// endpoint (internal/keyserver, docs/cluster/DESIGN.md D42): TLS 1.3 with the
// server verified against a CA bundle, the projected ServiceAccount token as
// bearer, and a small TTL cache so the controller is asked once per tenant
// per TTL. It implements ports.ClusterKeys.
package keyclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// ErrDenied is returned when the controller refuses the request (bad token,
// wrong identity, unknown or inactive tenant).
var ErrDenied = errors.New("key endpoint denied the request")

// Config configures a Client.
type Config struct {
	URL       string        // https://host:port
	CAFile    string        // CA bundle that signed the endpoint's certificate
	TokenFile string        // projected ServiceAccount token (audience sendora-keys)
	TTL       time.Duration // cache lifetime (default 10 min)
	// LockedTTL is how long a "locked" answer (ports.ErrLocked) is remembered
	// for a tenant (default 1 s): requests for a locked tenant then answer
	// without asking a controller each time, which under load would exhaust
	// the key endpoint's rate limit (429) and turn the 423 into a 503.
	LockedTTL time.Duration
	HTTP      *http.Client // tests; overrides the TLS setup
	// Peers lists the base URLs (https://ip:port) of every controller replica
	// that is currently serving the key endpoint; the KEK calls that must
	// reach all controllers use it (D44). Default: the addresses the host of
	// URL resolves to (a headless Service lists every ready controller pod).
	Peers func(ctx context.Context) ([]string, error)
	Now   func() time.Time
}

type entry struct {
	body []byte // the response body; wiped on Close
	exp  time.Time
}

// Client fetches and caches derived key material.
type Client struct {
	cfg  Config
	http *http.Client

	pool *x509.CertPool // CA bundle (nil with Config.HTTP)

	mu     sync.Mutex
	cache  map[string]entry
	locked map[string]time.Time // key -> until when the "locked" answer is reused
	closed bool
}

// New validates cfg and prepares the TLS client.
func New(cfg Config) (*Client, error) {
	if !strings.HasPrefix(cfg.URL, "https://") {
		return nil, errors.New("key endpoint URL must be https://")
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	if cfg.TokenFile == "" {
		return nil, errors.New("key token file is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.LockedTTL <= 0 {
		cfg.LockedTTL = time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Client{cfg: cfg, http: cfg.HTTP, cache: map[string]entry{}, locked: map[string]time.Time{}}
	if c.http == nil {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("key endpoint CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("key endpoint CA file holds no certificate")
		}
		c.pool = pool
		c.http = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		}}
	}
	return c, nil
}

// Platform implements ports.ClusterKeys.
func (c *Client) Platform(ctx context.Context) (ports.PlatformKeys, error) {
	var k ports.PlatformKeys
	return k, c.get(ctx, "/v1/platform", "platform", nil, &k)
}

// Tenant implements ports.ClusterKeys.
func (c *Client) Tenant(ctx context.Context, id string) (ports.TenantKeys, error) {
	var k ports.TenantKeys
	return k, c.get(ctx, "/v1/tenant", "tenant/"+id, map[string]string{"tenant_id": id}, &k)
}

func (c *Client) get(ctx context.Context, path, key string, req any, out any) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("key client closed")
	}
	if e, ok := c.cache[key]; ok && c.cfg.Now().Before(e.exp) {
		err := json.Unmarshal(e.body, out)
		c.mu.Unlock()
		return err
	}
	if until, ok := c.locked[key]; ok {
		if c.cfg.Now().Before(until) {
			c.mu.Unlock()
			return ports.ErrLocked
		}
		delete(c.locked, key)
	}
	c.mu.Unlock()

	body, err := c.fetch(ctx, path, req)
	if err != nil {
		if errors.Is(err, ports.ErrLocked) {
			c.Forget(key) // the controller reports a lock: never serve a cached key for it
			c.mu.Lock()
			if !c.closed {
				c.locked[key] = c.cfg.Now().Add(c.cfg.LockedTTL)
			}
			c.mu.Unlock()
		}
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		clear(body)
		return fmt.Errorf("key endpoint: invalid response: %w", err)
	}
	c.mu.Lock()
	if old, ok := c.cache[key]; ok {
		clear(old.body)
	}
	if c.closed {
		clear(body)
	} else {
		c.cache[key] = entry{body: body, exp: c.cfg.Now().Add(c.cfg.TTL)}
	}
	c.mu.Unlock()
	return nil
}

func (c *Client) fetch(ctx context.Context, path string, req any) ([]byte, error) {
	status, data, err := c.post(ctx, c.http, c.cfg.URL, path, req)
	if err != nil {
		return nil, err
	}
	if err := statusError(status); err != nil {
		return nil, err
	}
	return data, nil
}

// statusError maps a key endpoint status to the client's errors (nil for 200).
func statusError(status int) error {
	switch {
	case status == http.StatusOK:
		return nil
	case status == http.StatusLocked:
		return ports.ErrLocked
	case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound:
		return fmt.Errorf("%w: %d %s", ErrDenied, status, http.StatusText(status))
	default:
		return fmt.Errorf("key endpoint: %d %s", status, http.StatusText(status))
	}
}

// post sends req as JSON to base+path with the projected token and returns the
// status and (limited) body.
func (c *Client) post(ctx context.Context, hc *http.Client, base, path string, req any) (int, []byte, error) {
	tok, err := os.ReadFile(c.cfg.TokenFile) // re-read: projected tokens rotate
	if err != nil {
		return 0, nil, fmt.Errorf("key token: %w", err)
	}
	var rd io.Reader = http.NoBody
	if req != nil {
		b, _ := json.Marshal(req)
		rd = bytes.NewReader(b)
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	hr.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	hr.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(hr)
	if err != nil {
		return 0, nil, fmt.Errorf("key endpoint: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, data, nil
}

// Forget drops the cached answer under key ("tenant/<id>", "platform"),
// including a remembered "locked" answer.
func (c *Client) Forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.locked, key)
	if e, ok := c.cache[key]; ok {
		clear(e.body)
		delete(c.cache, key)
	}
}

// ForgetTenant drops tenant id's cached keys (after the tenant's KEK changed
// or the tenant was locked).
func (c *Client) ForgetTenant(id string) { c.Forget("tenant/" + id) }

// Close wipes the cache; later calls fail.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.cache {
		clear(e.body)
		delete(c.cache, k)
	}
	clear(c.locked)
	c.closed = true
	return nil
}
