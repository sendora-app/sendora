// SPDX-License-Identifier: AGPL-3.0-or-later

package keyclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/keyserver"
)

// Presenting a tenant's KEK (docs/cluster/DESIGN.md D44). The KEK travels over
// the key endpoint's TLS 1.3 connection to the controllers and is never
// stored: an unlock must reach EVERY controller replica (each keeps the key in
// its own memory), so these calls address each replica by IP, not the
// Service's virtual address.

// Errors of the KEK calls.
var (
	// ErrKEKRefused: a controller refused the presented key.
	ErrKEKRefused = errors.New("the key was refused")
	// ErrNoControllers: the key endpoint lists no controller.
	ErrNoControllers = errors.New("no controller replica is reachable")
)

// CallError is an error answer of a controller with its status and message
// (never key material).
type CallError struct {
	Status  int
	Message string
}

func (e *CallError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("key endpoint: %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("key endpoint: %d %s", e.Status, http.StatusText(e.Status))
}

// AckError reports that not every controller replica acknowledged a call that
// must reach all of them. The operation on the replicas that did acknowledge
// has taken effect.
type AckError struct {
	Acked, Total int
	Failed       []string // addresses (no secrets)
	Cause        error
}

func (e *AckError) Error() string {
	return fmt.Sprintf("only %d of %d controller replicas acknowledged (%s): %v", e.Acked, e.Total, strings.Join(e.Failed, ", "), e.Cause)
}

func (e *AckError) Unwrap() error { return e.Cause }

// peers lists the controller replicas.
func (c *Client) peers(ctx context.Context) ([]string, error) {
	if c.cfg.Peers != nil {
		return c.cfg.Peers(ctx)
	}
	u, err := url.Parse(c.cfg.URL)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolving the controllers: %w", err)
	}
	sort.Strings(addrs)
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, "https://"+net.JoinHostPort(a, port))
	}
	return out, nil
}

// peerClient is the HTTP client for one replica address: the certificate is
// still checked against the Service's host name.
func (c *Client) peerClient() *http.Client {
	if c.pool == nil {
		return c.http // tests supply their own
	}
	u, _ := url.Parse(c.cfg.URL)
	return &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: c.pool, MinVersion: tls.VersionTLS13, ServerName: u.Hostname()},
	}}
}

// call posts req to one replica and decodes the answer.
func (c *Client) call(ctx context.Context, hc *http.Client, base, path string, req any) (keyserver.Response, error) {
	var out keyserver.Response
	status, body, err := c.post(ctx, hc, base, path, req)
	if err != nil {
		return out, err
	}
	_ = json.Unmarshal(body, &out)
	switch status {
	case http.StatusOK:
		return out, nil
	case http.StatusForbidden:
		if out.Error == keyserver.MsgKeyRefused { // the endpoint's own answer, not an auth failure
			return out, ErrKEKRefused
		}
	}
	return out, &CallError{Status: status, Message: out.Error}
}

// fanOut sends req to every replica concurrently and requires every one to
// answer 200. It returns the first successful answer.
func (c *Client) fanOut(ctx context.Context, path string, req any) (keyserver.Response, error) {
	var first keyserver.Response
	peers, err := c.peers(ctx)
	if err != nil {
		return first, err
	}
	if len(peers) == 0 {
		return first, ErrNoControllers
	}
	hc := c.peerClient()
	type result struct {
		peer string
		res  keyserver.Response
		err  error
	}
	results := make([]result, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.call(ctx, hc, p, path, req)
			results[i] = result{p, res, err}
		}()
	}
	wg.Wait()
	var failed []string
	var cause error
	acked := 0
	for _, r := range results {
		if r.err == nil {
			if acked == 0 {
				first = r.res
			}
			acked++
			continue
		}
		failed = append(failed, hostOf(r.peer))
		if cause == nil || errors.Is(r.err, ErrKEKRefused) {
			cause = r.err
		}
	}
	if acked == len(peers) {
		return first, nil
	}
	if errors.Is(cause, ErrKEKRefused) && acked == 0 {
		return first, ErrKEKRefused
	}
	return first, &AckError{Acked: acked, Total: len(peers), Failed: failed, Cause: cause}
}

func hostOf(base string) string {
	if u, err := url.Parse(base); err == nil {
		return u.Host
	}
	return base
}

// one sends req to one replica (the first that is reachable).
func (c *Client) one(ctx context.Context, path string, req any) (keyserver.Response, error) {
	peers, err := c.peers(ctx)
	if err != nil {
		return keyserver.Response{}, err
	}
	if len(peers) == 0 {
		return keyserver.Response{}, ErrNoControllers
	}
	hc := c.peerClient()
	var last error
	for _, p := range peers {
		res, err := c.call(ctx, hc, p, path, req)
		var ce *CallError
		if err == nil || errors.Is(err, ErrKEKRefused) || errors.As(err, &ce) {
			return res, err // the replica answered: that answer stands
		}
		last = err // not reachable: try the next one
	}
	return keyserver.Response{}, last
}

// Unlock presents tenant's KEK to every controller replica. All must accept
// it (an AckError names the ones that did not; those stay locked for the
// tenant until unlocked again).
func (c *Client) Unlock(ctx context.Context, tenant, kek string) (keyserver.Response, error) {
	res, err := c.fanOut(ctx, "/v1/kek/unlock", keyserver.Request{TenantID: tenant, KEK: kek})
	c.ForgetTenant(tenant)
	return res, err
}

// Lock makes every controller replica forget tenant's KEK.
func (c *Client) Lock(ctx context.Context, tenant string) error {
	_, err := c.fanOut(ctx, "/v1/kek/lock", keyserver.Request{TenantID: tenant})
	c.ForgetTenant(tenant)
	return err
}

// Status asks every replica whether tenant is unlocked on it and returns how
// many are, of how many.
func (c *Client) Status(ctx context.Context, tenant string) (mode, fingerprint string, unlocked, total int, err error) {
	peers, err := c.peers(ctx)
	if err != nil {
		return "", "", 0, 0, err
	}
	hc := c.peerClient()
	for _, p := range peers {
		total++
		res, e := c.call(ctx, hc, p, "/v1/kek/status", keyserver.Request{TenantID: tenant})
		if e != nil {
			continue
		}
		mode, fingerprint = res.Mode, res.Fingerprint
		if res.Unlocked {
			unlocked++
		}
	}
	if total > 0 && mode == "" {
		err = errors.New("no controller answered")
	}
	return
}

// Switch moves the tenant to the tenant-supplied KEK (one controller does the
// hand-over), then unlocks every replica with it.
func (c *Client) Switch(ctx context.Context, tenant, kek, actor string) (keyserver.Response, error) {
	res, err := c.one(ctx, "/v1/kek/switch", keyserver.Request{TenantID: tenant, KEK: kek, Actor: actor})
	if err != nil {
		return res, err
	}
	c.ForgetTenant(tenant)
	if _, uerr := c.fanOut(ctx, "/v1/kek/unlock", keyserver.Request{TenantID: tenant, KEK: kek}); uerr != nil {
		return res, fmt.Errorf("the key was switched but not every controller took it up: %w", uerr)
	}
	return res, nil
}

// Replace swaps the tenant's KEK and unlocks every replica with the new one.
func (c *Client) Replace(ctx context.Context, tenant, oldKEK, newKEK, actor string) (keyserver.Response, error) {
	res, err := c.one(ctx, "/v1/kek/replace", keyserver.Request{TenantID: tenant, OldKEK: oldKEK, NewKEK: newKEK, Actor: actor})
	if err != nil {
		return res, err
	}
	c.ForgetTenant(tenant)
	if _, uerr := c.fanOut(ctx, "/v1/kek/unlock", keyserver.Request{TenantID: tenant, KEK: newKEK}); uerr != nil {
		return res, fmt.Errorf("the key was replaced but not every controller took it up: %w", uerr)
	}
	return res, nil
}

// Release returns the tenant to the platform's KEK and makes every replica
// forget the tenant's.
func (c *Client) Release(ctx context.Context, tenant, kek, actor string) (keyserver.Response, error) {
	res, err := c.one(ctx, "/v1/kek/release", keyserver.Request{TenantID: tenant, KEK: kek, Actor: actor})
	if err != nil {
		return res, err
	}
	c.ForgetTenant(tenant)
	if lerr := c.Lock(ctx, tenant); lerr != nil {
		return res, fmt.Errorf("the key was released but not every controller forgot it: %w", lerr)
	}
	return res, nil
}
