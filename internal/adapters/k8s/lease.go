// SPDX-License-Identifier: AGPL-3.0-or-later

// Package k8s holds the Kubernetes adapters of the Cluster flavour
// (docs/cluster/DESIGN.md 2A.2, 4.3): leader election of the controller
// Deployment with a coordination.k8s.io/v1 Lease, through a minimal REST
// client (standard library only, no client-go). The controller's
// ServiceAccount needs get, create and update on leases in its namespace.
package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Service-account files mounted into every pod with automountServiceAccountToken.
const (
	saDir           = "/var/run/secrets/kubernetes.io/serviceaccount"
	saTokenFile     = saDir + "/token"
	saCAFile        = saDir + "/ca.crt"
	saNamespaceFile = saDir + "/namespace"
)

// microTime is the Kubernetes MicroTime wire format.
const microTime = "2006-01-02T15:04:05.000000Z07:00"

// LeaseConfig configures a LeaseElector.
type LeaseConfig struct {
	// Name of the Lease object (for example "sendora-controller").
	Name string
	// Namespace of the Lease; empty = the pod's namespace (service account).
	Namespace string
	// Identity of this candidate (the pod name); must be unique.
	Identity string
	// LeaseDuration is how long a lease is valid without renewal (default
	// 15 s), RenewDeadline how long the leader keeps trying to renew before
	// it steps down (default 10 s), RetryPeriod the loop period (default 2 s).
	LeaseDuration, RenewDeadline, RetryPeriod time.Duration
	// APIServer is the API base URL; empty = in-cluster
	// (https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT).
	APIServer string
	// TokenFile and CAFile default to the mounted service account.
	TokenFile, CAFile string
	// Client overrides the HTTP client (tests); it must trust the API server.
	Client *http.Client
	// Logf receives leadership changes (default log.Printf).
	Logf func(string, ...any)
	// Now is the clock (tests); time.Now when nil.
	Now func() time.Time
}

// LeaseElector elects one leader among the candidates sharing a Lease. It
// implements postgres.Elector. The epoch is leaseTransitions + 1, which the
// API server's optimistic concurrency (resourceVersion) makes strictly
// increasing with every change of holder.
type LeaseElector struct {
	cfg    LeaseConfig
	client *http.Client
	base   string
	logf   func(string, ...any)
	now    func() time.Time

	mu        sync.Mutex
	leader    bool
	epoch     int64
	lastRenew time.Time // last successful renewal (leader)
	observed  string    // holder|renewTime|resourceVersion last seen
	observeAt time.Time // local time the record last changed (skew-free expiry)
	holder    string
}

// NewLeaseElector validates cfg and prepares the client; Run starts it.
func NewLeaseElector(cfg LeaseConfig) (*LeaseElector, error) {
	if cfg.Name == "" || cfg.Identity == "" {
		return nil, errors.New("lease: name and identity are required")
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = 15 * time.Second
	}
	if cfg.RenewDeadline <= 0 {
		cfg.RenewDeadline = 10 * time.Second
	}
	if cfg.RetryPeriod <= 0 {
		cfg.RetryPeriod = 2 * time.Second
	}
	if cfg.RenewDeadline >= cfg.LeaseDuration {
		return nil, errors.New("lease: the renew deadline must be shorter than the lease duration")
	}
	if cfg.TokenFile == "" {
		cfg.TokenFile = saTokenFile
	}
	if cfg.CAFile == "" {
		cfg.CAFile = saCAFile
	}
	if cfg.Namespace == "" {
		b, err := os.ReadFile(saNamespaceFile)
		if err != nil {
			return nil, fmt.Errorf("lease: namespace not configured and no service account: %w", err)
		}
		cfg.Namespace = strings.TrimSpace(string(b))
	}
	e := &LeaseElector{cfg: cfg, logf: cfg.Logf, now: cfg.Now, client: cfg.Client, base: cfg.APIServer}
	if e.logf == nil {
		e.logf = log.Printf
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.base == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("lease: not running in a cluster (KUBERNETES_SERVICE_HOST/PORT unset) and no API server configured")
		}
		e.base = "https://" + net.JoinHostPort(host, port)
	}
	if e.client == nil {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("lease: API server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("lease: API server CA file holds no certificate")
		}
		e.client = &http.Client{Timeout: cfg.RetryPeriod + 3*time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}}
	}
	return e, nil
}

// Leader implements postgres.Elector. A leader that could not renew within
// RenewDeadline is no longer the leader, even before the loop notices.
func (e *LeaseElector) Leader() (bool, int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.leader || e.now().Sub(e.lastRenew) > e.cfg.RenewDeadline {
		return false, 0
	}
	return true, e.epoch
}

// Holder returns the identity of the current holder as last observed.
func (e *LeaseElector) Holder() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.holder
}

// Run campaigns until ctx ends; then, when leading, it releases the Lease so
// another candidate takes over at once instead of after LeaseDuration.
func (e *LeaseElector) Run(ctx context.Context) {
	t := time.NewTicker(e.cfg.RetryPeriod)
	defer t.Stop()
	for {
		e.tryOnce(ctx)
		select {
		case <-ctx.Done():
			e.release()
			return
		case <-t.C:
		}
	}
}

type leaseSpec struct {
	HolderIdentity       *string `json:"holderIdentity,omitempty"`
	LeaseDurationSeconds *int32  `json:"leaseDurationSeconds,omitempty"`
	AcquireTime          *string `json:"acquireTime,omitempty"`
	RenewTime            *string `json:"renewTime,omitempty"`
	LeaseTransitions     *int32  `json:"leaseTransitions,omitempty"`
}

type lease struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   map[string]any `json:"metadata"`
	Spec       leaseSpec      `json:"spec"`
}

func (l *lease) resourceVersion() string {
	v, _ := l.Metadata["resourceVersion"].(string)
	return v
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (e *LeaseElector) path() string {
	return "/apis/coordination.k8s.io/v1/namespaces/" + url.PathEscape(e.cfg.Namespace) + "/leases"
}

// tryOnce reads the Lease and acquires or renews it when allowed.
func (e *LeaseElector) tryOnce(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, e.cfg.RetryPeriod+2*time.Second)
	defer cancel()
	now := e.now()
	cur, status, err := e.get(rctx)
	switch {
	case status == http.StatusNotFound:
		e.create(rctx, now)
		return
	case err != nil:
		e.logf("lease %s: read failed: %v", e.cfg.Name, err)
		e.checkDeadline()
		return
	}
	holder := str(cur.Spec.HolderIdentity)
	obs := holder + "|" + str(cur.Spec.RenewTime) + "|" + cur.resourceVersion()
	e.mu.Lock()
	if obs != e.observed {
		e.observed, e.observeAt = obs, now
	}
	e.holder = holder
	observeAt := e.observeAt
	e.mu.Unlock()
	dur := e.cfg.LeaseDuration
	if cur.Spec.LeaseDurationSeconds != nil && *cur.Spec.LeaseDurationSeconds > 0 {
		dur = time.Duration(*cur.Spec.LeaseDurationSeconds) * time.Second
	}
	transitions := int32(0)
	if cur.Spec.LeaseTransitions != nil {
		transitions = *cur.Spec.LeaseTransitions
	}
	mine := holder == e.cfg.Identity
	// Expiry is judged on the local clock from when this candidate last saw
	// the record change, never on the holder's timestamps (clock skew).
	expired := holder == "" || now.Sub(observeAt) > dur
	if !mine && !expired {
		e.setFollower(holder)
		return
	}
	ts := now.UTC().Format(microTime)
	secs := int32(e.cfg.LeaseDuration / time.Second)
	id := e.cfg.Identity
	next := *cur
	next.Spec.HolderIdentity = &id
	next.Spec.LeaseDurationSeconds = &secs
	next.Spec.RenewTime = &ts
	if !mine {
		transitions++
		next.Spec.AcquireTime = &ts
		next.Spec.LeaseTransitions = &transitions
	}
	if err := e.update(rctx, &next); err != nil {
		if !mine {
			e.setFollower(holder)
		} else {
			e.logf("lease %s: renewal failed: %v", e.cfg.Name, err)
			e.checkDeadline()
		}
		return
	}
	e.setLeader(int64(transitions)+1, now)
}

func (e *LeaseElector) create(ctx context.Context, now time.Time) {
	ts := now.UTC().Format(microTime)
	secs := int32(e.cfg.LeaseDuration / time.Second)
	id := e.cfg.Identity
	zero := int32(0)
	l := lease{APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Metadata: map[string]any{"name": e.cfg.Name, "namespace": e.cfg.Namespace},
		Spec: leaseSpec{HolderIdentity: &id, LeaseDurationSeconds: &secs, AcquireTime: &ts, RenewTime: &ts, LeaseTransitions: &zero}}
	if _, err := e.do(ctx, http.MethodPost, e.path(), &l, nil); err != nil {
		e.logf("lease %s: create failed: %v", e.cfg.Name, err)
		return
	}
	e.setLeader(1, now)
}

func (e *LeaseElector) setLeader(epoch int64, now time.Time) {
	e.mu.Lock()
	was := e.leader
	e.leader, e.epoch, e.lastRenew, e.holder = true, epoch, now, e.cfg.Identity
	e.mu.Unlock()
	if !was {
		e.logf("lease %s: %s is now the leader (epoch %d)", e.cfg.Name, e.cfg.Identity, epoch)
	}
}

func (e *LeaseElector) setFollower(holder string) {
	e.mu.Lock()
	was := e.leader
	e.leader, e.epoch, e.holder = false, 0, holder
	e.mu.Unlock()
	if was {
		e.logf("lease %s: %s lost the leadership to %q", e.cfg.Name, e.cfg.Identity, holder)
	}
}

// checkDeadline steps down when the last renewal is older than RenewDeadline.
func (e *LeaseElector) checkDeadline() {
	e.mu.Lock()
	stepDown := e.leader && e.now().Sub(e.lastRenew) > e.cfg.RenewDeadline
	if stepDown {
		e.leader, e.epoch = false, 0
	}
	e.mu.Unlock()
	if stepDown {
		e.logf("lease %s: %s could not renew within %s and stepped down", e.cfg.Name, e.cfg.Identity, e.cfg.RenewDeadline)
	}
}

// release hands the Lease back (empty holder, 1 s duration) when leading.
func (e *LeaseElector) release() {
	e.mu.Lock()
	leading := e.leader
	e.leader, e.epoch = false, 0
	e.mu.Unlock()
	if !leading {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cur, _, err := e.get(ctx)
	if err != nil || str(cur.Spec.HolderIdentity) != e.cfg.Identity {
		return
	}
	empty := ""
	one := int32(1)
	ts := e.now().UTC().Format(microTime)
	cur.Spec.HolderIdentity, cur.Spec.LeaseDurationSeconds, cur.Spec.RenewTime = &empty, &one, &ts
	if err := e.update(ctx, cur); err == nil {
		e.logf("lease %s: %s released the leadership", e.cfg.Name, e.cfg.Identity)
	}
}

func (e *LeaseElector) get(ctx context.Context) (*lease, int, error) {
	var l lease
	status, err := e.do(ctx, http.MethodGet, e.path()+"/"+url.PathEscape(e.cfg.Name), nil, &l)
	if err != nil {
		return nil, status, err
	}
	return &l, status, nil
}

// update replaces the Lease; the resourceVersion in l makes a concurrent
// change fail with 409 Conflict.
func (e *LeaseElector) update(ctx context.Context, l *lease) error {
	_, err := e.do(ctx, http.MethodPut, e.path()+"/"+url.PathEscape(e.cfg.Name), l, nil)
	return err
}

// do sends one request with the service-account token (re-read every time:
// projected tokens rotate).
func (e *LeaseElector) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.base+path, rd)
	if err != nil {
		return 0, err
	}
	if tok, err := os.ReadFile(e.cfg.TokenFile); err == nil {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	} else if e.cfg.Client == nil {
		return 0, fmt.Errorf("service account token: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return resp.StatusCode, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, msg)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}
