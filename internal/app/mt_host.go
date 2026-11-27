// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sendora-app/sendora/internal/netguard"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/storage"
	"github.com/sendora-app/sendora/internal/store"
)

// Multi-tenant mode (SENDORA_MULTI_TENANT=true, docs/MULTI-TENANT.md).
//
// One process serves many tenants. TenantHost routes every request by its
// host: <slug>.<base domain> or a verified custom domain goes to that tenant's
// own *Server (own store, keys and secrets); admin.<base domain> goes to the
// platform console; any other host gets a plain 404, so hosts cannot be used
// to find out which tenants exist. Tenant servers are opened on the first
// request and closed when idle (least recently used first when the maximum
// number of open tenants is reached).

// MultiTenantConfig configures a TenantHost.
type MultiTenantConfig struct {
	Platform *platform.Platform
	// BaseDomain is SENDORA_BASE_DOMAIN: host name with an optional :port that
	// is only used to build URLs (e.g. "localhost:9090" for local testing).
	BaseDomain      string
	Static          fs.FS
	Version         string
	TrustedProxies  []*net.IPNet
	ForceLocalLogin bool
	// Managed are the platform settings set by the environment (read-only in the console).
	Managed map[string]bool
	// Cluster is set by a Cluster replica (web or controller; cluster.go):
	// tenant stores live in PostgreSQL and state is shared across replicas.
	Cluster *ClusterRuntime
	// KEK talks to the controllers about tenant-supplied keys (D44): the
	// admin API of a tenant-managed tenant and the unlock endpoint of a
	// locked one. nil: the Cluster flavour is not in use.
	KEK KEKService
}

// TenantHost serves all tenants and the platform console.
type TenantHost struct {
	cfg      MultiTenantConfig
	P        *platform.Platform
	baseHost string // without port
	basePort string // ":9090" or ""
	scheme   string
	console  *platformConsole

	mu       sync.Mutex
	open     map[string]*tenantEntry
	opening  map[string]chan struct{}
	closing  map[string]chan struct{}
	deleting map[string]bool
	jobsCtx  context.Context
	shutdown bool

	now func() time.Time
	// restartFn is set by main: orderly stop, then restart (Platform settings).
	restartFn func()
	// portWarned: the missing-port warning was logged (warnPortOnce).
	portWarned atomic.Bool
	// openBackend opens object storage backends (storage.Open; tests replace it).
	openBackend func(context.Context, storage.Config) (storage.Backend, error)
	// unsubscribe ends the Cluster routing subscription (Shutdown).
	unsubscribe func()
	// missMu and missAt bound reloadOnMiss (Cluster).
	missMu sync.Mutex
	missAt time.Time
	// unlockMu and unlockHits throttle the public unlock endpoint when no shared limiter exists.
	unlockMu   sync.Mutex
	unlockHits map[string]*unlockBudget
	// keyRefreshMu and keyRefreshAt bound the key refetch of openStore (Cluster).
	keyRefreshMu sync.Mutex
	keyRefreshAt map[string]time.Time
}

// keyRefreshEvery is the shortest interval between two refetches of one
// tenant's keys after ports.ErrUnknownKEK: it keeps a tenant whose keys really
// do not open its keyring from sending every request on to the controllers.
var keyRefreshEvery = 5 * time.Second

// keyRefreshDue reports whether tenant id's keys may be fetched again now, and
// records the attempt when they may.
func (h *TenantHost) keyRefreshDue(id string) bool {
	h.keyRefreshMu.Lock()
	defer h.keyRefreshMu.Unlock()
	now := time.Now()
	if last, ok := h.keyRefreshAt[id]; ok && now.Sub(last) < keyRefreshEvery {
		return false
	}
	if h.keyRefreshAt == nil {
		h.keyRefreshAt = map[string]time.Time{}
	}
	for k, at := range h.keyRefreshAt { // keep the map small
		if now.Sub(at) >= keyRefreshEvery {
			delete(h.keyRefreshAt, k)
		}
	}
	h.keyRefreshAt[id] = now
	return true
}

type tenantEntry struct {
	id      string
	fp      string // tenantFingerprint at open (Cluster: reopen when it changes)
	srv     *Server
	handler http.Handler
	cancel  context.CancelFunc
	refs    int
	last    time.Time
}

var (
	errTenantsBusy    = errors.New("too many tenants are open; try again shortly")
	errTenantUnusable = errors.New("tenant unavailable")
)

// NewTenantHost prepares multi-tenant serving; Start begins the background jobs.
func NewTenantHost(cfg MultiTenantConfig) (*TenantHost, error) {
	base := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.BaseDomain), "."))
	if base == "" {
		return nil, errors.New("SENDORA_BASE_DOMAIN is required in multi-tenant mode")
	}
	host, port := base, ""
	if h, p, err := net.SplitHostPort(base); err == nil {
		host, port = h, ":"+p
	}
	if _, ok := platform.NormalizeDomain("x." + host); !ok {
		return nil, fmt.Errorf("SENDORA_BASE_DOMAIN %q is not a valid host name", cfg.BaseDomain)
	}
	h := &TenantHost{cfg: cfg, P: cfg.Platform, baseHost: host, basePort: port, scheme: "https",
		open: map[string]*tenantEntry{}, opening: map[string]chan struct{}{}, closing: map[string]chan struct{}{}, deleting: map[string]bool{},
		jobsCtx: context.Background(), now: time.Now, openBackend: storage.Open}
	if loopbackHost(host) {
		h.scheme = "http"
	}
	h.console = newPlatformConsole(h)
	if cl := cfg.Cluster; cl != nil {
		h.P.OnChange = func() {
			if err := cl.Coordinator.Notify(context.Background(), TopicRoutes); err != nil {
				log.Printf("cluster: routing notification: %v", err)
			}
		}
		ch, unsub := cl.Coordinator.Subscribe(TopicRoutes)
		h.unsubscribe = unsub
		go func() {
			for range ch {
				h.revalidate()
			}
		}()
	}
	return h, nil
}

// revalidate re-reads the routing data after another replica changed it and
// reopens every open tenant whose platform record or storage changed (status,
// quotas, domains, network policy, storage), as the replica that made the
// change does for itself.
func (h *TenantHost) revalidate() {
	if err := h.P.Reload(); err != nil {
		log.Printf("cluster: reloading the routing data: %v", err)
		return
	}
	h.mu.Lock()
	open := make(map[string]string, len(h.open))
	for id, e := range h.open {
		open[id] = e.fp
	}
	h.mu.Unlock()
	for id, fp := range open {
		t, err := h.P.Tenant(id)
		if err != nil {
			h.reopen(id)
			continue
		}
		sc, err := h.P.Storage(id)
		if err != nil || tenantFingerprint(t, sc) != fp {
			h.reopen(id)
		}
	}
}

// reloadOnMiss re-reads the routing data once for a host this Cluster replica
// does not know (yet): another replica may have just created the tenant and
// the notification reaches web replicas only through version polling. At
// most one reload per second per replica, so unknown hosts cannot turn into
// a query flood; concurrent misses wait for the reload in progress. It
// reports whether the caller should look the host up again.
func (h *TenantHost) reloadOnMiss() bool {
	if h.cfg.Cluster == nil {
		return false
	}
	h.missMu.Lock()
	defer h.missMu.Unlock()
	if time.Since(h.missAt) < time.Second {
		return true // reloaded a moment ago (possibly while this request waited)
	}
	h.missAt = time.Now()
	if err := h.P.Reload(); err != nil {
		log.Printf("cluster: reloading the routing data for an unknown host: %v", err)
		return false
	}
	return true
}

// openStore opens tenant t's store: its SQLCipher file, or in the Cluster
// flavour its PostgreSQL database.
func (h *TenantHost) openStore(t *platform.Tenant) (*store.Store, error) {
	dir, err := h.P.TenantDir(t.ID)
	if err != nil {
		return nil, err
	}
	if h.cfg.Cluster != nil && h.cfg.Cluster.Fresh != nil {
		h.cfg.Cluster.Fresh(t)
	}
	st, err := h.openStoreWithKeys(t, dir)
	// Cluster: a KEK switch or replacement through another replica leaves this
	// replica's cached keys without the tenant's new KEK. Fetch them again
	// instead of failing until the cache expires.
	if err != nil && errors.Is(err, ports.ErrUnknownKEK) && h.cfg.Cluster != nil && h.cfg.Cluster.ForgetKeys != nil && h.keyRefreshDue(t.ID) {
		h.cfg.Cluster.ForgetKeys(t.ID)
		st, err = h.openStoreWithKeys(t, dir)
	}
	return st, err
}

func (h *TenantHost) openStoreWithKeys(t *platform.Tenant, dir string) (*store.Store, error) {
	dbKey, root, err := h.P.TenantKeys(t)
	if err != nil {
		return nil, err
	}
	defer clear(dbKey)
	defer clear(root)
	if h.cfg.Cluster != nil {
		if root == nil {
			root = append([]byte(nil), dbKey...)
		}
		return h.cfg.Cluster.OpenStore(t, dir, root)
	}
	return store.OpenTenant(dir, dbKey, root, false)
}

// ConsoleHost is the platform console's host name.
func (h *TenantHost) ConsoleHost() string { return "admin." + h.baseHost }

// ConsoleURL is the platform console's public URL.
func (h *TenantHost) ConsoleURL() string { return h.scheme + "://" + h.ConsoleHost() + h.basePort }

// tenantURL is the public URL of a tenant: its primary custom domain (https)
// or its subdomain.
func (h *TenantHost) tenantURL(r platform.Route) string {
	if r.PrimaryDomain != "" {
		return "https://" + r.PrimaryDomain
	}
	return h.scheme + "://" + platform.SubdomainHost(r.Slug, h.baseHost) + h.basePort
}

func (h *TenantHost) primaryHost(r platform.Route) string {
	if r.PrimaryDomain != "" {
		return r.PrimaryDomain
	}
	return platform.SubdomainHost(r.Slug, h.baseHost)
}

func (h *TenantHost) peerTrusted(r *http.Request) bool {
	ip := net.ParseIP(peerHost(r))
	if ip == nil {
		return false
	}
	for _, n := range h.cfg.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// requestHost is the host the client asked for: X-Forwarded-Host only from a
// trusted proxy, otherwise the Host header. It returns the raw value (with
// port) and the normalised host name (lowercase, no port, no trailing dot).
func (h *TenantHost) requestHost(r *http.Request) (raw, host string) {
	raw = r.Host
	if h.peerTrusted(r) {
		if xf := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); xf != "" {
			raw = xf
		}
	}
	host = raw
	if hh, _, err := net.SplitHostPort(raw); err == nil {
		host = hh
	}
	return raw, strings.TrimSuffix(strings.ToLower(host), ".")
}

func plainNotFound(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.Error(w, "404 page not found", http.StatusNotFound)
}

const suspendedPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Unavailable</title>` +
	`<style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f8fafc;color:#0f172a}main{max-width:32rem;padding:2rem;text-align:center}</style></head>` +
	`<body><main><h1>Temporarily unavailable</h1><p>This service is currently not available. Please contact your administrator.</p>` +
	`<p lang="nl">Deze dienst is op dit moment niet beschikbaar. Neem contact op met je beheerder.</p></main></body></html>`

// ServeHTTP routes a request by host.
func (h *TenantHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, host := h.requestHost(r)
	h.warnPortOnce(raw)
	// The container health check and orchestrator probes use any host.
	if r.URL.Path == "/api/health" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		jout(w, 200, map[string]any{"status": "ok"})
		return
	}
	if host == h.ConsoleHost() {
		h.console.ServeHTTP(w, r)
		return
	}
	id, ok := h.P.TenantForHost(host, h.baseHost)
	route, routed := h.P.RouteOf(id)
	if (!ok || !routed || route.Status == platform.StatusImporting) && h.reloadOnMiss() {
		// Cluster: the tenant may have been created (or provisioned) on
		// another replica since this one last heard of it.
		id, ok = h.P.TenantForHost(host, h.baseHost)
		route, routed = h.P.RouteOf(id)
	}
	if !ok {
		plainNotFound(w)
		return
	}
	ok = routed
	h.mu.Lock()
	deleting := h.deleting[id]
	h.mu.Unlock()
	if !ok || deleting || route.Status == platform.StatusImporting {
		plainNotFound(w)
		return
	}
	if route.Status != platform.StatusActive {
		w.Header().Set("Retry-After", "3600")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			jerr(w, http.StatusServiceUnavailable, "this organisation is suspended")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(suspendedPage))
		return
	}
	// One origin per tenant: cookies, WebAuthn and emailed links all use the
	// primary host; other hosts of the same tenant redirect there.
	if host != h.primaryHost(route) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			http.Redirect(w, r, h.tenantURL(route)+r.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}
		jerr(w, http.StatusMisdirectedRequest, "use the organisation's primary address")
		return
	}
	// A locked tenant (tenant-managed key not presented, D44) offers only the
	// unlock endpoint; everything else answers 423.
	if r.URL.Path == unlockPath && h.cfg.KEK != nil {
		h.serveUnlock(w, r, id, route)
		return
	}
	e, err := h.acquire(id)
	if err != nil {
		if errors.Is(err, ports.ErrLocked) {
			h.serveLocked(w, r, id, route)
			return
		}
		if errors.Is(err, errTenantsBusy) {
			w.Header().Set("Retry-After", "5")
		}
		log.Printf("tenant %s: %v", route.Slug, err)
		jerr(w, http.StatusServiceUnavailable, "temporarily unavailable; try again shortly")
		return
	}
	defer h.release(e, false)
	r.Host = raw
	e.handler.ServeHTTP(w, r)
}

// warnPortOnce logs once when requests arrive on a non-default port while the
// base domain has none: every generated link (emails, redirects) lacks it.
func (h *TenantHost) warnPortOnce(rawHost string) {
	if h.basePort != "" || h.portWarned.Load() {
		return
	}
	if _, p, err := net.SplitHostPort(rawHost); err == nil && p != "80" && p != "443" && h.portWarned.CompareAndSwap(false, true) {
		log.Printf("WARNING: requests arrive on port %s but the base domain %q has no port: generated links lack it. Set the base domain to %s:%s (console Platform settings or SENDORA_BASE_DOMAIN), or serve the platform on 80/443 behind a proxy", p, h.baseHost, h.baseHost, p)
	}
}

// acquire returns the open tenant, opening it when needed, with a reference
// that release gives back. Concurrent requests for a closed tenant open it once.
func (h *TenantHost) acquire(id string) (*tenantEntry, error) {
	for {
		h.mu.Lock()
		if h.shutdown || h.deleting[id] {
			h.mu.Unlock()
			return nil, errTenantUnusable
		}
		if e := h.open[id]; e != nil {
			e.refs++
			e.last = h.now()
			h.mu.Unlock()
			return e, nil
		}
		if ch := h.opening[id]; ch != nil {
			h.mu.Unlock()
			<-ch
			continue
		}
		if ch := h.closing[id]; ch != nil {
			h.mu.Unlock()
			<-ch
			continue
		}
		var victim *tenantEntry
		if len(h.open)+len(h.opening) >= h.maxOpen() {
			for _, e := range h.open {
				if e.refs == 0 && (victim == nil || e.last.Before(victim.last)) {
					victim = e
				}
			}
			if victim == nil {
				h.mu.Unlock()
				return nil, errTenantsBusy
			}
			delete(h.open, victim.id)
			h.closing[victim.id] = make(chan struct{})
		}
		ch := make(chan struct{})
		h.opening[id] = ch
		h.mu.Unlock()
		if victim != nil {
			h.finishClose(victim)
		}
		e, err := h.openTenant(id)
		h.mu.Lock()
		delete(h.opening, id)
		close(ch)
		if err != nil {
			h.mu.Unlock()
			return nil, err
		}
		e.refs, e.last = 1, h.now()
		h.open[id] = e
		h.mu.Unlock()
		return e, nil
	}
}

// release gives a reference back; idleNow lets the reaper close the tenant
// at its next run (used by the maintenance sweep).
func (h *TenantHost) release(e *tenantEntry, idleNow bool) {
	h.mu.Lock()
	e.refs--
	if idleNow {
		e.last = time.Time{}
	} else {
		e.last = h.now()
	}
	h.mu.Unlock()
}

// The settings are validated when saved; the clamps keep a tampered or
// out-of-range value from overflowing the conversions.
func (h *TenantHost) maxOpen() int {
	return boundedInt(h.P.SettingIntRange("max_open_tenants", 50, 1, 10000), 50)
}

func (h *TenantHost) idle() time.Duration {
	return time.Duration(h.P.SettingIntRange("tenant_idle_minutes", 15, 1, 1440)) * time.Minute
}

// boundedInt converts a (clamped) setting value to int; the bounds check sits
// next to the conversion so it is also evident to code scanning.
func boundedInt(n int64, def int) int {
	if n < 0 || n > math.MaxInt32 {
		return def
	}
	return int(n)
}

func (h *TenantHost) maintenanceInterval() time.Duration {
	return time.Duration(h.P.SettingIntRange("tenant_maintenance_hours", 6, 1, 168)) * time.Hour
}

// openTenant opens a tenant's store and server and starts its jobs.
func (h *TenantHost) openTenant(id string) (*tenantEntry, error) {
	t, err := h.P.Tenant(id)
	if err != nil {
		return nil, err
	}
	route, _ := h.P.RouteOf(id)
	st, err := h.openStore(t)
	if err != nil {
		return nil, err
	}
	sc, err := h.P.Storage(id)
	if err != nil {
		st.Close()
		return nil, err
	}
	st.Backends().OpenFn = h.openBackend
	srv, err := NewTenantServer(st, h.cfg.Static, h.cfg.Version, TenantOptions{
		ID: t.ID, Slug: t.Slug, BaseURL: h.tenantURL(route), MailDefault: h.P.MailDefault,
		Storage: sc, DefaultStorage: h.P.Resolve(id, sc), PlatformStorage: h.P.PlatformStorage().Describe(),
		AllowPrivateTargets: t.AllowPrivateTargets,
	})
	if err != nil {
		st.Close()
		return nil, err
	}
	srv.SetTrustedProxies(h.cfg.TrustedProxies)
	srv.SetForceLocalLogin(h.cfg.ForceLocalLogin)
	if h.cfg.KEK != nil {
		srv.AttachKEK(h.cfg.KEK, t.ID, t.Slug, func() (string, string) {
			cur, err := h.P.Tenant(t.ID)
			if err != nil {
				return t.KEKMode, t.KEKFingerprint
			}
			return cur.KEKMode, cur.KEKFingerprint
		})
	}
	if err := srv.SetTenantLimits(t.MaxUsers, t.MaxStorageBytes); err != nil {
		st.Close()
		return nil, err
	}
	h.mu.Lock()
	parent := h.jobsCtx
	h.mu.Unlock()
	ctx, cancel := context.WithCancel(parent)
	if cl := h.cfg.Cluster; cl != nil {
		srv.attachCluster(cl, id)
		if cl.RunJobs {
			srv.RunJobs(ctx)
		}
	} else {
		srv.RunJobs(ctx)
	}
	return &tenantEntry{id: id, fp: tenantFingerprint(t, sc), srv: srv, handler: srv.Router(), cancel: cancel}, nil
}

// finishClose closes an entry already removed from open and listed in closing.
func (h *TenantHost) finishClose(e *tenantEntry) {
	users, storage := e.srv.TenantStats()
	h.P.UpdateStats(e.id, users, storage)
	if err := e.srv.closeTenant(e.cancel); err != nil {
		log.Printf("closing tenant %s: %v", e.id, err)
	}
	h.mu.Lock()
	if ch := h.closing[e.id]; ch != nil {
		close(ch)
		delete(h.closing, e.id)
	}
	h.mu.Unlock()
}

// evict closes a tenant once its requests have finished (bounded wait). It
// reports whether the tenant is closed.
func (h *TenantHost) evict(id string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		h.mu.Lock()
		if ch := h.opening[id]; ch != nil {
			h.mu.Unlock()
			<-ch
			continue
		}
		e := h.open[id]
		if e == nil {
			ch := h.closing[id]
			h.mu.Unlock()
			if ch != nil {
				<-ch
			}
			return true
		}
		if e.refs == 0 {
			delete(h.open, id)
			h.closing[id] = make(chan struct{})
			h.mu.Unlock()
			h.finishClose(e)
			return true
		}
		h.mu.Unlock()
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// reap closes tenants idle for longer than the idle time.
func (h *TenantHost) reap() {
	idle := h.idle()
	h.mu.Lock()
	var victims []*tenantEntry
	for id, e := range h.open {
		if e.refs == 0 && h.now().Sub(e.last) >= idle {
			delete(h.open, id)
			h.closing[id] = make(chan struct{})
			victims = append(victims, e)
		}
	}
	h.mu.Unlock()
	for _, e := range victims {
		h.finishClose(e)
	}
}

// withTenant runs fn on a tenant's server (opening it when needed).
func (h *TenantHost) withTenant(id string, fn func(*Server) error) error {
	e, err := h.acquire(id)
	if err != nil {
		return err
	}
	defer h.release(e, false)
	return fn(e.srv)
}

// OpenTenants returns the IDs of the open tenants (sorted).
func (h *TenantHost) OpenTenants() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.open))
	for id := range h.open {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Start runs the background jobs until ctx ends: closing idle tenants,
// refreshing the console's counts, maintenance (clean-up, expiry mails, audit
// retention, backups) for tenants that are not open, and the platform's own
// session and audit retention clean-up.
func (h *TenantHost) Start(ctx context.Context) {
	h.mu.Lock()
	h.jobsCtx = ctx
	h.mu.Unlock()
	go func() {
		reap := time.NewTicker(30 * time.Second)
		defer reap.Stop()
		stats := time.NewTicker(5 * time.Minute)
		defer stats.Stop()
		sweep := time.NewTimer(5 * time.Minute)
		defer sweep.Stop()
		daily := time.NewTicker(24 * time.Hour)
		defer daily.Stop()
		// A Cluster web replica only serves: maintenance and the platform's
		// own clean-up run on the controller leader.
		jobs := h.cfg.Cluster == nil || h.cfg.Cluster.RunJobs
		if !jobs {
			sweep.Stop()
			daily.Stop()
		} else {
			h.platformMaintenance()
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-reap.C:
				h.reap()
				h.closeLocked()
				h.P.PruneSessions()
			case <-stats.C:
				h.refreshOpenStats()
			case <-sweep.C:
				h.MaintainIdleTenants(ctx)
				sweep.Reset(h.maintenanceInterval())
			case <-daily.C:
				h.platformMaintenance()
			}
		}
	}()
}

func (h *TenantHost) refreshOpenStats() {
	h.mu.Lock()
	var es []*tenantEntry
	for _, e := range h.open {
		e.refs++
		es = append(es, e)
	}
	h.mu.Unlock()
	for _, e := range es {
		users, storage := e.srv.TenantStats()
		h.P.UpdateStats(e.id, users, storage)
		h.release(e, false)
	}
}

// platformMaintenance applies the platform audit retention.
func (h *TenantHost) platformMaintenance() {
	days := h.P.SettingIntRange("platform_audit_retention_days", 365, 90, 36500)
	if n, err := h.P.St.AuditPurge(time.Now().AddDate(0, 0, -boundedInt(days, 365))); err != nil {
		log.Printf("platform audit retention: %v", err)
	} else if n > 0 {
		h.P.Audit(0, "system", "audit_purged", "platform", "ok", fmt.Sprintf("%d records older than %d days", n, days), "")
	}
	// Directories of deleted tenants whose removal was interrupted.
	ents, _ := os.ReadDir(filepath.Join(h.P.DataDir, "tenants"))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".deleting-") {
			os.RemoveAll(filepath.Join(h.P.DataDir, "tenants", e.Name()))
		}
	}
}

// MaintainIdleTenants opens every active tenant that is not open, one at a
// time, so its periodic jobs run (opening runs the clean-up; the daily backup
// runs when due), records its counts and lets the reaper close it again.
func (h *TenantHost) MaintainIdleTenants(ctx context.Context) {
	ts, err := h.P.Tenants("")
	if err != nil {
		return
	}
	for _, t := range ts {
		if ctx.Err() != nil {
			return
		}
		if t.Status != platform.StatusActive {
			continue
		}
		h.mu.Lock()
		_, isOpen := h.open[t.ID]
		busy := len(h.open)+1 >= h.maxOpen()
		h.mu.Unlock()
		if isOpen {
			continue
		}
		if busy {
			h.reap()
		}
		e, err := h.acquire(t.ID)
		if err != nil {
			log.Printf("tenant maintenance %s: %v", t.Slug, err)
			continue
		}
		if e.srv.BackupDue() {
			e.srv.autoBackup()
		}
		users, storage := e.srv.TenantStats()
		h.P.UpdateStats(t.ID, users, storage)
		h.release(e, true)
		h.evict(t.ID, 0)
	}
}

// Shutdown closes every open tenant (waiting a bounded time for requests).
func (h *TenantHost) Shutdown(wait time.Duration) {
	if h.unsubscribe != nil {
		h.unsubscribe()
	}
	h.mu.Lock()
	h.shutdown = true
	ids := make([]string, 0, len(h.open))
	for id := range h.open {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if !h.evict(id, wait) {
				// Still busy: close anyway, the process is ending.
				h.mu.Lock()
				e := h.open[id]
				if e != nil {
					delete(h.open, id)
					h.closing[id] = make(chan struct{})
				}
				h.mu.Unlock()
				if e != nil {
					h.finishClose(e)
				}
			}
		}(id)
	}
	wg.Wait()
}

// ---------- tenant lifecycle (used by the console) ----------

// CreateTenant registers a tenant, creates its database and its first
// administrator. It returns the one-time password link when it could not be
// emailed ("" when emailed).
//
// storageOffer is what the platform provides ("none" by default: the tenant
// sets up storage of its own; "platform" bucket; "local" disk) and allowOwn
// whether the tenant may configure storage of its own.
func (h *TenantHost) CreateTenant(actor, slug, name, adminUser, adminEmail string, maxUsers, maxStorage int64, storageOffer string, allowOwn bool) (*platform.Tenant, string, bool, error) {
	if storageOffer == "" {
		storageOffer = platform.OfferNone
	}
	if err := h.P.CheckOffer(storageOffer); err != nil {
		return nil, "", false, err
	}
	create := h.P.CreateTenant
	if h.cfg.Cluster != nil {
		create = h.P.CreatePendingTenant // never served before its database exists
	}
	t, err := create(slug, name, maxUsers, maxStorage)
	if err != nil {
		return nil, "", false, err
	}
	fail := func(err error) (*platform.Tenant, string, bool, error) {
		h.deleteTenantData(t.ID)
		h.P.DeleteTenantRow(t.ID)
		if cl := h.cfg.Cluster; cl != nil {
			if derr := cl.Drop(context.Background(), t.ID); derr != nil {
				log.Printf("cluster: dropping the database of failed tenant %s: %v", t.ID, derr)
			}
		}
		return nil, "", false, err
	}
	if err := h.P.SetStorage(t.ID, storageOffer, allowOwn); err != nil {
		return fail(err)
	}
	if cl := h.cfg.Cluster; cl != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		err := cl.Provision(ctx, t)
		cancel()
		if err != nil {
			return fail(fmt.Errorf("provisioning the tenant database: %w", err))
		}
		if err := h.P.Reload(); err != nil {
			return fail(err)
		}
	} else {
		dir, err := h.P.TenantDir(t.ID)
		if err != nil {
			return fail(err)
		}
		dbKey, _, err := h.P.TenantKeys(t)
		if err != nil {
			return fail(err)
		}
		st, err := store.OpenTenant(dir, dbKey, nil, true)
		clear(dbKey)
		if err != nil {
			return fail(err)
		}
		st.Close()
	}
	var link string
	var emailed bool
	err = h.withTenant(t.ID, func(s *Server) error {
		s.RecordPlatformEvent(actor, "tenant_created", "slug="+t.Slug+fmt.Sprintf(" max_users=%d max_storage_bytes=%d storage_offer=%s own_storage_allowed=%t", maxUsers, maxStorage, storageOffer, allowOwn))
		var perr error
		link, emailed, perr = s.ProvisionAdmin(actor, adminUser, adminEmail)
		return perr
	})
	if err != nil {
		h.evict(t.ID, 5*time.Second)
		return fail(err)
	}
	return t, link, emailed, nil
}

// SetTenantStatus suspends or resumes a tenant. A suspended tenant is closed
// once its requests have finished; new requests get 503.
func (h *TenantHost) SetTenantStatus(actor, id, status string) error {
	if status == platform.StatusSuspended {
		// Recorded in the tenant's own log first, while it can still be opened.
		h.withTenant(id, func(s *Server) error { s.RecordPlatformEvent(actor, "tenant_suspended", ""); return nil })
	}
	if err := h.P.SetStatus(id, status); err != nil {
		return err
	}
	if status == platform.StatusSuspended {
		go h.evict(id, 10*time.Minute)
	} else {
		h.withTenant(id, func(s *Server) error { s.RecordPlatformEvent(actor, "tenant_resumed", ""); return nil })
	}
	return nil
}

// SetTenantQuotas changes a tenant's limits and applies them at once when open.
func (h *TenantHost) SetTenantQuotas(actor, id string, maxUsers, maxStorage int64) error {
	if err := h.P.SetQuotas(id, maxUsers, maxStorage); err != nil {
		return err
	}
	return h.withTenant(id, func(s *Server) error {
		s.RecordPlatformEvent(actor, "tenant_quota_changed", fmt.Sprintf("max_users=%d max_storage_bytes=%d", maxUsers, maxStorage))
		return s.SetTenantLimits(maxUsers, maxStorage)
	})
}

// reopen closes an open tenant so that changed routing data (primary domain,
// storage configuration, network policy) applies at its next request.
func (h *TenantHost) reopen(id string) { go h.evict(id, 10*time.Minute) }

// reopenAll reopens every open tenant (the platform default storage changed).
func (h *TenantHost) reopenAll() {
	for _, id := range h.OpenTenants() {
		h.reopen(id)
	}
}

// deleteResult reports the object storage clean-up of a deleted tenant.
type deleteResult struct {
	Removed int
	Failed  []string
}

// DeleteTenant removes a tenant: its objects in object storage (everything
// under its prefix in the platform default, Sendora's objects in its own
// bucket), its database, files and backups. It refuses while requests are
// still running after a short wait, and when objects could not be removed
// unless force is set.
func (h *TenantHost) DeleteTenant(id string, force bool) (deleteResult, error) {
	h.mu.Lock()
	h.deleting[id] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.deleting, id)
		h.mu.Unlock()
	}()
	if !h.evict(id, 30*time.Second) {
		return deleteResult{}, errors.New("the tenant still has requests in progress; try again shortly")
	}
	res := h.removeTenantObjects(id)
	if len(res.Failed) > 0 && !force {
		return res, fmt.Errorf("objects in object storage could not be removed (%s); try again, or delete with force to leave them behind", strings.Join(res.Failed, "; "))
	}
	if err := h.deleteTenantData(id); err != nil {
		return res, err
	}
	if err := h.P.DeleteTenantRow(id); err != nil {
		return res, err
	}
	if cl := h.cfg.Cluster; cl != nil {
		if err := cl.Drop(context.Background(), id); err != nil {
			log.Printf("cluster: dropping the database of deleted tenant %s: %v", id, err)
		}
	}
	return res, nil
}

// objectArea is one place a tenant's objects may be: exclusive areas (the
// tenant's prefix in the platform default) are emptied completely, shared
// buckets only lose Sendora's objects (files/, backups/, probe/).
type objectArea struct {
	cfg       storage.Config
	exclusive bool
}

// tenantObjectAreas collects the platform's view (fixed prefix, own bucket)
// and every location recorded in the tenant's database (earlier platform
// defaults, own buckets, tenant-managed buckets).
func (h *TenantHost) tenantObjectAreas(id string) []objectArea {
	var areas []objectArea
	seen := map[string]bool{}
	add := func(c storage.Config, exclusive bool) {
		if c.Backend == storage.KindLocal || c.Backend == "" || seen[c.Identity()] {
			return
		}
		seen[c.Identity()] = true
		areas = append(areas, objectArea{c, exclusive})
	}
	prefix := platform.TenantPrefix(id)
	isTenantArea := func(c storage.Config) bool { return !c.TenantManaged && strings.HasSuffix(c.Prefix, prefix) }
	for _, c := range h.P.StorageLocations(id) {
		add(c, isTenantArea(c))
	}
	t, err := h.P.Tenant(id)
	if err != nil {
		return areas
	}
	st, err := h.openStore(t)
	if err != nil {
		return areas
	}
	defer st.Close()
	configs, _ := st.Repos().ObjectStorage().LocationConfigs(context.Background())
	for _, js := range configs {
		if c, err := storage.Unmarshal(js); err == nil {
			add(c, isTenantArea(c))
		}
	}
	return areas
}

// removeTenantObjects deletes a tenant's objects (see objectArea).
func (h *TenantHost) removeTenantObjects(id string) deleteResult {
	var res deleteResult
	allowPrivate := false
	if t, err := h.P.Tenant(id); err == nil {
		allowPrivate = t.AllowPrivateTargets
	}
	for _, a := range h.tenantObjectAreas(id) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		cfg := a.cfg
		if cfg.TenantManaged && !allowPrivate {
			cfg.DialContext = netguard.DialContext
		}
		n, err := deleteObjects(ctx, h.openBackend, cfg, a.exclusive)
		cancel()
		res.Removed += n
		if err != nil {
			log.Printf("deleting tenant %s: objects in %s: %v", id, a.cfg.Describe(), err)
			res.Failed = append(res.Failed, a.cfg.Describe()+": "+clip(err.Error(), 200))
		}
	}
	return res
}

// deleteObjects removes every object of an exclusive area, or Sendora's
// objects in a shared bucket, and returns how many were removed.
func deleteObjects(ctx context.Context, open func(context.Context, storage.Config) (storage.Backend, error), cfg storage.Config, exclusive bool) (int, error) {
	b, err := open(ctx, cfg)
	if err != nil {
		return 0, err
	}
	prefixes := []string{storage.FilePrefix, storage.BackupPrefix, storage.ProbePrefix}
	if exclusive {
		prefixes = []string{""}
	}
	n := 0
	for _, p := range prefixes {
		var keys []string
		if err := b.List(ctx, p, func(i storage.Info) error { keys = append(keys, i.Key); return nil }); err != nil {
			return n, err
		}
		for _, k := range keys {
			if err := b.Delete(ctx, k); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// deleteTenantData moves the tenant's directory aside (atomic) and removes it.
func (h *TenantHost) deleteTenantData(id string) error {
	dir, err := h.P.TenantDir(id)
	if err != nil {
		return err
	}
	aside := filepath.Join(filepath.Dir(dir), ".deleting-"+id)
	if err := os.Rename(dir, aside); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.RemoveAll(aside); err != nil {
		// platformMaintenance retries the removal.
		log.Printf("removing the data of deleted tenant %s: %v", id, err)
	}
	return nil
}

// SetRestarter registers how main restarts the process (Platform settings).
func (h *TenantHost) SetRestarter(fn func()) { h.restartFn = fn }
