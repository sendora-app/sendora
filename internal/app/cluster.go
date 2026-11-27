// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// Cluster flavour (docs/cluster/DESIGN.md 2.2, 4.2-4.6): N web replicas and a
// controller share one PostgreSQL platform database. Everything a replica
// kept in memory that must hold across replicas goes through the
// coordination ports here: request budgets, share-unlock and console
// throttles and IP-ban counters (RateLimiter), the stripe locks around
// read-check-write sequences (Lock), cache invalidation of settings, bans and
// routing (Coordinator.Notify/Subscribe) and outbox work signals
// (Coordinator.Signal). In the Community flavours none of this is attached
// and every path below falls through to the in-process behaviour.

// ClusterRuntime are the shared adapters and hooks a TenantHost uses in the
// Cluster flavour (MultiTenantConfig.Cluster).
type ClusterRuntime struct {
	Coordinator ports.Coordinator
	Lock        ports.Lock
	Limiter     ports.RateLimiter
	// OpenStore opens tenant t's store (pooled connection as the tenant's app
	// role); dir is its file directory, root its key root.
	OpenStore func(t *platform.Tenant, dir string, root []byte) (*store.Store, error)
	// Provision makes tenant t's database exist and sets it active (web:
	// signals the controller and waits; controller: provisions).
	Provision func(ctx context.Context, t *platform.Tenant) error
	// Drop removes a deleted tenant's database (web: signals the controller).
	Drop func(ctx context.Context, id string) error
	// KeyWriter returns tenant id's keyring service on a connection that may
	// write the control log and the keyring (the controller: the database
	// owner role; web replicas: nil), and a release function. Tenant key
	// rotation (keys_admin.go) runs through it.
	KeyWriter func(ctx context.Context, id string) (*keyring.Service, func(), error)
	// KeyCheck reports whether tenant id's keys can be had right now
	// (ports.ErrLocked when it is tenant-managed and locked, D44). A web
	// replica serves it from the key client's cache, so a lock is noticed
	// within the cache lifetime. Optional.
	KeyCheck func(ctx context.Context, id string) error
	// Fresh, when set, runs before a tenant's store is opened: it drops key
	// material cached under another master key version than the tenant's
	// record names (D46).
	Fresh func(t *platform.Tenant)
	// ForgetKeys, when set, drops the key material cached for tenant id. A
	// store open that fails with ports.ErrUnknownKEK (the tenant's KEK changed
	// through another replica since the keys were cached) calls it and opens
	// once more with fresh keys, at most once per keyRefreshEvery per tenant.
	ForgetKeys func(id string)
	// RunJobs: this host runs the tenants' background jobs and the
	// platform maintenance (the controller leader). Web replicas only serve.
	RunJobs bool
}

// Work-signal kinds and notification topics of the Cluster flavour.
const (
	WorkDownloadMail = "download_mail"
	WorkProvision    = "provision"
	WorkDrop         = "drop"
	TopicRoutes      = "routes"
)

func topicSettings(tenant string) string { return "settings:" + tenant }
func topicIPBans(tenant string) string   { return "ipbans:" + tenant }

// clusterTenant is a tenant server's attachment to the cluster runtime.
type clusterTenant struct {
	rt       *ClusterRuntime
	tenantID string
	cancels  []func()
	warned   atomic.Bool
}

// attachCluster connects a tenant server to the cluster runtime: settings
// writes and bans are announced to the other replicas, and their
// announcements refresh this replica's caches. Every replica also polls the
// versions (Coordinator), so a lost notification costs at most one poll.
func (s *Server) attachCluster(rt *ClusterRuntime, tenantID string) {
	c := &clusterTenant{rt: rt, tenantID: tenantID}
	s.cl = c
	s.St.SetSettingsHook(func() {
		if err := rt.Coordinator.Notify(context.Background(), topicSettings(tenantID)); err != nil {
			c.warn("settings notification", err)
		}
	})
	follow := func(topic string, fn func()) {
		ch, cancel := rt.Coordinator.Subscribe(topic)
		c.cancels = append(c.cancels, cancel)
		go func() {
			for range ch {
				fn()
			}
		}()
	}
	follow(topicSettings(tenantID), s.St.NoteRemoteSettingsChange)
	follow(topicIPBans(tenantID), s.loadIPBans)
	follow(topicKeys(tenantID), s.refreshKeys)
}

// detachCluster stops the subscriptions (the tenant is closing).
func (s *Server) detachCluster() {
	if s.cl == nil {
		return
	}
	for _, cancel := range s.cl.cancels {
		cancel()
	}
	s.cl.cancels = nil
}

// warn logs a degraded shared operation once per tenant server (the
// in-process fallback keeps the replica serving).
func (c *clusterTenant) warn(what string, err error) {
	if c.warned.CompareAndSwap(false, true) {
		log.Printf("cluster: tenant %s: %s failed, using this replica's own state: %v", c.tenantID, what, err)
	}
}

// key scopes a shared key to the tenant (the limiter HMACs it).
func (c *clusterTenant) key(k string) string { return c.tenantID + "|" + k }

// perReplicaBudget lists the high-volume request budgets that stay per
// replica (design 4.2: shared counters only for the expensive and
// security-relevant routes; general budgets are budget ÷ replicas).
func perReplicaBudget(key string) bool {
	for _, p := range []string{"download:", "i18n:", "refresh:", "profile:"} {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// sharedAllowN is allowN on the shared counters: n units are charged, and
// given back when they exceed limit (so refused requests cost nothing, as in
// memory). handled is false when the cluster is not attached, the budget is
// per replica, or the database failed (the caller falls back to memory).
func (s *Server) sharedAllowN(key string, n, limit int, window time.Duration) (allowed, handled bool) {
	if s.cl == nil || perReplicaBudget(key) {
		return false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	scope := "budget:" + strconv.FormatInt(window.Milliseconds(), 10)
	got, err := s.cl.rt.Limiter.HitN(ctx, scope, s.cl.key(key), n, window)
	if err != nil {
		s.cl.warn("shared request budget", err)
		return false, false
	}
	if got > limit {
		s.cl.rt.Limiter.HitN(ctx, scope, s.cl.key(key), -n, window)
		return false, true
	}
	return true, true
}

// ---------- share unlock budgets ----------

const (
	scopeUnlock      = "unlock"
	scopeUnlockBlock = "unlock-block"
)

// unlockReserve is failThrottle.reserveAttempt across replicas.
func (s *Server) unlockReserve(keys []unlockKey, now time.Time) (time.Duration, bool) {
	if s.cl == nil {
		return s.shareThrottle.reserveAttempt(keys, now)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	l := s.cl.rt.Limiter
	for _, k := range keys {
		until, blocked, err := l.Blocked(ctx, scopeUnlockBlock, s.cl.key(k.key))
		if err != nil {
			s.cl.warn("share unlock budget", err)
			return s.shareThrottle.reserveAttempt(keys, now)
		}
		if blocked {
			return until.Sub(now), false
		}
	}
	for i, k := range keys {
		n, err := l.Hit(ctx, scopeUnlock, s.cl.key(k.key), shareUnlockWindow)
		if err != nil || n > k.limit {
			for _, done := range keys[:i+1] {
				l.HitN(ctx, scopeUnlock, s.cl.key(done.key), -1, shareUnlockWindow)
			}
			if err != nil {
				s.cl.warn("share unlock budget", err)
				return s.shareThrottle.reserveAttempt(keys, now)
			}
			return now.Truncate(shareUnlockWindow).Add(shareUnlockWindow).Sub(now), false
		}
	}
	return 0, true
}

// unlockFail keeps the reserved attempt as a failure and blocks every key
// whose budget is used up.
func (s *Server) unlockFail(keys []unlockKey, now time.Time) {
	if s.cl == nil {
		s.shareThrottle.failAttempt(keys, now)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	l := s.cl.rt.Limiter
	for _, k := range keys {
		n, err := l.HitN(ctx, scopeUnlock, s.cl.key(k.key), 0, shareUnlockWindow)
		if err == nil && n >= k.limit {
			l.Block(ctx, scopeUnlockBlock, s.cl.key(k.key), now.Add(shareUnlockBlock))
		}
	}
}

// unlockSucceeded gives the reserved attempt back and clears the client's
// own budget (keys[0]).
func (s *Server) unlockSucceeded(keys []unlockKey) {
	if s.cl == nil {
		s.shareThrottle.releaseAttempt(keys)
		s.shareThrottle.clear(keys[0].key)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	l := s.cl.rt.Limiter
	for _, k := range keys[1:] {
		l.HitN(ctx, scopeUnlock, s.cl.key(k.key), -1, shareUnlockWindow)
	}
	l.Reset(ctx, scopeUnlock, s.cl.key(keys[0].key))
}

// ---------- IP bans ----------

// sharedIPFailure counts a failed attempt of ban key across replicas and
// reports whether the ban threshold is reached (handled false: not attached
// or the database failed).
func (s *Server) sharedIPFailure(key string) (reached, handled bool) {
	if s.cl == nil {
		return false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	n, err := s.cl.rt.Limiter.Hit(ctx, "ipfail", s.cl.key(key), ipBanWindow)
	if err != nil {
		s.cl.warn("shared IP failure counter", err)
		return false, false
	}
	if n < ipBanThreshold {
		return false, true
	}
	s.cl.rt.Limiter.Reset(ctx, "ipfail", s.cl.key(key))
	return true, true
}

// bansChanged tells the other replicas to reload the bans.
func (s *Server) bansChanged() {
	if s.cl == nil {
		return
	}
	if err := s.cl.rt.Coordinator.Notify(context.Background(), topicIPBans(s.cl.tenantID)); err != nil {
		s.cl.warn("ban notification", err)
	}
}

// ---------- stripe locks ----------

// stripe takes the in-process stripe lock of key and, in the Cluster
// flavour, the cluster-wide lock of the same name, so read-check-write
// sequences stay serialised across replicas. If the shared lock cannot be
// taken (database unavailable), the replica proceeds with its own lock only
// and logs it once.
func (s *Server) stripe(locks *[64]sync.Mutex, key string) func() {
	unlock := lockStripe(locks, key)
	if s.cl == nil {
		return unlock
	}
	h := sha256.Sum256([]byte(key))
	name := s.cl.tenantID + ":" + s.stripeKind(locks) + ":" + hex.EncodeToString(h[:16])
	release, err := holdLock(s.cl.rt.Lock, name, 30*time.Second)
	if err != nil {
		s.cl.warn("cluster lock "+s.stripeKind(locks), err)
		return unlock
	}
	return func() {
		release()
		unlock()
	}
}

func (s *Server) stripeKind(locks *[64]sync.Mutex) string {
	switch locks {
	case &s.uploadLocks:
		return "upload"
	case &s.verificationLocks:
		return "verification"
	case &s.identityLocks:
		return "identity"
	case &s.loginLocks:
		return "login"
	}
	return "stripe"
}

// holdLock takes name through l (waiting at most wait) and returns the
// release function: WithLock's critical section is held open until release.
func holdLock(l ports.Lock, name string, wait time.Duration) (func(), error) {
	acquired := make(chan error, 1)
	release := make(chan struct{})
	finished := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	go func() {
		defer close(finished)
		err := l.WithLock(ctx, name, func(context.Context) error {
			acquired <- nil
			<-release
			return nil
		})
		if err != nil {
			select {
			case acquired <- err:
			default:
			}
		}
	}()
	if err := <-acquired; err != nil {
		cancel()
		return nil, err
	}
	// The wait bound applies to acquisition only: once held, the section
	// must not end because ctx ran out.
	return func() {
		close(release)
		<-finished
		cancel()
	}, nil
}

// ---------- outbox work signals ----------

// signalWork records that this tenant has outbox work of kind for the
// controller's workers (design 4.3, M8); in the Community flavours the
// in-process worker is woken directly by the caller.
func (s *Server) signalWork(kind string) {
	if s.cl == nil {
		return
	}
	if err := s.cl.rt.Coordinator.Signal(context.Background(), kind, s.cl.tenantID); err != nil {
		// The periodic sweep finds the outbox row anyway.
		s.cl.warn("work signal "+kind, err)
	}
}

// jobFence advances the tenant's fence of kind to the leadership epoch in
// tx (design 4.3, M7). Outside the Cluster flavour there is one process and
// nothing to fence. ok is false for a former leader (stale epoch).
func (s *Server) jobFence(ctx context.Context, tx ports.Tx, kind string) (bool, error) {
	if s.cl == nil {
		return true, nil
	}
	epoch := s.cl.rt.Coordinator.Epoch()
	if epoch <= 0 {
		return false, nil
	}
	return tx.JobFences().Advance(ctx, kind, epoch)
}

// WakeDownloadMail wakes the tenant's download-notification worker.
func (s *Server) WakeDownloadMail() {
	select {
	case s.downloadMailWake <- struct{}{}:
	default:
	}
}

// WakeDownloadMail opens tenant id (when needed) and wakes its
// download-notification worker (the controller's work-signal consumer).
func (h *TenantHost) WakeDownloadMail(id string) error {
	return h.withTenant(id, func(s *Server) error {
		s.WakeDownloadMail()
		return nil
	})
}

// tenantFingerprint is what an open tenant was opened with; a replica
// reopens the tenant when another replica changed any of it.
func tenantFingerprint(t *platform.Tenant, sc *platform.StorageConfig) string {
	return fmt.Sprintf("%s|%s|%s|%d|%d|%t|%s|%s|%d|%+v", t.Status, t.Slug, t.PrimaryDomain, t.MaxUsers, t.MaxStorageBytes, t.AllowPrivateTargets, t.KEKMode, t.KEKFingerprint, t.MasterVersion, sc)
}

// spendMFAToken marks mfa_token jti as spent and reports whether this was
// its first use. In the Cluster flavour the decision is shared by every
// replica (design 4.2: MFA replay joins the RateLimiter port): a token
// completed on one replica must not complete again on another, even with a
// fresh second factor. The block records the spend for the token's whole
// life; the counter settles two replicas spending the same token at the same
// moment (exactly one sees 1). If the shared state is unavailable the spend
// is refused (fail closed; logged once): the user signs in again.
func (s *Server) spendMFAToken(jti string, exp time.Time) bool {
	if c := s.cl; c != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		first, err := c.spendOnce(ctx, "mfa-jti", c.key(jti), exp)
		if err != nil {
			c.warn("mfa token single use (refused)", err)
			return false
		}
		s.mfaUsed.mark(jti, exp) // the local fast path of parseMFAToken
		return first
	}
	return s.mfaUsed.mark(jti, exp)
}

// spendOnceWindow is twice the longest lifetime of a single-use token
// (mfa_token, WebAuthn ceremony).
const spendOnceWindow = 2 * max(mfaTokenTTL, waCeremonyTTL)

// spendOnce reports whether (scope, key) is spent for the first time; it
// stays spent until until.
func (c *clusterTenant) spendOnce(ctx context.Context, scope, key string, until time.Time) (bool, error) {
	if _, blocked, err := c.rt.Limiter.Blocked(ctx, scope, key); err != nil || blocked {
		return false, err
	}
	// A fixed window (the bucket key includes its length) twice the longest
	// single-use lifetime: concurrent spends land in the same bucket unless
	// they straddle a window boundary; the block (set right after) covers
	// every later spend.
	n, err := c.rt.Limiter.Hit(ctx, scope, key, spendOnceWindow)
	if err != nil || n > 1 {
		return false, err
	}
	return true, c.rt.Limiter.Block(ctx, scope, key, until)
}

// Step-up grants in the Cluster flavour (design 4.2: step-up grants join the
// RateLimiter port). A grant is a block on (user, session start) until the
// grant time plus the longest possible window, so every replica can recover
// the grant time (until - stepUpMaxMinutes) and apply its current window.

func stepUpSharedKey(uid, session int64) string {
	return "stepup|" + strconv.FormatInt(uid, 10) + "|" + strconv.FormatInt(session, 10)
}

// shareStepUp announces a step-up grant made on this replica.
func (s *Server) shareStepUp(uid int64, session, at time.Time) {
	c := s.cl
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.rt.Limiter.Block(ctx, "stepup", c.key(stepUpSharedKey(uid, session.Unix())), at.Add(stepUpMaxMinutes*time.Minute)); err != nil {
		c.warn("step-up grant", err)
	}
}

// sharedStepUpAt returns the time of a step-up grant another replica made for
// (uid, session start), if any.
func (s *Server) sharedStepUpAt(uid, session int64) (time.Time, bool) {
	c := s.cl
	if c == nil {
		return time.Time{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	until, blocked, err := c.rt.Limiter.Blocked(ctx, "stepup", c.key(stepUpSharedKey(uid, session)))
	if err != nil {
		c.warn("step-up grant", err)
		return time.Time{}, false
	}
	if !blocked {
		return time.Time{}, false
	}
	return until.Add(-stepUpMaxMinutes * time.Minute), true
}
