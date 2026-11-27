// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sendora-app/sendora/internal/ports"
)

// Cluster coordination on the platform database (docs/cluster/DESIGN.md 2A.2,
// 4.2, 4.3, 4.6): the Coordinator (work signals, change notifications by
// LISTEN/NOTIFY with version polling, leadership from an Elector), the Lock
// (lease rows) and the RateLimiter (UNLOGGED counters, logged blocks). All
// statements are single autocommit statements, so they work through PgBouncer
// in transaction mode; only LISTEN needs a direct connection, and without one
// the version polling alone keeps caches within PollInterval.

var (
	_ ports.Coordinator = (*Coordinator)(nil)
	_ ports.Lock        = (*Lock)(nil)
	_ ports.RateLimiter = (*RateLimiter)(nil)
)

// notifyChannel is the LISTEN/NOTIFY channel; the payload is
// "<schema>/<topic>" so databases shared by several schemas (the conformance
// suite's scratch schemas) do not wake each other's subscribers.
const notifyChannel = "sendora_coord"

// Elector reports leadership; the Kubernetes Lease adapter (internal/adapters/k8s)
// implements it. epoch grows with every change of leader.
type Elector interface {
	Leader() (leader bool, epoch int64)
}

// StaticElector is a fixed leadership: never the leader (web pods, which
// hold no Lease) or always (tests).
type StaticElector struct {
	Lead  bool
	Epoch int64
}

// Leader implements Elector.
func (e StaticElector) Leader() (bool, int64) {
	if !e.Lead {
		return false, 0
	}
	return true, e.Epoch
}

// CoordinatorConfig configures NewCoordinator.
type CoordinatorConfig struct {
	// DB is the platform database (through the pooler is fine).
	DB *sql.DB
	// Listen is a direct connection to the same database for LISTEN; nil
	// means version polling only.
	Listen *pgx.ConnConfig
	// Elector decides leadership; nil means never the leader.
	Elector Elector
	// PollInterval is the version polling period (default 10 s, design 4.6).
	PollInterval time.Duration
	// Logf receives reconnect messages (default log.Printf).
	Logf func(string, ...any)
}

// Coordinator implements ports.Coordinator on the platform database.
type Coordinator struct {
	q       pq
	listen  *pgx.ConnConfig
	elector Elector
	poll    time.Duration
	logf    func(string, ...any)
	schema  string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu   sync.Mutex
	next int
	subs map[string]map[int]chan struct{}
	seen map[string]int64 // topic -> last polled version

	listening atomic.Bool
}

// NewCoordinator starts the coordinator's poller (and listener, when
// configured). Close stops them.
func NewCoordinator(ctx context.Context, cfg CoordinatorConfig) (*Coordinator, error) {
	if cfg.DB == nil {
		return nil, errors.New("coordinator: database required")
	}
	c := &Coordinator{q: pq{raw: cfg.DB}, listen: cfg.Listen, elector: cfg.Elector, poll: cfg.PollInterval, logf: cfg.Logf,
		subs: map[string]map[int]chan struct{}{}, seen: map[string]int64{}}
	if c.elector == nil {
		c.elector = StaticElector{}
	}
	if c.poll <= 0 {
		c.poll = 10 * time.Second
	}
	if c.logf == nil {
		c.logf = log.Printf
	}
	if err := c.q.scan(ctx, `SELECT current_schema()`, nil, &c.schema); err != nil {
		return nil, err
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.wg.Add(1)
	go c.pollLoop()
	if c.listen != nil {
		c.wg.Add(1)
		go c.listenLoop()
	}
	return c, nil
}

// Close stops the poller and the listener and closes every subscription.
func (c *Coordinator) Close() {
	c.cancel()
	c.wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	for topic, m := range c.subs {
		for id, ch := range m {
			close(ch)
			delete(m, id)
		}
		delete(c.subs, topic)
	}
}

// Listening reports whether the LISTEN connection is up (readiness, metrics).
func (c *Coordinator) Listening() bool { return c.listening.Load() }

// IsLeader implements ports.Coordinator.
func (c *Coordinator) IsLeader() bool {
	ok, _ := c.elector.Leader()
	return ok
}

// Epoch implements ports.Coordinator.
func (c *Coordinator) Epoch() int64 {
	ok, e := c.elector.Leader()
	if !ok {
		return 0
	}
	return e
}

// RunPeriodic implements ports.Coordinator: every interval, fn runs if this
// process is the leader at that moment.
func (c *Coordinator) RunPeriodic(ctx context.Context, name string, interval time.Duration, fn func(context.Context)) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if c.IsLeader() {
					fn(ctx)
				}
			}
		}
	}()
}

// Notify implements ports.Coordinator: it bumps the topic's version (read by
// every replica's poller) and sends a NOTIFY (delivered at commit to every
// listener), then wakes this process's own subscribers at once.
func (c *Coordinator) Notify(ctx context.Context, topic string) error {
	_, err := c.q.ExecContext(ctx, `WITH v AS (
		INSERT INTO coord_versions(topic, version) VALUES(?, 1)
		ON CONFLICT (topic) DO UPDATE SET version = coord_versions.version + 1 RETURNING version)
		SELECT pg_notify('`+notifyChannel+`', current_schema() || '/' || ?) FROM v`, topic, topic)
	c.fire(topic)
	return err
}

// Subscribe implements ports.Coordinator. The topic's current version is
// read first, so a notification right after Subscribe returns is seen by the
// poller even when the LISTEN connection is down.
func (c *Coordinator) Subscribe(topic string) (<-chan struct{}, func()) {
	c.mu.Lock()
	_, known := c.seen[topic]
	c.mu.Unlock()
	if !known {
		ctx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
		var v int64
		err := c.q.scan(ctx, `SELECT version FROM coord_versions WHERE topic = ?`, []any{topic}, &v)
		cancel()
		if err == nil || errors.Is(err, ports.ErrNotFound) {
			c.mu.Lock()
			if _, ok := c.seen[topic]; !ok {
				c.seen[topic] = v
			}
			c.mu.Unlock()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.next
	c.next++
	ch := make(chan struct{}, 1)
	if c.subs[topic] == nil {
		c.subs[topic] = map[int]chan struct{}{}
	}
	c.subs[topic][id] = ch
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if m := c.subs[topic]; m != nil {
				if _, ok := m[id]; ok {
					delete(m, id)
					close(ch)
				}
				if len(m) == 0 {
					delete(c.subs, topic)
					delete(c.seen, topic)
				}
			}
		})
	}
}

// Signal implements ports.Coordinator.
func (c *Coordinator) Signal(ctx context.Context, kind, tenant string) error {
	if _, err := c.q.ExecContext(ctx, `INSERT INTO coord_signals(kind, tenant_id) VALUES(?, ?) ON CONFLICT DO NOTHING`, kind, tenant); err != nil {
		return err
	}
	return c.Notify(ctx, ports.WorkTopic(kind))
}

// TakeSignals implements ports.Coordinator. Concurrent takers skip each
// other's rows (SKIP LOCKED), so a signal is handed to one worker.
func (c *Coordinator) TakeSignals(ctx context.Context, kind string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := c.q.QueryContext(ctx, `DELETE FROM coord_signals WHERE kind = ? AND tenant_id IN (
		SELECT tenant_id FROM coord_signals WHERE kind = ? ORDER BY signalled_at, tenant_id LIMIT ? FOR UPDATE SKIP LOCKED)
		RETURNING tenant_id, signalled_at`, kind, kind, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type sig struct {
		tenant string
		at     time.Time
	}
	var got []sig
	for rows.Next() {
		var s sig
		if err := rows.Scan(&s.tenant, &s.at); err != nil {
			return nil, err
		}
		got = append(got, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(got, func(i, j int) bool {
		if !got[i].at.Equal(got[j].at) {
			return got[i].at.Before(got[j].at)
		}
		return got[i].tenant < got[j].tenant
	})
	out := make([]string, len(got))
	for i, s := range got {
		out[i] = s.tenant
	}
	return out, nil
}

// fire wakes the subscribers of topic (coalescing: a pending wake is kept).
func (c *Coordinator) fire(topic string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ch := range c.subs[topic] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// fireAll wakes every subscriber: after the listener (re)connects,
// notifications may have been missed, so every cache revalidates (4.6).
func (c *Coordinator) fireAll() {
	c.mu.Lock()
	topics := make([]string, 0, len(c.subs))
	for t := range c.subs {
		topics = append(topics, t)
	}
	c.mu.Unlock()
	for _, t := range topics {
		c.fire(t)
	}
}

func (c *Coordinator) pollLoop() {
	defer c.wg.Done()
	t := time.NewTicker(c.poll)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.pollOnce()
		}
	}
}

// pollOnce compares the subscribed topics' versions with the last poll and
// wakes the subscribers of every topic that moved. A topic seen for the first
// time only records its version.
func (c *Coordinator) pollOnce() {
	c.mu.Lock()
	topics := make([]string, 0, len(c.subs))
	for t := range c.subs {
		topics = append(topics, t)
	}
	c.mu.Unlock()
	if len(topics) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.poll)
	defer cancel()
	rows, err := c.q.QueryContext(ctx, `SELECT topic, version FROM coord_versions WHERE topic = ANY(?)`, topics)
	if err != nil {
		return
	}
	current := map[string]int64{}
	for rows.Next() {
		var t string
		var v int64
		if rows.Scan(&t, &v) == nil {
			current[t] = v
		}
	}
	rows.Close()
	if rows.Err() != nil {
		return
	}
	var moved []string
	c.mu.Lock()
	for _, t := range topics {
		if _, subscribed := c.subs[t]; !subscribed {
			continue
		}
		v := current[t]
		if old, ok := c.seen[t]; ok && old != v {
			moved = append(moved, t)
		}
		c.seen[t] = v
	}
	c.mu.Unlock()
	for _, t := range moved {
		c.fire(t)
	}
}

// listenLoop keeps one direct LISTEN connection, reconnecting with backoff
// (a failover drops it); every reconnect wakes all subscribers, which
// revalidate their caches (design 4.6). Before the first connection the
// poller and Subscribe's version baseline cover missed notifications.
func (c *Coordinator) listenLoop() {
	defer c.wg.Done()
	backoff := time.Second
	prefix := c.schema + "/"
	connected := false
	for c.ctx.Err() == nil {
		conn, err := pgx.ConnectConfig(c.ctx, c.listen)
		if err == nil {
			if _, err = conn.Exec(c.ctx, "LISTEN "+notifyChannel); err == nil {
				c.listening.Store(true)
				backoff = time.Second
				if connected {
					c.fireAll() // notifications may have been missed while down
				}
				connected = true
				for {
					n, werr := conn.WaitForNotification(c.ctx)
					if werr != nil {
						err = werr
						break
					}
					if topic, ok := strings.CutPrefix(n.Payload, prefix); ok {
						c.fire(topic)
					}
				}
				c.listening.Store(false)
			}
			conn.Close(context.Background())
		}
		if c.ctx.Err() != nil {
			return
		}
		c.logf("coordinator: LISTEN connection lost (%v); reconnecting in %s, polling every %s meanwhile", err, backoff, c.poll)
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// ---------- Lock ----------

// Lock implements ports.Lock with lease rows in coord_locks. Taking and
// releasing are single statements; while fn runs the lease is renewed every
// TTL/3. A holder that stalls longer than TTL (a frozen process, a network
// partition) loses the lock: TTL bounds how long a crashed holder blocks
// others, and fn must stay short against it.
type Lock struct {
	q      pq
	holder string
	ttl    time.Duration
}

// NewLock returns a Lock on db; holder names this process in coord_locks
// (diagnostics only), ttl is the lease (default 30 s).
func NewLock(db *sql.DB, holder string, ttl time.Duration) *Lock {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Lock{q: pq{raw: db}, holder: holder, ttl: ttl}
}

// WithLock implements ports.Lock.
func (l *Lock) WithLock(ctx context.Context, name string, fn func(context.Context) error) error {
	b := make([]byte, 8)
	rand.Read(b)
	token := l.holder + "/" + hex.EncodeToString(b)
	wait := 2 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := affected(l.q.ExecContext(ctx, `INSERT INTO coord_locks(name, holder, until) VALUES(?, ?, clock_timestamp() + ? * interval '1 millisecond')
			ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, until = EXCLUDED.until WHERE coord_locks.until < clock_timestamp()`,
			name, token, l.ttl.Milliseconds()))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n == 1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, 100*time.Millisecond)
	}
	stop := make(chan struct{})
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		t := time.NewTicker(l.ttl / 3)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				rctx, cancel := context.WithTimeout(context.Background(), l.ttl/3)
				l.q.ExecContext(rctx, `UPDATE coord_locks SET until = clock_timestamp() + ? * interval '1 millisecond' WHERE name = ? AND holder = ?`, l.ttl.Milliseconds(), name, token)
				cancel()
			}
		}
	}()
	err := fn(ctx)
	close(stop)
	<-renewed
	rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l.q.ExecContext(rctx, `DELETE FROM coord_locks WHERE name = ? AND holder = ?`, name, token)
	return err
}

// ---------- RateLimiter ----------

// RateLimiter implements ports.RateLimiter on the platform database (design
// 4.2): fixed-window counters in the UNLOGGED rate_buckets, blocks in the
// logged rate_blocks. Keys are stored as an HMAC (key material from the
// caller), so client addresses never reach the database.
type RateLimiter struct {
	q    pq
	key  []byte
	now  func() time.Time
	hits atomic.Int64
}

// NewRateLimiter returns a RateLimiter on db. hmacKey (32 bytes, or nil to
// store keys as given) hashes the keys; now is time.Now when nil.
func NewRateLimiter(db *sql.DB, hmacKey []byte, now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{q: pq{raw: db}, key: append([]byte(nil), hmacKey...), now: now}
}

func (r *RateLimiter) hashKey(scope, key string) string {
	if len(r.key) == 0 {
		return key
	}
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(scope))
	m.Write([]byte{0})
	m.Write([]byte(key))
	return hex.EncodeToString(m.Sum(nil))
}

// Hit implements ports.RateLimiter.
func (r *RateLimiter) Hit(ctx context.Context, scope, key string, window time.Duration) (int, error) {
	return r.HitN(ctx, scope, key, 1, window)
}

// HitN implements ports.RateLimiter.
func (r *RateLimiter) HitN(ctx context.Context, scope, key string, n int, window time.Duration) (int, error) {
	if window <= 0 {
		window = time.Second
	}
	now := r.now()
	if r.hits.Add(1)%512 == 0 {
		r.sweep(ctx, now)
	}
	var count int64
	err := r.q.scan(ctx, `INSERT INTO rate_buckets(scope, key, window_ms, window_start, count) VALUES(?, ?, ?, ?, GREATEST(?::bigint, 0))
		ON CONFLICT (scope, key, window_ms, window_start) DO UPDATE SET count = GREATEST(rate_buckets.count + EXCLUDED.count + LEAST(?::bigint, 0), 0)
		RETURNING count`, []any{scope, r.hashKey(scope, key), window.Milliseconds(), now.Truncate(window).UnixMilli(), n, n}, &count)
	return int(count), err
}

// Block implements ports.RateLimiter.
func (r *RateLimiter) Block(ctx context.Context, scope, key string, until time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO rate_blocks(scope, key, until_ms) VALUES(?, ?, ?)
		ON CONFLICT (scope, key) DO UPDATE SET until_ms = GREATEST(rate_blocks.until_ms, EXCLUDED.until_ms)`, scope, r.hashKey(scope, key), until.UnixMilli())
	return err
}

// Blocked implements ports.RateLimiter.
func (r *RateLimiter) Blocked(ctx context.Context, scope, key string) (time.Time, bool, error) {
	var until int64
	err := r.q.scan(ctx, `SELECT until_ms FROM rate_blocks WHERE scope = ? AND key = ? AND until_ms > ?`, []any{scope, r.hashKey(scope, key), r.now().UnixMilli()}, &until)
	if errors.Is(err, ports.ErrNotFound) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return time.UnixMilli(until), true, nil
}

// Reset implements ports.RateLimiter.
func (r *RateLimiter) Reset(ctx context.Context, scope, key string) error {
	k := r.hashKey(scope, key)
	if _, err := r.q.ExecContext(ctx, `DELETE FROM rate_buckets WHERE scope = ? AND key = ?`, scope, k); err != nil {
		return err
	}
	_, err := r.q.ExecContext(ctx, `DELETE FROM rate_blocks WHERE scope = ? AND key = ?`, scope, k)
	return err
}

// sweep drops ended windows and blocks (best effort).
func (r *RateLimiter) sweep(ctx context.Context, now time.Time) {
	ms := now.UnixMilli()
	r.q.ExecContext(ctx, `DELETE FROM rate_buckets WHERE window_start + window_ms < ?`, ms)
	r.q.ExecContext(ctx, `DELETE FROM rate_blocks WHERE until_ms < ?`, ms)
}
