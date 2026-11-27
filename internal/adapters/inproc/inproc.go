// SPDX-License-Identifier: AGPL-3.0-or-later

// Package inproc holds the in-process adapters of the Community flavours
// (one process, one replica): Coordinator, Lock and RateLimiter
// (docs/cluster/DESIGN.md section 2A.2). Their contracts are tested by
// internal/conformance.
package inproc

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

var (
	_ ports.Coordinator = (*Coordinator)(nil)
	_ ports.Lock        = (*Lock)(nil)
	_ ports.RateLimiter = (*RateLimiter)(nil)
)

// Coordinator is the single-process coordinator: always the leader, periodic
// jobs on tickers, notifications through in-memory channels.
type Coordinator struct {
	mu      sync.Mutex
	next    int
	subs    map[string]map[int]chan struct{}
	signals map[string]map[string]uint64 // kind -> tenant -> order of the signal
	order   uint64
}

// NewCoordinator returns a Coordinator.
func NewCoordinator() *Coordinator {
	return &Coordinator{subs: map[string]map[int]chan struct{}{}, signals: map[string]map[string]uint64{}}
}

// IsLeader is always true: the only process is the leader.
func (c *Coordinator) IsLeader() bool { return true }

// Epoch is 1: the single process is the only leader there ever is.
func (c *Coordinator) Epoch() int64 { return 1 }

// Signal records work of kind for tenant and wakes ports.WorkTopic(kind).
func (c *Coordinator) Signal(ctx context.Context, kind, tenant string) error {
	c.mu.Lock()
	m := c.signals[kind]
	if m == nil {
		m = map[string]uint64{}
		c.signals[kind] = m
	}
	if _, ok := m[tenant]; !ok {
		c.order++
		m[tenant] = c.order
	}
	c.mu.Unlock()
	return c.Notify(ctx, ports.WorkTopic(kind))
}

// TakeSignals removes and returns up to limit signalled tenants, oldest first.
func (c *Coordinator) TakeSignals(ctx context.Context, kind string, limit int) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.signals[kind]
	out := make([]string, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return m[out[i]] < m[out[j]] })
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	for _, t := range out {
		delete(m, t)
	}
	if len(m) == 0 {
		delete(c.signals, kind)
	}
	return out, nil
}

// RunPeriodic runs fn every interval in its own goroutine until ctx ends.
func (c *Coordinator) RunPeriodic(ctx context.Context, name string, interval time.Duration, fn func(context.Context)) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fn(ctx)
			}
		}
	}()
}

// Notify wakes every subscriber of topic. A subscriber that has not consumed
// the previous signal keeps one pending signal (coalescing).
func (c *Coordinator) Notify(ctx context.Context, topic string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ch := range c.subs[topic] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return nil
}

// Subscribe registers a subscriber of topic.
func (c *Coordinator) Subscribe(topic string) (<-chan struct{}, func()) {
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
			delete(c.subs[topic], id)
			if len(c.subs[topic]) == 0 {
				delete(c.subs, topic)
			}
			close(ch)
		})
	}
}

// Lock is a set of named mutexes that honour context cancellation.
type Lock struct {
	mu    sync.Mutex
	locks map[string]*namedLock
}

type namedLock struct {
	ch    chan struct{} // capacity 1: holding the token means holding the lock
	users int           // goroutines holding or waiting; the entry is freed at 0
}

// NewLock returns a Lock.
func NewLock() *Lock { return &Lock{locks: map[string]*namedLock{}} }

// WithLock runs fn while holding name.
func (l *Lock) WithLock(ctx context.Context, name string, fn func(context.Context) error) error {
	l.mu.Lock()
	nl := l.locks[name]
	if nl == nil {
		nl = &namedLock{ch: make(chan struct{}, 1)}
		l.locks[name] = nl
	}
	nl.users++
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		nl.users--
		if nl.users == 0 {
			delete(l.locks, name)
		}
		l.mu.Unlock()
	}()
	select {
	case nl.ch <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-nl.ch }()
	return fn(ctx)
}

// RateLimiter keeps fixed-window counters in memory. Windows are aligned to
// multiples of their length since the Unix epoch; expired counters are
// dropped lazily.
type RateLimiter struct {
	mu       sync.Mutex
	now      func() time.Time
	counters map[rlKey]rlCount
	blocks   map[rlKey]time.Time
	hits     int
}

type rlKey struct{ scope, key string }
type rlCount struct {
	start  time.Time
	window time.Duration
	n      int
}

// NewRateLimiter returns a RateLimiter. now is time.Now when nil (tests pass
// a fake clock).
func NewRateLimiter(now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{now: now, counters: map[rlKey]rlCount{}, blocks: map[rlKey]time.Time{}}
}

// Hit counts one event and returns the count in the current window.
func (r *RateLimiter) Hit(ctx context.Context, scope, key string, window time.Duration) (int, error) {
	return r.HitN(ctx, scope, key, 1, window)
}

// HitN counts n events (n < 0 gives events back) and returns the count.
func (r *RateLimiter) HitN(ctx context.Context, scope, key string, n int, window time.Duration) (int, error) {
	if window <= 0 {
		window = time.Second
	}
	now := r.now()
	start := now.Truncate(window)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits++
	if r.hits%1024 == 0 {
		r.sweep(now)
	}
	k := rlKey{scope, key}
	c := r.counters[k]
	if !c.start.Equal(start) || c.window != window {
		c = rlCount{start: start, window: window}
	}
	c.n = max(c.n+n, 0)
	r.counters[k] = c
	return c.n, nil
}

// Block refuses (scope, key) until until; an earlier block is never shortened.
func (r *RateLimiter) Block(ctx context.Context, scope, key string, until time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := rlKey{scope, key}
	if until.After(r.blocks[k]) {
		r.blocks[k] = until
	}
	return nil
}

// Blocked reports whether (scope, key) is blocked now.
func (r *RateLimiter) Blocked(ctx context.Context, scope, key string) (time.Time, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := rlKey{scope, key}
	until, ok := r.blocks[k]
	if !ok {
		return time.Time{}, false, nil
	}
	if !r.now().Before(until) {
		delete(r.blocks, k)
		return time.Time{}, false, nil
	}
	return until, true, nil
}

// Reset forgets the counter and the block of (scope, key).
func (r *RateLimiter) Reset(ctx context.Context, scope, key string) error {
	r.mu.Lock()
	delete(r.counters, rlKey{scope, key})
	delete(r.blocks, rlKey{scope, key})
	r.mu.Unlock()
	return nil
}

// sweep drops counters whose window has ended. The caller holds r.mu.
func (r *RateLimiter) sweep(now time.Time) {
	for k, c := range r.counters {
		if !now.Before(c.start.Add(c.window)) {
			delete(r.counters, k)
		}
	}
	for k, until := range r.blocks {
		if !now.Before(until) {
			delete(r.blocks, k)
		}
	}
}
