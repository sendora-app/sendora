// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunLock pins the contract of ports.Lock.
func RunLock(t *testing.T, newLock func(testing.TB) ports.Lock) {
	ctx := context.Background()

	t.Run("MutualExclusion", func(t *testing.T) {
		l := newLock(t)
		var inside, max, total atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					err := l.WithLock(ctx, "quota", func(context.Context) error {
						n := inside.Add(1)
						for {
							m := max.Load()
							if n <= m || max.CompareAndSwap(m, n) {
								break
							}
						}
						total.Add(1)
						inside.Add(-1)
						return nil
					})
					if err != nil {
						t.Error(err)
					}
				}
			}()
		}
		wg.Wait()
		if max.Load() != 1 || total.Load() != 160 {
			t.Fatalf("max holders %d (want 1), runs %d (want 160)", max.Load(), total.Load())
		}
	})

	t.Run("NamesAreIndependent", func(t *testing.T) {
		l := newLock(t)
		err := l.WithLock(ctx, "a", func(ctx context.Context) error {
			done := make(chan error, 1)
			go func() { done <- l.WithLock(ctx, "b", func(context.Context) error { return nil }) }()
			select {
			case err := <-done:
				return err
			case <-time.After(5 * time.Second):
				return errors.New("lock b blocked while a was held")
			}
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ReturnsFnError", func(t *testing.T) {
		want := errors.New("boom")
		if err := newLock(t).WithLock(ctx, "x", func(context.Context) error { return want }); !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
	})

	t.Run("ContextCancelWhileWaiting", func(t *testing.T) {
		l := newLock(t)
		held, release := make(chan struct{}), make(chan struct{})
		go l.WithLock(ctx, "x", func(context.Context) error {
			close(held)
			<-release
			return nil
		})
		<-held
		defer close(release)
		cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		ran := false
		err := l.WithLock(cctx, "x", func(context.Context) error { ran = true; return nil })
		if !errors.Is(err, context.DeadlineExceeded) || ran {
			t.Fatalf("waiting on a held lock past the deadline: err %v, fn ran %v", err, ran)
		}
	})
}

// RunRateLimiter pins the contract of ports.RateLimiter. newLimiter receives a
// clock it must use, so window boundaries are deterministic.
func RunRateLimiter(t *testing.T, newLimiter func(t testing.TB, now func() time.Time) ports.RateLimiter) {
	ctx := context.Background()
	newClock := func() (func() time.Time, func(time.Duration)) {
		var mu sync.Mutex
		cur := time.Unix(1_800_000_000, 0) // a multiple of every window used below
		return func() time.Time { mu.Lock(); defer mu.Unlock(); return cur },
			func(d time.Duration) { mu.Lock(); cur = cur.Add(d); mu.Unlock() }
	}

	t.Run("CountsWithinWindow", func(t *testing.T) {
		now, _ := newClock()
		r := newLimiter(t, now)
		for want := 1; want <= 5; want++ {
			n, err := r.Hit(ctx, "login", "192.0.2.1", time.Minute)
			if err != nil || n != want {
				t.Fatalf("hit %d: got %d, %v", want, n, err)
			}
		}
	})

	t.Run("KeysAndScopesAreIndependent", func(t *testing.T) {
		now, _ := newClock()
		r := newLimiter(t, now)
		r.Hit(ctx, "login", "a", time.Minute)
		r.Hit(ctx, "login", "a", time.Minute)
		if n, _ := r.Hit(ctx, "login", "b", time.Minute); n != 1 {
			t.Fatalf("other key: %d", n)
		}
		if n, _ := r.Hit(ctx, "unlock", "a", time.Minute); n != 1 {
			t.Fatalf("other scope: %d", n)
		}
	})

	t.Run("NewWindowRestarts", func(t *testing.T) {
		now, advance := newClock()
		r := newLimiter(t, now)
		r.Hit(ctx, "login", "a", time.Minute)
		r.Hit(ctx, "login", "a", time.Minute)
		advance(59 * time.Second)
		if n, _ := r.Hit(ctx, "login", "a", time.Minute); n != 3 {
			t.Fatalf("same window: %d", n)
		}
		advance(time.Second)
		if n, _ := r.Hit(ctx, "login", "a", time.Minute); n != 1 {
			t.Fatalf("next window: %d", n)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		now, _ := newClock()
		r := newLimiter(t, now)
		r.Hit(ctx, "login", "a", time.Minute)
		r.Hit(ctx, "login", "a", time.Minute)
		if err := r.Reset(ctx, "login", "a"); err != nil {
			t.Fatal(err)
		}
		if n, _ := r.Hit(ctx, "login", "a", time.Minute); n != 1 {
			t.Fatalf("after reset: %d", n)
		}
	})

	t.Run("ConcurrentHitsAreAllCounted", func(t *testing.T) {
		now, _ := newClock()
		r := newLimiter(t, now)
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); r.Hit(ctx, "login", "a", time.Hour) }()
		}
		wg.Wait()
		if n, _ := r.Hit(ctx, "login", "a", time.Hour); n != 51 {
			t.Fatalf("after 50 concurrent hits: %d, want 51", n)
		}
	})

	t.Run("HitNAndGiveBack", func(t *testing.T) {
		now, _ := newClock()
		r := newLimiter(t, now)
		if n, err := r.HitN(ctx, "mail", "u1", 5, time.Hour); err != nil || n != 5 {
			t.Fatalf("hit 5: %d, %v", n, err)
		}
		if n, _ := r.HitN(ctx, "mail", "u1", -2, time.Hour); n != 3 {
			t.Fatalf("give back 2: %d", n)
		}
		if n, _ := r.HitN(ctx, "mail", "u1", -10, time.Hour); n != 0 {
			t.Fatalf("never below zero: %d", n)
		}
		if n, _ := r.HitN(ctx, "mail", "u2", -1, time.Hour); n != 0 {
			t.Fatalf("give back on an unused key: %d", n)
		}
		if n, _ := r.Hit(ctx, "mail", "u1", time.Hour); n != 1 {
			t.Fatalf("after give back: %d", n)
		}
	})

	t.Run("BlockAndExpiry", func(t *testing.T) {
		now, advance := newClock()
		r := newLimiter(t, now)
		if _, blocked, err := r.Blocked(ctx, "unlock", "s1"); err != nil || blocked {
			t.Fatalf("fresh key blocked: %v, %v", blocked, err)
		}
		until := now().Add(10 * time.Minute)
		if err := r.Block(ctx, "unlock", "s1", until); err != nil {
			t.Fatal(err)
		}
		// A shorter block never shortens the longer one.
		if err := r.Block(ctx, "unlock", "s1", now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		got, blocked, err := r.Blocked(ctx, "unlock", "s1")
		if err != nil || !blocked || !got.Equal(until) {
			t.Fatalf("blocked: %v until %v (want %v), %v", blocked, got, until, err)
		}
		if _, blocked, _ := r.Blocked(ctx, "unlock", "s2"); blocked {
			t.Fatal("other key blocked")
		}
		if _, blocked, _ := r.Blocked(ctx, "setup", "s1"); blocked {
			t.Fatal("other scope blocked")
		}
		advance(10 * time.Minute)
		if _, blocked, _ := r.Blocked(ctx, "unlock", "s1"); blocked {
			t.Fatal("still blocked after the block ended")
		}
	})

	t.Run("ResetClearsBlock", func(t *testing.T) {
		now, _ := newClock()
		r := newLimiter(t, now)
		r.Block(ctx, "unlock", "s1", now().Add(time.Hour))
		if err := r.Reset(ctx, "unlock", "s1"); err != nil {
			t.Fatal(err)
		}
		if _, blocked, _ := r.Blocked(ctx, "unlock", "s1"); blocked {
			t.Fatal("blocked after reset")
		}
	})
}

// RunRateLimiterShared pins that two limiter instances (two replicas) share
// their counters and blocks. newPair returns two instances on one backend.
func RunRateLimiterShared(t *testing.T, newPair func(t testing.TB, now func() time.Time) (ports.RateLimiter, ports.RateLimiter)) {
	ctx := context.Background()
	cur := time.Unix(1_800_000_000, 0)
	a, b := newPair(t, func() time.Time { return cur })
	a.Hit(ctx, "login", "203.0.113.9", time.Minute)
	a.Hit(ctx, "login", "203.0.113.9", time.Minute)
	if n, err := b.Hit(ctx, "login", "203.0.113.9", time.Minute); err != nil || n != 3 {
		t.Fatalf("hit on the second replica: %d, %v (want 3)", n, err)
	}
	a.Block(ctx, "ban", "203.0.113.0/24", cur.Add(time.Hour))
	if _, blocked, err := b.Blocked(ctx, "ban", "203.0.113.0/24"); err != nil || !blocked {
		t.Fatalf("block not seen by the second replica: %v, %v", blocked, err)
	}
	b.Reset(ctx, "ban", "203.0.113.0/24")
	if _, blocked, _ := a.Blocked(ctx, "ban", "203.0.113.0/24"); blocked {
		t.Fatal("reset on the second replica not seen by the first")
	}
}

// RunLockShared pins mutual exclusion across two Lock instances (two
// replicas) on one backend.
func RunLockShared(t *testing.T, newPair func(testing.TB) (ports.Lock, ports.Lock)) {
	ctx := context.Background()
	a, b := newPair(t)
	var inside, max, total atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		l := a
		if i%2 == 1 {
			l = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := l.WithLock(ctx, "tenant-x:upload:1", func(context.Context) error {
					n := inside.Add(1)
					for {
						m := max.Load()
						if n <= m || max.CompareAndSwap(m, n) {
							break
						}
					}
					time.Sleep(time.Millisecond)
					total.Add(1)
					inside.Add(-1)
					return nil
				}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if max.Load() != 1 || total.Load() != 40 {
		t.Fatalf("max holders %d (want 1), runs %d (want 40)", max.Load(), total.Load())
	}
}

// RunCoordinator pins the contract of ports.Coordinator for a single member.
// (Multi-member tests, such as exactly one leader, join with the Cluster adapter.)
func RunCoordinator(t *testing.T, newCoordinator func(testing.TB) ports.Coordinator) {
	t.Run("NotifyReachesSubscribers", func(t *testing.T) {
		c := newCoordinator(t)
		a, cancelA := c.Subscribe("settings")
		defer cancelA()
		b, cancelB := c.Subscribe("settings")
		defer cancelB()
		other, cancelO := c.Subscribe("routing")
		defer cancelO()
		if err := c.Notify(context.Background(), "settings"); err != nil {
			t.Fatal(err)
		}
		for i, ch := range []<-chan struct{}{a, b} {
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
				t.Fatalf("subscriber %d not notified", i)
			}
		}
		select {
		case <-other:
			t.Fatal("subscriber of another topic notified")
		case <-time.After(20 * time.Millisecond):
		}
	})

	t.Run("NotifyCoalescesAndNeverBlocks", func(t *testing.T) {
		c := newCoordinator(t)
		ch, cancel := c.Subscribe("settings")
		defer cancel()
		for i := 0; i < 100; i++ {
			if err := c.Notify(context.Background(), "settings"); err != nil {
				t.Fatal(err)
			}
		}
		<-ch
	})

	t.Run("CancelClosesChannel", func(t *testing.T) {
		c := newCoordinator(t)
		ch, cancel := c.Subscribe("settings")
		cancel()
		cancel() // idempotent
		if _, ok := <-ch; ok {
			t.Fatal("channel still open after cancel")
		}
		if err := c.Notify(context.Background(), "settings"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("RunPeriodicOnLeaderUntilCancel", func(t *testing.T) {
		c := newCoordinator(t)
		if !c.IsLeader() {
			t.Skip("not the leader")
		}
		ctx, cancel := context.WithCancel(context.Background())
		var runs, concurrent, maxConcurrent atomic.Int32
		c.RunPeriodic(ctx, "test", 5*time.Millisecond, func(context.Context) {
			n := concurrent.Add(1)
			if n > maxConcurrent.Load() {
				maxConcurrent.Store(n)
			}
			runs.Add(1)
			time.Sleep(2 * time.Millisecond)
			concurrent.Add(-1)
		})
		deadline := time.Now().Add(5 * time.Second)
		for runs.Load() < 3 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		if runs.Load() < 3 {
			t.Fatalf("only %d runs", runs.Load())
		}
		if maxConcurrent.Load() > 1 {
			t.Fatalf("fn ran concurrently with itself")
		}
		time.Sleep(20 * time.Millisecond) // let a run in flight finish
		after := runs.Load()
		time.Sleep(30 * time.Millisecond)
		if runs.Load() != after {
			t.Fatalf("runs continued after cancel")
		}
	})

	t.Run("EpochWhileLeader", func(t *testing.T) {
		c := newCoordinator(t)
		if c.IsLeader() && c.Epoch() <= 0 {
			t.Fatalf("leader with epoch %d", c.Epoch())
		}
		if !c.IsLeader() && c.Epoch() != 0 {
			t.Fatalf("follower with epoch %d", c.Epoch())
		}
	})

	t.Run("SignalsCoalesceAndAreTakenOnce", func(t *testing.T) {
		c := newCoordinator(t)
		ctx := context.Background()
		wake, cancel := c.Subscribe(ports.WorkTopic("mail"))
		defer cancel()
		for _, tn := range []string{"t1", "t2", "t1", "t3"} {
			if err := c.Signal(ctx, "mail", tn); err != nil {
				t.Fatal(err)
			}
			time.Sleep(2 * time.Millisecond) // distinct signal times
		}
		c.Signal(ctx, "forward", "t9")
		select {
		case <-wake:
		case <-time.After(5 * time.Second):
			t.Fatal("work topic not notified")
		}
		got, err := c.TakeSignals(ctx, "mail", 2)
		if err != nil || len(got) != 2 || got[0] != "t1" || got[1] != "t2" {
			t.Fatalf("first take: %v, %v (want [t1 t2])", got, err)
		}
		got, _ = c.TakeSignals(ctx, "mail", 10)
		if len(got) != 1 || got[0] != "t3" {
			t.Fatalf("second take: %v (want [t3])", got)
		}
		if got, _ := c.TakeSignals(ctx, "mail", 10); len(got) != 0 {
			t.Fatalf("taken twice: %v", got)
		}
		if got, _ := c.TakeSignals(ctx, "forward", 10); len(got) != 1 || got[0] != "t9" {
			t.Fatalf("other kind: %v", got)
		}
		if got, err := c.TakeSignals(ctx, "mail", 0); err != nil || len(got) != 0 {
			t.Fatalf("limit 0: %v, %v", got, err)
		}
	})
}

// RunCoordinatorShared pins the multi-replica contract: a notification on one
// member wakes the subscribers of another, a signal from one member is taken
// once by either, and concurrent takers never receive the same signal.
func RunCoordinatorShared(t *testing.T, newPair func(testing.TB) (ports.Coordinator, ports.Coordinator)) {
	ctx := context.Background()
	t.Run("NotifyCrossesMembers", func(t *testing.T) {
		a, b := newPair(t)
		ch, cancel := b.Subscribe("routes")
		defer cancel()
		time.Sleep(50 * time.Millisecond) // the subscription is polled/listened from now on
		if err := a.Notify(ctx, "routes"); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatal("notification on member A did not reach member B")
		}
	})
	t.Run("SignalTakenOnceAcrossMembers", func(t *testing.T) {
		a, b := newPair(t)
		const n = 40
		for i := 0; i < n; i++ {
			if err := a.Signal(ctx, "mail", "tenant"+strconv.Itoa(i)); err != nil {
				t.Fatal(err)
			}
		}
		var mu sync.Mutex
		seen := map[string]int{}
		var wg sync.WaitGroup
		for _, c := range []ports.Coordinator{a, b, a, b} {
			wg.Add(1)
			go func(c ports.Coordinator) {
				defer wg.Done()
				for {
					got, err := c.TakeSignals(ctx, "mail", 3)
					if err != nil {
						t.Error(err)
						return
					}
					if len(got) == 0 {
						return
					}
					mu.Lock()
					for _, g := range got {
						seen[g]++
					}
					mu.Unlock()
				}
			}(c)
		}
		wg.Wait()
		if len(seen) != n {
			t.Fatalf("%d distinct signals taken, want %d", len(seen), n)
		}
		for k, v := range seen {
			if v != 1 {
				t.Fatalf("signal %s taken %d times", k, v)
			}
		}
	})
}

// RunJobFences pins ports.JobFenceRepository (design 4.3, M7).
func RunJobFences(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	st := open(t)
	f := st.JobFences()
	if v, err := f.Current(ctx, "download_mail"); err != nil || v != 0 {
		t.Fatalf("fresh fence: %d, %v", v, err)
	}
	for _, step := range []struct {
		fence int64
		ok    bool
	}{{3, true}, {3, true}, {2, false}, {7, true}, {0, false}} {
		ok, err := f.Advance(ctx, "download_mail", step.fence)
		if err != nil || ok != step.ok {
			t.Fatalf("advance to %d: %v, %v (want %v)", step.fence, ok, err, step.ok)
		}
	}
	if v, _ := f.Current(ctx, "download_mail"); v != 7 {
		t.Fatalf("fence %d, want 7", v)
	}
	if v, _ := f.Current(ctx, "forward"); v != 0 {
		t.Fatalf("other kind: %d", v)
	}
	// Inside a transaction: visible there, gone after rollback; a stale
	// fence in a transaction changes nothing.
	tx, err := st.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := tx.JobFences().Advance(ctx, "download_mail", 9); err != nil || !ok {
		t.Fatalf("advance in tx: %v, %v", ok, err)
	}
	if v, _ := tx.JobFences().Current(ctx, "download_mail"); v != 9 {
		t.Fatalf("in tx: %d", v)
	}
	tx.Rollback()
	if v, _ := f.Current(ctx, "download_mail"); v != 7 {
		t.Fatalf("after rollback: %d, want 7", v)
	}
	tx, err = st.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := tx.JobFences().Advance(ctx, "download_mail", 8); !ok {
		t.Fatal("advance 8 in tx refused")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.Current(ctx, "download_mail"); v != 8 {
		t.Fatalf("after commit: %d, want 8", v)
	}
}
