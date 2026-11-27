// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunIPBans pins the contract of ports.IPBanRepository.
func RunIPBans(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	// Whole seconds: every adapter stores one-second precision.
	now := time.Unix(1_800_000_000, 0)

	t.Run("EmptyList", func(t *testing.T) {
		r := open(t).IPBans()
		got, err := r.List(ctx)
		if err != nil || len(got) != 0 {
			t.Fatalf("List on empty store = %v, %v", got, err)
		}
	})

	t.Run("PutListRoundTrip", func(t *testing.T) {
		r := open(t).IPBans()
		want := []ports.IPBan{
			{Key: "192.0.2.1", Until: now.Add(30 * time.Minute), Strikes: 1, LastStrike: now},
			{Key: "2001:db8::/64", Until: now.Add(time.Hour), Strikes: 2, LastStrike: now.Add(-time.Minute)},
		}
		for _, b := range want {
			if err := r.Put(ctx, b); err != nil {
				t.Fatal(err)
			}
		}
		assertBans(t, r, want)
	})

	t.Run("PutReplaces", func(t *testing.T) {
		r := open(t).IPBans()
		if err := r.Put(ctx, ports.IPBan{Key: "192.0.2.1", Until: now, Strikes: 1, LastStrike: now}); err != nil {
			t.Fatal(err)
		}
		b := ports.IPBan{Key: "192.0.2.1", Until: now.Add(2 * time.Hour), Strikes: 3, LastStrike: now.Add(time.Minute)}
		if err := r.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
		assertBans(t, r, []ports.IPBan{b})
	})

	t.Run("SubSecondTruncated", func(t *testing.T) {
		r := open(t).IPBans()
		b := ports.IPBan{Key: "192.0.2.9", Until: now.Add(1500 * time.Millisecond), Strikes: 1, LastStrike: now.Add(900 * time.Millisecond)}
		if err := r.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
		assertBans(t, r, []ports.IPBan{{Key: b.Key, Until: now.Add(time.Second), Strikes: 1, LastStrike: now}})
	})

	t.Run("Delete", func(t *testing.T) {
		r := open(t).IPBans()
		keep := ports.IPBan{Key: "192.0.2.2", Until: now, Strikes: 1, LastStrike: now}
		for _, b := range []ports.IPBan{keep, {Key: "192.0.2.3", Until: now, Strikes: 1, LastStrike: now}} {
			if err := r.Put(ctx, b); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.Delete(ctx, "192.0.2.3"); err != nil {
			t.Fatal(err)
		}
		if err := r.Delete(ctx, "198.51.100.7"); err != nil {
			t.Fatalf("deleting a missing key must not fail: %v", err)
		}
		assertBans(t, r, []ports.IPBan{keep})
	})

	t.Run("Prune", func(t *testing.T) {
		r := open(t).IPBans()
		memory := 24 * time.Hour
		bans := []ports.IPBan{
			// Ended and strikes expired: removed.
			{Key: "gone", Until: now.Add(-time.Hour), Strikes: 1, LastStrike: now.Add(-48 * time.Hour)},
			// Still active: kept even though the strike is old.
			{Key: "active", Until: now.Add(time.Hour), Strikes: 4, LastStrike: now.Add(-48 * time.Hour)},
			// Ended but the strike is remembered: kept.
			{Key: "remembered", Until: now.Add(-time.Hour), Strikes: 2, LastStrike: now.Add(-time.Hour)},
			// Boundaries are exclusive: ends exactly now, strike exactly memory ago.
			{Key: "boundary", Until: now, Strikes: 1, LastStrike: now.Add(-memory)},
		}
		for _, b := range bans {
			if err := r.Put(ctx, b); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.Prune(ctx, now, now.Add(-memory)); err != nil {
			t.Fatal(err)
		}
		assertBans(t, r, bans[1:])
	})

	t.Run("ConcurrentPuts", func(t *testing.T) {
		r := open(t).IPBans()
		const n = 16
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs <- r.Put(ctx, ports.IPBan{Key: fmt.Sprintf("198.51.100.%d", i), Until: now, Strikes: i, LastStrike: now})
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := r.List(ctx)
		if err != nil || len(got) != n {
			t.Fatalf("List after %d concurrent puts: %d rows, %v", n, len(got), err)
		}
	})
}

func assertBans(t *testing.T, r ports.IPBanRepository, want []ports.IPBan) {
	t.Helper()
	got, err := r.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Key < got[j].Key })
	w := append([]ports.IPBan(nil), want...)
	sort.Slice(w, func(i, j int) bool { return w[i].Key < w[j].Key })
	if len(got) != len(w) {
		t.Fatalf("got %d bans %+v, want %d %+v", len(got), got, len(w), w)
	}
	for i := range w {
		g := got[i]
		if g.Key != w[i].Key || !g.Until.Equal(w[i].Until) || g.Strikes != w[i].Strikes || !g.LastStrike.Equal(w[i].LastStrike) {
			t.Fatalf("ban %d = %+v, want %+v", i, g, w[i])
		}
	}
}
