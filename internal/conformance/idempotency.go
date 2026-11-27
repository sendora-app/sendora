// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunIdempotency: the idempotency key contract (design 4.1, D29).
func RunIdempotency(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	lease := now.Add(time.Minute)
	claim := func(t *testing.T, s ports.Store, scope, key, req string, at time.Time) ports.IdempotencyClaim {
		t.Helper()
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c, err := tx.Idempotency().Claim(ctx, scope, key, req, at, at.Add(time.Minute))
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return c
	}

	t.Run("Lifecycle", func(t *testing.T) {
		s := open(t)
		r := s.Idempotency()
		if c := claim(t, s, "u:1", "k1", "h1", now); c.State != ports.IdempotencyNew {
			t.Fatalf("first claim = %+v", c)
		}
		if c := claim(t, s, "u:1", "k1", "h1", now); c.State != ports.IdempotencyInProgress {
			t.Fatalf("claim during the lease = %+v", c)
		}
		if c := claim(t, s, "u:1", "k1", "h2", now); c.State != ports.IdempotencyMismatch {
			t.Fatalf("claim with another request = %+v", c)
		}
		// Scopes are separate.
		if c := claim(t, s, "u:2", "k1", "h2", now); c.State != ports.IdempotencyNew {
			t.Fatalf("claim in another scope = %+v", c)
		}
		if n, err := r.MarkReplayed(ctx, "u:1", "k1", now); err != nil || n != 0 {
			t.Fatalf("MarkReplayed before completion = %d, %v", n, err)
		}
		resp := []byte{0, 1, 2, 0xff}
		if err := r.Complete(ctx, "u:1", "k1", 201, resp); err != nil {
			t.Fatal(err)
		}
		c := claim(t, s, "u:1", "k1", "h1", now.Add(time.Hour))
		if c.State != ports.IdempotencyDone || c.Status != 201 || !bytes.Equal(c.Response, resp) {
			t.Fatalf("claim after completion = %+v", c)
		}
		// Completion is final: Complete and Release leave it alone.
		if err := r.Complete(ctx, "u:1", "k1", 500, nil); err != nil {
			t.Fatal(err)
		}
		if err := r.Release(ctx, "u:1", "k1"); err != nil {
			t.Fatal(err)
		}
		if c := claim(t, s, "u:1", "k1", "h1", now); c.State != ports.IdempotencyDone || c.Status != 201 {
			t.Fatalf("completed key changed: %+v", c)
		}
		if n, err := r.MarkReplayed(ctx, "u:1", "k1", now); err != nil || n != 1 {
			t.Fatalf("MarkReplayed = %d, %v", n, err)
		}
		// Release frees an in-progress key for a retry.
		if err := r.Release(ctx, "u:2", "k1"); err != nil {
			t.Fatal(err)
		}
		if c := claim(t, s, "u:2", "k1", "h3", now); c.State != ports.IdempotencyNew {
			t.Fatalf("claim after release = %+v", c)
		}
	})

	t.Run("ExpiredLeaseIsTakenOver", func(t *testing.T) {
		s := open(t)
		if c := claim(t, s, "u:1", "k", "h", now); c.State != ports.IdempotencyNew {
			t.Fatal(c)
		}
		if c := claim(t, s, "u:1", "k", "h", lease.Add(-time.Second)); c.State != ports.IdempotencyInProgress {
			t.Fatalf("before the lease ends: %+v", c)
		}
		if c := claim(t, s, "u:1", "k", "h", lease); c.State != ports.IdempotencyNew {
			t.Fatalf("at the lease end: %+v", c)
		}
		if c := claim(t, s, "u:1", "k", "h", lease); c.State != ports.IdempotencyInProgress {
			t.Fatalf("the takeover did not renew the lease: %+v", c)
		}
	})

	t.Run("Expire", func(t *testing.T) {
		s := open(t)
		claim(t, s, "u:1", "old", "h", now.Add(-25*time.Hour))
		claim(t, s, "u:1", "new", "h", now)
		n, err := s.Idempotency().Expire(ctx, now.Add(-24*time.Hour))
		if err != nil || n != 1 {
			t.Fatalf("Expire = %d, %v", n, err)
		}
		if c := claim(t, s, "u:1", "old", "h", now); c.State != ports.IdempotencyNew {
			t.Fatalf("expired key still known: %+v", c)
		}
		if c := claim(t, s, "u:1", "new", "h", now); c.State != ports.IdempotencyInProgress {
			t.Fatalf("young key lost: %+v", c)
		}
	})

	t.Run("ConcurrentClaimsSerialise", func(t *testing.T) {
		s := open(t)
		const n = 8
		var wg sync.WaitGroup
		states := make(chan ports.IdempotencyState, n)
		errs := make(chan error, n)
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tx, err := s.Begin(ctx)
				if err != nil {
					errs <- err
					return
				}
				c, err := tx.Idempotency().Claim(ctx, "u:1", "race", "h", now, lease)
				if err != nil {
					tx.Rollback()
					errs <- err
					return
				}
				if err := tx.Commit(); err != nil {
					errs <- err
					return
				}
				states <- c.State
			}()
		}
		wg.Wait()
		close(states)
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		count := map[ports.IdempotencyState]int{}
		for st := range states {
			count[st]++
		}
		if count[ports.IdempotencyNew] != 1 || count[ports.IdempotencyInProgress] != n-1 {
			t.Fatalf("claims = %v, want exactly one new", fmt.Sprint(count))
		}
	})
}
