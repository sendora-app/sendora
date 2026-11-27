// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// staleKeysCluster is a Cluster runtime whose cached keys miss the tenant's
// KEK (it was switched through another replica) until ForgetKeys runs.
type staleKeysCluster struct {
	mu      sync.Mutex
	p       *platform.Platform
	stale   bool
	other   error // returned instead when set
	opens   int
	forgets int
}

func (c *staleKeysCluster) runtime() *ClusterRuntime {
	return &ClusterRuntime{
		OpenStore: func(t *platform.Tenant, dir string, _ []byte) (*store.Store, error) {
			c.mu.Lock()
			c.opens++
			stale, other := c.stale, c.other
			c.mu.Unlock()
			if other != nil {
				return nil, other
			}
			if stale {
				return nil, fmt.Errorf("opening the keyring: %w", ports.ErrUnknownKEK)
			}
			dbKey, root, err := c.p.TenantKeys(t)
			if err != nil {
				return nil, err
			}
			return store.OpenTenant(dir, dbKey, root, false)
		},
		ForgetKeys: func(string) {
			c.mu.Lock()
			c.forgets++
			c.stale = false
			c.mu.Unlock()
		},
	}
}

func (c *staleKeysCluster) set(stale bool, other error) {
	c.mu.Lock()
	c.stale, c.other = stale, other
	c.mu.Unlock()
}

func (c *staleKeysCluster) counts() (opens, forgets int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opens, c.forgets
}

// A store open that fails because the cached keys miss the tenant's KEK drops
// them and opens again with fresh ones, at most once per keyRefreshEvery per
// tenant; other errors never drop the cache.
func TestOpenStoreRefetchesKeysAfterUnknownKEK(t *testing.T) {
	m := newMTEnv(t)
	m.newTenant("acme")
	tn, err := m.p.TenantBySlug("acme")
	if err != nil {
		t.Fatal(err)
	}
	c := &staleKeysCluster{p: m.p}
	m.h.cfg.Cluster = c.runtime()
	t.Cleanup(func() { m.h.cfg.Cluster = nil })
	open := func() error {
		st, err := m.h.openStore(tn)
		if err == nil {
			st.Close()
		}
		return err
	}

	c.set(true, nil)
	if err := open(); err != nil {
		t.Fatalf("stale keys were not fetched again: %v", err)
	}
	if o, f := c.counts(); o != 2 || f != 1 {
		t.Fatalf("after one refetch: opens=%d forgets=%d, want 2 and 1", o, f)
	}

	// Within the interval: no second refetch, the error is reported.
	c.set(true, nil)
	if err := open(); !errors.Is(err, ports.ErrUnknownKEK) {
		t.Fatalf("throttled: %v, want ErrUnknownKEK", err)
	}
	if o, f := c.counts(); o != 3 || f != 1 {
		t.Fatalf("throttled: opens=%d forgets=%d, want 3 and 1", o, f)
	}

	// After the interval it may fetch again.
	m.h.keyRefreshMu.Lock()
	m.h.keyRefreshAt[tn.ID] = time.Now().Add(-keyRefreshEvery)
	m.h.keyRefreshMu.Unlock()
	if err := open(); err != nil {
		t.Fatalf("after the interval: %v", err)
	}
	if o, f := c.counts(); o != 5 || f != 2 {
		t.Fatalf("after the interval: opens=%d forgets=%d, want 5 and 2", o, f)
	}

	// Any other failure keeps the cache.
	m.h.keyRefreshMu.Lock()
	m.h.keyRefreshAt = nil
	m.h.keyRefreshMu.Unlock()
	boom := errors.New("database unavailable")
	c.set(false, boom)
	if err := open(); !errors.Is(err, boom) {
		t.Fatalf("other error: %v", err)
	}
	if o, f := c.counts(); o != 6 || f != 2 {
		t.Fatalf("other error: opens=%d forgets=%d, want 6 and 2", o, f)
	}
}
