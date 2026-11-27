// SPDX-License-Identifier: AGPL-3.0-or-later

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAPI serves one namespace's leases with the API server's optimistic
// concurrency: PUT must carry the current resourceVersion (else 409).
type fakeAPI struct {
	mu     sync.Mutex
	leases map[string]map[string]any
	rv     int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	const prefix = "/apis/coordination.k8s.io/v1/namespaces/test/leases"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/")
	write := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	switch r.Method {
	case http.MethodGet:
		l, ok := f.leases[name]
		if !ok {
			write(404, map[string]any{"reason": "NotFound"})
			return
		}
		write(200, l)
	case http.MethodPost, http.MethodPut:
		var l map[string]any
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &l); err != nil {
			write(400, nil)
			return
		}
		md, _ := l["metadata"].(map[string]any)
		if r.Method == http.MethodPost {
			name, _ = md["name"].(string)
			if _, ok := f.leases[name]; ok {
				write(409, map[string]any{"reason": "AlreadyExists"})
				return
			}
		} else {
			cur, ok := f.leases[name]
			if !ok {
				write(404, nil)
				return
			}
			if md["resourceVersion"] != cur["metadata"].(map[string]any)["resourceVersion"] {
				write(409, map[string]any{"reason": "Conflict"})
				return
			}
		}
		f.rv++
		md["resourceVersion"] = strconv.Itoa(f.rv)
		l["metadata"] = md
		f.leases[name] = l
		write(200, l)
	default:
		write(405, nil)
	}
}

// partition fails every request while cut is set (a network partition).
type partition struct {
	cut  atomic.Bool
	next http.RoundTripper
}

func (p *partition) RoundTrip(r *http.Request) (*http.Response, error) {
	if p.cut.Load() {
		return nil, errors.New("partitioned")
	}
	return p.next.RoundTrip(r)
}

func newTestElector(t *testing.T, url, id string, rt http.RoundTripper) *LeaseElector {
	t.Helper()
	e, err := NewLeaseElector(LeaseConfig{Name: "sendora-controller", Namespace: "test", Identity: id, APIServer: url,
		LeaseDuration: 600 * time.Millisecond, RenewDeadline: 400 * time.Millisecond, RetryPeriod: 50 * time.Millisecond,
		TokenFile: os.DevNull, Client: &http.Client{Transport: rt, Timeout: time.Second}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// watch fails the test if two candidates ever lead at once and returns the
// first leader seen after since.
func waitLeader(t *testing.T, es []*LeaseElector, timeout time.Duration) (int, int64) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		leaders, idx, epoch := 0, -1, int64(0)
		for i, e := range es {
			if ok, ep := e.Leader(); ok {
				leaders++
				idx, epoch = i, ep
			}
		}
		if leaders > 1 {
			t.Fatal("two leaders at once")
		}
		if leaders == 1 {
			return idx, epoch
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no leader")
	return -1, 0
}

func TestLeaseOneLeaderAndHandover(t *testing.T) {
	api := httptest.NewServer(&fakeAPI{leases: map[string]map[string]any{}})
	defer api.Close()
	parts := []*partition{{next: http.DefaultTransport}, {next: http.DefaultTransport}}
	es := []*LeaseElector{newTestElector(t, api.URL, "pod-a", parts[0]), newTestElector(t, api.URL, "pod-b", parts[1])}
	ctxs := make([]context.CancelFunc, 2)
	done := make([]chan struct{}, 2)
	for i, e := range es {
		ctx, cancel := context.WithCancel(context.Background())
		ctxs[i], done[i] = cancel, make(chan struct{})
		go func(e *LeaseElector, d chan struct{}) { e.Run(ctx); close(d) }(e, done[i])
	}
	defer func() {
		for i := range es {
			ctxs[i]()
			<-done[i]
		}
	}()

	first, epoch1 := waitLeader(t, es, 3*time.Second)
	// Stable: the same leader for a while, never two.
	stableUntil := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(stableUntil) {
		idx, _ := waitLeader(t, es, time.Second)
		if idx != first {
			t.Fatalf("leadership moved without cause")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Orderly stop: the leader releases, the other takes over at once.
	ctxs[first]()
	<-done[first]
	other := 1 - first
	start := time.Now()
	idx, epoch2 := waitLeader(t, es, 2*time.Second)
	if idx != other || epoch2 <= epoch1 {
		t.Fatalf("after release: leader %d epoch %d (want %d, > %d)", idx, epoch2, other, epoch1)
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("handover after release took %s", took)
	}

	// Restart the stopped candidate; it follows.
	ctx, cancel := context.WithCancel(context.Background())
	ctxs[first], done[first] = cancel, make(chan struct{})
	go func(e *LeaseElector, d chan struct{}) { e.Run(ctx); close(d) }(es[first], done[first])
	time.Sleep(200 * time.Millisecond)
	if idx, _ := waitLeader(t, es, time.Second); idx != other {
		t.Fatal("restarted candidate took the lease from a live leader")
	}

	// Crash-like loss: the leader is partitioned from the API server. It
	// steps down after the renew deadline, and the other candidate takes
	// over only after the lease duration, never overlapping.
	parts[other].cut.Store(true)
	start = time.Now()
	idx, epoch3 := waitLeader(t, es, 3*time.Second)
	for idx == other {
		time.Sleep(5 * time.Millisecond)
		idx, epoch3 = waitLeader(t, es, 3*time.Second)
	}
	if epoch3 <= epoch2 {
		t.Fatalf("epoch did not grow: %d after %d", epoch3, epoch2)
	}
	if took := time.Since(start); took < 400*time.Millisecond || took > 3*time.Second {
		t.Fatalf("takeover after partition took %s", took)
	}
	parts[other].cut.Store(false)
}
