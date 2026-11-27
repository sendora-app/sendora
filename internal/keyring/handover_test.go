// SPDX-License-Identifier: AGPL-3.0-or-later

package keyring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/adapters/keysource"
	"github.com/sendora-app/sendora/internal/ports"
)

// handoverSetup is a keyring wrapped under the "platform" KEK with a second,
// "tenant" KEK also loaded in the key source. Events are MACed under the
// platform KEK, as the Cluster does.
func handoverSetup(t *testing.T) (*Service, *memLog, *memRing, string, string) {
	t.Helper()
	pk, tk := newKEK(t), newKEK(t)
	ks, err := keysource.NewFromKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	platformRef := keysource.Fingerprint(pk)
	log, ring := &memLog{}, &memRing{}
	clock := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	s := &Service{KS: ks, Log: log, Ring: ring, MACRef: platformRef, Now: func() time.Time { clock = clock.Add(time.Second); return clock }}
	if err := ks.AddNamed("tenant:x", tk, false); err != nil {
		t.Fatal(err)
	}
	return s, log, ring, platformRef, "tenant:x"
}

func refsOf(t *testing.T, s *Service) map[string]int {
	t.Helper()
	r, err := s.WrapRefs(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHandoverMovesAllWraps(t *testing.T) {
	ctx := context.Background()
	s, _, ring, from, to := handoverSetup(t)
	if err := s.Init(ctx, "t1", "controller"); err != nil {
		t.Fatal(err)
	}
	before, err := s.Load(ctx, "t1", PurposeData, 0)
	if err != nil {
		t.Fatal(err)
	}
	committed := false
	var steps []string
	err = s.Handover(ctx, "t1", "admin", from, to, HandoverOptions{
		Commit: func(context.Context) error {
			committed = true
			if r := refsOf(t, s); r[from] != len(Purposes) || r[to] != len(Purposes) {
				t.Fatalf("both wraps must exist at the commit: %v", r)
			}
			return nil
		},
		Step: func(step, detail string) { steps = append(steps, step) },
	})
	if err != nil || !committed {
		t.Fatalf("Handover: %v committed=%v", err, committed)
	}
	if r := refsOf(t, s); r[from] != 0 || r[to] != len(Purposes) {
		t.Fatalf("after: %v", r)
	}
	if len(ring.rows) != len(Purposes) {
		t.Fatalf("%d rows left, want one per purpose", len(ring.rows))
	}
	after, err := s.Load(ctx, "t1", PurposeData, 0)
	if err != nil || string(after.DEK) != string(before.DEK) {
		t.Fatalf("the DEK changed or cannot be loaded: %v", err)
	}
	st, err := s.Verify(ctx, "t1")
	if err != nil || st.Handover.Phase != HandoverComplete || st.Handover.From != from || st.Handover.To != to {
		t.Fatalf("verify: %+v %v", st, err)
	}
	if want := []string{"begun", "wrapped", "verified", "committed", "removed"}; len(steps) != len(want) {
		t.Fatalf("steps = %v", steps)
	}
	// The reverse direction works.
	if err := s.Handover(ctx, "t1", "admin", to, from, HandoverOptions{}); err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if r := refsOf(t, s); r[to] != 0 || r[from] != len(Purposes) {
		t.Fatalf("after reverse: %v", r)
	}
}

// The old KEK is gone: a key source that only knows the new KEK reads the keys,
// one that only knows the old one cannot.
func TestHandoverDestroysTheOldWrap(t *testing.T) {
	ctx := context.Background()
	s, log, ring, from, to := handoverSetup(t)
	if err := s.Init(ctx, "t1", "controller"); err != nil {
		t.Fatal(err)
	}
	if err := s.Handover(ctx, "t1", "admin", from, to, HandoverOptions{}); err != nil {
		t.Fatal(err)
	}
	op := &Service{KS: s.KS, Log: log, Ring: ring, MACRef: from}
	for _, r := range ring.rows {
		if r.KEKRef == from {
			t.Fatalf("a wrap under the platform KEK survived: %s", r.Purpose)
		}
	}
	if _, err := op.Load(ctx, "t1", PurposeData, 0); err != nil {
		t.Fatalf("the service with both KEKs must still read: %v", err)
	}
}

// failRing fails the n-th mutating call ("crash"), then behaves again.
type failRing struct {
	*memRing
	n, calls int
}

var errCrash = errors.New("crash")

func (f *failRing) tick() error {
	f.calls++
	if f.calls == f.n {
		return errCrash
	}
	return nil
}
func (f *failRing) Add(ctx context.Context, r ports.KeyringRow) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.memRing.Add(ctx, r)
}
func (f *failRing) Remove(ctx context.Context, tenant, id string) (bool, error) {
	if err := f.tick(); err != nil {
		return false, err
	}
	return f.memRing.Remove(ctx, tenant, id)
}

type failLog struct {
	*memLog
	n, calls int
}

func (f *failLog) Append(ctx context.Context, e ports.ControlLogEvent) error {
	f.calls++
	if f.calls == f.n {
		return errCrash
	}
	return f.memLog.Append(ctx, e)
}

// A crash at any point of the hand-over leaves a keyring that verifies and
// opens, and repeating the hand-over completes it.
func TestHandoverResumesAfterACrashAtEveryStep(t *testing.T) {
	ctx := context.Background()
	for _, target := range []string{"log", "ring"} {
		for n := 1; n <= 40; n++ {
			s, log, ring, from, to := handoverSetup(t)
			if err := s.Init(ctx, "t1", "c"); err != nil {
				t.Fatal(err)
			}
			fl, fr := &failLog{memLog: log}, &failRing{memRing: ring}
			if target == "log" {
				fl.n = n
			} else {
				fr.n = n
			}
			s.Log, s.Ring = fl, fr
			err := s.Handover(ctx, "t1", "a", from, to, HandoverOptions{})
			if err == nil {
				if (target == "log" && fl.calls < n) || (target == "ring" && fr.calls < n) {
					break // n is beyond the last call of a run: all crash points covered
				}
				t.Fatalf("%s crash %d: no error", target, n)
			}
			if !errors.Is(err, errCrash) {
				t.Fatalf("%s crash %d: %v", target, n, err)
			}
			// Mid-way state: verifies, opens (under both KEKs), never without a wrap.
			if _, err := s.Verify(ctx, "t1"); err != nil {
				t.Fatalf("%s crash %d: keyring does not verify: %v", target, n, err)
			}
			if _, err := s.Load(ctx, "t1", PurposeData, 0); err != nil {
				t.Fatalf("%s crash %d: cannot load: %v", target, n, err)
			}
			for _, p := range Purposes {
				if w, _ := ring.Wraps(ctx, "t1", p, 1); len(w) == 0 {
					t.Fatalf("%s crash %d: %s has no wrap", target, n, p)
				}
			}
			// Resume.
			fl.n, fr.n = 0, 0
			if err := s.Handover(ctx, "t1", "a", from, to, HandoverOptions{}); err != nil {
				t.Fatalf("%s crash %d: resume: %v", target, n, err)
			}
			if r := refsOf(t, s); r[from] != 0 || r[to] != len(Purposes) {
				t.Fatalf("%s crash %d: after resume %v", target, n, r)
			}
			if st, err := s.Verify(ctx, "t1"); err != nil || st.Handover.Phase != HandoverComplete {
				t.Fatalf("%s crash %d: %+v %v", target, n, st, err)
			}
		}
	}
}

func TestHandoverRefusals(t *testing.T) {
	ctx := context.Background()
	s, _, ring, from, to := handoverSetup(t)
	if err := s.Init(ctx, "t1", "c"); err != nil {
		t.Fatal(err)
	}
	if err := s.Handover(ctx, "t1", "a", from, from, HandoverOptions{}); err == nil {
		t.Fatal("same KEK")
	}
	if err := s.Handover(ctx, "t1", "a", from, "tenant:unknown", HandoverOptions{}); err == nil {
		t.Fatal("unknown target KEK")
	}
	// A failing Commit leaves both wraps.
	boom := errors.New("boom")
	if err := s.Handover(ctx, "t1", "a", from, to, HandoverOptions{Commit: func(context.Context) error { return boom }}); !errors.Is(err, boom) {
		t.Fatalf("commit error: %v", err)
	}
	if r := refsOf(t, s); r[from] != len(Purposes) || r[to] != len(Purposes) {
		t.Fatalf("after a failed commit: %v", r)
	}
	// Removing the last wrap is refused by the verifier: a log that says all
	// wraps are retired does not verify.
	if err := s.Handover(ctx, "t1", "a", from, to, HandoverOptions{}); err != nil {
		t.Fatal(err)
	}
	for i := range ring.rows {
		ring.rows[i].Wrapped = append([]byte(nil), ring.rows[i].Wrapped...)
		ring.rows[i].Wrapped[len(ring.rows[i].Wrapped)-1] ^= 1 // tamper
	}
	if _, err := s.Verify(ctx, "t1"); !errors.Is(err, ErrBroken) {
		t.Fatalf("tampered wraps verify: %v", err)
	}
}

func TestCanOpenNeedsTheRightKEK(t *testing.T) {
	ctx := context.Background()
	s, _, _, from, to := handoverSetup(t)
	if err := s.Init(ctx, "t1", "c"); err != nil {
		t.Fatal(err)
	}
	if err := s.CanOpen(ctx, "t1", to); err == nil {
		t.Fatal("no wrap under the tenant KEK yet")
	}
	if err := s.Handover(ctx, "t1", "a", from, to, HandoverOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.CanOpen(ctx, "t1", to); err != nil {
		t.Fatal(err)
	}
	if err := s.CanOpen(ctx, "t1", from); err == nil {
		t.Fatal("the platform KEK still opens the keyring")
	}
}

// masterSetup: a keyring wrapped and MACed under the old platform KEK, the
// new platform KEK loaded next to it, as during a master key rotation (D46).
func masterSetup(t *testing.T) (s *Service, log *memLog, ring *memRing, oldRef, newRef string, newOnly func() *Service) {
	t.Helper()
	ok, nk := newKEK(t), newKEK(t)
	ks, err := keysource.NewFromKey(ok)
	if err != nil {
		t.Fatal(err)
	}
	oldRef, newRef = keysource.Fingerprint(ok), keysource.Fingerprint(nk)
	if err := ks.AddNamed(newRef, nk, false); err != nil {
		t.Fatal(err)
	}
	log, ring = &memLog{}, &memRing{}
	clock := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { clock = clock.Add(time.Second); return clock }
	s = &Service{KS: ks, Log: log, Ring: ring, MACRef: oldRef, Now: now}
	newOnly = func() *Service {
		k2, err := keysource.NewFromKey(nk)
		if err != nil {
			t.Fatal(err)
		}
		return &Service{KS: k2, Log: s.Log, Ring: s.Ring, MACRef: newRef, Now: now}
	}
	return
}

// The master key rotation moves the MAC to the new KEK, a crash at any call
// is resumed, and afterwards a service that only knows the new KEK verifies
// the log (old events MACed under the retired KEK are covered by the head).
func TestMasterHandoverMACsUnderTheNewKEKAndResumes(t *testing.T) {
	ctx := context.Background()
	for _, target := range []string{"log", "ring"} {
		for n := 1; n <= 60; n++ {
			s, log, ring, from, to, newOnly := masterSetup(t)
			if err := s.Init(ctx, "t1", "c"); err != nil {
				t.Fatal(err)
			}
			before, err := s.Load(ctx, "t1", PurposeData, 0)
			if err != nil {
				t.Fatal(err)
			}
			fl, fr := &failLog{memLog: log}, &failRing{memRing: ring}
			if target == "log" {
				fl.n = n
			} else {
				fr.n = n
			}
			s.Log, s.Ring = fl, fr
			opt := HandoverOptions{MACUnderTo: true}
			err = s.Handover(ctx, "t1", "a", from, to, opt)
			if err == nil {
				if (target == "log" && fl.calls < n) || (target == "ring" && fr.calls < n) {
					break
				}
				t.Fatalf("%s crash %d: no error", target, n)
			}
			if !errors.Is(err, errCrash) {
				t.Fatalf("%s crash %d: %v", target, n, err)
			}
			// A restart builds the service again from the old record: MACRef is the old KEK.
			s.MACRef = from
			if _, err := s.Verify(ctx, "t1"); err != nil {
				t.Fatalf("%s crash %d: does not verify with both KEKs: %v", target, n, err)
			}
			if _, err := s.Load(ctx, "t1", PurposeData, 0); err != nil {
				t.Fatalf("%s crash %d: cannot load: %v", target, n, err)
			}
			fl.n, fr.n = 0, 0
			if err := s.Handover(ctx, "t1", "a", from, to, opt); err != nil {
				t.Fatalf("%s crash %d: resume: %v", target, n, err)
			}
			if r := refsOf(t, s); r[from] != 0 || r[to] != len(Purposes) {
				t.Fatalf("%s crash %d: after resume %v", target, n, r)
			}
			// The new KEK alone verifies and opens everything; the head is MACed under it.
			no := newOnly()
			st, err := no.Verify(ctx, "t1")
			if err != nil || st.Head.MACKEK != to {
				t.Fatalf("%s crash %d: new KEK alone: %v head mac %q", target, n, err, st.Head.MACKEK)
			}
			after, err := no.Load(ctx, "t1", PurposeData, 0)
			if err != nil || string(after.DEK) != string(before.DEK) {
				t.Fatalf("%s crash %d: DEK after: %v", target, n, err)
			}
			// New events (a key rotation) are MACed under the new KEK and verify.
			if _, err := no.Rotate(ctx, "t1", PurposeData, "admin"); err != nil {
				t.Fatalf("%s crash %d: rotate after: %v", target, n, err)
			}
			if _, err := no.Verify(ctx, "t1"); err != nil {
				t.Fatalf("%s crash %d: verify after rotate: %v", target, n, err)
			}
		}
	}
}

// A retired KEK in the middle of the log is tolerated only because the head
// verifies; a head under an unknown KEK, or a forged MAC, is not.
func TestVerifyNeedsTheHeadMAC(t *testing.T) {
	ctx := context.Background()
	s, log, _, from, to, newOnly := masterSetup(t)
	if err := s.Init(ctx, "t1", "c"); err != nil {
		t.Fatal(err)
	}
	if err := s.Handover(ctx, "t1", "a", from, to, HandoverOptions{MACUnderTo: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := newOnly().Verify(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	// Old-KEK-only service: the head is MACed under the new KEK it does not hold.
	old, _ := keysource.NewFromKey(newKEK(t))
	if _, err := (&Service{KS: old, Log: log, Ring: s.Ring}).Verify(ctx, "t1"); err == nil {
		t.Fatal("a service without the head's KEK verified the log")
	}
	// A forged MAC on a middle event whose KEK is loaded is still refused.
	log.ev[2].MAC = append([]byte(nil), log.ev[2].MAC...)
	log.ev[2].MAC[0] ^= 1
	if _, err := s.Verify(ctx, "t1"); !errors.Is(err, ErrBroken) {
		t.Fatalf("forged MAC: %v", err)
	}
}
