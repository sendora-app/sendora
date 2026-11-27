// SPDX-License-Identifier: AGPL-3.0-or-later

package keyring

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"testing"
)

func kindsOf(t *testing.T, log *memLog, kind string) int {
	t.Helper()
	n := 0
	for _, e := range log.ev {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// A crash at any write of a rotation (log or keyring) leaves a keyring that
// verifies and keeps serving the active version; the next rotation abandons
// the interrupted version, deletes its wraps and creates a new one.
func TestRotateResumesAfterACrashAtEveryWrite(t *testing.T) {
	ctx := context.Background()
	for _, target := range []string{"log", "ring"} {
		for n := 1; n <= 20; n++ {
			s, log, ring := setup(t)
			if err := s.Init(ctx, "t1", "c"); err != nil {
				t.Fatal(err)
			}
			v1, err := s.Load(ctx, "t1", PurposeData, 0)
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
			_, err = s.Rotate(ctx, "t1", PurposeData, "a")
			if err == nil {
				if (target == "log" && fl.calls < n) || (target == "ring" && fr.calls < n) {
					break // beyond the last write: every crash point is covered
				}
				t.Fatalf("%s crash %d: no error", target, n)
			}
			if !errors.Is(err, errCrash) {
				t.Fatalf("%s crash %d: %v", target, n, err)
			}
			st, err := s.Verify(ctx, "t1")
			if err != nil {
				t.Fatalf("%s crash %d: the keyring does not verify: %v", target, n, err)
			}
			cur, err := s.Load(ctx, "t1", PurposeData, 0)
			if err != nil || cur.Version != st.Active[PurposeData] {
				t.Fatalf("%s crash %d: the active key does not load: %v", target, n, err)
			}
			// Resume: the next rotation completes.
			fl.n, fr.n = 0, 0
			staged := st.Staged(PurposeData) // set when the crash hit after key_confirmed
			next, err := s.Rotate(ctx, "t1", PurposeData, "a")
			if err != nil {
				t.Fatalf("%s crash %d: resume: %v", target, n, err)
			}
			if staged != 0 && next != staged {
				t.Fatalf("%s crash %d: the staged version %d was not activated (got %d)", target, n, staged, next)
			}
			st, err = s.Verify(ctx, "t1")
			if err != nil || st.Active[PurposeData] != next || next < 2 {
				t.Fatalf("%s crash %d: after resume active=%d next=%d: %v", target, n, st.Active[PurposeData], next, err)
			}
			old, err := s.Load(ctx, "t1", PurposeData, 1)
			if err != nil || !bytes.Equal(old.DEK, v1.DEK) {
				t.Fatalf("%s crash %d: version 1 is no longer readable: %v", target, n, err)
			}
			// No row of a version that was never confirmed survives, and every
			// row is backed (Verify checked that) and belongs to a usable version.
			for _, r := range ring.rows {
				if r.Purpose == PurposeData && !containsInt(st.Versions[PurposeData], r.Version) {
					t.Fatalf("%s crash %d: row of unusable version %d left", target, n, r.Version)
				}
			}
			for v, state := range st.States[PurposeData] {
				if state == StateCreated {
					t.Fatalf("%s crash %d: version %d still interrupted after the resume", target, n, v)
				}
			}
		}
	}
}

func containsInt(l []int, v int) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// The state that the earlier write order left after a crash: key_created and
// the wrap row exist, wrap_added does not. It verifies (the version is not
// usable), its key cannot be loaded, and the next rotation abandons it and
// removes the row.
func TestRotateRepairsARowWithoutItsWrapAdded(t *testing.T) {
	ctx := context.Background()
	s, log, ring := setup(t)
	if err := s.Init(ctx, "t1", "c"); err != nil {
		t.Fatal(err)
	}
	a, err := s.appenderFor(ctx, "t1", "old", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.add(ctx, "key_created", PurposeFiles, 2, PurposeFiles, "2", "kid", "fp"); err != nil {
		t.Fatal(err)
	}
	rows, _ := ring.Wraps(ctx, "t1", PurposeFiles, 1)
	orphan := rows[0]
	orphan.Version, orphan.WrapID = 2, "orphan-wrap"
	ring.rows = append(ring.rows, orphan)

	st, err := s.Verify(ctx, "t1")
	if err != nil {
		t.Fatalf("an interrupted creation must not break the keyring: %v", err)
	}
	if st.Active[PurposeFiles] != 1 || containsInt(st.Versions[PurposeFiles], 2) || st.Highest[PurposeFiles] != 2 {
		t.Fatalf("state: %+v", st)
	}
	if _, err := s.Load(ctx, "t1", PurposeFiles, 2); err == nil {
		t.Fatal("an unconfirmed version was loaded")
	}
	v, err := s.Rotate(ctx, "t1", PurposeFiles, "a")
	if err != nil || v != 3 {
		t.Fatalf("Rotate = %d, %v; want 3 (2 is never created again)", v, err)
	}
	st, err = s.Verify(ctx, "t1")
	if err != nil || st.Active[PurposeFiles] != 3 || st.States[PurposeFiles][2] != StateAbandoned {
		t.Fatalf("after the repair: %+v %v", st, err)
	}
	if w, _ := ring.Wraps(ctx, "t1", PurposeFiles, 2); len(w) != 0 {
		t.Fatal("the orphan row was not removed")
	}
	if kindsOf(t, log, "key_abandoned") != 1 {
		t.Fatal("the abandonment is not recorded")
	}
}

// key_abandoned is only valid for a creation that never got confirmed, and an
// abandoned version can neither get a wrap nor be confirmed afterwards.
func TestVerifyRefusesMisusedAbandonment(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		events func(a *appender) error
	}{
		{"abandon a confirmed version", func(a *appender) error {
			_, err := a.add(ctx, "key_abandoned", PurposeData, 1, PurposeData, "1")
			return err
		}},
		{"confirm an abandoned version", func(a *appender) error {
			if _, err := a.add(ctx, "key_created", PurposeData, 2, PurposeData, "2", "k", "f"); err != nil {
				return err
			}
			if _, err := a.add(ctx, "key_abandoned", PurposeData, 2, PurposeData, "2"); err != nil {
				return err
			}
			_, err := a.add(ctx, "key_confirmed", PurposeData, 2, PurposeData, "2")
			return err
		}},
		{"wrap an abandoned version", func(a *appender) error {
			if _, err := a.add(ctx, "key_created", PurposeData, 2, PurposeData, "2", "k", "f"); err != nil {
				return err
			}
			if _, err := a.add(ctx, "key_abandoned", PurposeData, 2, PurposeData, "2"); err != nil {
				return err
			}
			_, err := a.add(ctx, "wrap_added", PurposeData, 2, PurposeData, "2", "w", "ref", "hash")
			return err
		}},
		{"abandon twice", func(a *appender) error {
			if _, err := a.add(ctx, "key_created", PurposeData, 2, PurposeData, "2", "k", "f"); err != nil {
				return err
			}
			for i := 0; i < 2; i++ {
				if _, err := a.add(ctx, "key_abandoned", PurposeData, 2, PurposeData, strconv.Itoa(2)); err != nil {
					return err
				}
			}
			return nil
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, _ := setup(t)
			if err := s.Init(ctx, "t1", "c"); err != nil {
				t.Fatal(err)
			}
			a, err := s.appenderFor(ctx, "t1", "x", false)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.events(a); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Verify(ctx, "t1"); !errors.Is(err, ErrBroken) {
				t.Fatalf("Verify = %v, want ErrBroken", err)
			}
		})
	}
}
