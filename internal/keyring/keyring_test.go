// SPDX-License-Identifier: AGPL-3.0-or-later

package keyring

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/adapters/keysource"
	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/ports"
)

// memLog and memRing are in-memory ports whose rows the tests can tamper with.
type memLog struct{ ev []ports.ControlLogEvent }

func (m *memLog) Append(_ context.Context, e ports.ControlLogEvent) error {
	var n int64
	for _, x := range m.ev {
		if x.TenantID == e.TenantID {
			n++
		}
	}
	if e.Seq != n+1 {
		return ports.ErrControlLogConflict
	}
	m.ev = append(m.ev, e)
	return nil
}
func (m *memLog) Latest(_ context.Context, tenant string) (ports.ControlLogEvent, error) {
	for i := len(m.ev) - 1; i >= 0; i-- {
		if m.ev[i].TenantID == tenant {
			return m.ev[i], nil
		}
	}
	return ports.ControlLogEvent{}, ports.ErrNotFound
}
func (m *memLog) BySeq(_ context.Context, tenant string, seq int64) (ports.ControlLogEvent, error) {
	for _, e := range m.ev {
		if e.TenantID == tenant && e.Seq == seq {
			return e, nil
		}
	}
	return ports.ControlLogEvent{}, ports.ErrNotFound
}
func (m *memLog) List(_ context.Context, tenant string, from, to int64) ([]ports.ControlLogEvent, error) {
	out := []ports.ControlLogEvent{}
	for _, e := range m.ev {
		if e.TenantID == tenant && e.Seq >= from && (to == 0 || e.Seq <= to) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

type memRing struct{ rows []ports.KeyringRow }

func (m *memRing) Add(_ context.Context, r ports.KeyringRow) error {
	m.rows = append(m.rows, r)
	return nil
}
func (m *memRing) Active(_ context.Context, tenant, purpose string, version int) (ports.KeyringRow, error) {
	var best *ports.KeyringRow
	for i := range m.rows {
		r := &m.rows[i]
		if r.TenantID == tenant && r.Purpose == purpose && r.Version == version && (best == nil || !r.CreatedAt.Before(best.CreatedAt)) {
			best = r
		}
	}
	if best == nil {
		return ports.KeyringRow{}, ports.ErrNotFound
	}
	return *best, nil
}
func (m *memRing) ListVersions(_ context.Context, tenant, purpose string) ([]int, error) {
	seen := map[int]bool{}
	for _, r := range m.rows {
		if r.TenantID == tenant && r.Purpose == purpose {
			seen[r.Version] = true
		}
	}
	out := []int{}
	for v := range seen {
		out = append(out, v)
	}
	sort.Ints(out)
	return out, nil
}

func (m *memRing) Wraps(_ context.Context, tenant, purpose string, version int) ([]ports.KeyringRow, error) {
	out := []ports.KeyringRow{}
	for i := len(m.rows) - 1; i >= 0; i-- {
		r := m.rows[i]
		if r.TenantID == tenant && r.Purpose == purpose && r.Version == version {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memRing) Remove(_ context.Context, tenant, wrapID string) (bool, error) {
	for i, r := range m.rows {
		if r.TenantID == tenant && r.WrapID == wrapID {
			m.rows = append(m.rows[:i], m.rows[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

func newKEK(t *testing.T) []byte {
	k := make([]byte, 32)
	rand.Read(k)
	return k
}

func setup(t *testing.T) (*Service, *memLog, *memRing) {
	ks, err := keysource.NewFromKey(newKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	log, ring := &memLog{}, &memRing{}
	clock := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	s := &Service{KS: ks, Log: log, Ring: ring, Now: func() time.Time { clock = clock.Add(time.Second); return clock }}
	return s, log, ring
}

func TestInitVerifyLoad(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	if _, err := s.Verify(ctx, "t1"); !errors.Is(err, ErrNoLog) {
		t.Fatalf("Verify before Init: %v", err)
	}
	if err := s.Init(ctx, "t1", "controller"); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx, "t1", "controller"); err == nil {
		t.Fatal("Init twice")
	}
	st, err := s.Verify(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Events != 1+len(Purposes)*4 || st.Head.Seq != int64(st.Events) {
		t.Fatalf("events = %d, head %d", st.Events, st.Head.Seq)
	}
	for _, p := range Purposes {
		if st.Active[p] != 1 {
			t.Fatalf("active %s = %d", p, st.Active[p])
		}
	}
	k, err := s.Load(ctx, "t1", PurposeData, 0)
	if err != nil || len(k.DEK) != 32 || k.Version != 1 || k.KeyID == "" {
		t.Fatalf("Load = %+v, %v", k, err)
	}
	a, _ := Subkey(k, "users.email")
	b, _ := Subkey(k, "users.email")
	c, _ := Subkey(k, "users.name")
	if !bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(a, k.DEK) {
		t.Fatal("subkeys must be deterministic, per use, and not the raw key")
	}
	idx, _ := s.Load(ctx, "t1", PurposeIndex, 0)
	if bytes.Equal(idx.DEK, k.DEK) {
		t.Fatal("purposes share a key")
	}
	other := &Service{KS: s.KS, Log: s.Log, Ring: s.Ring}
	if err := other.Init(ctx, "t2", "controller"); err != nil {
		t.Fatal(err)
	}
	k2, _ := s.Load(ctx, "t2", PurposeData, 0)
	if bytes.Equal(k.DEK, k2.DEK) {
		t.Fatal("two tenants share a data key")
	}
}

func TestRotate(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	if _, err := s.Rotate(ctx, "t1", PurposeData, "admin"); !errors.Is(err, ErrNoLog) {
		t.Fatalf("Rotate without a log: %v", err)
	}
	s.Init(ctx, "t1", "controller")
	v1, _ := s.Load(ctx, "t1", PurposeData, 0)
	n, err := s.Rotate(ctx, "t1", PurposeData, "tenant-admin")
	if err != nil || n != 2 {
		t.Fatalf("Rotate = %d, %v", n, err)
	}
	st, err := s.Verify(ctx, "t1")
	if err != nil || st.Active[PurposeData] != 2 || st.Active[PurposeIndex] != 1 {
		t.Fatalf("after rotation: %+v, %v", st, err)
	}
	cur, _ := s.Load(ctx, "t1", PurposeData, 0)
	old, err := s.Load(ctx, "t1", PurposeData, 1)
	if err != nil || cur.Version != 2 || old.Version != 1 || !bytes.Equal(old.DEK, v1.DEK) || bytes.Equal(cur.DEK, old.DEK) {
		t.Fatalf("v1 must stay readable and v2 differ: cur %d old %d, %v", cur.Version, old.Version, err)
	}
	if _, err := s.Load(ctx, "t1", PurposeData, 3); err == nil {
		t.Fatal("Load of a version that does not exist")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		tamper func(*memLog, *memRing)
	}{
		{"body changed", func(l *memLog, _ *memRing) { l.ev[4].Body[len(l.ev[4].Body)-1] ^= 1 }},
		{"event hash replaced", func(l *memLog, _ *memRing) { l.ev[4].EventHash = bytes.Repeat([]byte{1}, 32) }},
		{"MAC replaced", func(l *memLog, _ *memRing) { l.ev[6].MAC = bytes.Repeat([]byte{2}, 32) }},
		{"events swapped", func(l *memLog, _ *memRing) {
			l.ev[3], l.ev[4] = l.ev[4], l.ev[3]
			l.ev[3].Seq, l.ev[4].Seq = l.ev[4].Seq, l.ev[3].Seq
		}},
		{"event removed", func(l *memLog, _ *memRing) { l.ev = append(l.ev[:5], l.ev[6:]...) }},
		{"kind changed in the row", func(l *memLog, _ *memRing) { l.ev[2].Kind = "key_activated" }},
		{"previous hash changed", func(l *memLog, _ *memRing) { l.ev[3].PrevHash = bytes.Repeat([]byte{3}, 32) }},
		{"wrapped key replaced", func(_ *memLog, r *memRing) { r.rows[0].Wrapped = bytes.Repeat([]byte{4}, len(r.rows[0].Wrapped)) }},
		{"wrap row for another purpose", func(_ *memLog, r *memRing) {
			r.rows[0].Wrapped, r.rows[1].Wrapped = r.rows[1].Wrapped, r.rows[0].Wrapped
		}},
		{"keyring row without an event", func(_ *memLog, r *memRing) {
			extra := r.rows[0]
			extra.WrapID, extra.Wrapped, extra.CreatedAt = "forged", bytes.Repeat([]byte{5}, 60), extra.CreatedAt.Add(time.Hour)
			r.rows = append(r.rows, extra)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, log, ring := setup(t)
			if err := s.Init(ctx, "t1", "controller"); err != nil {
				t.Fatal(err)
			}
			c.tamper(log, ring)
			if _, err := s.Verify(ctx, "t1"); !errors.Is(err, ErrBroken) {
				t.Fatalf("Verify = %v, want ErrBroken", err)
			}
			if _, err := s.Load(ctx, "t1", PurposeData, 0); err == nil {
				t.Fatal("Load served a key from a broken log")
			}
		})
	}

	t.Run("another KEK", func(t *testing.T) {
		s, _, _ := setup(t)
		s.Init(ctx, "t1", "controller")
		wrong, _ := keysource.NewFromKey(newKEK(t))
		s.KS = wrong
		if _, err := s.Verify(ctx, "t1"); !errors.Is(err, ErrBroken) {
			t.Fatalf("Verify with a different KEK = %v", err)
		}
	})
	t.Run("log copied to another tenant", func(t *testing.T) {
		s, log, _ := setup(t)
		s.Init(ctx, "t1", "controller")
		for _, e := range append([]ports.ControlLogEvent(nil), log.ev...) {
			e.TenantID = "t2"
			log.ev = append(log.ev, e)
		}
		if _, err := s.Verify(ctx, "t2"); !errors.Is(err, ErrBroken) {
			t.Fatalf("a copied log verified for another tenant: %v", err)
		}
	})
}

// A KEK rotation: events written under the new KEK carry its fingerprint and
// the whole log verifies while both KEKs are mounted; without the old KEK the
// old events cannot be verified or unwrapped.
func TestKEKRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	k1, k2 := newKEK(t), newKEK(t)
	os.WriteFile(filepath.Join(dir, "kek-"+keysource.Fingerprint(k1)), k1, 0o600)
	ks, err := keysource.NewFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	log, ring := &memLog{}, &memRing{}
	s := &Service{KS: ks, Log: log, Ring: ring}
	if err := s.Init(ctx, "t1", "controller"); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Load(ctx, "t1", PurposeData, 0)

	os.WriteFile(filepath.Join(dir, "kek-"+keysource.Fingerprint(k2)), k2, 0o600)
	if err := ks.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := ks.SetActive(keysource.Fingerprint(k2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rotate(ctx, "t1", PurposeData, "admin"); err != nil {
		t.Fatal(err)
	}
	last := log.ev[len(log.ev)-1]
	if last.MACKEK != keysource.Fingerprint(k2) || log.ev[0].MACKEK != keysource.Fingerprint(k1) {
		t.Fatalf("MAC KEKs: first %s last %s", log.ev[0].MACKEK, last.MACKEK)
	}
	if _, err := s.Verify(ctx, "t1"); err != nil {
		t.Fatalf("Verify with both KEKs: %v", err)
	}
	if again, err := s.Load(ctx, "t1", PurposeData, 1); err != nil || !bytes.Equal(again.DEK, before.DEK) {
		t.Fatalf("v1 under the old KEK: %v", err)
	}
	os.Remove(filepath.Join(dir, "kek-"+keysource.Fingerprint(k1)))
	ks2, _ := keysource.NewFromDir(dir)
	s.KS = ks2
	// The head is MACed under the new KEK, so the log still verifies (D46,
	// design 6.3); what the old KEK protected, the wrap of v1, cannot be opened.
	if _, err := s.Verify(ctx, "t1"); err != nil {
		t.Fatalf("Verify without the old KEK = %v", err)
	}
	if _, err := s.Load(ctx, "t1", PurposeData, 1); err == nil {
		t.Fatal("v1 opened without the old KEK")
	}
}

func TestStageActivateRetire(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	if err := s.Init(ctx, "t1", "controller"); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Verify(ctx, "t1")
	if st.States[PurposeIndex][1] != StateActive || st.Staged(PurposeIndex) != 0 {
		t.Fatalf("initial states %+v", st.States)
	}
	// A staged version exists and loads, but is not active.
	v, err := s.Stage(ctx, "t1", PurposeIndex, "admin")
	if err != nil || v != 2 {
		t.Fatalf("Stage = %d, %v", v, err)
	}
	if _, err := s.Stage(ctx, "t1", PurposeIndex, "admin"); !errors.Is(err, ErrStaged) {
		t.Fatalf("a second Stage: %v, want ErrStaged", err)
	}
	st, _ = s.Verify(ctx, "t1")
	if st.Active[PurposeIndex] != 1 || st.Staged(PurposeIndex) != 2 || st.States[PurposeIndex][2] != StateConfirmed {
		t.Fatalf("after Stage: %+v active %v", st.States, st.Active)
	}
	if k, err := s.Load(ctx, "t1", PurposeIndex, 2); err != nil || k.Version != 2 {
		t.Fatalf("Load of the staged version: %+v, %v", k, err)
	}
	if k, err := s.Load(ctx, "t1", PurposeIndex, 0); err != nil || k.Version != 1 {
		t.Fatalf("the active version changed before Activate: %+v, %v", k, err)
	}
	// Retiring needs decrypt-only: neither the active nor a staged version.
	for _, ver := range []int{1, 2, 9} {
		if err := s.Retire(ctx, "t1", PurposeIndex, ver, "admin"); !errors.Is(err, ErrNotRetirable) {
			t.Fatalf("Retire(%d) = %v, want ErrNotRetirable", ver, err)
		}
	}
	if err := s.Activate(ctx, "t1", PurposeIndex, 1, "admin"); !errors.Is(err, ErrNotStaged) {
		t.Fatalf("activating the active version: %v", err)
	}
	if err := s.Activate(ctx, "t1", PurposeIndex, 2, "admin"); err != nil {
		t.Fatal(err)
	}
	st, _ = s.Verify(ctx, "t1")
	if st.Active[PurposeIndex] != 2 || st.States[PurposeIndex][1] != StateDecryptOnly || st.States[PurposeIndex][2] != StateActive {
		t.Fatalf("after Activate: %+v", st.States)
	}
	if err := s.Retire(ctx, "t1", PurposeIndex, 1, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(ctx, "t1", PurposeIndex, 1, "admin"); !errors.Is(err, ErrNotRetirable) {
		t.Fatalf("retiring twice: %v", err)
	}
	st, err = s.Verify(ctx, "t1")
	if err != nil || st.States[PurposeIndex][1] != StateRetired {
		t.Fatalf("after Retire: %+v, %v", st.States, err)
	}
	// The wrapped key stays (backups need it) and can still be loaded for reading;
	// new writes only ever use the active version.
	if k, err := s.Load(ctx, "t1", PurposeIndex, 1); err != nil || k.Version != 1 {
		t.Fatalf("Load of a retired version: %+v, %v", k, err)
	}
	if k, _ := s.Load(ctx, "t1", PurposeIndex, 0); k.Version != 2 {
		t.Fatalf("active = %d", k.Version)
	}
}

func TestVerifyRejectsBadStateTransitions(t *testing.T) {
	ctx := context.Background()
	for name, forge := range map[string]func(a *appender) error{
		"retiring an active key": func(a *appender) error {
			_, err := a.add(ctx, "key_retired", PurposeData, 1, PurposeData, "1")
			return err
		},
		"deactivating the active key": func(a *appender) error {
			_, err := a.add(ctx, "key_decrypt_only", PurposeData, 1, PurposeData, "1")
			return err
		},
		"deactivating an unknown key": func(a *appender) error {
			_, err := a.add(ctx, "key_decrypt_only", PurposeData, 7, PurposeData, "7")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := setup(t)
			if err := s.Init(ctx, "t1", "c"); err != nil {
				t.Fatal(err)
			}
			a, err := s.appenderFor(ctx, "t1", "forger", false)
			if err != nil {
				t.Fatal(err)
			}
			if err := forge(a); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Verify(ctx, "t1"); !errors.Is(err, ErrBroken) {
				t.Fatalf("Verify = %v, want ErrBroken", err)
			}
		})
	}
}

func TestCodecFollowsRotationAndOpensOldVersions(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	if err := s.Init(ctx, "t1", "c"); err != nil {
		t.Fatal(err)
	}
	c, err := NewCodec(ctx, s, "t1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	old, err := c.Seal("users", "name", "1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := c.Refresh(ctx); err != nil || changed {
		t.Fatalf("Refresh without a rotation = %v, %v", changed, err)
	}
	if _, err := s.Rotate(ctx, "t1", PurposeData, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rotate(ctx, "t1", PurposeIndex, "admin"); err != nil {
		t.Fatal(err)
	}
	before, _ := c.BlindIndex("users", "email", "a@b.c")
	if changed, err := c.Refresh(ctx); err != nil || !changed {
		t.Fatalf("Refresh after a rotation = %v, %v", changed, err)
	}
	if d, i := c.Versions(); d != 2 || i != 2 {
		t.Fatalf("versions %d/%d, want 2/2", d, i)
	}
	if after, _ := c.BlindIndex("users", "email", "a@b.c"); bytes.Equal(before, after) {
		t.Fatal("the blind index did not change with the key")
	}
	if got, err := c.Open("users", "name", "1", old); err != nil || got != "alice" {
		t.Fatalf("a value of version 1: %q, %v", got, err)
	}
	if s2, _ := c.Seal("users", "name", "1", "alice"); s2 == old {
		t.Fatal("sealed twice to the same text")
	} else if v, ok := colenc.TextVersion(s2); !ok || v != 2 {
		t.Fatalf("a new value is on version %d, want 2", v)
	}
	// A key version the keyring does not know fails closed.
	ct, _ := colenc.DecodeText(old)
	ct[4] = 42
	if _, err := c.Open("users", "name", "1", colenc.EncodeText(ct)); err == nil {
		t.Fatal("an unknown version opened")
	}
	// A staged index version is readable through a view without becoming active.
	if _, err := s.Stage(ctx, "t1", PurposeIndex, "admin"); err != nil {
		t.Fatal(err)
	}
	view, release, err := c.IndexView(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	staged, _ := view.BlindIndex("users", "email", "a@b.c")
	if cur, _ := c.BlindIndex("users", "email", "a@b.c"); bytes.Equal(staged, cur) {
		t.Fatal("the staged index equals the active one")
	}
	if _, i := c.Versions(); i != 2 {
		t.Fatalf("the index key became active by staging: %d", i)
	}
}
