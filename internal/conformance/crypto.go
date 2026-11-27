// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/adapters/keysource"
	"github.com/sendora-app/sendora/internal/ports"
)

// ctlEvent builds a control-log event whose hash is unique per (tenant, seq, kind).
func ctlEvent(tenant string, seq int64, prev []byte, kind, purpose string, version int) ports.ControlLogEvent {
	body := []byte(tenant + "|" + kind + "|" + purpose)
	body = append(body, byte(seq), byte(version))
	h := sha256.Sum256(append(body, prev...))
	return ports.ControlLogEvent{
		TenantID: tenant, Seq: seq, PrevHash: prev, Kind: kind, Purpose: purpose, Version: version,
		Body: body, EventHash: h[:], MACKEK: "kek-0001", MAC: bytes.Repeat([]byte{byte(seq)}, 32),
	}
}

// RunControlLogAndKeyring pins the contracts of ControlLogRepository (design
// 6.3: a per-tenant chain that only grows by one linked event at a time, and a
// key version created once) and KeyringRepository (wraps are added, never
// changed; the newest wrap of a version is the active one).
func RunControlLogAndKeyring(t *testing.T, cl ports.ControlLogRepository, kr ports.KeyringRepository) {
	ctx := context.Background()

	t.Run("ControlLog", func(t *testing.T) {
		if _, err := cl.Latest(ctx, "t-a"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Latest of an empty log: %v", err)
		}
		if _, err := cl.BySeq(ctx, "t-a", 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("BySeq of an empty log: %v", err)
		}
		if l, err := cl.List(ctx, "t-a", 1, 0); err != nil || l == nil || len(l) != 0 {
			t.Fatalf("List of an empty log: %v, %v", l, err)
		}

		genesis := ctlEvent("t-a", 1, bytes.Repeat([]byte{9}, 32), "genesis", "", 0)
		if err := cl.Append(ctx, genesis); err != nil {
			t.Fatalf("Append genesis: %v", err)
		}
		created := ctlEvent("t-a", 2, genesis.EventHash, "key_created", "data", 1)
		if err := cl.Append(ctx, created); err != nil {
			t.Fatalf("Append key_created: %v", err)
		}
		got, err := cl.BySeq(ctx, "t-a", 2)
		if err != nil || got.Kind != "key_created" || got.Purpose != "data" || got.Version != 1 ||
			!bytes.Equal(got.EventHash, created.EventHash) || !bytes.Equal(got.PrevHash, genesis.EventHash) ||
			!bytes.Equal(got.Body, created.Body) || got.MACKEK != "kek-0001" || !bytes.Equal(got.MAC, created.MAC) || got.CreatedAt.IsZero() {
			t.Fatalf("BySeq(2) = %+v, %v", got, err)
		}
		if g, err := cl.BySeq(ctx, "t-a", 1); err != nil || g.Purpose != "" || g.Version != 0 {
			t.Fatalf("an event without purpose/version reads back empty: %+v, %v", g, err)
		}
		if l, err := cl.Latest(ctx, "t-a"); err != nil || l.Seq != 2 {
			t.Fatalf("Latest = %d, %v", l.Seq, err)
		}

		// Only the next, linked event is accepted; nothing is written otherwise.
		refused := map[string]ports.ControlLogEvent{
			"sequence taken":        ctlEvent("t-a", 2, genesis.EventHash, "key_activated", "data", 1),
			"gap in the sequence":   ctlEvent("t-a", 4, created.EventHash, "key_activated", "data", 1),
			"wrong previous hash":   ctlEvent("t-a", 3, genesis.EventHash, "key_activated", "data", 1),
			"unknown first event":   ctlEvent("t-a", 3, bytes.Repeat([]byte{1}, 32), "key_activated", "data", 1),
			"version created twice": ctlEvent("t-a", 3, created.EventHash, "key_created", "data", 1),
		}
		for name, e := range refused {
			if err := cl.Append(ctx, e); !errors.Is(err, ports.ErrControlLogConflict) {
				t.Fatalf("%s: %v, want ErrControlLogConflict", name, err)
			}
		}
		if l, _ := cl.Latest(ctx, "t-a"); l.Seq != 2 {
			t.Fatalf("a refused event changed the log: latest %d", l.Seq)
		}
		activated := ctlEvent("t-a", 3, created.EventHash, "key_activated", "data", 1)
		if err := cl.Append(ctx, activated); err != nil {
			t.Fatalf("Append key_activated: %v", err)
		}
		// Another version of the same purpose is a new key.
		v2 := ctlEvent("t-a", 4, activated.EventHash, "key_created", "data", 2)
		if err := cl.Append(ctx, v2); err != nil {
			t.Fatalf("Append key_created v2: %v", err)
		}

		// Chains are per tenant.
		other := ctlEvent("t-b", 1, bytes.Repeat([]byte{7}, 32), "genesis", "", 0)
		if err := cl.Append(ctx, other); err != nil {
			t.Fatalf("Append for another tenant: %v", err)
		}
		if l, _ := cl.List(ctx, "t-b", 1, 0); len(l) != 1 {
			t.Fatalf("tenant b has %d events", len(l))
		}
		if l, err := cl.List(ctx, "t-a", 1, 0); err != nil || len(l) != 4 || l[0].Seq != 1 || l[3].Seq != 4 {
			t.Fatalf("List(1..) = %d events, %v", len(l), err)
		}
		if l, err := cl.List(ctx, "t-a", 2, 3); err != nil || len(l) != 2 || l[0].Seq != 2 || l[1].Seq != 3 {
			t.Fatalf("List(2..3) = %d events, %v", len(l), err)
		}
	})

	t.Run("Keyring", func(t *testing.T) {
		if _, err := kr.Active(ctx, "t-a", "data", 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Active of an unknown key: %v", err)
		}
		if v, err := kr.ListVersions(ctx, "t-a", "data"); err != nil || v == nil || len(v) != 0 {
			t.Fatalf("ListVersions of an unknown purpose: %v, %v", v, err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		wrap := func(version int, wrapID string, at time.Time, tag byte) ports.KeyringRow {
			return ports.KeyringRow{TenantID: "t-a", Purpose: "data", Version: version, KeyID: "key-" + wrapID, WrapID: wrapID,
				KEKRef: "kek-0001", Wrapped: bytes.Repeat([]byte{tag}, 60), Fingerprint: bytes.Repeat([]byte{tag}, 32), CreatedAt: at}
		}
		for _, row := range []ports.KeyringRow{wrap(1, "w1", now, 1), wrap(2, "w2", now, 2)} {
			if err := kr.Add(ctx, row); err != nil {
				t.Fatalf("Add %s: %v", row.WrapID, err)
			}
		}
		if err := kr.Add(ctx, wrap(1, "w1", now, 3)); err == nil {
			t.Fatal("a wrap id was added twice")
		}
		if v, err := kr.ListVersions(ctx, "t-a", "data"); err != nil || len(v) != 2 || v[0] != 1 || v[1] != 2 {
			t.Fatalf("ListVersions = %v, %v", v, err)
		}
		a, err := kr.Active(ctx, "t-a", "data", 1)
		if err != nil || a.WrapID != "w1" || a.KEKRef != "kek-0001" || a.KeyID != "key-w1" || !bytes.Equal(a.Wrapped, bytes.Repeat([]byte{1}, 60)) || !bytes.Equal(a.Fingerprint, bytes.Repeat([]byte{1}, 32)) {
			t.Fatalf("Active(v1) = %+v, %v", a, err)
		}
		// A rewrap under a newer KEK is a newer row for the same version.
		rewrap := wrap(1, "w1b", now.Add(time.Minute), 4)
		rewrap.KEKRef = "kek-0002"
		if err := kr.Add(ctx, rewrap); err != nil {
			t.Fatalf("Add rewrap: %v", err)
		}
		if a, err := kr.Active(ctx, "t-a", "data", 1); err != nil || a.WrapID != "w1b" || a.KEKRef != "kek-0002" {
			t.Fatalf("Active after a rewrap = %+v, %v", a, err)
		}
		if _, err := kr.Active(ctx, "t-b", "data", 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("another tenant sees the keyring: %v", err)
		}
		if _, err := kr.Active(ctx, "t-a", "files", 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("another purpose: %v", err)
		}

		// Wraps lists every wrap of a version, newest first; Remove deletes one (D44).
		ws, err := kr.Wraps(ctx, "t-a", "data", 1)
		if err != nil || len(ws) != 2 || ws[0].WrapID != "w1b" || ws[1].WrapID != "w1" || ws[0].KEKRef != "kek-0002" || ws[1].KEKRef != "kek-0001" {
			t.Fatalf("Wraps(v1) = %+v, %v", ws, err)
		}
		if !bytes.Equal(ws[1].Wrapped, bytes.Repeat([]byte{1}, 60)) || ws[1].KeyID != "key-w1" {
			t.Fatalf("Wraps returns the stored row: %+v", ws[1])
		}
		if ws, err := kr.Wraps(ctx, "t-a", "data", 9); err != nil || ws == nil || len(ws) != 0 {
			t.Fatalf("Wraps of an unknown version = %v, %v", ws, err)
		}
		if ws, err := kr.Wraps(ctx, "t-b", "data", 1); err != nil || len(ws) != 0 {
			t.Fatalf("another tenant's Wraps = %v, %v", ws, err)
		}
		if ok, err := kr.Remove(ctx, "t-b", "w1"); err != nil || ok {
			t.Fatalf("Remove by another tenant = %v, %v", ok, err)
		}
		if ok, err := kr.Remove(ctx, "t-a", "w1"); err != nil || !ok {
			t.Fatalf("Remove = %v, %v", ok, err)
		}
		if ok, err := kr.Remove(ctx, "t-a", "w1"); err != nil || ok {
			t.Fatalf("Remove twice = %v, %v", ok, err)
		}
		if ws, _ := kr.Wraps(ctx, "t-a", "data", 1); len(ws) != 1 || ws[0].WrapID != "w1b" {
			t.Fatalf("after Remove: %+v", ws)
		}
		if a, err := kr.Active(ctx, "t-a", "data", 2); err != nil || a.WrapID != "w2" {
			t.Fatalf("another version is untouched: %+v, %v", a, err)
		}
	})
}

// RunKeySource pins the KeySource contract: wraps are bound to their AAD and
// KEK version, the control MAC is deterministic and separated per tenant, and
// the active KEK comes first in the fingerprint list.
func RunKeySource(t *testing.T, open func(testing.TB) ports.KeySource) {
	ctx := context.Background()
	ks := open(t)
	dek := make([]byte, 32)
	rand.Read(dek)
	aad := []byte("tenant-a/data/1")

	fps, err := ks.KEKFingerprints(ctx)
	if err != nil || len(fps) == 0 || fps[0] == "" {
		t.Fatalf("KEKFingerprints = %v, %v", fps, err)
	}
	wrapped, ref, err := ks.Wrap(ctx, dek, aad)
	if err != nil || ref != fps[0] || bytes.Contains(wrapped, dek) {
		t.Fatalf("Wrap: ref %q (active %q), %v", ref, fps[0], err)
	}
	if got, err := ks.Unwrap(ctx, wrapped, aad, ref); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap: %v", err)
	}
	if w2, _, _ := ks.Wrap(ctx, dek, aad); bytes.Equal(w2, wrapped) {
		t.Fatal("two wraps of the same key are identical (nonce reuse)")
	}
	if _, err := ks.Unwrap(ctx, wrapped, []byte("tenant-b/data/1"), ref); err == nil {
		t.Fatal("unwrap with another AAD")
	}
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 1
	if _, err := ks.Unwrap(ctx, tampered, aad, ref); err == nil {
		t.Fatal("unwrap of a tampered wrap")
	}
	if _, err := ks.Unwrap(ctx, wrapped, aad, "no-such-kek"); err == nil {
		t.Fatal("unwrap under an unknown KEK version")
	}
	msg := []byte("event hash")
	m1, err := ks.ControlMAC(ctx, "tenant-a", msg)
	if err != nil || len(m1) != 32 {
		t.Fatalf("ControlMAC: %d bytes, %v", len(m1), err)
	}
	if m2, _ := ks.ControlMAC(ctx, "tenant-a", msg); !bytes.Equal(m1, m2) {
		t.Fatal("ControlMAC is not deterministic")
	}
	if m3, _ := ks.ControlMAC(ctx, "tenant-b", msg); bytes.Equal(m1, m3) {
		t.Fatal("ControlMAC does not depend on the tenant")
	}
	if m4, err := ks.ControlMACWith(ctx, fps[0], "tenant-a", msg); err != nil || !bytes.Equal(m1, m4) {
		t.Fatalf("ControlMACWith(active) differs from ControlMAC: %v", err)
	}
	if _, err := ks.ControlMACWith(ctx, "no-such-kek", "tenant-a", msg); err == nil {
		t.Fatal("ControlMACWith under an unknown KEK version")
	}
}

func openFileKeySource(t testing.TB) ports.KeySource {
	k := make([]byte, 32)
	rand.Read(k)
	ks, err := keysource.NewFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}
