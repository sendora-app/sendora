// SPDX-License-Identifier: AGPL-3.0-or-later

package keyserver

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/adapters/keysource"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// Tenant-supplied KEK on the controller (docs/cluster/DESIGN.md D41, D44).
//
// A tenant-managed tenant's data keys are wrapped under a KEK that only the
// tenant holds. Each controller replica keeps the wrapping key derived from it
// in memory, per tenant, after the tenant presented the KEK to it (Unlock). It
// is never written anywhere; a controller that restarts is locked for the
// tenant until it is unlocked again. The manager below also performs the
// hand-overs (switch, replace, release) on the tenant's owner connection.

// Errors of the KEK operations; the HTTP layer maps them to status codes.
var (
	ErrWrongKEK         = errors.New("the key does not match this tenant's keyring")
	ErrNotTenantManaged = errors.New("the tenant does not use its own key")
	ErrTenantManaged    = errors.New("the tenant already uses its own key")
	ErrBusy             = errors.New("another key operation of this tenant is running")
)

// RingFunc opens tenant id's control log and keyring on a connection that may
// write them (the database owner role) and returns a release function.
type RingFunc func(ctx context.Context, id string) (ports.ControlLogRepository, ports.KeyringRepository, func(), error)

type held struct {
	wrap        []byte
	fingerprint string // of the tenant's KEK
	since       time.Time
}

// KEKManager holds the unlocked tenants of one controller replica and runs the
// KEK hand-overs.
type KEKManager struct {
	P      *platform.Platform
	Ring   RingFunc
	Master []byte
	Logf   func(string, ...any) // never key material

	mu     sync.Mutex
	open   map[string]held
	busy   map[string]bool
	failed map[string]*bucket
}

// NewKEKManager returns a manager for p; ring opens a tenant's keyring for
// writing and master is the controller's master key.
func NewKEKManager(p *platform.Platform, ring RingFunc, master []byte, logf func(string, ...any)) *KEKManager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &KEKManager{P: p, Ring: ring, Master: master, Logf: logf, open: map[string]held{}, busy: map[string]bool{}, failed: map[string]*bucket{}}
}

// Wrap returns a copy of the wrapping key of tenant id when it is unlocked on
// this controller with the KEK of fingerprint fp (the one the platform record
// names); ok is false otherwise.
func (m *KEKManager) Wrap(id, fp string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.open[id]
	if !ok || subtle.ConstantTimeCompare([]byte(h.fingerprint), []byte(fp)) != 1 {
		return nil, false
	}
	return append([]byte(nil), h.wrap...), true
}

// Unlocked reports whether tenant id is unlocked on this controller.
func (m *KEKManager) Unlocked(id string) bool {
	t, err := m.P.Tenant(id)
	if err != nil || t.KEKMode != platform.KEKTenant {
		return false
	}
	w, ok := m.Wrap(id, t.KEKFingerprint)
	clear(w)
	return ok
}

// Lock forgets tenant id's key.
func (m *KEKManager) Lock(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h, ok := m.open[id]; ok {
		clear(h.wrap)
		delete(m.open, id)
	}
}

func (m *KEKManager) hold(id string, wrap []byte, fp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.open[id]; ok {
		clear(old.wrap)
	}
	m.open[id] = held{wrap: append([]byte(nil), wrap...), fingerprint: fp, since: time.Now()}
}

// allowAttempt limits wrong-key attempts per tenant (token bucket, 10 per
// minute): a presented key costs a keyring verification.
func (m *KEKManager) allowAttempt(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	b := m.failed[id]
	if b == nil {
		if len(m.failed) > 4096 {
			clear(m.failed)
		}
		b = &bucket{tokens: 10, at: now}
		m.failed[id] = b
	}
	b.tokens = min(b.tokens+now.Sub(b.at).Seconds()*(10.0/60), 10)
	b.at = now
	return b.tokens >= 1
}

func (m *KEKManager) failAttempt(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b := m.failed[id]; b != nil {
		b.tokens--
	}
}

// ErrTooManyAttempts is returned when too many wrong keys were presented.
var ErrTooManyAttempts = errors.New("too many attempts; try again later")

func (m *KEKManager) begin(id string) (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.busy[id] {
		return nil, ErrBusy
	}
	m.busy[id] = true
	return func() { m.mu.Lock(); delete(m.busy, id); m.mu.Unlock() }, nil
}

// session is the keyring of one tenant with the keys an operation needs.
type session struct {
	svc     *keyring.Service
	ks      *keysource.FileKeySource
	root    []byte
	release func()
}

func (m *KEKManager) session(ctx context.Context, id string, wraps ...[]byte) (*session, error) {
	t, err := m.P.Tenant(id)
	if err != nil {
		return nil, err
	}
	dbKey, root, err := m.P.TenantKeys(t)
	if err != nil {
		return nil, err
	}
	if root == nil {
		root = append([]byte(nil), dbKey...)
	}
	clear(dbKey)
	logs, ring, release, err := m.Ring(ctx, id)
	if err != nil {
		clear(root)
		return nil, err
	}
	var first []byte
	if len(wraps) > 0 {
		first = wraps[0]
	}
	svc, err := store.RemoteKeyringWithTenantKEK(logs, ring, root, first)
	if err != nil {
		release()
		clear(root)
		return nil, err
	}
	ks, ok := svc.KS.(*keysource.FileKeySource)
	if !ok {
		release()
		clear(root)
		return nil, keyring.ErrNoRefWrapper
	}
	for _, w := range wraps[min(1, len(wraps)):] {
		if err := ks.AddNamed(store.TenantWrapRef(w), w, false); err != nil {
			release()
			clear(root)
			return nil, err
		}
	}
	return &session{svc: svc, ks: ks, root: root, release: func() { release(); clear(root) }}, nil
}

func (m *KEKManager) tenantFor(id string) (*platform.Tenant, error) {
	t, err := m.P.Tenant(id)
	if err != nil {
		return nil, err
	}
	if t.Status != platform.StatusActive && t.Status != platform.StatusSuspended {
		return nil, ErrUnknownTenant
	}
	return t, nil
}

// Unlock checks that kek (32 bytes) is the key of tenant-managed tenant id and
// holds its wrapping key in memory. The check is that every key of the
// tenant's keyring opens with it and that its fingerprint is the recorded one.
func (m *KEKManager) Unlock(ctx context.Context, id string, kek []byte) (string, error) {
	t, err := m.tenantFor(id)
	if err != nil {
		return "", err
	}
	if t.KEKMode != platform.KEKTenant {
		return "", ErrNotTenantManaged
	}
	if !m.allowAttempt(id) {
		return "", ErrTooManyAttempts
	}
	fp := store.TenantKEKFingerprint(kek)
	if subtle.ConstantTimeCompare([]byte(fp), []byte(t.KEKFingerprint)) != 1 {
		m.failAttempt(id)
		return "", ErrWrongKEK
	}
	w, err := store.TenantWrapKey(kek)
	if err != nil {
		return "", err
	}
	defer clear(w)
	s, err := m.session(ctx, id, w)
	if err != nil {
		return "", err
	}
	defer s.release()
	if err := s.svc.CanOpen(ctx, store.ColumnKeyID, store.TenantWrapRef(w)); err != nil {
		if errors.Is(err, keyring.ErrBroken) || errors.Is(err, keyring.ErrNoLog) {
			return "", err
		}
		m.failAttempt(id)
		return "", ErrWrongKEK
	}
	m.hold(id, w, fp)
	return fp, nil
}

// Result is what a hand-over did, for the tenant's audit log.
type Result struct {
	Fingerprint string   // of the tenant's KEK afterwards ("" for platform-managed)
	Steps       []string // human-readable steps, never key material
}

func stepper(res *Result) keyring.HandoverStep {
	return func(step, detail string) {
		if detail != "" {
			step += ": " + detail
		}
		res.Steps = append(res.Steps, step)
	}
}

// Switch moves a platform-managed tenant to the tenant-supplied kek: wraps
// under the tenant's KEK are added, verified, the platform's wraps destroyed.
// A repeated call after a crash continues where it stopped.
func (m *KEKManager) Switch(ctx context.Context, id string, kek []byte, actor string) (Result, error) {
	var res Result
	t, err := m.tenantFor(id)
	if err != nil {
		return res, err
	}
	fp := store.TenantKEKFingerprint(kek)
	if t.KEKMode == platform.KEKTenant && t.KEKFingerprint != fp {
		return res, ErrTenantManaged
	}
	done, err := m.begin(id)
	if err != nil {
		return res, err
	}
	defer done()
	w, err := store.TenantWrapKey(kek)
	if err != nil {
		return res, err
	}
	defer clear(w)
	s, err := m.session(ctx, id, w)
	if err != nil {
		return res, err
	}
	defer s.release()
	from, err := store.PlatformKEKRef(s.root)
	if err != nil {
		return res, err
	}
	to := store.TenantWrapRef(w)
	err = s.svc.Handover(ctx, store.ColumnKeyID, actor, from, to, keyring.HandoverOptions{
		Step: stepper(&res),
		Commit: func(ctx context.Context) error {
			return m.P.SetKEK(id, platform.KEKTenant, fp)
		},
	})
	if err != nil {
		return res, err
	}
	m.hold(id, w, fp)
	res.Fingerprint = fp
	m.Logf("keys: tenant %s now uses its own KEK %s", id, fp)
	return res, nil
}

// Replace swaps the tenant's KEK oldKEK for newKEK (rewrap, not re-encrypt).
func (m *KEKManager) Replace(ctx context.Context, id string, oldKEK, newKEK []byte, actor string) (Result, error) {
	var res Result
	t, err := m.tenantFor(id)
	if err != nil {
		return res, err
	}
	if t.KEKMode != platform.KEKTenant {
		return res, ErrNotTenantManaged
	}
	oldFP, newFP := store.TenantKEKFingerprint(oldKEK), store.TenantKEKFingerprint(newKEK)
	if oldFP == newFP {
		return res, errors.New("the new key is the same as the old key")
	}
	if t.KEKFingerprint != oldFP && t.KEKFingerprint != newFP { // newFP: resuming a hand-over that already switched
		m.failAttempt(id)
		return res, ErrWrongKEK
	}
	if !m.allowAttempt(id) {
		return res, ErrTooManyAttempts
	}
	done, err := m.begin(id)
	if err != nil {
		return res, err
	}
	defer done()
	ow, err := store.TenantWrapKey(oldKEK)
	if err != nil {
		return res, err
	}
	defer clear(ow)
	nw, err := store.TenantWrapKey(newKEK)
	if err != nil {
		return res, err
	}
	defer clear(nw)
	s, err := m.session(ctx, id, nw, ow)
	if err != nil {
		return res, err
	}
	defer s.release()
	err = s.svc.Handover(ctx, store.ColumnKeyID, actor, store.TenantWrapRef(ow), store.TenantWrapRef(nw), keyring.HandoverOptions{
		Step: stepper(&res),
		Commit: func(ctx context.Context) error {
			return m.P.SetKEK(id, platform.KEKTenant, newFP)
		},
	})
	if err != nil {
		return res, err
	}
	m.hold(id, nw, newFP)
	res.Fingerprint = newFP
	m.Logf("keys: tenant %s replaced its KEK %s by %s", id, oldFP, newFP)
	return res, nil
}

// Release returns a tenant-managed tenant to platform-managed: the data keys
// are wrapped under the platform's KEK again and the tenant's wraps destroyed.
func (m *KEKManager) Release(ctx context.Context, id string, kek []byte, actor string) (Result, error) {
	var res Result
	t, err := m.tenantFor(id)
	if err != nil {
		return res, err
	}
	fp := store.TenantKEKFingerprint(kek)
	if t.KEKMode == platform.KEKTenant && t.KEKFingerprint != fp {
		m.failAttempt(id)
		return res, ErrWrongKEK
	}
	if !m.allowAttempt(id) {
		return res, ErrTooManyAttempts
	}
	done, err := m.begin(id)
	if err != nil {
		return res, err
	}
	defer done()
	w, err := store.TenantWrapKey(kek)
	if err != nil {
		return res, err
	}
	defer clear(w)
	s, err := m.session(ctx, id, w)
	if err != nil {
		return res, err
	}
	defer s.release()
	to, err := store.PlatformKEKRef(s.root)
	if err != nil {
		return res, err
	}
	from := store.TenantWrapRef(w)
	refs, err := s.svc.WrapRefs(ctx, store.ColumnKeyID)
	if err != nil {
		return res, err
	}
	if refs[from] == 0 { // nothing to hand back: the key is not this tenant's (or all done)
		if t.KEKMode == platform.KEKPlatform {
			return res, ErrNotTenantManaged
		}
		m.failAttempt(id)
		return res, ErrWrongKEK
	}
	err = s.svc.Handover(ctx, store.ColumnKeyID, actor, from, to, keyring.HandoverOptions{
		Step: stepper(&res),
		Commit: func(ctx context.Context) error {
			return m.P.SetKEK(id, platform.KEKPlatform, "")
		},
	})
	if err != nil {
		return res, err
	}
	m.Lock(id)
	m.Logf("keys: tenant %s returned to the platform's KEK", id)
	return res, nil
}

// kekFor is the hex wrapping key of a tenant-managed tenant for the key
// endpoint ("" for a platform-managed one); ports.ErrLocked when the tenant is
// tenant-managed and not unlocked on this controller.
func (l *Local) kekFor(t *platform.Tenant) (string, error) {
	if t.KEKMode != platform.KEKTenant {
		return "", nil
	}
	if l.KEK == nil {
		return "", ports.ErrLocked
	}
	w, ok := l.KEK.Wrap(t.ID, t.KEKFingerprint)
	if !ok {
		return "", ports.ErrLocked
	}
	defer clear(w)
	return hex.EncodeToString(w), nil
}
