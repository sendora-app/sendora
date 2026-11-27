// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keyring creates, reads and verifies a tenant's keys (docs/cluster/
// DESIGN.md 6.2, 6.3): versioned data-encryption keys (DEKs) wrapped by the
// KEK (ports.KeySource), and the authenticated control log that records every
// key event. Nothing here touches SQL; it works on the ports.
package keyring

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/sendora-app/sendora/internal/controllog"
	"github.com/sendora-app/sendora/internal/ports"
)

// Purposes of a tenant's DEKs (design 6.2). Every key is used for one
// primitive only; the raw DEK never encrypts data directly (Subkey).
const (
	PurposeData     = "data"      // column encryption
	PurposeIndex    = "index"     // blind indexes
	PurposeSecrets  = "secrets"   // token signing secret, HMAC keys, TOTP secrets
	PurposeFiles    = "files"     // filecrypt master key
	PurposeAuditMAC = "audit-mac" // audit chain HMAC key
	PurposeAuditEnc = "audit-enc" // audit field encryption
)

// Purposes lists the DEK series created for every new tenant.
var Purposes = []string{PurposeData, PurposeIndex, PurposeSecrets, PurposeFiles, PurposeAuditMAC, PurposeAuditEnc}

// Key is an unwrapped DEK. Callers clear Key.DEK when done.
type Key struct {
	Purpose string
	Version int
	KeyID   string
	DEK     []byte
}

// Subkey derives the key for one use of a DEK: HKDF-SHA256(DEK, info =
// "sendora/v1/" ‖ purpose ‖ "/" ‖ sub) (design 6.2).
func Subkey(k Key, sub string) ([]byte, error) {
	return hkdf.Key(sha256.New, k.DEK, nil, "sendora/v1/"+k.Purpose+"/"+sub, 32)
}

// Service is the key manager of one database's control log and keyring: the
// platform database (for every tenant and the platform itself) or a tenant
// database (for that tenant).
type Service struct {
	KS   ports.KeySource
	Log  ports.ControlLogRepository
	Ring ports.KeyringRepository
	Now  func() time.Time // default time.Now
	// MACRef names the KEK that MACs control-log events (default: the active
	// one). With a tenant-supplied KEK the log is still MACed under the
	// platform's KEK, so it verifies without the tenant's key (D44); the
	// tenant's KEK only protects the wraps.
	MACRef string
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Errors reported by Verify.
var (
	ErrNoLog  = errors.New("keyring: tenant has no control log")
	ErrBroken = errors.New("keyring: control log verification failed")
)

// appender appends linked, MACed events to one tenant's chain.
type appender struct {
	s      *Service
	tenant string
	seq    int64
	prev   []byte
	actor  string
}

func (a *appender) add(ctx context.Context, kind, purpose string, version int, fields ...string) (ports.ControlLogEvent, error) {
	a.seq++
	ts := a.s.now()
	body := controllog.CanonicalBody(a.tenant, a.seq, a.prev, kind, fields, a.actor, ts.Format(time.RFC3339Nano))
	hash := controllog.ComputeEventHash(body)
	macRef := a.s.MACRef
	if macRef == "" {
		fps, err := a.s.KS.KEKFingerprints(ctx)
		if err != nil || len(fps) == 0 {
			return ports.ControlLogEvent{}, fmt.Errorf("keyring: no usable KEK: %v", err)
		}
		macRef = fps[0]
	}
	mac, err := a.s.KS.ControlMACWith(ctx, macRef, a.tenant, hash)
	if err != nil {
		return ports.ControlLogEvent{}, err
	}
	e := ports.ControlLogEvent{TenantID: a.tenant, Seq: a.seq, PrevHash: a.prev, Kind: kind, Purpose: purpose, Version: version,
		Body: body, EventHash: hash, MACKEK: macRef, MAC: mac, CreatedAt: ts}
	if err := a.s.Log.Append(ctx, e); err != nil {
		return ports.ControlLogEvent{}, err
	}
	a.prev = hash
	return e, nil
}

// appenderFor continues tenant's chain after its latest event (ErrNoLog when
// there is none and create is false).
func (s *Service) appenderFor(ctx context.Context, tenant, actor string, create bool) (*appender, error) {
	last, err := s.Log.Latest(ctx, tenant)
	switch {
	case err == nil:
		return &appender{s: s, tenant: tenant, seq: last.Seq, prev: last.EventHash, actor: actor}, nil
	case errors.Is(err, ports.ErrNotFound) && create:
		return &appender{s: s, tenant: tenant, actor: actor}, nil
	case errors.Is(err, ports.ErrNotFound):
		return nil, ErrNoLog
	}
	return nil, err
}

// Init creates a tenant's control log (genesis) and the first version of every
// purpose: key_created, wrap_added, key_confirmed, key_activated. It refuses a
// tenant that already has a log.
func (s *Service) Init(ctx context.Context, tenant, actor string) error {
	if _, err := s.Log.Latest(ctx, tenant); err == nil {
		return fmt.Errorf("keyring: tenant %s already has a control log", tenant)
	} else if !errors.Is(err, ports.ErrNotFound) {
		return err
	}
	chainID := uuid.NewString()
	a := &appender{s: s, tenant: tenant, prev: controllog.GenesisPrevHash(tenant, chainID), actor: actor}
	if _, err := a.add(ctx, "genesis", "", 0, chainID, actor); err != nil {
		return err
	}
	for _, purpose := range Purposes {
		if err := s.createKey(ctx, a, purpose, 1, true); err != nil {
			return err
		}
	}
	return nil
}

// Key states (design 6.3): created, confirmed, active, decrypt_only, retired;
// abandoned for a version whose creation was interrupted before key_confirmed
// (it never encrypted anything and is never used).
const (
	StateCreated     = "created"
	StateAbandoned   = "abandoned"
	StateConfirmed   = "confirmed"
	StateActive      = "active"
	StateDecryptOnly = "decrypt_only"
	StateRetired     = "retired"
)

// Errors of the rotation operations.
var (
	ErrStaged       = errors.New("keyring: a new version of this purpose is already staged")
	ErrNotStaged    = errors.New("keyring: the version is not a confirmed, not yet active version")
	ErrNotRetirable = errors.New("keyring: only a decrypt-only version can be retired")
)

// Rotate creates the next version of purpose and makes it the active one; the
// previous version stays readable (decrypt-only). A version that an earlier
// Rotate confirmed but did not activate (a crash in between) is activated
// instead of creating another one.
func (s *Service) Rotate(ctx context.Context, tenant, purpose, actor string) (int, error) {
	next, err := s.Stage(ctx, tenant, purpose, actor)
	if errors.Is(err, ErrStaged) {
		st, verr := s.Verify(ctx, tenant)
		if verr != nil {
			return 0, verr
		}
		next, err = st.Staged(purpose), nil
	}
	if err != nil {
		return 0, err
	}
	return next, s.Activate(ctx, tenant, purpose, next, actor)
}

// Stage creates the next version of purpose (key_created, wrap_added,
// key_confirmed) without activating it, and returns it. The active version
// keeps encrypting until Activate; a staged version is usable for reading
// (Load with its version) and for preparing work such as rebuilding blind
// indexes. Only one version of a purpose can be staged at a time.
func (s *Service) Stage(ctx context.Context, tenant, purpose, actor string) (int, error) {
	st, err := s.Verify(ctx, tenant)
	if err != nil {
		return 0, err
	}
	if st.Staged(purpose) != 0 {
		return 0, ErrStaged
	}
	a, err := s.appenderFor(ctx, tenant, actor, false)
	if err != nil {
		return 0, err
	}
	// An earlier Stage that stopped before key_confirmed (a crash) left a
	// version that was never usable: record it as abandoned and delete its
	// wraps, which never opened any data.
	for _, v := range st.Interrupted(purpose) {
		if _, err := a.add(ctx, "key_abandoned", purpose, v, purpose, strconv.Itoa(v)); err != nil {
			return 0, err
		}
		st.States[purpose][v] = StateAbandoned
	}
	if err := s.removeUnconfirmedWraps(ctx, tenant, purpose, st); err != nil {
		return 0, err
	}
	// The next version follows every version the log ever created (an
	// abandoned one is never created again) and every row that exists.
	next := st.Highest[purpose] + 1
	versions, err := s.Ring.ListVersions(ctx, tenant, purpose)
	if err != nil {
		return 0, err
	}
	if len(versions) > 0 && versions[len(versions)-1] >= next {
		next = versions[len(versions)-1] + 1
	}
	if err := s.createKey(ctx, a, purpose, next, false); err != nil {
		return 0, err
	}
	return next, nil
}

// removeUnconfirmedWraps deletes the wrap rows of purpose's versions that were
// never confirmed (interrupted or abandoned creations).
func (s *Service) removeUnconfirmedWraps(ctx context.Context, tenant, purpose string, st *State) error {
	for v, state := range st.States[purpose] {
		if state != StateCreated && state != StateAbandoned {
			continue
		}
		rows, err := s.Ring.Wraps(ctx, tenant, purpose, v)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if _, err := s.Ring.Remove(ctx, tenant, row.WrapID); err != nil {
				return err
			}
		}
	}
	return nil
}

// Activate makes the confirmed, staged version of purpose the one that
// encrypts; the previously active version becomes decrypt-only.
func (s *Service) Activate(ctx context.Context, tenant, purpose string, version int, actor string) error {
	st, err := s.Verify(ctx, tenant)
	if err != nil {
		return err
	}
	if st.States[purpose][version] != StateConfirmed || version <= st.Active[purpose] {
		return ErrNotStaged
	}
	a, err := s.appenderFor(ctx, tenant, actor, false)
	if err != nil {
		return err
	}
	ver := strconv.Itoa(version)
	if _, err := a.add(ctx, "key_activated", purpose, version, purpose, ver); err != nil {
		return err
	}
	if prev := st.Active[purpose]; prev > 0 {
		_, err = a.add(ctx, "key_decrypt_only", purpose, prev, purpose, strconv.Itoa(prev))
	}
	return err
}

// Retire marks a decrypt-only version of purpose retired: it is never used for
// new writes again. Its wrapped key stays in the keyring (backups made before
// the retirement still need it), so the operator can purge it later. The
// caller checks that no data still uses the version.
func (s *Service) Retire(ctx context.Context, tenant, purpose string, version int, actor string) error {
	st, err := s.Verify(ctx, tenant)
	if err != nil {
		return err
	}
	if st.States[purpose][version] != StateDecryptOnly {
		return ErrNotRetirable
	}
	a, err := s.appenderFor(ctx, tenant, actor, false)
	if err != nil {
		return err
	}
	_, err = a.add(ctx, "key_retired", purpose, version, purpose, strconv.Itoa(version))
	return err
}

// createKey runs the write-ahead sequence for one new key version: the
// key_created event comes before any wrap exists, wrap_added names the wrap by
// hash before its row is written, then confirmed and activated. A crash at any
// point before key_confirmed leaves a version that Verify ignores and the next
// Stage abandons; no row ever exists that no event backs.
func (s *Service) createKey(ctx context.Context, a *appender, purpose string, version int, activate bool) error {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	defer clear(dek)
	return s.createKeyWith(ctx, a, purpose, version, dek, activate)
}

// createKeyWith is createKey for a given DEK (a key carried over from another
// keyring, see InitCarrying).
func (s *Service) createKeyWith(ctx context.Context, a *appender, purpose string, version int, dek []byte, activate bool) error {
	keyID := uuid.NewString()
	ver := strconv.Itoa(version)
	if _, err := a.add(ctx, "key_created", purpose, version, purpose, ver, keyID, hex.EncodeToString(controllog.KeyFingerprint(dek))); err != nil {
		return err
	}
	aad := controllog.WrapAAD(a.tenant, purpose, version)
	wrapped, kekRef, err := s.KS.Wrap(ctx, dek, aad)
	if err != nil {
		return err
	}
	wrapID := uuid.NewString()
	if _, err := a.add(ctx, "wrap_added", purpose, version, purpose, ver, wrapID, kekRef, wrapHash(wrapped, aad)); err != nil {
		return err
	}
	if err := s.Ring.Add(ctx, ports.KeyringRow{TenantID: a.tenant, Purpose: purpose, Version: version, KeyID: keyID, WrapID: wrapID,
		KEKRef: kekRef, Wrapped: wrapped, Fingerprint: controllog.KeyFingerprint(dek), CreatedAt: s.now()}); err != nil {
		return err
	}
	if _, err := a.add(ctx, "key_confirmed", purpose, version, purpose, ver); err != nil {
		return err
	}
	if !activate {
		return nil
	}
	_, err = a.add(ctx, "key_activated", purpose, version, purpose, ver)
	return err
}

func wrapHash(wrapped, aad []byte) string {
	h := sha256.New()
	h.Write(wrapped)
	h.Write(aad)
	return hex.EncodeToString(h.Sum(nil))
}

// State is the verified outcome of replaying a tenant's control log.
type State struct {
	TenantID string
	Head     ports.ControlLogEvent
	Events   int
	// Active and Versions map purpose to the active and all usable (confirmed)
	// versions; a version whose creation never reached key_confirmed is not
	// in Versions, its rows are neither checked nor used.
	Active   map[string]int
	Versions map[string][]int
	// Highest maps purpose to the highest version the log created, usable or
	// not (the next version follows it).
	Highest map[string]int
	// States maps purpose and version to the version's state (State*).
	States map[string]map[int]string
	// Handover is the newest KEK hand-over recorded in the log (zero when
	// there was none); Phase is HandoverBegun until it completes.
	Handover Handover
	// Removed lists the wrap ids that a wrap_removed event retired (a row that
	// still exists for one of them is waiting for its deletion).
	Removed map[string]bool
}

// Interrupted returns purpose's versions whose creation stopped before
// key_confirmed and that are not yet recorded as abandoned.
func (st *State) Interrupted(purpose string) []int {
	var out []int
	for v, state := range st.States[purpose] {
		if state == StateCreated {
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// Staged returns the version of purpose that is confirmed but not yet active
// (0 when there is none).
func (st *State) Staged(purpose string) int {
	for v, state := range st.States[purpose] {
		if state == StateConfirmed && v > st.Active[purpose] {
			return v
		}
	}
	return 0
}

// Verify replays tenant's whole control log and applies the rules of design
// 6.3: contiguous sequence numbers, every event hashed over its body and linked
// to the previous one, every MAC valid under the KEK it names, the genesis
// bound to the tenant, key versions created once, every wrap row backed by a
// wrap_added event with a matching hash, and no activation before confirmation.
// It reports the active version of each purpose. Truncation of the newest
// events is not detectable from the log alone: compare Head with an anchor kept
// elsewhere (design 6.3, journal).
func (s *Service) Verify(ctx context.Context, tenant string) (*State, error) {
	events, err := s.Log.List(ctx, tenant, 1, 0)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, ErrNoLog
	}
	fail := func(seq int64, format string, args ...any) (*State, error) {
		return nil, fmt.Errorf("%w: event %d: %s", ErrBroken, seq, fmt.Sprintf(format, args...))
	}
	st := &State{TenantID: tenant, Active: map[string]int{}, Versions: map[string][]int{}, Highest: map[string]int{}, States: map[string]map[int]string{}}
	set := func(purpose string, version int, state string) {
		if st.States[purpose] == nil {
			st.States[purpose] = map[int]string{}
		}
		st.States[purpose][version] = state
	}
	type kv struct {
		purpose string
		version int
	}
	created := map[kv]bool{}
	confirmed := map[kv]bool{}
	abandoned := map[kv]bool{}
	wraps := map[string]string{} // wrap_id -> expected hash, from wrap_added events
	st.Removed = map[string]bool{}
	var prev []byte
	for i, e := range events {
		want := int64(i + 1)
		if e.Seq != want || e.TenantID != tenant {
			return fail(e.Seq, "sequence is not %d for tenant %s", want, tenant)
		}
		if !bytes.Equal(controllog.ComputeEventHash(e.Body), e.EventHash) {
			return fail(e.Seq, "event hash does not match the body")
		}
		b, err := controllog.DecodeBody(e.Body)
		if err != nil {
			return fail(e.Seq, "%v", err)
		}
		if b.TenantID != tenant || b.Seq != e.Seq || b.Kind != e.Kind || !bytes.Equal(b.PrevHash, e.PrevHash) {
			return fail(e.Seq, "row does not match its body")
		}
		mac, err := s.KS.ControlMACWith(ctx, e.MACKEK, tenant, e.EventHash)
		switch {
		case err != nil && errors.Is(err, ports.ErrKEKUnavailable) && i < len(events)-1:
			// The KEK of an old event was retired (D46). The head's MAC,
			// checked below when it is reached, authenticates every earlier
			// event through the hash chain, so this one needs no MAC check.
		case err != nil:
			return fail(e.Seq, "MAC: %v", err)
		case !hmacEqual(mac, e.MAC):
			return fail(e.Seq, "MAC does not verify")
		}
		if i == 0 {
			if e.Kind != "genesis" || len(b.Fields) < 1 || !bytes.Equal(e.PrevHash, controllog.GenesisPrevHash(tenant, b.Fields[0])) {
				return fail(e.Seq, "first event is not a genesis bound to this tenant")
			}
		} else if e.Kind == "genesis" || !bytes.Equal(e.PrevHash, prev) {
			return fail(e.Seq, "not linked to the previous event")
		}
		prev = e.EventHash
		purpose, version := e.Purpose, e.Version
		k := kv{purpose, version}
		switch e.Kind {
		case "key_created":
			if created[k] {
				return fail(e.Seq, "%s v%d created twice", purpose, version)
			}
			created[k] = true
			set(purpose, version, StateCreated)
			if version > st.Highest[purpose] {
				st.Highest[purpose] = version
			}
		case "key_abandoned":
			if !created[k] || confirmed[k] || abandoned[k] {
				return fail(e.Seq, "abandoning %s v%d, which is not an interrupted creation", purpose, version)
			}
			abandoned[k] = true
			set(purpose, version, StateAbandoned)
		case "wrap_added":
			if !created[k] || abandoned[k] || len(b.Fields) < 5 {
				return fail(e.Seq, "wrap for a key that was not created")
			}
			wraps[b.Fields[2]] = b.Fields[4]
		case "wrap_removed":
			if !created[k] || len(b.Fields) < 4 {
				return fail(e.Seq, "wrap removed for a key that was not created")
			}
			if _, ok := wraps[b.Fields[2]]; !ok {
				return fail(e.Seq, "removing a wrap that was never added")
			}
			st.Removed[b.Fields[2]] = true
		case "kek_handover":
			if len(b.Fields) < 3 || (b.Fields[0] != HandoverBegun && b.Fields[0] != HandoverComplete) {
				return fail(e.Seq, "malformed KEK hand-over event")
			}
			st.Handover = Handover{Phase: b.Fields[0], From: b.Fields[1], To: b.Fields[2], Seq: e.Seq}
		case "key_confirmed":
			if !created[k] || confirmed[k] || abandoned[k] {
				return fail(e.Seq, "confirming a key that was not created")
			}
			confirmed[k] = true
			set(purpose, version, StateConfirmed)
			st.Versions[purpose] = append(st.Versions[purpose], version)
		case "key_activated":
			if !confirmed[k] {
				return fail(e.Seq, "activating %s v%d before it was confirmed", purpose, version)
			}
			if prev := st.Active[purpose]; prev > 0 && st.States[purpose][prev] == StateActive {
				set(purpose, prev, StateDecryptOnly)
			}
			st.Active[purpose] = version
			set(purpose, version, StateActive)
		case "key_decrypt_only":
			if !created[k] || st.Active[purpose] == version {
				return fail(e.Seq, "%s v%d cannot be made decrypt-only", purpose, version)
			}
			if st.States[purpose][version] != StateRetired {
				set(purpose, version, StateDecryptOnly)
			}
		case "key_retired":
			if st.States[purpose][version] != StateDecryptOnly {
				return fail(e.Seq, "retiring %s v%d, which is not decrypt-only", purpose, version)
			}
			set(purpose, version, StateRetired)
		}
	}
	for _, vs := range st.Versions {
		sort.Ints(vs)
	}
	// Every wrap row must be named by a wrap_added event with the same hash,
	// and every version keeps at least one wrap that no event retired.
	for _, purpose := range sortedKeys(st.Versions) {
		for _, v := range st.Versions[purpose] {
			rows, err := s.Ring.Wraps(ctx, tenant, purpose, v)
			if err != nil || len(rows) == 0 {
				return nil, fmt.Errorf("%w: keyring row %s v%d: %v", ErrBroken, purpose, v, err)
			}
			live := 0
			for _, row := range rows {
				want, ok := wraps[row.WrapID]
				if !ok || want != wrapHash(row.Wrapped, controllog.WrapAAD(tenant, purpose, v)) {
					return nil, fmt.Errorf("%w: keyring row %s v%d is not backed by a wrap_added event", ErrBroken, purpose, v)
				}
				if !st.Removed[row.WrapID] {
					live++
				}
			}
			if live == 0 {
				return nil, fmt.Errorf("%w: keyring %s v%d has no wrap left", ErrBroken, purpose, v)
			}
		}
	}
	st.Head = events[len(events)-1]
	st.Events = len(events)
	return st, nil
}

// Load returns the unwrapped DEK of purpose at version (0 = the active version
// of the verified log).
func (s *Service) Load(ctx context.Context, tenant, purpose string, version int) (Key, error) {
	st, err := s.Verify(ctx, tenant)
	if err != nil {
		return Key{}, err
	}
	if version == 0 {
		version = st.Active[purpose]
	}
	if version == 0 {
		return Key{}, fmt.Errorf("keyring: no active %s key for %s", purpose, tenant)
	}
	if !slices.Contains(st.Versions[purpose], version) {
		return Key{}, ports.ErrNotFound // never created, or never confirmed: not usable
	}
	rows, err := s.Ring.Wraps(ctx, tenant, purpose, version)
	if err != nil {
		return Key{}, err
	}
	if len(rows) == 0 {
		return Key{}, ports.ErrNotFound
	}
	// A version can have wraps under several KEKs (a hand-over in progress);
	// the first one this service holds the KEK of opens it.
	var first error
	for _, row := range rows {
		if st.Removed[row.WrapID] {
			continue
		}
		dek, err := s.unwrapRow(ctx, tenant, row)
		if err != nil {
			if first == nil || errors.Is(err, ErrBroken) {
				first = err
			}
			continue
		}
		return Key{Purpose: purpose, Version: version, KeyID: row.KeyID, DEK: dek}, nil
	}
	if first == nil {
		first = ports.ErrNotFound
	}
	return Key{}, first
}

// unwrapRow opens one wrap and checks the DEK against its recorded fingerprint.
func (s *Service) unwrapRow(ctx context.Context, tenant string, row ports.KeyringRow) ([]byte, error) {
	dek, err := s.KS.Unwrap(ctx, row.Wrapped, controllog.WrapAAD(tenant, row.Purpose, row.Version), row.KEKRef)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(controllog.KeyFingerprint(dek), row.Fingerprint) {
		clear(dek)
		return nil, fmt.Errorf("%w: unwrapped %s v%d does not match its fingerprint", ErrBroken, row.Purpose, row.Version)
	}
	return dek, nil
}
