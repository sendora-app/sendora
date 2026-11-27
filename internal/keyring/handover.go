// SPDX-License-Identifier: AGPL-3.0-or-later

package keyring

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"github.com/sendora-app/sendora/internal/controllog"
	"github.com/sendora-app/sendora/internal/ports"
)

// KEK hand-over (docs/cluster/DESIGN.md D41, D44): every DEK of a database is
// wrapped under one KEK, the platform's or a tenant-supplied one. A hand-over
// moves all wraps from one KEK ("from") to another ("to") in an order that
// never leaves a version without a readable wrap:
//
//  1. kek_handover "begun" is logged,
//  2. every version gets a second wrap under "to" (wrap_added),
//  3. every new wrap is opened again with "to" and compared with the DEK's
//     fingerprint,
//  4. the caller's Commit hook runs (the platform record switches mode),
//  5. every wrap under "from" is retired (wrap_removed) and deleted as the
//     database owner,
//  6. kek_handover "complete" is logged.
//
// Every step is idempotent and judged from the keyring itself, so a crash
// anywhere is resumed by calling Handover again with the same arguments.

// Phases of a hand-over event.
const (
	HandoverBegun    = "begun"
	HandoverComplete = "complete"
)

// Handover is the newest kek_handover event of a log.
type Handover struct {
	Phase    string // HandoverBegun or HandoverComplete; "" when there was none
	From, To string // KEK references
	Seq      int64
}

// ErrNoRefWrapper is returned when the service's KeySource cannot wrap under a
// named KEK.
var ErrNoRefWrapper = errors.New("keyring: the key source cannot wrap under a named KEK")

// RefWrapper is a KeySource that can wrap under, and tell whether it holds,
// a named KEK (adapters/keysource.FileKeySource).
type RefWrapper interface {
	WrapWith(ctx context.Context, dek, aad []byte, kekRef string) ([]byte, error)
	Has(kekRef string) bool
}

// HandoverStep reports progress to the caller (audit trail).
type HandoverStep func(step string, detail string)

// HandoverOptions configures Handover.
type HandoverOptions struct {
	// Commit runs after the new wraps verified and before the old ones are
	// destroyed; it must make the new KEK the one the rest of the system
	// uses (the platform record). A failing Commit stops the hand-over with
	// both wraps in place.
	Commit func(ctx context.Context) error
	// Step is told of each phase (optional).
	Step HandoverStep
	// MACUnderTo makes "to" the KEK that MACs the log from the verified
	// step on: a kek_attest event under "to" is appended before Commit, and
	// the service's MACRef stays "to" for the rest of the call and after
	// it. Used when the old KEK is going away for good (the master key
	// rotation, D46); a tenant-supplied KEK never MACs the log (D44).
	MACUnderTo bool
}

// WrapRefs returns, per KEK reference, how many wraps under it exist in the
// verified keyring (retired wraps excluded).
func (s *Service) WrapRefs(ctx context.Context, tenant string) (map[string]int, error) {
	st, err := s.Verify(ctx, tenant)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for purpose, versions := range st.Versions {
		for _, v := range versions {
			rows, err := s.Ring.Wraps(ctx, tenant, purpose, v)
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				if !st.Removed[r.WrapID] {
					out[r.KEKRef]++
				}
			}
		}
	}
	return out, nil
}

// CanOpen reports whether every version of the keyring can be unwrapped with
// the KEK named ref (and matches its fingerprint). It is how an unlock proves
// that a presented KEK is the right one.
func (s *Service) CanOpen(ctx context.Context, tenant, ref string) error {
	st, err := s.Verify(ctx, tenant)
	if err != nil {
		return err
	}
	for _, purpose := range sortedKeys(st.Versions) {
		for _, v := range st.Versions[purpose] {
			rows, err := s.Ring.Wraps(ctx, tenant, purpose, v)
			if err != nil {
				return err
			}
			ok := false
			for _, row := range rows {
				if row.KEKRef != ref || st.Removed[row.WrapID] {
					continue
				}
				dek, err := s.unwrapRow(ctx, tenant, row)
				if err != nil {
					return fmt.Errorf("%s v%d: %w", purpose, v, err)
				}
				clear(dek)
				ok = true
				break
			}
			if !ok {
				return fmt.Errorf("keyring: %s v%d has no wrap under %s", purpose, v, ref)
			}
		}
	}
	return nil
}

// Handover moves every wrap from the KEK "from" to the KEK "to"; the service's
// KeySource must hold both (RefWrapper). See the package comment above for
// the order of the steps.
func (s *Service) Handover(ctx context.Context, tenant, actor, from, to string, opt HandoverOptions) error {
	rw, ok := s.KS.(RefWrapper)
	if !ok {
		return ErrNoRefWrapper
	}
	if from == to {
		return errors.New("keyring: the old and the new KEK are the same")
	}
	if !rw.Has(from) || !rw.Has(to) {
		return errors.New("keyring: both KEKs of a hand-over must be present")
	}
	step := opt.Step
	if step == nil {
		step = func(string, string) {}
	}
	st, err := s.Verify(ctx, tenant)
	if err != nil {
		return err
	}
	a, err := s.appenderFor(ctx, tenant, actor, false)
	if err != nil {
		return err
	}
	if st.Handover.Phase != HandoverBegun || st.Handover.From != from || st.Handover.To != to {
		if _, err := a.add(ctx, "kek_handover", "", 0, HandoverBegun, from, to); err != nil {
			return err
		}
	}
	step("begun", from+" -> "+to)
	// 2. wraps under "to".
	added := 0
	for _, purpose := range sortedKeys(st.Versions) {
		for _, v := range st.Versions[purpose] {
			n, err := s.addWrap(ctx, a, rw, tenant, purpose, v, from, to, st.Removed)
			if err != nil {
				return fmt.Errorf("wrapping %s v%d under the new KEK: %w", purpose, v, err)
			}
			added += n
		}
	}
	step("wrapped", strconv.Itoa(added)+" wraps added")
	// 3. the new wraps must open.
	if err := s.CanOpen(ctx, tenant, to); err != nil {
		return fmt.Errorf("the new KEK does not open the keyring: %w", err)
	}
	step("verified", "every key opens with the new KEK")
	// 3b. from here on the new KEK MACs the log: the head then verifies
	// with the new KEK alone, which is all a replica opened with it holds.
	if opt.MACUnderTo {
		if err := s.AttestMAC(ctx, tenant, actor, to); err != nil {
			return err
		}
		step("attested", "the log is MACed under the new KEK")
	}
	// 4. switch over.
	if opt.Commit != nil {
		if err := opt.Commit(ctx); err != nil {
			return fmt.Errorf("switching the tenant over: %w", err)
		}
	}
	step("committed", "")
	// 5. destroy the wraps under "from" (re-read: events were appended).
	st, err = s.Verify(ctx, tenant)
	if err != nil {
		return err
	}
	a, err = s.appenderFor(ctx, tenant, actor, false)
	if err != nil {
		return err
	}
	removed := 0
	for _, purpose := range sortedKeys(st.Versions) {
		for _, v := range st.Versions[purpose] {
			n, err := s.removeWraps(ctx, a, tenant, purpose, v, from, to, st.Removed)
			if err != nil {
				return fmt.Errorf("removing the old wraps of %s v%d: %w", purpose, v, err)
			}
			removed += n
		}
	}
	step("removed", strconv.Itoa(removed)+" wraps destroyed")
	// 6. done.
	if opt.MACUnderTo {
		if err := s.AttestMAC(ctx, tenant, actor, to); err != nil {
			return err
		}
	}
	if st.Handover.Phase != HandoverComplete || st.Handover.From != from || st.Handover.To != to || removed > 0 {
		if _, err := a.add(ctx, "kek_handover", "", 0, HandoverComplete, from, to); err != nil {
			return err
		}
	}
	return nil
}

// addWrap gives (purpose, version) a wrap under to when it has none, from the
// DEK that a wrap under from opens. It returns how many wraps it added.
func (s *Service) addWrap(ctx context.Context, a *appender, rw RefWrapper, tenant, purpose string, version int, from, to string, removed map[string]bool) (int, error) {
	rows, err := s.Ring.Wraps(ctx, tenant, purpose, version)
	if err != nil {
		return 0, err
	}
	var src *ports.KeyringRow
	for i, r := range rows {
		if removed[r.WrapID] {
			continue
		}
		if r.KEKRef == to {
			return 0, nil // already there (resumed hand-over)
		}
		if r.KEKRef == from && src == nil {
			src = &rows[i]
		}
	}
	if src == nil {
		return 0, fmt.Errorf("no wrap under the old KEK to start from")
	}
	dek, err := s.unwrapRow(ctx, tenant, *src)
	if err != nil {
		return 0, err
	}
	defer clear(dek)
	aad := controllog.WrapAAD(tenant, purpose, version)
	wrapped, err := rw.WrapWith(ctx, dek, aad, to)
	if err != nil {
		return 0, err
	}
	wrapID := uuid.NewString()
	ver := strconv.Itoa(version)
	// The event names the wrap before the row exists, so a crash between the
	// two leaves a harmless event, never a row the log does not know.
	if _, err := a.add(ctx, "wrap_added", purpose, version, purpose, ver, wrapID, to, wrapHash(wrapped, aad)); err != nil {
		return 0, err
	}
	err = s.Ring.Add(ctx, ports.KeyringRow{TenantID: tenant, Purpose: purpose, Version: version, KeyID: src.KeyID, WrapID: wrapID,
		KEKRef: to, Wrapped: wrapped, Fingerprint: src.Fingerprint, CreatedAt: s.now()})
	if err != nil {
		return 0, err
	}
	return 1, nil
}

// removeWraps retires and deletes the wraps of (purpose, version) under from,
// provided a wrap under to remains. It returns how many it destroyed.
func (s *Service) removeWraps(ctx context.Context, a *appender, tenant, purpose string, version int, from, to string, removed map[string]bool) (int, error) {
	rows, err := s.Ring.Wraps(ctx, tenant, purpose, version)
	if err != nil {
		return 0, err
	}
	haveTo := false
	for _, r := range rows {
		if r.KEKRef == to && !removed[r.WrapID] {
			haveTo = true
		}
	}
	if !haveTo {
		return 0, errors.New("refusing to remove the last wrap of a key")
	}
	n := 0
	ver := strconv.Itoa(version)
	for _, r := range rows {
		if r.KEKRef != from {
			continue
		}
		if !removed[r.WrapID] {
			if _, err := a.add(ctx, "wrap_removed", purpose, version, purpose, ver, r.WrapID, r.KEKRef); err != nil {
				return n, err
			}
		}
		if _, err := s.Ring.Remove(ctx, tenant, r.WrapID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// AttestMAC makes ref the KEK that MACs the log: it appends a kek_attest event
// under ref unless the newest event already is MACed under it, and keeps ref
// as the service's MACRef. It moves nothing else: the master key rotation
// uses it alone for tenant-managed tenants, whose wraps stay under the
// tenant's own KEK (D46). The KeySource must hold ref.
func (s *Service) AttestMAC(ctx context.Context, tenant, actor, ref string) error {
	last, err := s.Log.Latest(ctx, tenant)
	if errors.Is(err, ports.ErrNotFound) {
		return ErrNoLog
	}
	if err != nil {
		return err
	}
	s.MACRef = ref
	if last.MACKEK == ref {
		return nil
	}
	a, err := s.appenderFor(ctx, tenant, actor, false)
	if err != nil {
		return err
	}
	_, err = a.add(ctx, "kek_attest", "", 0, ref)
	return err
}
