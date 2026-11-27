// SPDX-License-Identifier: AGPL-3.0-or-later

package keyserver

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/masterkey"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/store"
)

// Master key rotation (docs/cluster/DESIGN.md D46), run by the controller
// leader. One tenant at a time moves from master key version v to v+1:
//
//   - platform-managed: Service.Handover from the platform KEK of v to the one
//     of v+1 (second wrap under the new KEK, verified, the log attested under
//     the new KEK, the tenant's record switched to v+1 while both wraps exist,
//     the old wraps destroyed). No data is re-encrypted: only the wraps move.
//   - tenant-managed: the wraps stay under the tenant's own KEK and the
//     operator has no key to move; only the log's MAC moves (AttestMAC) and
//     the record switches. No tenant key is needed or touched.
//
// Both are idempotent and judged from the keyring itself: after a crash (or a
// controller change) the next pass repeats the call and it continues.

// MasterRotator runs the rotation.
type MasterRotator struct {
	P       *platform.Platform
	Masters *masterkey.Set
	Ring    RingFunc
	// KEK serializes with the tenant-KEK operations of the same tenant.
	KEK  *KEKManager
	Logf func(string, ...any)
	// Audit, when set, is told of the start and the end of each tenant's move
	// (never key material).
	Audit func(action, tenantID, detail string)

	mu      sync.Mutex
	running bool
}

// Errors of the rotation (the platform's, re-exported).
var (
	ErrRotationBusy = platform.ErrMasterBusy
	ErrNoSuchStep   = platform.ErrMasterStep
)

func (r *MasterRotator) logf(f string, a ...any) {
	if r.Logf != nil {
		r.Logf(f, a...)
	}
}

// MasterStatus is the operator's view plus what this controller holds.
type MasterStatus struct {
	platform.MasterStatus
	// Held are the versions this controller can read.
	Held []int `json:"held"`
}

// Status reads the platform records (no keyring is opened).
func (r *MasterRotator) Status() (MasterStatus, error) {
	ps, err := r.P.MasterStatus()
	if err != nil {
		return MasterStatus{}, err
	}
	out := MasterStatus{MasterStatus: ps}
	if r.Masters != nil {
		out.Held = r.Masters.Versions()
	}
	return out, nil
}

// Start requests the rotation to version target (see
// Platform.StartMasterRotation); this controller must hold the key.
func (r *MasterRotator) Start(target int) error {
	st := r.P.MasterState()
	if st.Target > 0 {
		return ErrRotationBusy
	}
	if target != st.Active+1 {
		return ErrNoSuchStep
	}
	if r.Masters == nil {
		return errors.New("master key versions are not available here")
	}
	if _, err := r.Masters.Key(target); err != nil {
		return fmt.Errorf("version %d is not mounted on this controller: %w", target, err)
	}
	return r.P.StartMasterRotation(target)
}

// Retire marks version v as retired (see Platform.RetireMasterVersion).
func (r *MasterRotator) Retire(v int) error { return r.P.RetireMasterVersion(v) }

// Pass performs one pass over the tenants: every one that is not yet on the
// target version (or has an unfinished hand-over) is moved. It returns true
// when nothing is left, and then records the end of the rotation. It does
// nothing when no rotation is requested.
func (r *MasterRotator) Pass(ctx context.Context) (done bool, err error) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return false, ErrRotationBusy
	}
	r.running = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.running = false; r.mu.Unlock() }()

	st := r.P.MasterState()
	if st.Target == 0 {
		return true, nil
	}
	if r.Masters == nil {
		return false, errors.New("master key versions are not available here")
	}
	if _, err := r.Masters.Key(st.Target); err != nil {
		r.note("version %d is not mounted on the controller that leads: mount it and the rotation continues", st.Target)
		return false, err
	}
	if st.Active < st.Target {
		if err := r.P.SetMasterSetting("master_active_version", fmt.Sprint(st.Target)); err != nil {
			return false, err
		}
	}
	all, err := r.P.Tenants("")
	if err != nil {
		return false, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Slug < all[j].Slug })
	var failed, waiting int
	for _, t := range all {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if t.KeyMode == platform.KeyLegacy {
			continue // its root does not derive from the master key
		}
		if t.Status == platform.StatusImporting {
			waiting++ // not provisioned yet; it is created on the target version or moved later
			continue
		}
		if t.Status != platform.StatusActive && t.Status != platform.StatusSuspended {
			continue
		}
		if err := r.RotateTenant(ctx, t.ID, st.Target); err != nil {
			failed++
			r.logf("keys: master rotation of tenant %s: %v", t.ID, err)
		}
	}
	if failed > 0 || waiting > 0 {
		r.note("%d tenant(s) not moved yet, %d waiting to be provisioned; retrying", failed, waiting)
		return false, nil
	}
	r.note("")
	if err := r.P.SetMasterSetting("master_rotation_target", "0"); err != nil {
		return false, err
	}
	r.logf("keys: master key rotation to version %d finished", st.Target)
	if r.Audit != nil {
		r.Audit("master_rotation_finished", "", fmt.Sprintf("version=%d", st.Target))
	}
	return true, nil
}

func (r *MasterRotator) note(f string, a ...any) {
	msg := f
	if len(a) > 0 {
		msg = fmt.Sprintf(f, a...)
	}
	if r.P.Setting("master_rotation_note") != msg {
		r.P.SetMasterSetting("master_rotation_note", msg)
	}
}

// RotateTenant moves one tenant to master key version to. A tenant more than
// one version behind (one created before the tenant insert recorded the
// active version, or one an earlier rotation left behind) is moved one version
// at a time, each step the same resumable hand-over; every version in between
// is still mounted, because a version is not retirable while a tenant is on it
// or on an older one. Safe to repeat: after a crash it continues.
func (r *MasterRotator) RotateTenant(ctx context.Context, id string, to int) error {
	if to < 2 {
		return errors.New("no earlier master key version")
	}
	t, err := r.P.Tenant(id)
	if err != nil {
		return err
	}
	cur := t.MasterVersion
	if cur > to {
		return nil
	}
	// First finish a step that ended at the current version: a crash after its
	// commit leaves the old wraps in place until that step completes.
	if cur >= 2 {
		if err := r.rotateStep(ctx, id, cur); err != nil {
			return err
		}
	}
	for v := cur + 1; v <= to; v++ {
		if err := r.rotateStep(ctx, id, v); err != nil {
			return err
		}
	}
	return nil
}

// rotateStep moves one tenant from master key version to-1 to version to, or
// completes that move after a crash.
func (r *MasterRotator) rotateStep(ctx context.Context, id string, to int) error {
	t, err := r.P.Tenant(id)
	if err != nil {
		return err
	}
	if t.MasterVersion > to {
		return nil
	}
	from := to - 1
	if t.MasterVersion < from {
		return fmt.Errorf("tenant is at master key version %d, expected %d or %d", t.MasterVersion, from, to)
	}
	if r.KEK != nil {
		done, err := r.KEK.begin(id)
		if err != nil {
			return err
		}
		defer done()
	}
	_, rootOld, err := r.roots(t, from)
	if err != nil {
		return err
	}
	defer clear(rootOld)
	_, rootNew, err := r.roots(t, to)
	if err != nil {
		return err
	}
	defer clear(rootNew)
	logs, ring, release, err := r.Ring(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	svc, oldRef, newRef, err := store.RemoteKeyringForMasterRotation(logs, ring, rootOld, rootNew)
	if err != nil {
		return err
	}
	st, err := svc.Verify(ctx, store.ColumnKeyID)
	if err != nil {
		return err
	}
	const actor = "master key rotation"
	commit := func(context.Context) error {
		_, err := r.P.SetMasterVersion(id, from, to) // false: already at `to` (resumed)
		return err
	}
	if t.KEKMode == platform.KEKTenant {
		if t.MasterVersion == to && st.Head.MACKEK == newRef {
			return nil
		}
		if err := svc.AttestMAC(ctx, store.ColumnKeyID, actor, newRef); err != nil {
			return err
		}
		if err := commit(ctx); err != nil {
			return err
		}
		// A writer that still used the old record may have appended an event
		// under the old KEK meanwhile: the head must end up under the new one.
		if err := svc.AttestMAC(ctx, store.ColumnKeyID, actor, newRef); err != nil {
			return err
		}
		r.audited("master_tenant_moved", id, fmt.Sprintf("tenant-managed; mac only; version %d -> %d", from, to))
		return nil
	}
	if t.MasterVersion == to && st.Handover.Phase == keyring.HandoverComplete && st.Handover.From == oldRef && st.Handover.To == newRef && st.Head.MACKEK == newRef {
		return nil // nothing to do
	}
	if t.MasterVersion == to && (st.Handover.From != oldRef || st.Handover.To != newRef) && st.Head.MACKEK == newRef {
		return nil // reached this version without this hand-over (created on it): nothing to move
	}
	r.audited("master_tenant_move_started", id, fmt.Sprintf("version %d -> %d", from, to))
	err = svc.Handover(ctx, store.ColumnKeyID, actor, oldRef, newRef, keyring.HandoverOptions{Commit: commit, MACUnderTo: true})
	if err != nil {
		return err
	}
	r.audited("master_tenant_moved", id, fmt.Sprintf("version %d -> %d", from, to))
	return nil
}

func (r *MasterRotator) audited(action, id, detail string) {
	if r.Audit != nil {
		r.Audit(action, id, detail)
	}
}

// roots returns the tenant's database key and key root derived from version v.
func (r *MasterRotator) roots(t *platform.Tenant, v int) (dbKey, root []byte, err error) {
	dbKey, root, err = r.P.TenantKeysAt(t, v)
	if err != nil {
		return nil, nil, err
	}
	if root == nil {
		root = append([]byte(nil), dbKey...)
	}
	clear(dbKey)
	return nil, root, nil
}
