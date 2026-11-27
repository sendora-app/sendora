// SPDX-License-Identifier: AGPL-3.0-or-later

package platform

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sendora-app/sendora/internal/masterkey"
	"github.com/sendora-app/sendora/internal/ports"
)

// Master key versions (docs/cluster/DESIGN.md D46). The platform database
// records, per tenant, which version of the master key its derived material
// comes from, and a few platform-wide numbers.

// MasterState is the platform-wide master key bookkeeping.
type MasterState struct {
	// Active is the version new tenants start on.
	Active int `json:"active"`
	// Target is the version a running rotation moves every platform-managed
	// tenant to (0: no rotation requested).
	Target int `json:"target"`
	// Retired lists the versions that were retired: refused for any
	// derivation, their key files may be removed from the Secret.
	Retired []int `json:"retired"`
	// Infra is the version the platform's own material (platform database
	// password and key, rate-limit key) and every tenant's database role
	// password derive from; a constant in this build (D46).
	Infra int `json:"infra"`
	// Note is the controller's last message about the rotation (progress or
	// the reason it stopped); empty when none.
	Note string `json:"note,omitempty"`
}

// MasterState reads the bookkeeping.
func (p *Platform) MasterState() MasterState {
	return MasterState{
		Active:  int(p.SettingInt("master_active_version", 1)),
		Target:  int(p.SettingInt("master_rotation_target", 0)),
		Retired: parseVersions(p.Setting("master_retired")),
		Infra:   masterkey.InfraVersion,
		Note:    p.Setting("master_rotation_note"),
	}
}

// SetMasterSetting stores one internal master setting (a number, or text for
// the note) and tells the other replicas.
func (p *Platform) SetMasterSetting(key, value string) error {
	if !MasterSettings[key] {
		return fmt.Errorf("%s is not a master rotation setting", key)
	}
	if key != "master_rotation_note" {
		if key == "master_retired" {
			// a comma separated list of versions
		} else if n, err := strconv.Atoi(value); err != nil || n < 0 {
			return fmt.Errorf("%s must be a whole number", key)
		}
	}
	defer p.changed()
	return p.repo.PlatformSettings().Update(context.Background(), key, value)
}

func parseVersions(s string) []int {
	var out []int
	for _, f := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

// Errors of the rotation requests.
var (
	ErrMasterBusy = errors.New("a master key rotation is already in progress")
	ErrMasterStep = errors.New("the new master key version must be exactly one above the active one")
)

// MasterStatus is the operator's view of the master key versions.
type MasterStatus struct {
	MasterState
	// Tenants counts tenants per master version.
	Tenants map[int]int `json:"tenants"`
	// Retirable lists the versions that can be retired now.
	Retirable []int `json:"retirable"`
	// InProgress is true while a rotation is requested and not finished.
	InProgress bool `json:"in_progress"`
}

// MasterStatus reads the records.
func (p *Platform) MasterStatus() (MasterStatus, error) {
	counts, err := p.MasterCounts()
	if err != nil {
		return MasterStatus{}, err
	}
	st := p.MasterState()
	out := MasterStatus{MasterState: st, Tenants: counts, InProgress: st.Target > 0, Retirable: []int{}}
	for v := 1; v < st.Active; v++ {
		if masterRetirable(v, st, counts) == nil {
			out.Retirable = append(out.Retirable, v)
		}
	}
	return out, nil
}

// masterRetirable says why version v cannot be retired (nil when it can).
func masterRetirable(v int, st MasterState, counts map[int]int) error {
	switch {
	case slices.Contains(st.Retired, v):
		return fmt.Errorf("version %d is already retired", v)
	case v == st.Infra:
		return fmt.Errorf("version %d still derives the platform's own keys and the database passwords; those are not rotated in this build", v)
	case st.Target > 0:
		return errors.New("a rotation is in progress")
	case v >= st.Active:
		return fmt.Errorf("version %d is the active one or newer", v)
	}
	for tv, n := range counts {
		if tv <= v && n > 0 {
			return fmt.Errorf("%d tenant(s) still use version %d", n, tv)
		}
	}
	return nil
}

// StartMasterRotation requests the rotation to version target: it must be the
// active version plus one and no rotation may be running. New tenants use it
// from then on; the controller leader moves the others (it checks that it
// holds the key and says so in the note when it does not).
func (p *Platform) StartMasterRotation(target int) error {
	st := p.MasterState()
	if st.Target > 0 {
		return ErrMasterBusy
	}
	if target != st.Active+1 {
		return ErrMasterStep
	}
	if err := p.SetMasterSetting("master_rotation_note", ""); err != nil {
		return err
	}
	return p.SetMasterSetting("master_rotation_target", strconv.Itoa(target))
}

// RetireMasterVersion records version v as retired: refused while a tenant is
// on it or on an older one, for the infrastructure version, the active one,
// and during a rotation. Its key file can then be removed from the Secret
// (after the backups that need it have expired).
func (p *Platform) RetireMasterVersion(v int) error {
	counts, err := p.MasterCounts()
	if err != nil {
		return err
	}
	st := p.MasterState()
	if err := masterRetirable(v, st, counts); err != nil {
		return err
	}
	list := append(append([]int(nil), st.Retired...), v)
	sort.Ints(list)
	parts := make([]string, len(list))
	for i, n := range list {
		parts[i] = strconv.Itoa(n)
	}
	return p.SetMasterSetting("master_retired", strings.Join(parts, ","))
}

// SetMasterVersion moves a tenant from master version from to version to (the
// controller does this inside the hand-over of the tenant's KEK, while both
// wraps exist). It reports whether the tenant was at from.
func (p *Platform) SetMasterVersion(id string, from, to int) (bool, error) {
	defer p.changed()
	n, err := p.repo.Tenants().SetMasterVersion(context.Background(), id, from, to)
	if err != nil {
		return false, err
	}
	if n == 0 {
		if _, err := p.repo.Tenants().ByID(context.Background(), id); err != nil {
			if err == ports.ErrNotFound {
				return false, ErrNotFound
			}
			return false, err
		}
	}
	return n == 1, nil
}

// MasterCounts counts the tenants per master version.
func (p *Platform) MasterCounts() (map[int]int, error) {
	return p.repo.Tenants().CountByMasterVersion(context.Background())
}
