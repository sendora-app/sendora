// SPDX-License-Identifier: AGPL-3.0-or-later

package keyring

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/google/uuid"

	"github.com/sendora-app/sendora/internal/controllog"
	"github.com/sendora-app/sendora/internal/ports"
)

// Carried is one key version moved from one keyring to another.
type Carried struct {
	Purpose string
	Version int
	DEK     []byte
}

// Export returns the keys of purposes that are still usable (active or
// decrypt-only; a retired version is not carried), oldest version first.
// The caller clears the DEKs.
func (s *Service) Export(ctx context.Context, tenant string, purposes ...string) ([]Carried, error) {
	st, err := s.Verify(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var out []Carried
	for _, p := range purposes {
		for _, v := range st.Versions[p] {
			if state := st.States[p][v]; state != StateActive && state != StateDecryptOnly {
				continue
			}
			k, err := s.Load(ctx, tenant, p, v)
			if err != nil {
				for _, c := range out {
					clear(c.DEK)
				}
				return nil, err
			}
			out = append(out, Carried{Purpose: p, Version: v, DEK: k.DEK})
		}
	}
	return out, nil
}

// InitCarrying is Init for a keyring that keeps keys of another one: the
// carried versions are created with their own version numbers and DEKs (the
// highest carried version of a purpose is active, the others decrypt-only) so
// what they protect (stored files, the audit chain's MAC) stays readable when
// a database is re-keyed. Every other purpose starts fresh at version 1.
func (s *Service) InitCarrying(ctx context.Context, tenant, actor string, carried []Carried) error {
	if _, err := s.Log.Latest(ctx, tenant); err == nil {
		return fmt.Errorf("keyring: tenant %s already has a control log", tenant)
	} else if err != ports.ErrNotFound {
		return err
	}
	byPurpose := map[string][]Carried{}
	for _, c := range carried {
		byPurpose[c.Purpose] = append(byPurpose[c.Purpose], c)
	}
	chainID := uuid.NewString()
	a := &appender{s: s, tenant: tenant, prev: controllog.GenesisPrevHash(tenant, chainID), actor: actor}
	if _, err := a.add(ctx, "genesis", "", 0, chainID, actor); err != nil {
		return err
	}
	for _, purpose := range Purposes {
		list := byPurpose[purpose]
		if len(list) == 0 {
			if err := s.createKey(ctx, a, purpose, 1, true); err != nil {
				return err
			}
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Version < list[j].Version })
		prev := 0
		for _, c := range list {
			if err := s.createKeyWith(ctx, a, purpose, c.Version, c.DEK, true); err != nil {
				return err
			}
			if prev > 0 {
				if _, err := a.add(ctx, "key_decrypt_only", purpose, prev, purpose, strconv.Itoa(prev)); err != nil {
					return err
				}
			}
			prev = c.Version
		}
	}
	return nil
}
