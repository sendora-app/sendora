// SPDX-License-Identifier: AGPL-3.0-or-later

// Package masterkey loads the versioned master key of the Cluster flavour
// (docs/cluster/DESIGN.md D46). SENDORA_DB_KEY_FILE names either one key file
// (version 1, exactly as before) or a directory with one file per version,
// "master-<n>" (n >= 1, 32 raw bytes each, the same permission rules as the
// single file). Which version a tenant's derived material comes from is
// recorded per tenant in the platform database, never here: this package only
// answers "give me version n".
package masterkey

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"

	"github.com/sendora-app/sendora/internal/store"
)

// InfraVersion is the master key version that the platform's own derived
// material and the tenants' database role passwords come from. Rotating those
// is not part of this build (D46), so version InfraVersion can never be retired.
const InfraVersion = 1

var nameRe = regexp.MustCompile(`^master-([1-9][0-9]{0,5})$`)

// ErrUnknownVersion is returned for a version this process does not hold (not
// yet mounted, or removed).
var ErrUnknownVersion = errors.New("master key version not available")

// Set is the versions of the master key held by one process.
type Set struct {
	mu   sync.RWMutex
	path string
	keys map[int][]byte
}

// Load reads path: a single key file (version 1) or a directory of
// master-<n> files. At least one version is required.
func Load(path string) (*Set, error) {
	s := &Set{path: path}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// FromKey wraps one key as version 1 (tests and the single-file case).
func FromKey(key []byte) *Set {
	return &Set{keys: map[int][]byte{1: append([]byte(nil), key...)}}
}

// FromVersions wraps explicit versions (tests).
func FromVersions(v map[int][]byte) *Set {
	s := &Set{keys: map[int][]byte{}}
	for n, k := range v {
		s.keys[n] = append([]byte(nil), k...)
	}
	return s
}

// Reload re-reads the path (a newly mounted version appears without a
// restart). A version that was loaded and has disappeared is dropped; a
// failing read keeps the previous set.
func (s *Set) Reload() error {
	if s.path == "" {
		return nil
	}
	fi, err := os.Stat(s.path)
	if err != nil {
		return errors.New("database key file cannot be opened")
	}
	keys := map[int][]byte{}
	if !fi.IsDir() {
		k, err := store.ReadDatabaseKey(s.path)
		if err != nil {
			return err
		}
		keys[1] = k
	} else {
		ents, err := os.ReadDir(s.path)
		if err != nil {
			return fmt.Errorf("reading the master key directory: %w", err)
		}
		for _, e := range ents {
			m := nameRe.FindStringSubmatch(e.Name())
			if m == nil {
				continue // Secret mounts add ..data and friends
			}
			n, _ := strconv.Atoi(m[1])
			k, err := store.ReadDatabaseKey(filepath.Join(s.path, e.Name()))
			if err != nil {
				return fmt.Errorf("master key version %d: %w", n, err)
			}
			keys[n] = k
		}
		if len(keys) == 0 {
			return errors.New("the master key directory holds no master-<n> file")
		}
	}
	s.mu.Lock()
	for _, old := range s.keys {
		clear(old)
	}
	s.keys = keys
	s.mu.Unlock()
	return nil
}

// Key returns a copy of version v (the caller clears it). A missing version
// triggers one Reload, so a version mounted a moment ago is found.
func (s *Set) Key(v int) ([]byte, error) {
	if k, ok := s.get(v); ok {
		return k, nil
	}
	if err := s.Reload(); err == nil {
		if k, ok := s.get(v); ok {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, v)
}

func (s *Set) get(v int) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[v]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), k...), true
}

// Has reports whether version v is held (without reloading).
func (s *Set) Has(v int) bool { _, ok := s.get(v); return ok }

// Versions lists the held versions, ascending.
func (s *Set) Versions() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]int, 0, len(s.keys))
	for n := range s.keys {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// Highest is the newest held version.
func (s *Set) Highest() int {
	vs := s.Versions()
	if len(vs) == 0 {
		return 0
	}
	return vs[len(vs)-1]
}

// Close wipes the keys.
func (s *Set) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, k := range s.keys {
		clear(k)
		delete(s.keys, n)
	}
}
