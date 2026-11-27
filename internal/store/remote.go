// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/sendora-app/sendora/internal/ports"
)

// ErrRemoteStore is returned by the operations that only exist for a local
// SQLCipher database (backups by sqlcipher_export, the cipher version) when
// the store is backed by a remote database (the Cluster flavour).
var ErrRemoteStore = errors.New("not available for a PostgreSQL-backed store")

// OpenRemote returns a Store whose repositories are repos (the PostgreSQL
// adapter of the Cluster flavour) instead of a local SQLCipher file. The
// database is migrated and seeded by the controller (design 13.2), never here.
// root is the secret the keyring's KEK is derived from (as a tenant's database
// key in multi-tenant mode); file content and the audit chain's MAC come from
// the keyring's own DEKs; dataDir holds the
// files of the local storage location (a shared RWX volume with N replicas).
// closeFn releases the database handle.
func OpenRemote(repos ports.Store, dataDir string, root []byte, closeFn func() error, opts ...RemoteOpt) (*Store, error) {
	if repos == nil {
		return nil, errors.New("repositories required")
	}
	if len(root) != 32 {
		return nil, errors.New("root key must contain 32 bytes")
	}
	for _, d := range []string{"", "shares", "uploads", "branding", "backgrounds"} {
		p := filepath.Join(dataDir, d)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, err
		}
	}
	s := &Store{DataDir: dataDir, rootKey: append([]byte(nil), root...), closeFn: closeFn}
	s.reposOnce.Do(func() { s.repos = repos })
	var cfg remoteCfg
	for _, o := range opts {
		o(&cfg)
	}
	s.tenantWrap = cfg.wrapKey
	if cfg.columns {
		if err := s.enableRemoteColumns(repos, root, cfg.wrapKey); err != nil {
			clear(s.rootKey)
			return nil, err
		}
	}
	return s, nil
}

// Remote reports whether the store is backed by a remote database
// (OpenRemote) rather than a local SQLCipher file.
func (s *Store) Remote() bool { return s.DB == nil && s.repos != nil }

// SetSettingsHook sets fn to run after every settings write through this
// store (SetSetting, SettingsChanged); the Cluster flavour uses it to tell
// the other replicas (design 4.6). nil (the default) does nothing.
func (s *Store) SetSettingsHook(fn func()) { s.settingsHook.Store(&fn) }

// NoteRemoteSettingsChange moves SettingsGen on after another replica wrote
// settings, so caches keyed on it refresh (it does not call the hook).
func (s *Store) NoteRemoteSettingsChange() { s.settingsGen.Add(1) }

func (s *Store) settingsWritten() {
	s.settingsGen.Add(1)
	if p := s.settingsHook.Load(); p != nil && *p != nil {
		(*p)()
	}
}
