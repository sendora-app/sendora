// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/ports"
)

// PlatformDBFile is the platform database of multi-tenant mode, in DATA_DIR.
const PlatformDBFile = "platform.db"

// OpenPlatform opens (or, with initialize, creates) the platform database of
// multi-tenant mode. The returned Store only has the settings table, the audit
// chain tables and whatever the caller adds with extra (the platform package's
// schema); tenant tables such as users or shares do not exist in it. The audit
// methods (AuditAppend, AuditVerify, AuditVerifyIncremental, AuditPurge) work
// as for a tenant store, with the audit key derived from key.
func OpenPlatform(dataDir string, key []byte, initialize bool, extra []string) (*Store, error) {
	return openPlatform(dataDir, key, initialize, extra, false)
}

// UpgradePlatformColumnEncryption converts the platform database in dataDir
// that a 0.2 multi-tenant installation left behind: it creates the database's
// column keys and encrypts the plaintext values of its encrypted columns, in
// place. key is the platform database key (PlatformDBKey of the master key).
// It returns how many values it encrypted (0 for a database that needs no
// conversion). Offline, after a safety copy.
func UpgradePlatformColumnEncryption(dataDir string, key []byte, extra []string) (int, error) {
	s, err := openPlatform(dataDir, key, false, extra, true)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	return s.columnsUpgraded, nil
}

func openPlatform(dataDir string, key []byte, initialize bool, extra []string, upgrade bool) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("platform database key must contain 32 bytes")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dataDir, PlatformDBFile)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		if !initialize {
			return nil, errors.New("platform database missing; explicit initialization required (SENDORA_DB_INITIALIZE=true)")
		}
	} else if err != nil {
		return nil, err
	} else if db, err := openCipherDB(p, key, true); err != nil {
		return nil, err
	} else {
		db.Close()
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()
	db, err := openCipherDB(p, key, false)
	if err != nil {
		return nil, err
	}
	if err := sqlite.InitPlatformSchema(db, extra); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{DB: db, DataDir: dataDir, Path: p, cipherKey: append([]byte(nil), key...), rootKey: append([]byte(nil), key...)}
	// The platform's secrets (administrators' TOTP secrets, legacy tenant
	// roots) are column-encrypted like a tenant's. A platform database with
	// such plaintext (created before column encryption) is refused.
	if err := s.enableColumnEncryption(upgrade); err != nil {
		db.Close()
		if errors.Is(err, ErrLegacyColumns) {
			return nil, fmt.Errorf("%w; for the platform database: sendora-db upgrade-encryption -platform -data-dir %s", err, dataDir)
		}
		return nil, err
	}
	// The schema version marker is a setting, so it is sealed: it is written
	// here, with the keys, and not by the schema.
	if err := s.PlatformRepo().EnsureSchemaVersion(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// PlatformRepo returns the platform repositories on a store opened with
// OpenPlatform, with the platform's column encryption applied.
func (s *Store) PlatformRepo() *sqlite.PlatformStore {
	r := sqlite.NewPlatform(s.DB)
	r.SetCodec(s.ColumnCodec())
	return r
}

// ColumnCodec returns the codec of the store's encrypted columns, nil when
// the store has none.
func (s *Store) ColumnCodec() ports.ColumnCodec {
	if s.codec == nil {
		return nil
	}
	return s.codec
}
