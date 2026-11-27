// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"regexp"
)

// Key hierarchy of multi-tenant mode (docs/MULTI-TENANT.md).
//
// The master key (SENDORA_DB_KEY_FILE) is never used directly as a database
// key in multi-tenant mode. Every database gets its own key, derived with
// HKDF-SHA256 (no salt) and a domain-separated label as the info string:
//
//	platform.db           HKDF(master, "sendora/v1/platform-db")
//	tenants/<id>/...      HKDF(master, "sendora/v1/tenant-db/<id>")
//
// Within a tenant everything else is derived from its own database key exactly
// as in single-tenant mode: the share file master key (filecrypt.MasterKey),
// the audit chain key, and — because they are random values stored in the
// tenant's own database — the token signing secret and all HMAC keys. A token,
// cookie, link or file of one tenant therefore never verifies or decrypts in
// another: the other tenant has neither the database row nor the key.
//
// A tenant converted from a single-tenant installation (tenant-import) keeps
// the original key as its "root" for the file and audit keys, so the files and
// the audit chain written before the conversion stay readable and verifiable;
// only the database itself is re-encrypted with the derived key.

// PlatformDBLabel is the HKDF info string of the platform database key.
const PlatformDBLabel = "sendora/v1/platform-db"

const tenantDBLabelPrefix = "sendora/v1/tenant-db/"

// TenantIDPattern is the form of a tenant ID: 26 lowercase base32 characters
// (130 random bits), used as directory name and key derivation context.
var TenantIDPattern = regexp.MustCompile(`^[a-z2-7]{26}$`)

// DeriveKey derives a 32-byte key from the master key for one purpose.
func DeriveKey(master []byte, label string) ([]byte, error) {
	if len(master) != 32 {
		return nil, errors.New("master key must contain 32 bytes")
	}
	if label == "" {
		return nil, errors.New("key label required")
	}
	return hkdf.Key(sha256.New, master, nil, label, 32)
}

// TenantDBKey is the SQLCipher key of one tenant's database.
func TenantDBKey(master []byte, tenantID string) ([]byte, error) {
	if !TenantIDPattern.MatchString(tenantID) {
		return nil, errors.New("invalid tenant id")
	}
	return DeriveKey(master, tenantDBLabelPrefix+tenantID)
}

// PlatformDBKey is the SQLCipher key of the platform database.
func PlatformDBKey(master []byte) ([]byte, error) { return DeriveKey(master, PlatformDBLabel) }

// OpenTenant opens (or, with initialize, creates) a tenant's store. dbKey is
// the tenant's derived database key; root is nil for a native tenant and the
// pre-conversion key for an imported one (see the comment above).
func OpenTenant(dataDir string, dbKey, root []byte, initialize bool) (*Store, error) {
	if root != nil && len(root) != 32 {
		return nil, errors.New("tenant root key must contain 32 bytes")
	}
	if _, err := OpenEncryptedCheck(dataDir, dbKey, initialize); err != nil {
		return nil, err
	}
	return openStoreRoot(dataDir, dbKey, root)
}

// OpenEncryptedCheck performs OpenEncrypted's checks (explicit initialization,
// no plaintext, readable with the key) without opening the store. It reports
// whether the database already existed.
func OpenEncryptedCheck(dataDir string, key []byte, initialize bool) (bool, error) {
	if len(key) != 32 {
		return false, errors.New("database key must contain 32 bytes")
	}
	p, err := DBPath(dataDir)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(p); os.IsNotExist(err) {
		if !initialize {
			return false, errors.New("database missing; explicit initialization required")
		}
		return false, nil
	}
	db, err := openCipherDB(p, key, true)
	if err != nil {
		return true, err
	}
	db.Close()
	return true, nil
}

// TenantStorageUsage is the total size of the tenant's stored and reserved
// files (the platform's storage quota counts both).
func (s *Store) TenantStorageUsage() (int64, error) {
	ctx := context.Background()
	stored, err := s.Repos().Quota().TotalStoredBytes(ctx)
	if err != nil {
		return 0, err
	}
	reserved, err := s.Repos().Quota().TotalReservedBytes(ctx)
	if err != nil {
		return 0, err
	}
	return stored + reserved, nil
}

// RekeyDatabaseFile re-encrypts the database at path from oldKey to newKey via
// a verified sqlcipher_export copy next to it, then atomically replaces the
// original. The original stays untouched until the copy has been verified.
func RekeyDatabaseFile(path string, oldKey, newKey []byte) error {
	tmp := path + ".rekey"
	for _, p := range []string{tmp, tmp + "-wal", tmp + "-shm"} {
		if err := removeIfExists(p); err != nil {
			return err
		}
	}
	if err := ExportDatabase(path, tmp, oldKey, newKey); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := removeIfExists(path + suffix); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// DatabaseReadable reports whether the database at path opens with key.
func DatabaseReadable(path string, key []byte) bool {
	db, err := openCipherDB(path, key, true)
	if err != nil {
		return false
	}
	db.Close()
	return true
}
