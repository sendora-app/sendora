// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/filecrypt"
)

// ErrLegacyFile is returned for a stored file whose recorded key is the old
// root-derived master key (written before files moved under the tenant's
// "files" DEK, D45). Such a file is never opened: convert the store with
// "sendora-db files-reencrypt" (or the files re-encryption job) first.
var ErrLegacyFile = errors.New("this file is encrypted under the legacy platform key; run: sendora-db files-reencrypt")

// EncRef is the value stored in files.enc_id of a file encrypted under version
// of the tenant's files key: the file id (hex, as in the file header) and the
// key version, "<id>.<version>". A value without a version is a legacy file.
func EncRef(id string, version int) string {
	if id == "" {
		return ""
	}
	return id + "." + strconv.Itoa(version)
}

// ParseEncRef splits an enc_id value into the file id and the files key
// version (0 for a legacy value: root-derived key).
func ParseEncRef(ref string) (id string, version int) {
	i := strings.LastIndexByte(ref, '.')
	if i < 0 {
		return ref, 0
	}
	v, err := strconv.Atoi(ref[i+1:])
	if err != nil || v < 1 {
		return ref, 0
	}
	return ref[:i], v
}

// NewFileKey returns the master key and the key version that new files are
// encrypted under: the active version of the tenant's files DEK. It is nil, 0
// for the plaintext fixture store, which stores share files unencrypted.
// Callers must not modify the slice.
func (s *Store) NewFileKey() (master []byte, version int, err error) {
	if s.codec == nil {
		return nil, 0, nil
	}
	return s.codec.FileMaster(0)
}

// FileMaster returns the master key a stored file (its files.enc_id value) was
// encrypted under and the file id to compare with its header. A legacy
// (root-derived) file is refused with ErrLegacyFile; so is a file of a retired
// key version.
func (s *Store) FileMaster(ref string) (master []byte, id string, err error) {
	id, version := ParseEncRef(ref)
	if version == 0 {
		return nil, "", ErrLegacyFile
	}
	if s.codec == nil {
		return nil, "", errors.New("file encryption key unavailable")
	}
	m, _, err := s.codec.FileMaster(version)
	if err != nil {
		return nil, "", err
	}
	return m, id, nil
}

// legacyFileMaster is the old root-derived master key. Only the conversion of
// legacy files uses it.
func (s *Store) legacyFileMaster() ([]byte, error) { return filecrypt.MasterKey(s.rootKey) }

// KeyFingerprint identifies a database key without revealing it: the first 8
// bytes (hex) of HMAC-SHA256(key, "sendora key fingerprint v1"). Operators
// compare it to confirm the same key is in use; it is safe to log.
func KeyFingerprint(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("sendora key fingerprint v1"))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// KeyFingerprint is the fingerprint of this store's key ("none" for the plaintext
// fixture store).
func (s *Store) KeyFingerprint() string {
	if !s.IsEncrypted() {
		return "none"
	}
	return KeyFingerprint(s.cipherKey)
}

// CipherVersion is the SQLCipher version string reported by the engine.
// A remote store (OpenRemote) reports "postgresql".
func (s *Store) CipherVersion() string {
	if s.DB == nil {
		return "postgresql"
	}
	return sqlite.CipherVersion(s.DB)
}

// EncryptionStatus counts stored share files by encryption state.
type EncryptionStatus struct {
	Encrypted int64 `json:"encrypted"` // files.enc = 1
	Plain     int64 `json:"plain"`     // files.enc = 0 (legacy, uploaded before 0.1.2)
}

func (s *Store) EncryptionStatus() (EncryptionStatus, error) {
	var st EncryptionStatus
	var err error
	st.Encrypted, st.Plain, err = s.Repos().Shares().CountFilesByEncryption(context.Background())
	return st, err
}
