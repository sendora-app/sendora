// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/sendora-app/sendora/internal/adapters/keysource"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/ports"
)

// Tenant-supplied KEK (docs/cluster/DESIGN.md D41, D44). The tenant presents
// 32 random bytes (base64). Nothing but the controller's memory ever holds the
// raw KEK: the processes that wrap and unwrap work with the wrapping key
// derived from it, and the platform record keeps only the KEK's fingerprint.

const tenantKEKWrapLabel = "sendora/v1/tenant-kek/wrap-key"

// TenantKEKBytes is the size of a tenant-supplied KEK.
const TenantKEKBytes = 32

// ParseTenantKEK decodes a presented KEK (standard or URL-safe base64, padding
// optional) and refuses anything that is not 32 bytes or is visibly not random.
func ParseTenantKEK(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("the key is empty")
	}
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err = enc.DecodeString(s); err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("the key must be base64 of 32 random bytes")
	}
	if len(raw) != TenantKEKBytes {
		clear(raw)
		return nil, errors.New("the key must be exactly 32 bytes (44 base64 characters)")
	}
	if err := checkKEKStrength(raw); err != nil {
		clear(raw)
		return nil, err
	}
	return raw, nil
}

// checkKEKStrength rejects keys that cannot be random: too few distinct bytes
// (all zero, repeated patterns) or a run-like sequence.
func checkKEKStrength(raw []byte) error {
	seen := map[byte]bool{}
	for _, b := range raw {
		seen[b] = true
	}
	if len(seen) < 12 {
		return errors.New("the key is too weak: generate one with sendora-db kek-generate")
	}
	asc, desc := true, true
	for i := 1; i < len(raw); i++ {
		if raw[i] != raw[i-1]+1 {
			asc = false
		}
		if raw[i] != raw[i-1]-1 {
			desc = false
		}
	}
	if asc || desc {
		return errors.New("the key is too weak: generate one with sendora-db kek-generate")
	}
	return nil
}

// TenantKEKFingerprint is the fingerprint the tenant sees and the platform
// record keeps (16 hex characters, HMAC-SHA256 of the KEK under a fixed label).
func TenantKEKFingerprint(raw []byte) string { return keysource.Fingerprint(raw) }

// TenantWrapKey derives the wrapping key a KEK stands for. It is what the
// controller hands to web replicas for an unlocked tenant (never the KEK).
func TenantWrapKey(raw []byte) ([]byte, error) { return DeriveKey(raw, tenantKEKWrapLabel) }

// TenantWrapRef is the kek_ref recorded with wraps made under the wrapping key.
func TenantWrapRef(wrap []byte) string { return "tenant:" + keysource.Fingerprint(wrap) }

// PlatformKEKRef is the kek_ref of the platform's KEK of a tenant with key
// root root.
func PlatformKEKRef(root []byte) (string, error) {
	kek, err := DeriveKey(root, columnKEKLabel)
	if err != nil {
		return "", err
	}
	defer clear(kek)
	return keysource.Fingerprint(kek), nil
}

// RemoteKeyringForMasterRotation is the keyring service of a tenant database
// during a master key rotation (D46): the platform KEK of the old master
// version (it MACs the log until the hand-over attests the new one) and the
// one of the new version are both loaded. oldRoot and newRoot are the tenant's
// key roots (Platform.TenantKeysAt); the returned references are the kek_ref
// of the wraps under each.
func RemoteKeyringForMasterRotation(logs ports.ControlLogRepository, ring ports.KeyringRepository, oldRoot, newRoot []byte) (svc *keyring.Service, oldRef, newRef string, err error) {
	ko, err := DeriveKey(oldRoot, columnKEKLabel)
	if err != nil {
		return nil, "", "", err
	}
	defer clear(ko)
	kn, err := DeriveKey(newRoot, columnKEKLabel)
	if err != nil {
		return nil, "", "", err
	}
	defer clear(kn)
	ks, err := keysource.NewFromKey(ko)
	if err != nil {
		return nil, "", "", err
	}
	oldRef, newRef = keysource.Fingerprint(ko), keysource.Fingerprint(kn)
	if oldRef == newRef {
		return nil, "", "", errors.New("the old and the new master key versions derive the same KEK")
	}
	if err := ks.AddNamed(newRef, kn, false); err != nil {
		return nil, "", "", err
	}
	return &keyring.Service{KS: ks, Log: logs, Ring: ring, MACRef: oldRef}, oldRef, newRef, nil
}
