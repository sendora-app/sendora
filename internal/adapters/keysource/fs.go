// SPDX-License-Identifier: AGPL-3.0-or-later

package keysource

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/sendora-app/sendora/internal/ports"
	"golang.org/x/crypto/hkdf"
)

// In-process / Local filesystem KeySource per DESIGN §6.2, §6.9:
// KEK fingerprint: first 16 hex chars of HMAC-SHA256(KEK, "sendora kek fingerprint v1")
// Subkeys derived via HKDF-SHA256:
// - Wrap key: HKDF(KEK, "sendora kek wrap v1")
// - ControlMAC key: HKDF(KEK, "sendora control-log mac v1")

type keyEntry struct {
	raw         []byte
	fingerprint string
	wrapKey     []byte
	macKey      []byte
}

type FileKeySource struct {
	mu     sync.RWMutex
	dir    string
	keys   map[string]keyEntry // fingerprint -> keyEntry
	active string              // active fingerprint
}

// NewFromKey creates a KeySource from a single raw 32-byte master key
func NewFromKey(rawKey []byte) (*FileKeySource, error) {
	if len(rawKey) != 32 {
		return nil, errors.New("KEK must be 32 bytes")
	}
	ks := &FileKeySource{
		keys: make(map[string]keyEntry),
	}
	ent, err := makeKeyEntry(rawKey)
	if err != nil {
		return nil, err
	}
	ks.keys[ent.fingerprint] = ent
	ks.active = ent.fingerprint
	return ks, nil
}

// NewFromDir loads all key files from a directory.
// Files can be named "kek-<fingerprint>" or any file containing 32 raw bytes.
func NewFromDir(dir string) (*FileKeySource, error) {
	ks := &FileKeySource{
		dir:  dir,
		keys: make(map[string]keyEntry),
	}
	if err := ks.Reload(); err != nil {
		return nil, err
	}
	return ks, nil
}

func Fingerprint(rawKey []byte) string {
	mac := hmac.New(sha256.New, rawKey)
	mac.Write([]byte("sendora kek fingerprint v1"))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:8]) // first 16 hex characters
}

func makeKeyEntry(rawKey []byte) (keyEntry, error) {
	fp := Fingerprint(rawKey)

	// Wrap key
	wrapRdr := hkdf.New(sha256.New, rawKey, nil, []byte("sendora kek wrap v1"))
	wrapKey := make([]byte, 32)
	if _, err := io.ReadFull(wrapRdr, wrapKey); err != nil {
		return keyEntry{}, err
	}

	// ControlMAC key
	macRdr := hkdf.New(sha256.New, rawKey, nil, []byte("sendora control-log mac v1"))
	macKey := make([]byte, 32)
	if _, err := io.ReadFull(macRdr, macKey); err != nil {
		return keyEntry{}, err
	}

	return keyEntry{
		raw:         append([]byte(nil), rawKey...),
		fingerprint: fp,
		wrapKey:     wrapKey,
		macKey:      macKey,
	}, nil
}

// Reload reads the directory for any updated or newly added KEK files
func (ks *FileKeySource) Reload() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.dir == "" {
		return nil
	}

	entries, err := os.ReadDir(ks.dir)
	if err != nil {
		return fmt.Errorf("reading key dir: %w", err)
	}

	newKeys := make(map[string]keyEntry)
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		path := filepath.Join(ks.dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading key %s: %w", path, err)
		}
		if len(data) != 32 {
			continue // skip non-32-byte files
		}
		ent, err := makeKeyEntry(data)
		if err != nil {
			return err
		}
		newKeys[ent.fingerprint] = ent
	}

	if len(newKeys) == 0 {
		return fmt.Errorf("no valid 32-byte KEK files found in %s", ks.dir)
	}

	ks.keys = newKeys
	// If active is not set or removed, default to first sorted fingerprint
	if _, ok := ks.keys[ks.active]; !ok {
		fps := make([]string, 0, len(ks.keys))
		for fp := range ks.keys {
			fps = append(fps, fp)
		}
		sort.Strings(fps)
		ks.active = fps[0]
	}
	return nil
}

// SetActive sets the active KEK version used for Wrap
func (ks *FileKeySource) SetActive(fingerprint string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, ok := ks.keys[fingerprint]; !ok {
		return fmt.Errorf("KEK fingerprint %s not found", fingerprint)
	}
	ks.active = fingerprint
	return nil
}

// Wrap encrypts a DEK under the active KEK version using AES-256-GCM
func (ks *FileKeySource) Wrap(ctx context.Context, dek, aad []byte) ([]byte, string, error) {
	ks.mu.RLock()
	activeFP := ks.active
	ent, ok := ks.keys[activeFP]
	ks.mu.RUnlock()

	if !ok {
		return nil, "", errors.New("no active KEK found")
	}

	block, err := aes.NewCipher(ent.wrapKey)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", err
	}

	sealed := gcm.Seal(nonce, nonce, dek, aad)
	return sealed, activeFP, nil
}

// Unwrap decrypts a wrapped DEK using specified KEK version
func (ks *FileKeySource) Unwrap(ctx context.Context, wrapped, aad []byte, kekRef string) ([]byte, error) {
	ks.mu.RLock()
	ent, ok := ks.keys[kekRef]
	ks.mu.RUnlock()

	if !ok {
		// Attempt reload once in case a new KEK was added to disk
		if err := ks.Reload(); err == nil {
			ks.mu.RLock()
			ent, ok = ks.keys[kekRef]
			ks.mu.RUnlock()
		}
		if !ok {
			return nil, fmt.Errorf("KEK version %q not found or expired: %w", kekRef, ports.ErrUnknownKEK)
		}
	}

	block, err := aes.NewCipher(ent.wrapKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(wrapped) < nonceSize+gcm.Overhead() {
		return nil, errors.New("invalid wrapped DEK length")
	}

	nonce := wrapped[:nonceSize]
	ciphertext := wrapped[nonceSize:]

	dek, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("DEK unwrap failed (tampered or wrong key/AAD)")
	}
	return dek, nil
}

// ControlMAC authenticates a tenant control-log event under the active KEK:
// HMAC-SHA256(ControlMAC(mac_kek), "sendora-control-mac-v1\x00" ‖ tenant_id ‖ "\x00" ‖ msg)
func (ks *FileKeySource) ControlMAC(ctx context.Context, tenantID string, msg []byte) ([]byte, error) {
	ks.mu.RLock()
	active := ks.active
	ks.mu.RUnlock()
	return ks.ControlMACWith(ctx, active, tenantID, msg)
}

// ControlMACWith is ControlMAC under the KEK version kekRef.
func (ks *FileKeySource) ControlMACWith(ctx context.Context, kekRef, tenantID string, msg []byte) ([]byte, error) {
	ks.mu.RLock()
	ent, ok := ks.keys[kekRef]
	ks.mu.RUnlock()
	if !ok {
		if err := ks.Reload(); err == nil {
			ks.mu.RLock()
			ent, ok = ks.keys[kekRef]
			ks.mu.RUnlock()
		}
		if !ok {
			return nil, fmt.Errorf("%w: %q", ports.ErrKEKUnavailable, kekRef)
		}
	}
	mac := hmac.New(sha256.New, ent.macKey)
	mac.Write([]byte("sendora-control-mac-v1\x00"))
	mac.Write([]byte(tenantID))
	mac.Write([]byte("\x00"))
	mac.Write(msg)
	return mac.Sum(nil), nil
}

// KEKFingerprints lists the fingerprints of all usable KEK versions, active first
func (ks *FileKeySource) KEKFingerprints(ctx context.Context) ([]string, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	res := make([]string, 0, len(ks.keys))
	if ks.active != "" {
		res = append(res, ks.active)
	}
	for fp := range ks.keys {
		if fp != ks.active {
			res = append(res, fp)
		}
	}
	return res, nil
}

var _ ports.KeySource = (*FileKeySource)(nil)

// AddNamed adds a KEK under the reference ref (the kek_ref recorded with its
// wraps), for example "tenant:<fingerprint>". Unlike a directory key, its
// reference is not its plain fingerprint, so one source can hold the
// platform's KEK and a tenant-supplied one side by side (D44). It does not
// change the active KEK unless active is set.
func (ks *FileKeySource) AddNamed(ref string, rawKey []byte, active bool) error {
	if ref == "" {
		return errors.New("KEK reference required")
	}
	ent, err := makeKeyEntry(rawKey)
	if err != nil {
		return err
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.keys == nil {
		ks.keys = make(map[string]keyEntry)
	}
	ks.keys[ref] = ent
	if active || ks.active == "" {
		ks.active = ref
	}
	return nil
}

// Has reports whether the source holds the KEK referenced by ref.
func (ks *FileKeySource) Has(ref string) bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	_, ok := ks.keys[ref]
	return ok
}

// WrapWith wraps dek under the KEK referenced by ref instead of the active
// one (hand-over of wraps from one KEK to another).
func (ks *FileKeySource) WrapWith(ctx context.Context, dek, aad []byte, ref string) ([]byte, error) {
	ks.mu.RLock()
	ent, ok := ks.keys[ref]
	ks.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("KEK %q not available", ref)
	}
	return sealWith(ent, dek, aad)
}

func sealWith(ent keyEntry, dek, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(ent.wrapKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek, aad), nil
}
