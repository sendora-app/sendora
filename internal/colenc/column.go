// SPDX-License-Identifier: AGPL-3.0-or-later

package colenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// DESIGN §6.5:
// Stored value: 0x01 ‖ key_version (u32 BE) ‖ nonce (12) ‖ ciphertext ‖ tag (16)
// AAD = length-prefixed canonical encoding:
//   "sendora-col-v1", format byte (0x01), key_id (16 bytes UUID), key_version (u32 BE), table, column, row_id (string)

const (
	FormatVersion1 = 0x01
	NonceSize      = 12
	TagSize        = 16
	HeaderSize     = 1 + 4 + NonceSize // 1 + 4 + 12 = 17 bytes
	MinCipherSize  = HeaderSize + TagSize
)

var (
	ErrInvalidCiphertext = errors.New("invalid column ciphertext")
	ErrDecryptionFailed  = errors.New("column decryption failed (tampered or wrong key)")
	ErrUnsupportedFormat = errors.New("unsupported column encryption format")
)

// CanonicalAAD builds the length-prefixed AAD for column encryption
func CanonicalAAD(keyID [16]byte, keyVersion uint32, table, column, rowID string) []byte {
	// Length-prefixed encoding:
	// items: ["sendora-col-v1", format (0x01), key_id, key_version_bytes, table, column, rowID]
	var verBytes [4]byte
	binary.BigEndian.PutUint32(verBytes[:], keyVersion)

	items := [][]byte{
		[]byte("sendora-col-v1"),
		{FormatVersion1},
		keyID[:],
		verBytes[:],
		[]byte(table),
		[]byte(column),
		[]byte(rowID),
	}

	totalLen := 0
	for _, it := range items {
		totalLen += binary.MaxVarintLen64 + len(it)
	}

	buf := make([]byte, 0, totalLen)
	var vbuf [binary.MaxVarintLen64]byte
	for _, it := range items {
		n := binary.PutUvarint(vbuf[:], uint64(len(it)))
		buf = append(buf, vbuf[:n]...)
		buf = append(buf, it...)
	}
	return buf
}

// Encrypt encrypts plaintext using AES-256-GCM according to DESIGN §6.5
func Encrypt(key []byte, keyID [16]byte, keyVersion uint32, table, column, rowID string, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("reading random nonce: %w", err)
	}

	aad := CanonicalAAD(keyID, keyVersion, table, column, rowID)

	// Result buffer: 1 (format) + 4 (version) + 12 (nonce) + ciphertext + 16 (tag)
	res := make([]byte, HeaderSize, HeaderSize+len(plaintext)+TagSize)
	res[0] = FormatVersion1
	binary.BigEndian.PutUint32(res[1:5], keyVersion)
	copy(res[5:HeaderSize], nonce)

	ciphertext := gcm.Seal(res, nonce, plaintext, aad)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM according to DESIGN §6.5
func Decrypt(key []byte, keyID [16]byte, table, column, rowID string, ciphertext []byte) ([]byte, uint32, error) {
	if len(ciphertext) < MinCipherSize {
		return nil, 0, ErrInvalidCiphertext
	}
	if ciphertext[0] != FormatVersion1 {
		return nil, 0, ErrUnsupportedFormat
	}

	keyVersion := binary.BigEndian.Uint32(ciphertext[1:5])
	nonce := ciphertext[5:HeaderSize]
	rawCiphertext := ciphertext[HeaderSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}

	aad := CanonicalAAD(keyID, keyVersion, table, column, rowID)

	plaintext, err := gcm.Open(nil, nonce, rawCiphertext, aad)
	if err != nil {
		return nil, 0, ErrDecryptionFailed
	}
	return plaintext, keyVersion, nil
}

// textPrefix marks an encrypted column value stored as text.
const textPrefix = "e1:"

// EncodeText renders a column ciphertext for a TEXT column.
func EncodeText(ciphertext []byte) string {
	return textPrefix + base64.RawURLEncoding.EncodeToString(ciphertext)
}

// DecodeText is the inverse of EncodeText; ok is false for a value that is not
// an encoded ciphertext (plaintext, empty, or a different prefix).
func DecodeText(s string) (ciphertext []byte, ok bool) {
	rest, found := strings.CutPrefix(s, textPrefix)
	if !found {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return nil, false
	}
	return b, true
}

// VersionPrefixLen is how many characters after the "e1:" prefix of a stored
// value carry the key version (format byte, version and the first nonce byte).
const VersionPrefixLen = 8

// TextVersion returns the key version of a stored encrypted value (ok false
// for a value that is not one). It reads only the first VersionPrefixLen
// characters after the prefix, so SQL can group by SUBSTR(col, 4, 8) and
// decode the groups with VersionOfPrefix instead of reading every value.
func TextVersion(s string) (version int, ok bool) {
	rest, found := strings.CutPrefix(s, textPrefix)
	if !found || len(rest) < VersionPrefixLen {
		return 0, false
	}
	return VersionOfPrefix(rest[:VersionPrefixLen])
}

// VersionOfPrefix decodes the key version from the VersionPrefixLen characters
// that follow the "e1:" prefix.
func VersionOfPrefix(p string) (int, bool) {
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || len(b) < 5 || b[0] != 0x01 {
		return 0, false
	}
	return int(binary.BigEndian.Uint32(b[1:5])), true
}
