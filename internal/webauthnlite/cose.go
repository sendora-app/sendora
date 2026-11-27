// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnlite

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
)

// COSE_Key labels (RFC 9052/9053).
const (
	coseKty = 1
	coseAlg = 3
	coseCrv = -1 // EC2/OKP curve, RSA modulus n
	coseX   = -2 // EC2/OKP x, RSA exponent e
	coseY   = -3 // EC2 y
)

const (
	minRSABits = 2048
	maxRSABits = 8192
	minRSAExp  = 65537
	maxRSAExp  = 1<<31 - 1
)

// coseKey is a parsed, validated credential public key.
type coseKey struct {
	Alg int
	pub crypto.PublicKey // *ecdsa.PublicKey, ed25519.PublicKey or *rsa.PublicKey
}

// parseCOSEKey strictly parses one COSE_Key map that must span all of raw.
func parseCOSEKey(raw []byte) (*coseKey, error) {
	v, err := decodeCBOR(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, wrap(ErrMalformed, "COSE key is not a map")
	}
	alg, ok := mapInt(m, int64(coseAlg))
	if !ok {
		return nil, wrap(ErrMalformed, "COSE key without algorithm")
	}
	kty, ok := mapInt(m, int64(coseKty))
	if !ok {
		return nil, wrap(ErrMalformed, "COSE key without key type")
	}
	switch alg {
	case AlgES256:
		return parseES256(m, kty)
	case AlgEdDSA:
		return parseEdDSA(m, kty)
	case AlgRS256:
		return parseRS256(m, kty)
	}
	return nil, wrap(ErrUnsupported, "COSE algorithm %d", alg)
}

func parseES256(m map[any]any, kty int64) (*coseKey, error) {
	if kty != 2 {
		return nil, wrap(ErrMalformed, "ES256 key with key type %d", kty)
	}
	crv, ok := mapInt(m, int64(coseCrv))
	if !ok {
		return nil, wrap(ErrMalformed, "EC key without curve")
	}
	if crv != 1 {
		return nil, wrap(ErrUnsupported, "EC curve %d (only P-256)", crv)
	}
	x, okx := mapBytes(m, int64(coseX))
	y, oky := mapBytes(m, int64(coseY))
	if !okx || !oky || len(x) != 32 || len(y) != 32 {
		return nil, wrap(ErrMalformed, "EC coordinates must be 32 bytes")
	}
	point := make([]byte, 0, 65)
	point = append(point, 4)
	point = append(point, x...)
	point = append(point, y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, wrap(ErrMalformed, "EC point is not on the P-256 curve")
	}
	return &coseKey{Alg: AlgES256, pub: pub}, nil
}

func parseEdDSA(m map[any]any, kty int64) (*coseKey, error) {
	if kty != 1 {
		return nil, wrap(ErrMalformed, "EdDSA key with key type %d", kty)
	}
	crv, ok := mapInt(m, int64(coseCrv))
	if !ok {
		return nil, wrap(ErrMalformed, "OKP key without curve")
	}
	if crv != 6 {
		return nil, wrap(ErrUnsupported, "OKP curve %d (only Ed25519)", crv)
	}
	x, ok := mapBytes(m, int64(coseX))
	if !ok || len(x) != ed25519.PublicKeySize {
		return nil, wrap(ErrMalformed, "Ed25519 key must be 32 bytes")
	}
	return &coseKey{Alg: AlgEdDSA, pub: ed25519.PublicKey(append([]byte(nil), x...))}, nil
}

func parseRS256(m map[any]any, kty int64) (*coseKey, error) {
	if kty != 3 {
		return nil, wrap(ErrMalformed, "RS256 key with key type %d", kty)
	}
	nb, okn := mapBytes(m, int64(coseCrv))
	eb, oke := mapBytes(m, int64(coseX))
	if !okn || !oke || len(nb) == 0 || len(eb) == 0 || len(eb) > 4 {
		return nil, wrap(ErrMalformed, "RSA key needs modulus and a short exponent")
	}
	n := new(big.Int).SetBytes(nb)
	if n.BitLen() > maxRSABits || n.Bit(0) == 0 {
		return nil, wrap(ErrMalformed, "RSA modulus is invalid")
	}
	if n.BitLen() < minRSABits {
		return nil, wrap(ErrUnsupported, "RSA modulus below %d bits", minRSABits)
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < minRSAExp || e.Int64() > maxRSAExp || e.Bit(0) == 0 {
		return nil, wrap(ErrUnsupported, "RSA exponent out of range")
	}
	return &coseKey{Alg: AlgRS256, pub: &rsa.PublicKey{N: n, E: int(e.Int64())}}, nil
}

// verify checks sig over msg (authenticatorData || clientDataHash).
func (k *coseKey) verify(msg, sig []byte) error {
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		if ecdsa.VerifyASN1(pub, h[:], sig) {
			return nil
		}
	case ed25519.PublicKey:
		if len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, msg, sig) {
			return nil
		}
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil {
			return nil
		}
	}
	return ErrBadSignature
}
