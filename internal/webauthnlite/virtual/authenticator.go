// SPDX-License-Identifier: AGPL-3.0-or-later

package virtual

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
)

// COSE algorithm ids (duplicated on purpose to stay independent).
const (
	ES256 = -7
	EdDSA = -8
	RS256 = -257
)

// Authenticator is a software authenticator holding one credential.
type Authenticator struct {
	Alg     int
	CredID  []byte
	Counter uint32 // value last returned; Assert increments before use
	AAGUID  [16]byte
	// LastAuthData is the authenticatorData of the most recent Register/Assert
	// call, before any Tamper* option, for independent parsing in tests.
	LastAuthData []byte
	signer       crypto.Signer
}

// Clone returns an authenticator with the same key but a fresh credential id,
// counter and AAGUID. It lets tests share one slow RSA key.
func (a *Authenticator) Clone() *Authenticator {
	c := &Authenticator{Alg: a.Alg, CredID: randBytes(32), signer: a.signer}
	copy(c.AAGUID[:], randBytes(16))
	return c
}

// New creates an authenticator with a fresh key of the given COSE algorithm.
// RS256 generates a 2048-bit key, which takes a moment.
func New(alg int) (*Authenticator, error) {
	a := &Authenticator{Alg: alg, CredID: randBytes(32)}
	copy(a.AAGUID[:], randBytes(16))
	var err error
	switch alg {
	case ES256:
		a.signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EdDSA:
		_, a.signer, err = ed25519.GenerateKey(rand.Reader)
	case RS256:
		a.signer, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		err = fmt.Errorf("virtual: unsupported alg %d", alg)
	}
	return a, err
}

// NewWithRSABits is like New(RS256) with a chosen modulus size (for negative
// tests with weak keys).
func NewWithRSABits(bits int) (*Authenticator, error) {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{Alg: RS256, CredID: randBytes(32), signer: k}
	copy(a.AAGUID[:], randBytes(16))
	return a, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// COSEKey returns the credential public key as an encoded COSE_Key.
func (a *Authenticator) COSEKey() []byte {
	switch k := a.signer.Public().(type) {
	case *ecdsa.PublicKey:
		pt, err := k.Bytes()
		if err != nil {
			panic(err)
		}
		return Encode(map[any]any{1: 2, 3: ES256, -1: 1, -2: pt[1:33], -3: pt[33:65]})
	case ed25519.PublicKey:
		return Encode(map[any]any{1: 1, 3: EdDSA, -1: 6, -2: []byte(k)})
	case *rsa.PublicKey:
		e := new(big.Int).SetInt64(int64(k.E)).Bytes()
		return Encode(map[any]any{1: 3, 3: RS256, -1: k.N.Bytes(), -2: e})
	}
	panic("virtual: unknown key type")
}

// PublicKey exposes the raw public key so tests can cross-check signatures
// with the standard library directly.
func (a *Authenticator) PublicKey() crypto.PublicKey { return a.signer.Public() }

// Options switches ceremony behaviour for positive and negative tests. The
// zero value produces a correct response.
type Options struct {
	Type        string  // clientData type override
	Origin      string  // clientData origin override
	RPID        string  // rpId hashed into authenticatorData (override)
	Challenge   []byte  // challenge placed in clientData (override)
	CrossOrigin bool    // clientData crossOrigin=true
	NoUP        bool    // clear the user-present flag
	UV          bool    // set the user-verified flag
	ExtraFlags  byte    // OR-ed into the flags byte (e.g. 0x10 BS, 0x40 AT)
	Counter     *uint32 // override the counter written into authenticatorData
	Extensions  []byte  // raw CBOR map; sets the ED flag
	Trailing    []byte  // raw bytes appended to authenticatorData (flag unchanged)

	Attestation string // registration: "none" (default), "packed-self", "packed-x5c", "fido-u2f"
	CredIDLen   int    // registration: credential id length override (0 keeps 32; use -1 for an empty id)

	TamperSignature  bool // flip a bit in the signature after signing
	TamperClientData bool // modify clientDataJSON after signing
	TamperAuthData   bool // flip a bit in authenticatorData after signing
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func clientDataJSON(typ, origin string, challenge []byte, cross bool) []byte {
	m := map[string]any{"type": typ, "challenge": b64u(challenge), "origin": origin, "crossOrigin": cross}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func (a *Authenticator) sign(msg []byte) []byte {
	var sig []byte
	var err error
	switch a.Alg {
	case ES256:
		h := sha256.Sum256(msg)
		sig, err = ecdsa.SignASN1(rand.Reader, a.signer.(*ecdsa.PrivateKey), h[:])
	case EdDSA:
		sig = ed25519.Sign(a.signer.(ed25519.PrivateKey), msg)
	case RS256:
		h := sha256.Sum256(msg)
		sig, err = rsa.SignPKCS1v15(rand.Reader, a.signer.(*rsa.PrivateKey), crypto.SHA256, h[:])
	}
	if err != nil {
		panic(err)
	}
	return sig
}

func flags(o Options, attested bool) byte {
	var f byte
	if !o.NoUP {
		f |= 0x01
	}
	if o.UV {
		f |= 0x04
	}
	if attested {
		f |= 0x40
	}
	if len(o.Extensions) > 0 {
		f |= 0x80
	}
	return f | o.ExtraFlags
}

func authDataHead(rpID string, f byte, counter uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, f)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], counter)
	return append(out, c[:]...)
}

func pick(override, dflt string) string {
	if override != "" {
		return override
	}
	return dflt
}

// Register produces a registration response for the given relying party and
// challenge: clientDataJSON and the CBOR attestationObject.
func (a *Authenticator) Register(rpID, origin string, challenge []byte, o Options) (clientData, attestationObject []byte) {
	cid := a.CredID
	switch {
	case o.CredIDLen < 0:
		cid = nil
	case o.CredIDLen > 0:
		cid = randBytes(o.CredIDLen)
	}
	counter := a.Counter
	if o.Counter != nil {
		counter = *o.Counter
	}
	ad := authDataHead(pick(o.RPID, rpID), flags(o, true), counter)
	ad = append(ad, a.AAGUID[:]...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(cid)))
	ad = append(ad, l[:]...)
	ad = append(ad, cid...)
	ad = append(ad, a.COSEKey()...)
	ad = append(ad, o.Extensions...)
	ad = append(ad, o.Trailing...)
	a.LastAuthData = append([]byte(nil), ad...)

	ch := o.Challenge
	if ch == nil {
		ch = challenge
	}
	cd := clientDataJSON(pick(o.Type, "webauthn.create"), pick(o.Origin, origin), ch, o.CrossOrigin)

	hash := sha256.Sum256(cd)
	format, stmt := "none", map[any]any{}
	switch o.Attestation {
	case "packed-self":
		format, stmt = "packed", map[any]any{"alg": a.Alg, "sig": a.sign(append(append([]byte(nil), ad...), hash[:]...))}
	case "packed-x5c":
		format, stmt = "packed", map[any]any{"alg": a.Alg, "sig": randBytes(70), "x5c": []any{randBytes(300)}}
	case "fido-u2f":
		format, stmt = "fido-u2f", map[any]any{"sig": randBytes(70), "x5c": []any{randBytes(300)}}
	}
	if o.TamperSignature {
		if s, ok := stmt["sig"].([]byte); ok {
			s[len(s)-1] ^= 1
		}
	}
	if o.TamperClientData {
		cd = append(cd, ' ')
	}
	if o.TamperAuthData {
		ad[len(ad)-1] ^= 1
	}
	obj := Encode(map[any]any{"fmt": format, "attStmt": stmt, "authData": ad})
	return cd, obj
}

// Assert produces an authentication response. Unless o.Counter is set the
// authenticator's counter is incremented first (a real authenticator does this).
func (a *Authenticator) Assert(rpID, origin string, challenge []byte, o Options) (clientData, authenticatorData, signature []byte) {
	if o.Counter != nil {
		a.Counter = *o.Counter
	} else {
		a.Counter++
	}
	ad := authDataHead(pick(o.RPID, rpID), flags(o, false), a.Counter)
	ad = append(ad, o.Extensions...)
	ad = append(ad, o.Trailing...)
	a.LastAuthData = append([]byte(nil), ad...)

	ch := o.Challenge
	if ch == nil {
		ch = challenge
	}
	cd := clientDataJSON(pick(o.Type, "webauthn.get"), pick(o.Origin, origin), ch, o.CrossOrigin)

	hash := sha256.Sum256(cd)
	sig := a.sign(append(append([]byte(nil), ad...), hash[:]...))
	if o.TamperSignature {
		sig[len(sig)-1] ^= 1
	}
	if o.TamperClientData {
		cd = append(cd, ' ')
	}
	if o.TamperAuthData {
		ad[len(ad)-1] ^= 1
	}
	return cd, ad, sig
}
