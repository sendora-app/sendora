// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnlite

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
)

// authenticatorData flag bits.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
	flagED = 0x80
)

const (
	maxClientDataJSON = 8 << 10
	maxAuthData       = 60 << 10
	maxCredIDLen      = 1023
	minChallengeLen   = 16
)

// Credential is a stored passkey / security key. PublicKey is the COSE_Key
// exactly as received at registration.
type Credential struct {
	ID        []byte
	PublicKey []byte
	Alg       int
	SignCount uint32
	AAGUID    []byte
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin *bool  `json:"crossOrigin"`
}

func checkClientData(rp RP, challenge []byte, wantType string, raw []byte) error {
	if rp.ID == "" || rp.Origin == "" {
		return wrap(ErrBadRPID, "relying party not configured")
	}
	if len(raw) == 0 || len(raw) > maxClientDataJSON {
		return wrap(ErrMalformed, "clientDataJSON size")
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return wrap(ErrMalformed, "clientDataJSON is not valid JSON")
	}
	if cd.Type != wantType {
		return wrap(ErrBadType, "got %q", cd.Type)
	}
	if len(challenge) < minChallengeLen {
		return wrap(ErrBadChallenge, "expected challenge missing")
	}
	got, err := DecodeBase64URL(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return ErrBadChallenge
	}
	if cd.Origin != rp.Origin {
		return wrap(ErrBadOrigin, "got %q", cd.Origin)
	}
	if cd.CrossOrigin != nil && *cd.CrossOrigin {
		return wrap(ErrBadOrigin, "cross-origin ceremony")
	}
	return nil
}

type authData struct {
	RPIDHash  [32]byte
	Flags     byte
	Counter   uint32
	AAGUID    []byte
	CredID    []byte
	COSERaw   []byte
	Extension map[any]any
}

// parseAuthData parses authenticatorData strictly: the byte layout must be
// consumed exactly. wantAT selects registration (attested credential data
// required) versus assertion (must be absent).
func parseAuthData(b []byte, wantAT bool) (*authData, error) {
	if len(b) < 37 || len(b) > maxAuthData {
		return nil, wrap(ErrMalformed, "authenticatorData length")
	}
	ad := &authData{Flags: b[32], Counter: binary.BigEndian.Uint32(b[33:37])}
	copy(ad.RPIDHash[:], b[:32])
	if ad.Flags&flagBS != 0 && ad.Flags&flagBE == 0 {
		return nil, wrap(ErrMalformed, "backup state without backup eligibility")
	}
	hasAT := ad.Flags&flagAT != 0
	if hasAT != wantAT {
		return nil, wrap(ErrMalformed, "attested credential data flag mismatch")
	}
	rest := b[37:]
	if hasAT {
		if len(rest) < 18 {
			return nil, wrap(ErrMalformed, "truncated attested credential data")
		}
		ad.AAGUID = append([]byte(nil), rest[:16]...)
		idLen := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if idLen == 0 || idLen > maxCredIDLen {
			return nil, wrap(ErrMalformed, "credential id length %d", idLen)
		}
		if len(rest) < idLen {
			return nil, wrap(ErrMalformed, "truncated credential id")
		}
		ad.CredID = append([]byte(nil), rest[:idLen]...)
		rest = rest[idLen:]
		_, n, err := decodeCBORPrefix(rest)
		if err != nil {
			return nil, err
		}
		ad.COSERaw = append([]byte(nil), rest[:n]...)
		rest = rest[n:]
	}
	if ad.Flags&flagED != 0 {
		v, n, err := decodeCBORPrefix(rest)
		if err != nil {
			return nil, err
		}
		m, ok := v.(map[any]any)
		if !ok || n != len(rest) {
			return nil, wrap(ErrMalformed, "extension data must be one CBOR map")
		}
		ad.Extension = m
		rest = nil
	}
	if len(rest) != 0 {
		return nil, wrap(ErrMalformed, "unexpected trailing authenticatorData bytes")
	}
	return ad, nil
}

func checkRPIDHash(rp RP, ad *authData) error {
	want := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(ad.RPIDHash[:], want[:]) != 1 {
		return ErrBadRPID
	}
	return nil
}

// VerifyRegistration verifies a registration ceremony response and returns the
// new credential. Attestation formats: "none"; and "packed" which is accepted
// as self attestation (signature checked with the credential key) or, when an
// x5c certificate chain is present, WITHOUT evaluating that chain: attestation
// trust is deliberately not evaluated, so the authenticator model is not
// established. Any other format is rejected.
func VerifyRegistration(rp RP, challenge, clientDataJSON, attestationObject []byte) (*Credential, error) {
	if err := checkClientData(rp, challenge, "webauthn.create", clientDataJSON); err != nil {
		return nil, err
	}
	v, err := decodeCBOR(attestationObject)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[any]any)
	if !ok || len(obj) != 3 {
		return nil, wrap(ErrMalformed, "attestation object must have fmt, attStmt and authData")
	}
	format, ok1 := mapString(obj, "fmt")
	stmt, ok2 := obj["attStmt"].(map[any]any)
	raw, ok3 := mapBytes(obj, "authData")
	if !ok1 || !ok2 || !ok3 {
		return nil, wrap(ErrMalformed, "attestation object fields")
	}
	ad, err := parseAuthData(raw, true)
	if err != nil {
		return nil, err
	}
	if err := checkRPIDHash(rp, ad); err != nil {
		return nil, err
	}
	if ad.Flags&flagUP == 0 {
		return nil, ErrUserPresence
	}
	key, err := parseCOSEKey(ad.COSERaw)
	if err != nil {
		return nil, err
	}
	if err := checkAttestation(format, stmt, key, raw, clientDataJSON); err != nil {
		return nil, err
	}
	return &Credential{
		ID:        ad.CredID,
		PublicKey: ad.COSERaw,
		Alg:       key.Alg,
		SignCount: ad.Counter,
		AAGUID:    ad.AAGUID,
	}, nil
}

func checkAttestation(format string, stmt map[any]any, key *coseKey, authData, clientDataJSON []byte) error {
	switch format {
	case "none":
		if len(stmt) != 0 {
			return wrap(ErrMalformed, "attestation \"none\" with a statement")
		}
		return nil
	case "packed":
		alg, okAlg := mapInt(stmt, "alg")
		sig, okSig := mapBytes(stmt, "sig")
		if !okAlg || !okSig {
			return wrap(ErrMalformed, "packed attestation needs alg and sig")
		}
		for k := range stmt {
			if k != "alg" && k != "sig" && k != "x5c" {
				return wrap(ErrUnsupported, "packed attestation field")
			}
		}
		if chain, present := stmt["x5c"]; present {
			certs, ok := chain.([]any)
			if !ok || len(certs) == 0 || len(certs) > 8 {
				return wrap(ErrMalformed, "x5c must be a short array")
			}
			for _, c := range certs {
				b, ok := c.([]byte)
				if !ok || len(b) == 0 || len(b) > 4096 {
					return wrap(ErrMalformed, "x5c certificate")
				}
			}
			// Trust chain deliberately not evaluated (see VerifyRegistration).
			return nil
		}
		if int(alg) != key.Alg {
			return wrap(ErrUnsupported, "self attestation algorithm differs from the credential algorithm")
		}
		hash := sha256.Sum256(clientDataJSON)
		msg := append(append([]byte(nil), authData...), hash[:]...)
		return key.verify(msg, sig)
	}
	return wrap(ErrUnsupported, "attestation format %q", format)
}

// VerifyAssertion verifies an authentication ceremony response for a stored
// credential and returns the new signature counter to persist. If the counter
// did not increase (and either value is non-zero) it returns the new counter
// together with ErrCounterRegression: treat it as a cloned authenticator.
func VerifyAssertion(rp RP, challenge []byte, cred Credential, clientDataJSON, authenticatorData, signature []byte) (uint32, error) {
	if err := checkClientData(rp, challenge, "webauthn.get", clientDataJSON); err != nil {
		return 0, err
	}
	ad, err := parseAuthData(authenticatorData, false)
	if err != nil {
		return 0, err
	}
	if err := checkRPIDHash(rp, ad); err != nil {
		return 0, err
	}
	if ad.Flags&flagUP == 0 {
		return 0, ErrUserPresence
	}
	key, err := parseCOSEKey(cred.PublicKey)
	if err != nil {
		return 0, err
	}
	if key.Alg != cred.Alg {
		return 0, wrap(ErrUnsupported, "credential algorithm does not match its key")
	}
	hash := sha256.Sum256(clientDataJSON)
	var msg bytes.Buffer
	msg.Write(authenticatorData)
	msg.Write(hash[:])
	if err := key.verify(msg.Bytes(), signature); err != nil {
		return 0, err
	}
	if !(cred.SignCount == 0 && ad.Counter == 0) && ad.Counter <= cred.SignCount {
		return ad.Counter, ErrCounterRegression
	}
	return ad.Counter, nil
}
