// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnlite

import "encoding/base64"

// COSE algorithm identifiers supported by this package.
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// b64 is base64url without padding, the encoding WebAuthn JSON helpers use.
var b64 = base64.RawURLEncoding

// Base64URL encodes bytes the way the browser helpers expect them.
func Base64URL(b []byte) string { return b64.EncodeToString(b) }

// DecodeBase64URL decodes unpadded base64url (strict).
func DecodeBase64URL(s string) ([]byte, error) { return b64.Strict().DecodeString(s) }

// UserEntity is the account a credential is registered for.
type UserEntity struct {
	ID          []byte
	Name        string
	DisplayName string
}

// PublicKeyCreationOptions is JSON-ready input for navigator.credentials
// .create({publicKey}); every binary value is base64url without padding and
// must be decoded by the client before use. (The type is not called
// CreationOptions because that name is the builder function.)
type PublicKeyCreationOptions struct {
	RP                     RPEntity               `json:"rp"`
	User                   UserJSON               `json:"user"`
	Challenge              string                 `json:"challenge"`
	PubKeyCredParams       []CredParam            `json:"pubKeyCredParams"`
	Timeout                int                    `json:"timeout"`
	ExcludeCredentials     []CredDescriptor       `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	Attestation            string                 `json:"attestation"`
}

// RPEntity is the relying party as the browser sees it.
type RPEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserJSON is UserEntity with the id base64url-encoded.
type UserJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// CredParam is one acceptable credential algorithm.
type CredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// CredDescriptor names an existing credential by its base64url id.
type CredDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// AuthenticatorSelection carries the authenticator requirements.
type AuthenticatorSelection struct {
	ResidentKey        string `json:"residentKey"`
	RequireResidentKey bool   `json:"requireResidentKey"`
	UserVerification   string `json:"userVerification"`
}

// PublicKeyRequestOptions is JSON-ready input for navigator.credentials
// .get({publicKey}).
type PublicKeyRequestOptions struct {
	Challenge        string           `json:"challenge"`
	RPID             string           `json:"rpId"`
	Timeout          int              `json:"timeout"`
	AllowCredentials []CredDescriptor `json:"allowCredentials"`
	UserVerification string           `json:"userVerification"`
}

const optionsTimeoutMS = 300000

func descriptors(ids [][]byte) []CredDescriptor {
	out := make([]CredDescriptor, 0, len(ids)) // never nil: JSON must be [] not null
	for _, id := range ids {
		out = append(out, CredDescriptor{Type: "public-key", ID: Base64URL(id)})
	}
	return out
}

// CreationOptions builds registration options: ES256, EdDSA and RS256,
// attestation "none", user verification and resident keys "preferred", and the
// already registered credential ids excluded.
func CreationOptions(rp RP, rpName string, user UserEntity, challenge []byte, exclude [][]byte) PublicKeyCreationOptions {
	return PublicKeyCreationOptions{
		RP:        RPEntity{ID: rp.ID, Name: rpName},
		User:      UserJSON{ID: Base64URL(user.ID), Name: user.Name, DisplayName: user.DisplayName},
		Challenge: Base64URL(challenge),
		PubKeyCredParams: []CredParam{
			{Type: "public-key", Alg: AlgES256},
			{Type: "public-key", Alg: AlgEdDSA},
			{Type: "public-key", Alg: AlgRS256},
		},
		Timeout:            optionsTimeoutMS,
		ExcludeCredentials: descriptors(exclude),
		AuthenticatorSelection: AuthenticatorSelection{
			ResidentKey: "preferred", RequireResidentKey: false, UserVerification: "preferred",
		},
		Attestation: "none",
	}
}

// RequestOptions builds assertion options limited to the allowed credentials.
func RequestOptions(rp RP, challenge []byte, allow [][]byte) PublicKeyRequestOptions {
	return PublicKeyRequestOptions{
		Challenge:        Base64URL(challenge),
		RPID:             rp.ID,
		Timeout:          optionsTimeoutMS,
		AllowCredentials: descriptors(allow),
		UserVerification: "preferred",
	}
}
