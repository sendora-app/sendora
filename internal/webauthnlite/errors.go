// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webauthnlite is a small, dependency-free WebAuthn relying-party
// verifier (standard library only) for using passkeys / security keys as a
// second factor. It implements registration and assertion verification for
// ES256, EdDSA and RS256 credentials with attestation "none" (and "packed"
// without evaluating any attestation trust chain).
//
// Deliberate limitations: attestation trust is NOT evaluated (no metadata
// service, no certificate chain validation), so the package cannot tell which
// authenticator model was used. Discoverable-credential (usernameless) login is
// not implemented; use it as a second factor after another factor.
package webauthnlite

import (
	"errors"
	"fmt"
)

// Typed errors. Callers should map them to generic client messages and log the
// detail server-side; use errors.Is to test them.
var (
	ErrMalformed         = errors.New("webauthn: malformed data")
	ErrUnsupported       = errors.New("webauthn: unsupported feature")
	ErrBadType           = errors.New("webauthn: wrong client data type")
	ErrBadChallenge      = errors.New("webauthn: challenge mismatch")
	ErrBadOrigin         = errors.New("webauthn: origin mismatch")
	ErrBadRPID           = errors.New("webauthn: relying party id mismatch")
	ErrUserPresence      = errors.New("webauthn: user presence missing")
	ErrBadSignature      = errors.New("webauthn: signature verification failed")
	ErrCounterRegression = errors.New("webauthn: signature counter did not increase (possible cloned authenticator)")
)

// wrap adds detail to a typed error while keeping errors.Is working.
func wrap(base error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", base, fmt.Sprintf(format, args...))
}
