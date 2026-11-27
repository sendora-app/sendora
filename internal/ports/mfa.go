// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"errors"
	"time"
)

// ErrDuplicate is returned (possibly wrapped) by writes that would store a
// second record under a key that must be unique.
var ErrDuplicate = errors.New("duplicate")

// WebAuthnKey is a WebAuthn credential as the assertion check needs it.
type WebAuthnKey struct {
	RowID     int64
	CredID    []byte
	PublicKey []byte
	Alg       int
	SignCount int64
}

// WebAuthnInfo is a WebAuthn credential as the account's factor list shows
// it. LastUsedAt is nil when the credential was never used.
type WebAuthnInfo struct {
	RowID      int64
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// MFARepository covers second factors (one TOTP authenticator per account,
// recovery codes, WebAuthn credentials) and their reset requests. Writes on
// missing rows are no-ops; counts of affected rows are 0 then.
type MFARepository interface {
	// CountConfirmedTOTP counts the account's confirmed authenticators (0/1).
	CountConfirmedTOTP(ctx context.Context, userID int64) (int, error)
	// CountWebAuthn counts the account's WebAuthn credentials.
	CountWebAuthn(ctx context.Context, userID int64) (int, error)
	// CountUnusedRecoveryCodes counts the account's recovery codes that were
	// not used yet.
	CountUnusedRecoveryCodes(ctx context.Context, userID int64) (int, error)

	// ConfirmedTOTP returns the secret and last accepted time step of the
	// account's confirmed authenticator; ErrNotFound when there is none.
	ConfirmedTOTP(ctx context.Context, userID int64) (secret string, lastCounter int64, err error)
	// TOTP returns the secret of the account's authenticator and whether it
	// is confirmed; ErrNotFound when there is none.
	TOTP(ctx context.Context, userID int64) (secret string, confirmed bool, err error)
	// StartTOTP stores a new unconfirmed authenticator with the secret
	// (last time step 0, created now), replacing an existing one.
	StartTOTP(ctx context.Context, userID int64, secret string) error
	// ConfirmTOTP confirms the account's unconfirmed authenticator and
	// records counter as its last time step.
	ConfirmTOTP(ctx context.Context, userID int64, counter int64) (int64, error)
	// AdvanceTOTPCounter records counter as the last time step of the
	// account's confirmed authenticator, only while the stored one is lower
	// (so each time step is accepted once).
	AdvanceTOTPCounter(ctx context.Context, userID int64, counter int64) (int64, error)
	// DeleteTOTP removes the account's authenticator.
	DeleteTOTP(ctx context.Context, userID int64) error

	// AddRecoveryCode stores an unused recovery code (its hash) for the
	// account. A hash the account already has is an error.
	AddRecoveryCode(ctx context.Context, userID int64, codeHash string) error
	// UseRecoveryCode marks the account's unused code codeHash used at the
	// current time; it returns 1 when it did and 0 otherwise (unknown or
	// already used), so each code works once.
	UseRecoveryCode(ctx context.Context, userID int64, codeHash string) (int64, error)
	// DeleteRecoveryCodes removes all of the account's recovery codes.
	DeleteRecoveryCodes(ctx context.Context, userID int64) error

	// WebAuthnKeys returns the account's WebAuthn credentials in creation
	// (row id) order. Unreadable rows are skipped; an iteration error ends
	// the list without failing it.
	WebAuthnKeys(ctx context.Context, userID int64) ([]WebAuthnKey, error)
	// ListWebAuthn returns the account's WebAuthn credentials for display
	// in creation (row id) order, with the same row handling as WebAuthnKeys.
	ListWebAuthn(ctx context.Context, userID int64) ([]WebAuthnInfo, error)
	// AddWebAuthn stores a new credential (never used yet, created now).
	// A credential id that is already stored (for any account) fails with
	// ErrDuplicate.
	AddWebAuthn(ctx context.Context, userID int64, credID, publicKey []byte, alg int, signCount int64, name string) error
	// RenameWebAuthn renames the account's credential rowID.
	RenameWebAuthn(ctx context.Context, rowID, userID int64, name string) (int64, error)
	// WebAuthnOwner returns the account of credential rowID; ErrNotFound
	// when there is none.
	WebAuthnOwner(ctx context.Context, rowID int64) (int64, error)
	// DeleteWebAuthn removes the account's credential rowID.
	DeleteWebAuthn(ctx context.Context, rowID, userID int64) error
	// DeleteAllWebAuthn removes all of the account's credentials.
	DeleteAllWebAuthn(ctx context.Context, userID int64) error
	// RecordWebAuthnUse stores the new signature counter of the account's
	// WebAuthn credential rowID and sets its last use to the current time.
	RecordWebAuthnUse(ctx context.Context, rowID, userID int64, signCount int64) error

	// CreateResetRequest stores an unused MFA reset request hash for the
	// account, made by requestedBy and valid until expiresAt.
	CreateResetRequest(ctx context.Context, hash string, userID, requestedBy int64, expiresAt time.Time) error
	// UseResetRequest marks the reset request hash used if it is unused,
	// expires after now and belongs to a non-guest account with a verified,
	// non-empty address; it returns the account and the requester. It
	// fails with ErrNotFound otherwise, so a request works once. Inside a
	// transaction it takes the write lock.
	UseResetRequest(ctx context.Context, hash string, now time.Time) (userID, requestedBy int64, err error)
	// DeleteResetRequest removes one reset request.
	DeleteResetRequest(ctx context.Context, hash string) error
	// DeleteResetRequestsForUser removes the account's MFA reset requests.
	DeleteResetRequestsForUser(ctx context.Context, userID int64) error
}
