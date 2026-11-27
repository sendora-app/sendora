// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"time"
)

// NewRefreshToken is one refresh token of a session (refresh-token family).
// Hash is the SHA-256 hex of the token; SessionID stays the same across
// rotations.
type NewRefreshToken struct {
	Hash      string
	UserID    int64
	ExpiresAt time.Time
	IssuedAt  time.Time
	Started   time.Time
	SessionID string
	UserAgent string
	IP        string
	Method    string
}

// ConsumedRefreshToken is what a consumed (deleted) live refresh token
// carried. Fields are nil where the stored value was NULL (older rows).
type ConsumedRefreshToken struct {
	UserID    int64
	IssuedAt  *time.Time
	Started   *time.Time
	SessionID *string
	Method    *string
}

// RefreshSession is one live refresh token as the session list shows it.
type RefreshSession struct {
	SessionID string
	Started   *time.Time // nil for older rows
	IssuedAt  *time.Time // last rotation
	ExpiresAt time.Time
	UserAgent string
	IP        string
	Method    string
}

// SessionRepository keeps sessions: refresh tokens (table refresh_tokens),
// spent refresh tokens for reuse detection (refresh_spent) and revoked
// access tokens (revoked_access_tokens). "Live" means expires_at is after
// the given now. Counts of affected rows are 0 when nothing matched.
type SessionRepository interface {
	// StartGuarded stores t only while the account exists, is enabled and g
	// still holds; it returns the number of rows stored (0 or 1).
	StartGuarded(ctx context.Context, t NewRefreshToken, g CredentialGuard) (int64, error)
	// Insert stores t (rotation inside a transaction).
	Insert(ctx context.Context, t NewRefreshToken) error
	// ConsumeLive deletes the refresh token hash if it is live at now and
	// returns what it carried; ErrNotFound when there is none.
	ConsumeLive(ctx context.Context, hash string, now time.Time) (ConsumedRefreshToken, error)
	// Consume deletes the refresh token hash whether live or not and returns
	// its account; ErrNotFound when there is none.
	Consume(ctx context.Context, hash string) (int64, error)
	// FindSpent returns the account and spend time of a spent refresh token
	// whose record is still kept at now; ErrNotFound otherwise.
	FindSpent(ctx context.Context, hash string, now time.Time) (userID int64, spentAt time.Time, err error)
	// MarkSpent records hash as spent; an existing record is kept unchanged.
	MarkSpent(ctx context.Context, hash string, userID int64, spentAt, expiresAt time.Time) error
	// DeleteSpentForUser forgets the account's spent tokens.
	DeleteSpentForUser(ctx context.Context, userID int64) error
	// CountLive counts the live refresh tokens of session sid of the account.
	CountLive(ctx context.Context, sid string, userID int64, now time.Time) (int, error)
	// ListLive returns the account's live refresh tokens that carry a
	// session id, in no particular order.
	ListLive(ctx context.Context, userID int64, now time.Time) ([]RefreshSession, error)
	// RevokeAllForUser deletes every refresh token of the account.
	RevokeAllForUser(ctx context.Context, userID int64) (int64, error)
	// RevokeSession deletes the refresh tokens of one session of the account.
	RevokeSession(ctx context.Context, userID int64, sid string) (int64, error)
	// RevokeOtherSessions deletes the account's refresh tokens of every
	// session except keepSID (tokens without a session id included).
	RevokeOtherSessions(ctx context.Context, userID int64, keepSID string) (int64, error)
	// RevokeAccessToken records a revoked access token until expiresAt; an
	// existing record is kept unchanged.
	RevokeAccessToken(ctx context.Context, hash string, expiresAt time.Time) error
	// CountRevokedAccess counts records of the revoked access token hash
	// that are still kept at now (0 or 1).
	CountRevokedAccess(ctx context.Context, hash string, now time.Time) (int, error)
}

// PasswordResetRepository keeps one-time reset links (table password_resets).
// Kind is "reset" (the default) or "welcome" (an account's first password).
type PasswordResetRepository interface {
	// Identity returns the username and address of the account of a link
	// that is unexpired at now; ErrNotFound otherwise.
	Identity(ctx context.Context, hash string, now time.Time) (username, email string, err error)
	// CreateForVerified stores a reset link for the account only while its
	// address is still email with a verified address, and its password hash
	// is still the non-empty passwordHash. It returns the rows stored (0/1).
	CreateForVerified(ctx context.Context, hash string, userID int64, expiresAt time.Time, email, passwordHash string) (int64, error)
	// UserFor returns the account of a link that is unexpired at now;
	// ErrNotFound otherwise.
	UserFor(ctx context.Context, hash string, now time.Time) (int64, error)
	// Consume deletes the unexpired link hash of the account and returns the
	// account and the link kind; ErrNotFound when there is none.
	Consume(ctx context.Context, hash string, now time.Time, userID int64) (int64, string, error)
	// Delete removes one link.
	Delete(ctx context.Context, hash string) error
	// DeleteForUser removes every link of the account.
	DeleteForUser(ctx context.Context, userID int64) error
	// CreateReset stores a link of kind "reset" for the account.
	CreateReset(ctx context.Context, hash string, userID int64, expiresAt time.Time) error
	// DeleteResetsForUser removes the account's links of kind "reset".
	DeleteResetsForUser(ctx context.Context, userID int64) error
	// CreateWelcome stores a link of kind "welcome" for the account.
	CreateWelcome(ctx context.Context, hash string, userID int64, expiresAt time.Time) error
	// DeleteWelcomesForUser removes the account's links of kind "welcome".
	DeleteWelcomesForUser(ctx context.Context, userID int64) error
	// CountWelcomesForUser counts the account's links of kind "welcome",
	// expired ones included.
	CountWelcomesForUser(ctx context.Context, userID int64) (int, error)
}

// EmailVerificationRepository keeps email confirmation codes
// (email_verifications, one per account) and the attempt counters
// (verification_attempts).
type EmailVerificationRepository interface {
	// Put stores the account's code, replacing an earlier one.
	Put(ctx context.Context, userID int64, code string, expiresAt time.Time) error
	// FindByUniqueEmail returns the code of the unverified non-guest account
	// whose trimmed, lower-cased address is email, if no other account has
	// that address, and whether the account is a pending registration.
	// ErrNotFound when there is none.
	FindByUniqueEmail(ctx context.Context, email string) (userID int64, code string, expiresAt time.Time, pending bool, err error)
	// RecordAttempt counts one attempt for the account and returns the count
	// in the current window. A window that ended at or before now starts
	// again at 1 and lasts until newExpiry.
	RecordAttempt(ctx context.Context, userID int64, newExpiry, now time.Time) (int, error)
	// DeleteAttempts removes the account's attempt counter.
	DeleteAttempts(ctx context.Context, userID int64) error
	// DeleteForUser removes the account's code.
	DeleteForUser(ctx context.Context, userID int64) error
}

// PasswordHistoryRepository keeps former password hashes (password_history).
type PasswordHistoryRepository interface {
	// Recent returns up to n of the account's hashes, newest first.
	// Unreadable rows are skipped.
	Recent(ctx context.Context, userID int64, n int) ([]string, error)
	// Remember keeps the account's current hash (when it has one and keep>0)
	// as created at at, then prunes the history to the newest keep entries;
	// keep=0 empties it. Run it in the transaction that changes the
	// password, before the change.
	Remember(ctx context.Context, userID int64, keep int, at time.Time) error
}
