// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"time"
)

// IdempotencyState is the result of IdempotencyRepository.Claim.
type IdempotencyState int

const (
	// IdempotencyNew: the caller holds the claim and runs the request.
	IdempotencyNew IdempotencyState = iota
	// IdempotencyInProgress: another request with this key holds a live claim.
	IdempotencyInProgress
	// IdempotencyDone: the request ran; Status and Response are stored.
	IdempotencyDone
	// IdempotencyMismatch: the key was used for a different request.
	IdempotencyMismatch
)

// IdempotencyClaim is what Claim found or did.
type IdempotencyClaim struct {
	State    IdempotencyState
	Status   int    // IdempotencyDone: stored HTTP status
	Response []byte // IdempotencyDone: stored (encrypted) response
}

// IdempotencyRepository stores idempotency keys of mutating requests (design
// 4.1, D29), keyed by (scope, key hash). Keys, request hashes and responses
// arrive hashed and encrypted by core; the adapter stores bytes and strings.
type IdempotencyRepository interface {
	// Claim records the key for requestHash as in progress until leaseUntil
	// when it is unknown (IdempotencyNew). A known key with another request
	// hash is IdempotencyMismatch; a completed one IdempotencyDone with its
	// response; an in-progress one IdempotencyInProgress while its lease
	// lasts, and is taken over (IdempotencyNew, new lease) once the lease
	// has expired at now. Concurrent claims of one key serialise: exactly
	// one gets IdempotencyNew. Call it inside a Tx and commit before acting.
	Claim(ctx context.Context, scope, keyHash, requestHash string, now, leaseUntil time.Time) (IdempotencyClaim, error)
	// Complete stores the response of a claimed key; a key that is not in
	// progress is left alone.
	Complete(ctx context.Context, scope, keyHash string, status int, response []byte) error
	// Release removes an in-progress key, so a retry runs the request again
	// (the request failed without effect). A completed key stays.
	Release(ctx context.Context, scope, keyHash string) error
	// MarkReplayed notes a replay of a completed key at now and returns the
	// rows changed (1, or 0 when the key is not completed). Its clean commit
	// is the replay barrier: it proves the stored row is replicated.
	MarkReplayed(ctx context.Context, scope, keyHash string, now time.Time) (int64, error)
	// Expire removes keys created before before and returns how many.
	Expire(ctx context.Context, before time.Time) (int64, error)
}
