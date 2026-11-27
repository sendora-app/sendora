// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ports declares the interfaces core code needs from the outside world
// (docs/cluster/DESIGN.md section 2A.2, docs/adr/0003). Each flavour supplies
// adapters under internal/adapters: sqlite and inproc for the Community
// flavours, postgres, k8s and the key client for Cluster (later phases).
//
// Rules for this package: interfaces and plain data types only, no SQL, no
// imports of adapter packages. Contracts are pinned by internal/conformance; a
// method added here needs a conformance test there.
//
// Phase 1 grows the Store port one domain at a time as SQL moves out of
// internal/app, internal/store and internal/platform
// (docs/cluster/REPOSITORY-PATTERN.md).
package ports

import (
	"context"
	"errors"
	"time"
)

// Store is the database port: one repository per domain, plus transactions
// and commit-outcome classification (design 4.1). A Store is bound to one
// database: a tenant's (or the single-tenant installation's). The platform
// database of multi-tenant mode has its own port, PlatformStore; its audit
// chain is kept through a Store on that database (AuditChain only).
type Store interface {
	Repositories
	// Begin starts a write transaction. The repositories of the returned Tx
	// run inside it; nothing is visible to other sessions before Commit.
	// The transaction ends when ctx ends (callers that must not be cut short
	// pass context.Background()). Callers defer Rollback, which is a no-op
	// after Commit. Backends with one connection (SQLite) hold it for the
	// lifetime of the Tx: no other repository call may be made meanwhile.
	Begin(ctx context.Context) (Tx, error)
	// ReadSnapshot runs fn with repositories that all read one consistent
	// state of the database (a read transaction on a dedicated connection);
	// writes by others during fn are not seen. fn must not write.
	ReadSnapshot(ctx context.Context, fn func(Repositories) error) error
}

// Repositories is the set of domain repositories, available on the Store
// (each call autocommits) and on a Tx (calls join the transaction).
type Repositories interface {
	// AuditChain stores the hash-chained audit log.
	AuditChain() AuditChainRepository
	// AuditQuery reads the audit log for the API and exports.
	AuditQuery() AuditQueryRepository
	// System covers database health and a few installation-wide settings.
	System() SystemRepository
	// Settings covers the settings table.
	Settings() SettingsRepository
	// Themes covers UI themes.
	Themes() ThemeRepository
	// Stats answers the administrator dashboard.
	Stats() StatsRepository
	// Maintenance holds the periodic clean-up statements.
	Maintenance() MaintenanceRepository
	// PersonalData reads the personal data export.
	PersonalData() PersonalDataRepository
	// Mail covers email languages and template texts.
	Mail() MailRepository
	// UITranslations covers stored UI dictionaries.
	UITranslations() UITranslationRepository
	// ObjectStorage covers storage locations, queued remote deletions and
	// the file rows the storage migration moves.
	ObjectStorage() ObjectStorageRepository
	// StorageMigrations covers the records of storage migration runs.
	StorageMigrations() StorageMigrationRepository
	// IPBans persists address bans (the reference domain of phase 1).
	IPBans() IPBanRepository
	// Users are the accounts (table users).
	Users() UserRepository
	// Sessions are refresh-token families, spent refresh tokens and revoked
	// access tokens.
	Sessions() SessionRepository
	// PasswordResets are the one-time password reset and welcome links.
	PasswordResets() PasswordResetRepository
	// EmailVerifications are the email confirmation codes and attempt counters.
	EmailVerifications() EmailVerificationRepository
	// PasswordHistory keeps former password hashes for the reuse check.
	PasswordHistory() PasswordHistoryRepository
	// AuthProviders are the external sign-in providers and the accounts
	// linked to them.
	AuthProviders() AuthProviderRepository
	// ReverseInvites are upload invitations and their guest accounts.
	ReverseInvites() ReverseInviteRepository
	// MFA holds second factors (TOTP, recovery codes, WebAuthn) and their
	// reset requests.
	MFA() MFARepository
	// SignInHistory keeps fingerprints of recent sign-ins for the "new
	// sign-in" notification.
	SignInHistory() SignInHistoryRepository
	// Quota reads the inputs of storage accounting.
	Quota() QuotaRepository
	// Shares are the shares and their stored files.
	Shares() ShareRepository
	// Downloads are the recorded download starts of shares.
	Downloads() DownloadRepository
	// StorageLocations are the configured remote storage locations.
	StorageLocations() StorageLocationRepository
	// Uploads are the upload sessions and their declared files.
	Uploads() UploadRepository
	// DownloadMails is the outbox of download notification emails.
	DownloadMails() DownloadMailRepository
	// TenantLimits are the limits the platform sets for a tenant database
	// (multi-tenant mode).
	TenantLimits() TenantLimitRepository
	// Idempotency stores the idempotency keys of mutating requests.
	Idempotency() IdempotencyRepository
	// JobFences are the per-tenant fences of leased jobs (design 4.3).
	JobFences() JobFenceRepository
	// ControlLog stores the tenant control log (design 6.3).
	ControlLog() ControlLogRepository
	// Keyring stores the tenant's copy of wrapped DEKs (design 6.3).
	Keyring() KeyringRepository
	// ColumnKeys holds the tenant's key jobs and the online key rotation
	// operations (D43).
	ColumnKeys() ColumnKeyRepository
}

// Tx is a write transaction (see Store.Begin).
type Tx interface {
	Repositories
	// Commit makes the transaction's writes durable and classifies the
	// outcome (design 4.1, OutcomeOf): nil means committed; an error
	// wrapping ErrOutcomeUnknown means the writes may or may not survive
	// (PostgreSQL: any error returned by COMMIT, a connection lost or a
	// context ended after COMMIT was sent, or COMMIT answered with the
	// "canceling wait for synchronous replication" warning; SQLite: an I/O
	// error during COMMIT); any other error means nothing was written.
	// Idempotency keys and the claim-commit barrier that act on Unknown are
	// core work of a later step.
	Commit() error
	// Rollback discards the transaction; after Commit it does nothing and its
	// error can be ignored.
	Rollback() error
}

// ErrNotFound is returned (possibly wrapped) by repository methods that look
// up exactly one row when there is none.
var ErrNotFound = errors.New("not found")

// ErrReadInterrupted is returned (wrapped) by list methods whose contract
// says so when reading stopped after the listing had started: the rows
// returned so far are not the complete result.
var ErrReadInterrupted = errors.New("listing interrupted")

// CommitOutcome classifies how a write transaction ended (design 4.1).
type CommitOutcome int

const (
	// Committed: COMMIT returned cleanly; the write is durable.
	Committed CommitOutcome = iota
	// Failed: an error before COMMIT was sent; nothing was written.
	Failed
	// Unknown: COMMIT returned an error, the connection was lost after COMMIT
	// was sent, or (PostgreSQL) the sync-replication wait was cancelled. The
	// write may or may not survive; callers suppress side effects and retry
	// with the same idempotency key.
	Unknown
)

func (o CommitOutcome) String() string {
	switch o {
	case Committed:
		return "committed"
	case Failed:
		return "failed"
	case Unknown:
		return "unknown"
	}
	return "invalid"
}

// ErrOutcomeUnknown wraps errors whose CommitOutcome is Unknown.
var ErrOutcomeUnknown = errors.New("commit outcome unknown")

// OutcomeOf classifies the error returned by Tx.Commit (or PlatformTx.Commit):
// nil is Committed, an error wrapping ErrOutcomeUnknown is Unknown, any other
// error is Failed.
func OutcomeOf(commitErr error) CommitOutcome {
	switch {
	case commitErr == nil:
		return Committed
	case errors.Is(commitErr, ErrOutcomeUnknown):
		return Unknown
	}
	return Failed
}

// ErrTenantUserLimit is returned (wrapped, with the backend's message, which
// mentions "tenant user limit") when the tenant database refuses a new
// non-guest account because the platform's user limit is reached
// (TenantLimitRepository.Enable).
var ErrTenantUserLimit = errors.New("tenant user limit reached")

// ErrUnsupported is returned (wrapped) by a method whose contract allows a
// backend not to offer it (stated on the method).
var ErrUnsupported = errors.New("not supported by this backend")

// IPBan is one persisted address ban. Key is the grouped client address
// (IPv4 address or IPv6 /64, see internal/app/ipban.go). Times have
// one-second precision in every adapter.
type IPBan struct {
	Key        string
	Until      time.Time
	Strikes    int
	LastStrike time.Time
}

// IPBanRepository keeps address bans across restarts (table ip_bans). The
// counters that lead to a ban stay in the RateLimiter.
type IPBanRepository interface {
	// List returns every stored ban, in no particular order. Rows that cannot
	// be read are skipped (a damaged row must not lift the other bans).
	List(ctx context.Context) ([]IPBan, error)
	// Put inserts or replaces the ban for b.Key.
	Put(ctx context.Context, b IPBan) error
	// Delete removes the ban for key; a missing key is not an error.
	Delete(ctx context.Context, key string) error
	// Prune removes bans that ended before endedBefore and whose last strike
	// is older than strikeBefore.
	Prune(ctx context.Context, endedBefore, strikeBefore time.Time) error
}
