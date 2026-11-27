// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import "context"

// PlatformStore is the database port of the platform database of
// multi-tenant mode (tenants, their domains and storage decisions, platform
// administrators and their console sessions, platform settings). It is
// parallel to Store, which is bound to one tenant's database; the platform
// audit chain is kept through a Store on the same database (AuditChain).
//
// Times stored as Unix seconds (sessions, lockouts) are int64 Unix seconds in
// the port (0 = none); times stored as text (created_at, updated_at,
// stat_updated_at) are passed through as the RFC 3339 text the caller gave.
type PlatformStore interface {
	PlatformRepositories
	// Begin starts a write transaction (see Store.Begin for the rules).
	Begin(ctx context.Context) (PlatformTx, error)
}

// PlatformRepositories is the set of platform repositories, available on the
// PlatformStore (each call autocommits) and on a PlatformTx.
type PlatformRepositories interface {
	// Tenants are the tenants (table tenants).
	Tenants() TenantRepository
	// TenantDomains are the custom domains mapped to tenants.
	TenantDomains() TenantDomainRepository
	// TenantStorage holds the platform's storage decision per tenant.
	TenantStorage() TenantStorageRepository
	// PlatformAdmins are the platform administrators.
	PlatformAdmins() PlatformAdminRepository
	// PlatformSessions are the console sessions.
	PlatformSessions() PlatformSessionRepository
	// PlatformSettings are the platform settings.
	PlatformSettings() PlatformSettingsRepository
	// PlatformAudit reads the platform audit log.
	PlatformAudit() PlatformAuditRepository
	// ControlLog stores the platform-level control log.
	ControlLog() ControlLogRepository
	// Keyring stores tenant wrapped DEKs on the platform database.
	Keyring() KeyringRepository
}

// PlatformTx is a write transaction on the platform database.
type PlatformTx interface {
	PlatformRepositories
	// Commit makes the transaction's writes durable (see Tx.Commit).
	Commit() error
	// Rollback discards the transaction; after Commit it does nothing.
	Rollback() error
}

// TenantRecord is one tenant. LegacyRoot is nil unless the tenant was
// converted from a single-tenant installation with its own root key.
type TenantRecord struct {
	ID, Slug, Name, Status, CreatedAt string
	MaxUsers, MaxStorageBytes         int64
	KeyMode                           string
	// KEKMode is who holds the key-encryption key: "platform" (default) or
	// "tenant" (the tenant supplied its own, D41/D44). KEKFingerprint is the
	// fingerprint of the tenant-supplied KEK (empty for "platform"); it is
	// all the operator ever sees of it.
	KEKMode, KEKFingerprint string
	// MasterVersion is the version of the master key the tenant's derived
	// material comes from (D46); 1 for tenants that never rotated.
	MasterVersion               int
	LegacyRoot                  []byte
	PrimaryDomain               string
	StatUsers, StatStorageBytes int64
	StatUpdatedAt               string
	AllowPrivateTargets         bool
}

// TenantRoute is the routing data of a tenant.
type TenantRoute struct {
	ID, Slug, Status, PrimaryDomain string
}

// TenantRepository covers the tenants.
type TenantRepository interface {
	// ByID returns a tenant; ErrNotFound when unknown.
	ByID(ctx context.Context, id string) (TenantRecord, error)
	// BySlug returns a tenant by its slug (exact match; slugs are stored in
	// lower case); ErrNotFound when unknown.
	BySlug(ctx context.Context, slug string) (TenantRecord, error)
	// List returns the tenants ordered by slug. A non-empty search (lower
	// case) keeps the tenants whose slug or name, in lower case, contains it
	// literally (no wildcards), or that have a domain containing it.
	List(ctx context.Context, search string) ([]TenantRecord, error)
	// CountBySlug counts the tenants with the slug.
	CountBySlug(ctx context.Context, slug string) (int, error)
	// Insert stores a new tenant (no primary domain, statistics zero, private
	// targets not allowed). A taken id or slug is an error.
	Insert(ctx context.Context, t TenantRecord) error
	// SetStatus changes the status of a tenant that is active or suspended
	// and returns the number of tenants changed (0 or 1).
	SetStatus(ctx context.Context, id, status string) (int64, error)
	// Activate makes an importing tenant active (other tenants are left alone).
	Activate(ctx context.Context, id string) error
	// SetQuotas stores the limits and returns the number of tenants changed.
	SetQuotas(ctx context.Context, id string, maxUsers, maxStorageBytes int64) (int64, error)
	// SetName changes the display name.
	SetName(ctx context.Context, id, name string) error
	// UpdateStats stores the console counts and their time.
	UpdateStats(ctx context.Context, id string, users, storageBytes int64, at string) error
	// SetAllowPrivateTargets stores the flag and returns the number of
	// tenants changed.
	SetAllowPrivateTargets(ctx context.Context, id string, allow bool) (int64, error)
	// SetKEK stores the KEK mode ("platform" or "tenant") and the fingerprint
	// of the tenant-supplied KEK ("" for "platform"); it returns the number of
	// tenants changed.
	SetKEK(ctx context.Context, id, mode, fingerprint string) (int64, error)
	// SetMasterVersion moves a tenant from master version from to version to
	// (compare-and-swap on from); it returns the number of tenants changed
	// (0 when the tenant is not at from: a repeated or lost race).
	SetMasterVersion(ctx context.Context, id string, from, to int) (int64, error)
	// CountByMasterVersion counts the tenants (pending, active, suspended)
	// per master version.
	CountByMasterVersion(ctx context.Context) (map[int]int, error)
	// SetPrimaryDomain stores the primary domain ("" = the subdomain).
	SetPrimaryDomain(ctx context.Context, id, domain string) error
	// ClearPrimaryDomain resets the primary domain to "" when it is domain.
	ClearPrimaryDomain(ctx context.Context, id, domain string) error
	// Delete removes a tenant with its domains and storage decision; a
	// missing tenant is not an error.
	Delete(ctx context.Context, id string) error
	// DeleteImporting removes a tenant only while it is importing.
	DeleteImporting(ctx context.Context, id string) error
	// Routes returns the routing data of every tenant, in no particular order.
	Routes(ctx context.Context) ([]TenantRoute, error)
}

// TenantDomain is one domain mapped to a tenant.
type TenantDomain struct {
	Domain, TenantID, Kind string
	Verified               bool
	VerifyToken, CreatedAt string
}

// TenantDomainRepository covers the custom domains of tenants.
type TenantDomainRepository interface {
	// VerifiedCustom maps every verified custom domain of an existing tenant
	// to the tenant id.
	VerifiedCustom(ctx context.Context) (map[string]string, error)
	// List returns a tenant's domains ordered by domain.
	List(ctx context.Context, tenantID string) ([]TenantDomain, error)
	// AddCustom maps an unverified custom domain to a tenant. A domain that
	// is already mapped is an error.
	AddCustom(ctx context.Context, domain, tenantID, verifyToken, createdAt string) error
	// MarkVerified marks the tenant's custom domain verified and returns the
	// number of domains changed (0 or 1).
	MarkVerified(ctx context.Context, domain, tenantID string) (int64, error)
	// RemoveCustom unmaps the tenant's custom domain and returns the number
	// of domains removed (0 or 1).
	RemoveCustom(ctx context.Context, domain, tenantID string) (int64, error)
	// CountVerified counts the tenant's verified domains equal to domain.
	CountVerified(ctx context.Context, domain, tenantID string) (int, error)
}

// TenantStorageDecision is the platform's storage decision for a tenant.
type TenantStorageDecision struct {
	Offer         string
	TenantManaged bool
	UpdatedAt     string
}

// TenantStorageRepository covers the platform's storage decisions.
type TenantStorageRepository interface {
	// CreateDefault stores the decision of a new tenant: no offer, own storage
	// allowed (not an explicit choice), with the tenant's prefix.
	CreateDefault(ctx context.Context, tenantID, prefix, at string) error
	// Get returns a tenant's decision; ErrNotFound when none is stored.
	Get(ctx context.Context, tenantID string) (TenantStorageDecision, error)
	// Set stores a decision (an explicit choice) for an existing tenant,
	// creating it with prefix when absent, and returns the number of rows
	// written (0 when the tenant does not exist).
	Set(ctx context.Context, tenantID, prefix, offer string, tenantManaged bool, at string) (int64, error)
}

// PlatformAdmin is a platform administrator.
type PlatformAdmin struct {
	ID                 int64
	Username, Email    string
	TOTPEnabled        bool
	CreatedAt          string
	PasswordHash       string
	TOTPSecret         string
	PendingTOTP        string
	LastCounter        int64
	Failures           int
	LockedUntil        int64 // Unix seconds, 0 = not locked
	MustChangePassword bool
}

// PlatformAdminRepository covers the platform administrators.
type PlatformAdminRepository interface {
	// Count returns the number of administrators.
	Count(ctx context.Context) (int, error)
	// ByName looks an administrator up by username, ignoring ASCII letter
	// case; ErrNotFound when unknown.
	ByName(ctx context.Context, username string) (PlatformAdmin, error)
	// ByID looks an administrator up; ErrNotFound when unknown.
	ByID(ctx context.Context, id int64) (PlatformAdmin, error)
	// List returns every administrator ordered by username, ignoring ASCII
	// letter case.
	List(ctx context.Context) ([]PlatformAdmin, error)
	// Create stores an administrator and returns its id. A username taken
	// (ignoring ASCII letter case) is an error.
	Create(ctx context.Context, username, email, passwordHash, createdAt string) (int64, error)
	// CreateFirst stores an administrator only while there is none, atomically;
	// created is false when one already existed.
	CreateFirst(ctx context.Context, username, email, passwordHash, createdAt string) (id int64, created bool, err error)
	// DeleteUnlessLast removes an administrator (with their sessions) unless
	// it is the only one, and returns the number removed (0 or 1).
	DeleteUnlessLast(ctx context.Context, id int64) (int64, error)
	// SetPassword replaces the password hash and clears must-change.
	SetPassword(ctx context.Context, id int64, hash string) error
	// SetTemporaryPassword replaces the password hash, sets must-change and
	// clears the failure counter and lock.
	SetTemporaryPassword(ctx context.Context, id int64, hash string) error
	// NoteLoginFailure increments the failure counter and, once it reaches
	// limit, sets the lock to lockUntil (Unix seconds).
	NoteLoginFailure(ctx context.Context, id int64, limit int, lockUntil int64) error
	// ClearLoginFailures resets the failure counter and lock.
	ClearLoginFailures(ctx context.Context, id int64) error
	// SetPendingTOTP stores a TOTP secret awaiting confirmation.
	SetPendingTOTP(ctx context.Context, id int64, secret string) error
	// EnableTOTP promotes a non-empty pending secret to the active one and
	// records counter as the last used time step.
	EnableTOTP(ctx context.Context, id, counter int64) error
	// UseTOTPCounter records counter when it is newer than the last used one
	// and returns the number of administrators changed (0 or 1).
	UseTOTPCounter(ctx context.Context, id, counter int64) (int64, error)
	// ResetTOTP removes the active and pending TOTP secrets.
	ResetTOTP(ctx context.Context, id int64) error
}

// PlatformSession is a console session (by the hash of its token). Times are
// Unix seconds; MFAAt is 0 before the second factor.
type PlatformSession struct {
	Hash                           string
	AdminID                        int64
	Stage                          string
	CreatedAt, LastSeen, ExpiresAt int64
	MFAAt                          int64
}

// PlatformSessionRepository covers the console sessions.
type PlatformSessionRepository interface {
	// Create stores a session. Stage is one of mfa, enroll, full.
	Create(ctx context.Context, s PlatformSession) error
	// Get returns a session; ErrNotFound when unknown.
	Get(ctx context.Context, hash string) (PlatformSession, error)
	// Touch sets the last activity time.
	Touch(ctx context.Context, hash string, lastSeen int64) error
	// Promote moves a session to the full stage with its MFA time.
	Promote(ctx context.Context, hash string, mfaAt int64) error
	// SetMFAAt records a fresh second-factor confirmation.
	SetMFAAt(ctx context.Context, hash string, mfaAt int64) error
	// Delete ends a session; a missing one is not an error.
	Delete(ctx context.Context, hash string) error
	// DeleteForAdmin ends every session of an administrator.
	DeleteForAdmin(ctx context.Context, adminID int64) error
	// DeleteWithoutTOTP ends the sessions of administrators without TOTP.
	DeleteWithoutTOTP(ctx context.Context) error
	// PruneExpired removes sessions that expired before the Unix time.
	PruneExpired(ctx context.Context, before int64) error
}

// PlatformSettingsRepository covers the platform settings (key/value with a
// group, like a tenant's settings).
type PlatformSettingsRepository interface {
	// Get returns a setting's value; ErrNotFound when not stored.
	Get(ctx context.Context, key string) (string, error)
	// Update changes an existing setting; a missing key is left alone.
	Update(ctx context.Context, key, value string) error
	// EnsureDefault stores the setting when the key is not stored yet.
	EnsureDefault(ctx context.Context, key, value, group string) error
}

// PlatformAuditRepository reads the platform audit log.
type PlatformAuditRepository interface {
	// Page returns up to limit records, newest first, with seq < before
	// (before <= 0: from the newest).
	Page(ctx context.Context, before int64, limit int) ([]AuditRecord, error)
}
