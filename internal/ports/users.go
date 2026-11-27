// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"time"
)

// UserRecord is one account row as core code reads it. Nullable columns are
// pointers (nil = NULL). Quota values are returned as stored, unparsed:
// core code validates them (internal/store.ResolveQuota).
type UserRecord struct {
	ID                 int64
	Username           string
	Name               string
	Email              string
	Admin              bool
	MustChangePassword bool
	IsGuest            bool
	Auditor            bool
	EmailVerified      bool
	// CreatedAt is the creation time rendered as RFC 3339 with nanoseconds
	// (time.RFC3339Nano), the form core code has always returned in the API.
	CreatedAt    string
	PasswordHash string
	Language     string
	UILanguage   string
	// QuotaBytes, QuotaInheritsDefault and DefaultQuota are the decimal text
	// of the account's quota, its inheritance flag ("0"/"1") and the setting
	// default_storage_quota_bytes; nil when NULL or (DefaultQuota) missing.
	QuotaBytes             *string
	QuotaInheritsDefault   *string
	DefaultQuota           *string
	LoginFailures          int64
	LoginLockedUntil       int64 // Unix seconds, 0 = not locked
	MFAPolicy              string
	MFAEpoch               int64
	Disabled               bool
	DisabledReason         string
	PasswordChangedAt      *time.Time
	PasswordRotationExempt bool
}

// AccessReviewRecord is an account with the lifecycle details of the access
// review report. Times are nil when unknown.
type AccessReviewRecord struct {
	UserRecord
	Created, RoleChangedAt, EmailChangedAt, LastLoginAt, DisabledAt      *time.Time
	CreatedBy, RoleChangedBy, EmailChangedBy, DisabledBy, DisabledReason string
}

// CredentialGuard is the compare-and-set condition of account writes that
// must not apply when the account's identity or credentials changed since
// it was read: the write only matches while password hash, email address and
// the must-change flag still equal these values.
type CredentialGuard struct {
	PasswordHash       string
	Email              string
	MustChangePassword bool
}

// NewUser is an account to create.
type NewUser struct {
	Username            string
	Name                string
	Email               string
	PasswordHash        string
	Admin               bool
	MustChangePassword  bool
	EmailVerified       bool
	PendingRegistration bool
	Language            string
	UILanguage          string
	PasswordChangedAt   time.Time
	// QuotaBytes, when set, gives the account its own quota (not inherited).
	QuotaBytes *int64
}

// ProfileUpdate is a self-service profile change (UpdateProfile).
// PasswordChanged resets the failure counter and lock, sets
// password_changed_at to ChangedAt and clears the expiry warning.
// A nil UILanguage keeps the stored value.
type ProfileUpdate struct {
	Name               string
	Email              string
	EmailVerified      bool
	PasswordHash       string
	MustChangePassword bool
	Language           string
	UILanguage         *string
	PasswordChanged    bool
	ChangedAt          time.Time
}

// AdminUserUpdate is an administrator's change of an account (AdminUpdate).
// Nil pointers keep the stored value. EmailUnverified marks the address
// unverified; PasswordChanged behaves as in ProfileUpdate.
type AdminUserUpdate struct {
	Name                 string
	Email                string
	Admin                bool
	PasswordHash         string
	QuotaBytes           *int64
	QuotaInheritsDefault *bool
	MFAPolicy            *string
	RotationExempt       *bool
	EmailUnverified      bool
	PasswordChanged      bool
	ChangedAt            time.Time
}

// UserRepository reads and writes accounts. Methods that return a count of
// affected rows report 0 when no account matched (an unknown id is not an
// error). Lookups of a single account return ErrNotFound when none matches.
type UserRepository interface {
	// CreateExternal creates an account without a local password for a
	// provider sign-in and returns its id.
	CreateExternal(ctx context.Context, username, name, email string, emailVerified int) (int64, error)
	// FillEmptyEmail sets an unverified address on an account that has none
	// and returns the rows changed.
	FillEmptyEmail(ctx context.Context, id int64, email string) (int64, error)
	// Email returns the account's address (ErrNotFound when unknown).
	Email(ctx context.Context, id int64) (string, error)
	// ErasedAt returns when the account was erased (nil when not).
	ErasedAt(ctx context.Context, id int64) (*time.Time, error)
	// IsAdmin reports the account's administrator flag (ErrNotFound when
	// unknown).
	IsAdmin(ctx context.Context, id int64) (bool, error)
	// CountOtherUnerasedAdmins counts the non-guest, not erased
	// administrators other than id.
	CountOtherUnerasedAdmins(ctx context.Context, id int64) (int, error)
	// LockForErasure is LockForDelete for a not yet erased account.
	LockForErasure(ctx context.Context, id int64) (int64, error)
	// EraseWithOwnedData removes the account's content (as
	// DeleteWithOwnedData, plus queued download mails, invites, sessions,
	// factors, links and history) and pseudonymises the account row
	// (username "erased-<id>", erasure time = current time), stopping at the
	// first error.
	EraseWithOwnedData(ctx context.Context, id int64) error
	// Roles returns the account's administrator, auditor and guest flags
	// (ErrNotFound when unknown).
	Roles(ctx context.Context, id int64) (admin, auditor, guest bool, err error)
	// ListForAccessReview returns every non-guest account with its lifecycle
	// details, ordered by username ignoring ASCII case, then id.
	ListForAccessReview(ctx context.Context) ([]AccessReviewRecord, error)
	// ByID returns the account with id (guests included).
	ByID(ctx context.Context, id int64) (UserRecord, error)
	// FindLocalByUsername returns the non-guest account whose username
	// equals username ignoring ASCII letter case; when several do (an old
	// database), the exact-case match wins.
	FindLocalByUsername(ctx context.Context, username string) (UserRecord, error)
	// FindLocalByUniqueEmail returns the non-guest account whose trimmed,
	// lower-cased address is email, only if no other account (guests
	// included) has that address.
	FindLocalByUniqueEmail(ctx context.Context, email string) (UserRecord, error)
	// FindVerifiedByUniqueEmail is FindLocalByUniqueEmail restricted to a
	// non-empty, verified address.
	FindVerifiedByUniqueEmail(ctx context.Context, email string) (UserRecord, error)
	// FindUnverifiedByUniqueEmail is FindLocalByUniqueEmail restricted to an
	// unverified address.
	FindUnverifiedByUniqueEmail(ctx context.Context, email string) (UserRecord, error)
	// ListLocal returns every non-guest account ordered by username.
	ListLocal(ctx context.Context) ([]UserRecord, error)
	// ListPasswordExpiryCandidates returns the non-guest, enabled accounts
	// with a local password that is subject to rotation, not yet flagged
	// for change, with a verified non-empty address, a known password time
	// and no expiry warning sent yet. Unreadable rows are skipped.
	ListPasswordExpiryCandidates(ctx context.Context) ([]UserRecord, error)

	// Count returns the number of accounts, guests included.
	Count(ctx context.Context) (int, error)
	// CountByUsernameFold counts accounts whose username equals username
	// ignoring ASCII letter case.
	CountByUsernameFold(ctx context.Context, username string) (int, error)
	// CountOtherWithEmail counts the accounts other than except whose stored
	// email, with surrounding white space removed and in lower case, equals
	// email (which the caller passes in canonical lower-case form).
	CountOtherWithEmail(ctx context.Context, email string, except int64) (int, error)
	// CreateProvisionedAdmin stores an administrator created by the platform
	// (multi-tenant mode): name = username, email not yet verified, English
	// for mail and UI, and returns its id. A taken username or email
	// (ErrDuplicate) and a reached tenant user limit (ErrTenantUserLimit,
	// text mentions "tenant user limit") are errors.
	CreateProvisionedAdmin(ctx context.Context, username, email, passwordHash string, passwordChangedAt time.Time) (int64, error)
	// Username returns the account's username (ErrNotFound when unknown).
	Username(ctx context.Context, id int64) (string, error)
	// PasswordHash returns the account's password hash ("" without one).
	PasswordHash(ctx context.Context, id int64) (string, error)
	// IsGuest reports whether the account is a guest (ErrNotFound when
	// unknown).
	IsGuest(ctx context.Context, id int64) (bool, error)

	// CreateFirstAdmin creates u as an administrator only while no account
	// exists. created is false (and id 0) when an account already existed.
	CreateFirstAdmin(ctx context.Context, u NewUser) (id int64, created bool, err error)
	// CreateRegistered creates a self-registered account (EmailVerified and
	// PendingRegistration are taken from u). A taken username or address is
	// an error.
	CreateRegistered(ctx context.Context, u NewUser) (int64, error)
	// Create creates an account for an administrator (Admin,
	// MustChangePassword and QuotaBytes are taken from u). A taken username
	// is an error.
	Create(ctx context.Context, u NewUser) (int64, error)
	// Delete removes the account (cascading to its dependent rows).
	Delete(ctx context.Context, id int64) error
	// SetAuditorIfNotAdmin makes a non-administrator an auditor.
	SetAuditorIfNotAdmin(ctx context.Context, id int64) error
	// SetAuditor sets or clears the auditor flag.
	SetAuditor(ctx context.Context, id int64, auditor bool) error

	// RecordLoginAttempt stores the failure counter and lock of a non-guest
	// account while g still holds.
	RecordLoginAttempt(ctx context.Context, id int64, failures, lockedUntil int64, g CredentialGuard) (int64, error)
	// ClearLoginLock resets the failure counter and lock of a non-guest
	// account.
	ClearLoginLock(ctx context.Context, id int64) (int64, error)
	// RecordLastLogin stores the time of a successful sign-in.
	RecordLastLogin(ctx context.Context, id int64, at time.Time) error
	// ReplacePasswordHash swaps the hash only while it still equals oldHash.
	ReplacePasswordHash(ctx context.Context, id int64, newHash, oldHash string) (int64, error)
	// SetPasswordAfterReset sets a non-guest account's password from a reset
	// link: the must-change flag, failure counter and lock are cleared, the
	// password time is set to at and the expiry warning cleared.
	SetPasswordAfterReset(ctx context.Context, id int64, hash string, at time.Time) (int64, error)
	// MarkEmailVerified marks a non-guest account's non-empty address
	// verified and ends its pending registration.
	MarkEmailVerified(ctx context.Context, id int64) error
	// VerifyEmailWithCode does the same for a still unverified account whose
	// address is email, only if code is the account's unexpired verification
	// code at now.
	VerifyEmailWithCode(ctx context.Context, id int64, email, code string, now time.Time) (int64, error)
	// UpdateProfile applies p while g holds.
	UpdateProfile(ctx context.Context, id int64, p ProfileUpdate, g CredentialGuard) (int64, error)
	// AdminUpdate applies a to a non-guest account while g holds.
	AdminUpdate(ctx context.Context, id int64, a AdminUserUpdate, g CredentialGuard) (int64, error)
	// ForcePasswordChange sets the must-change flag of a non-guest account.
	ForcePasswordChange(ctx context.Context, id int64) (int64, error)
	// FlagPasswordExpired sets the must-change flag of a non-guest account
	// whose hash is still hash and that is not flagged yet.
	FlagPasswordExpired(ctx context.Context, id int64, hash string) (int64, error)
	// MarkPasswordExpiryWarned records that the expiry warning for the
	// password hash was sent at, unless one was recorded already.
	MarkPasswordExpiryWarned(ctx context.Context, id int64, hash string, at time.Time) (int64, error)

	// LockForDelete takes the write lock on a non-guest account inside a
	// transaction (a no-op update); 0 when there is no such account.
	LockForDelete(ctx context.Context, id int64) (int64, error)
	// OwnedUploadIDs returns the upload sessions of the account, of the
	// guests of its invites and those it pays quota for.
	OwnedUploadIDs(ctx context.Context, id int64) ([]string, error)
	// OwnedShareLongIDs returns the long ids of the account's shares, of its
	// invites' guests and of shares that arrived through its invites.
	OwnedShareLongIDs(ctx context.Context, id int64) ([]string, error)
	// DeleteWithOwnedData removes the rows OwnedUploadIDs and
	// OwnedShareLongIDs list, the account's invite guests and the account,
	// in that order, stopping at the first error.
	DeleteWithOwnedData(ctx context.Context, id int64) error

	// LocalIDByUsername returns the id of the account FindLocalByUsername
	// would return.
	LocalIDByUsername(ctx context.Context, username string) (int64, error)
	// SetLoginFailures stores the failure counter and lock of the account.
	SetLoginFailures(ctx context.Context, id int64, failures, lockedUntil int64) error
	// ClearLoginFailures resets the failure counter and lock of the account
	// (guests included).
	ClearLoginFailures(ctx context.Context, id int64) error
	// BumpMFAEpoch increments the account's MFA epoch (factors changed).
	BumpMFAEpoch(ctx context.Context, id int64) error
	// BumpMFAEpochAndClearLock increments the MFA epoch and resets the
	// failure counter and lock (offline MFA reset).
	BumpMFAEpochAndClearLock(ctx context.Context, id int64) error

	// IsDisabled reports whether the account is disabled (ErrNotFound when
	// unknown).
	IsDisabled(ctx context.Context, id int64) (bool, error)
	// ShareOwnerDisabled reports whether the owner of share shareID, or the
	// inviter whose invitation the share arrived through, is disabled
	// (false for an unknown share).
	ShareOwnerDisabled(ctx context.Context, shareID int64) (bool, error)
	// CountActiveAdminsExcept counts the enabled non-guest administrators
	// other than account id.
	CountActiveAdminsExcept(ctx context.Context, id int64) (int, error)
	// SetCreatedBy records who created the account.
	SetCreatedBy(ctx context.Context, id int64, by string) error
	// NoteRoleChange records the time and actor of the last role change.
	NoteRoleChange(ctx context.Context, id int64, at time.Time, by string) error
	// NoteEmailChange records the time and actor of the last address change.
	NoteEmailChange(ctx context.Context, id int64, at time.Time, by string) error
	// Disable marks an enabled non-guest account disabled at at by by with
	// reason; 0 when there is no such account.
	Disable(ctx context.Context, id int64, at time.Time, by, reason string) (int64, error)
	// Enable clears the disabled state (time, actor, reason) of a disabled
	// non-guest account; 0 when there is no such account.
	Enable(ctx context.Context, id int64) (int64, error)
	// UploadsToRevoke returns the ids of the upload sessions of the account,
	// those whose quota it carries and those of the guests of its invites,
	// in no particular order (the set RevokeAccess deletes).
	UploadsToRevoke(ctx context.Context, id int64) ([]string, error)
	// RevokeAccess ends what a disabled account could still use, in this
	// order, stopping at the first error: it deletes the UploadsToRevoke
	// sessions, lets the account's open (not completed, expiring after now)
	// invites expire at now, deletes the refresh tokens of the account and
	// of its invite guests, its reset links, its verification code and its
	// MFA reset requests. It returns the number of invites it expired.
	RevokeAccess(ctx context.Context, id int64, now time.Time) (invitesRevoked int64, err error)

	// CreateGuest creates a guest account (no password, no address) and
	// returns its id. A taken username is an error.
	CreateGuest(ctx context.Context, username, name string) (int64, error)
	// EmailAndLanguage returns the account's address and mail language
	// (ErrNotFound when unknown).
	EmailAndLanguage(ctx context.Context, id int64) (email, language string, err error)
	// LockForUpload takes the write lock on the account inside a
	// transaction (a no-op write) while it exists with the given guest flag;
	// it returns the number of accounts matched (0 or 1).
	LockForUpload(ctx context.Context, id int64, isGuest bool) (int64, error)
	// GuestByID returns the guest account with id (ErrNotFound for an
	// unknown id or a non-guest account).
	GuestByID(ctx context.Context, id int64) (UserRecord, error)

	// TermsAcceptedVersion returns the terms version the account accepted
	// ("" when none; ErrNotFound when unknown).
	TermsAcceptedVersion(ctx context.Context, id int64) (string, error)
	// AcceptTerms records that the account accepted version at at.
	AcceptTerms(ctx context.Context, id int64, version string, at time.Time) error
}

// SignInHistoryRepository keeps hashed fingerprints of an account's recent
// sign-ins (browser family and address class), one record per account and
// fingerprint with the time it was last seen.
type SignInHistoryRepository interface {
	// PruneBefore forgets the account's fingerprints last seen before cutoff.
	PruneBefore(ctx context.Context, userID int64, cutoff time.Time) error
	// Stats returns how many fingerprints the account has and how many of
	// them equal fingerprint (0/1).
	Stats(ctx context.Context, userID int64, fingerprint string) (history, known int, err error)
	// Touch records fingerprint as seen at at, inserting or updating.
	Touch(ctx context.Context, userID int64, fingerprint string, at time.Time) error
	// KeepNewest forgets all but the account's n most recently seen
	// fingerprints.
	KeepNewest(ctx context.Context, userID int64, n int) error
}

// QuotaRepository reads what storage accounting needs. The quota policy is
// returned unparsed; core code validates it (internal/store.ResolveQuota).
type QuotaRepository interface {
	// Policy returns the decimal text of the account's quota, its
	// inheritance flag and the setting default_storage_quota_bytes (nil when
	// NULL or missing); ErrNotFound when the account is unknown.
	Policy(ctx context.Context, userID int64) (quota, inheritance, defaultQuota *string, err error)
	// CountUnattributedReservations counts upload sessions whose quota owner
	// is missing or a guest, or whose uploader is missing.
	CountUnattributedReservations(ctx context.Context) (int, error)
	// StoredBytes sums the sizes of the files of the account's shares.
	// A negative size or a sum beyond the int64 range is an error.
	StoredBytes(ctx context.Context, userID int64) (int64, error)
	// ReservedBytes sums the declared sizes of the files of the upload
	// sessions whose quota the account carries, with the same checks.
	ReservedBytes(ctx context.Context, userID int64) (int64, error)

	// StorageBackendSetting returns the setting storage_backend (ErrNotFound
	// when it is not set).
	StorageBackendSetting(ctx context.Context) (string, error)
	// TenantStorageLimit returns the storage limit the platform set for this
	// organisation in bytes (0 = none). Databases of a single-tenant
	// installation keep no limits and return an error.
	TenantStorageLimit(ctx context.Context) (int64, error)
	// TotalStoredBytes sums the sizes of every stored file.
	TotalStoredBytes(ctx context.Context) (int64, error)
	// TotalReservedBytes sums the declared sizes of every upload session's
	// files.
	TotalReservedBytes(ctx context.Context) (int64, error)
}
