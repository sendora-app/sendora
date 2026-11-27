// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"time"
)

// NewShare is a share to create. Nil pointers store no value (no invite, no
// download limit).
type NewShare struct {
	UserID        int64
	InviteID      *int64
	LongID        string
	Name          string
	Description   string
	PasswordHash  string
	DownloadLimit *int64
	ExpiresAt     time.Time
}

// NewShareFile is a stored file to add to a share. StorageID 0 is the local
// data directory (DiskPath set); other locations use ObjectKey.
type NewShareFile struct {
	ShareID   int64
	Name      string
	FullPath  string
	Size      int64
	Type      string
	DiskPath  string
	SHA256    string
	Integrity string
	Encrypted bool
	EncID     string
	StorageID int64
	ObjectKey string
}

// ShareFile is a stored file of a share as core code reads it, with the long
// id (and, for VerificationFiles, the name) of its share.
type ShareFile struct {
	ID        int64
	Name      string
	FullPath  string
	Size      int64
	Type      string
	DiskPath  string
	SHA256    string
	Integrity string
	Encrypted bool
	EncID     string
	LongID    string
	ShareName string
	StorageID int64
	ObjectKey string
}

// ShareRecord is one share as core code reads it. Owner is the owner's
// username ("" when the share has no owner any more); UserID is nil then.
// Size and FileCount cover the share's stored files.
type ShareRecord struct {
	ID            int64
	LongID        string
	Name          string
	Description   string
	Owner         string
	PasswordHash  string
	Status        string
	DownloadLimit *int64
	DownloadCount int64
	ExpiresAt     *time.Time
	CreatedAt     time.Time
	UserID        *int64
	Size          int64
	FileCount     int
}

// ShareFileSummary is a stored file as its share's owner lists it.
type ShareFileSummary struct {
	ID       int64
	Name     string
	FullPath string
	Size     int64
}

// ShareFilterKind selects the shares ShareFilter matches.
type ShareFilterKind int

const (
	// AnyShare matches every share.
	AnyShare ShareFilterKind = iota
	// SharePrunableByOwner matches shares of UserID that are not active or
	// expired before At.
	SharePrunableByOwner
	// ShareRetiredBefore matches shares that are not active and expired
	// before At (shares without expiry: created before At).
	ShareRetiredBefore
)

// ShareFilter is the condition a share must still meet to be removed
// (LongIDIf).
type ShareFilter struct {
	Kind   ShareFilterKind
	UserID int64
	At     time.Time
}

// ShareEdit is a partial change of a share by its owner; nil fields are
// kept. With SetDownloadLimit the limit becomes DownloadLimit (nil = none)
// and a share that was expired only because its old limit was used up is
// active again when the new limit (or no limit) admits downloads and it has
// not expired by Now.
type ShareEdit struct {
	Name             *string
	Description      *string
	SetDownloadLimit bool
	DownloadLimit    *int64
	Now              time.Time
	PasswordHash     *string
}

// Empty reports whether e changes nothing.
func (e ShareEdit) Empty() bool {
	return e.Name == nil && e.Description == nil && !e.SetDownloadLimit && e.PasswordHash == nil
}

// ShareRepository covers shares and their stored files.
type ShareRepository interface {
	// CountOwnedOrReceived counts the account's shares and the shares that
	// arrived through its invites.
	CountOwnedOrReceived(ctx context.Context, userID int64) (int64, error)
	// Create stores a new active share and returns its id. A long id that is
	// already taken is an error.
	Create(ctx context.Context, s NewShare) (int64, error)
	// AddFile stores a file of a share and returns its id.
	AddFile(ctx context.Context, f NewShareFile) (int64, error)
	// LongIDExists reports whether a share (in any status) has the long id.
	LongIDExists(ctx context.Context, longID string) (bool, error)

	// OwnedLongIDAndStatus returns the long id and status of the account's
	// share id (ErrNotFound when it has no such share).
	OwnedLongIDAndStatus(ctx context.Context, id, userID int64) (longID, status string, err error)
	// FilesTotalSize sums the sizes of the share's files (0 without files).
	FilesTotalSize(ctx context.Context, shareID int64) (int64, error)

	// ByID returns the share with id (ErrNotFound when unknown).
	ByID(ctx context.Context, id int64) (ShareRecord, error)
	// ByLongID returns the share with longID (ErrNotFound when unknown).
	ByLongID(ctx context.Context, longID string) (ShareRecord, error)
	// ListOwned returns the account's shares that are not deleted, newest
	// first. Unreadable rows are skipped; an error while iterating ends the
	// list without failing it.
	ListOwned(ctx context.Context, userID int64) ([]ShareRecord, error)
	// Files returns the share's stored files with its long id, ordered by
	// full path, then id (ShareName is not set). An error starting the read
	// is returned as is; a row that cannot be read or an error while
	// iterating is returned wrapped in ErrReadInterrupted.
	Files(ctx context.Context, shareID int64) ([]ShareFile, error)
	// ListFiles returns the share's stored files ordered by full path, then
	// id. Any read error fails the call.
	ListFiles(ctx context.Context, shareID int64) ([]ShareFileSummary, error)
	// FilePathsAndSizes returns the full path and size of each of the
	// share's files, in no particular order (only FullPath and Size are
	// set). Any read error fails the call.
	FilePathsAndSizes(ctx context.Context, shareID int64) ([]ShareFileSummary, error)
	// FileLocation returns where file fileID of share shareID is stored: its
	// recorded disk path, the share's long id and the storage location
	// (ErrNotFound when the share has no such file).
	FileLocation(ctx context.Context, fileID, shareID int64) (diskPath, longID string, storageID int64, err error)
	// CountFiles counts the share's files.
	CountFiles(ctx context.Context, shareID int64) (int, error)
	// DeleteFile removes file fileID of share shareID (a missing file is not
	// an error). Removing a file kept in a remote location queues its object
	// for deletion in the same transaction.
	DeleteFile(ctx context.Context, fileID, shareID int64) error
	// OwnedActiveLongID returns the long id of the account's share id unless
	// it is deleted (ErrNotFound otherwise).
	OwnedActiveLongID(ctx context.Context, id, userID int64) (string, error)

	// ReplacePasswordHash swaps the share's password hash only while it still
	// equals oldHash; it returns the number of shares changed.
	ReplacePasswordHash(ctx context.Context, id int64, newHash, oldHash string) (int64, error)
	// CountDownload atomically counts one download of an active share that
	// has not expired at now and whose limit is not used up, and returns the
	// new download count (ErrNotFound when the share admits no download).
	CountDownload(ctx context.Context, id int64, now time.Time) (int64, error)
	// Expire marks the share expired at at.
	Expire(ctx context.Context, id int64, at time.Time) error
	// Extend sets the share's expiry to until, makes it active and clears
	// its expiry warning.
	Extend(ctx context.Context, id int64, until time.Time) error
	// SetExpiry is Extend for the account's share unless it is deleted;
	// a nil expiresAt means it never expires. It returns the number of
	// shares changed.
	SetExpiry(ctx context.Context, id, userID int64, expiresAt *time.Time) (int64, error)
	// SetDownloadLimit sets the share's limit (nil = none) with the revival
	// rule of ShareEdit.SetDownloadLimit.
	SetDownloadLimit(ctx context.Context, id int64, limit *int64, now time.Time) error
	// Edit applies e (which must not be Empty) to the account's share unless
	// it is deleted; it returns the number of shares changed.
	Edit(ctx context.Context, id, userID int64, e ShareEdit) (int64, error)
	// PrunableIDs returns the ids of the account's shares that are not active
	// or expired before now, in no particular order. A row that cannot be
	// read is listed as 0; an error while iterating ends the list without
	// failing it.
	PrunableIDs(ctx context.Context, userID int64, now time.Time) ([]int64, error)

	// Lock takes the write lock on the share inside a transaction (a no-op
	// write; a missing share is not an error).
	Lock(ctx context.Context, id int64) error
	// LockOwnedForAppend takes the write lock on the account's share unless
	// it is deleted; it returns the number of shares matched (0 or 1).
	LockOwnedForAppend(ctx context.Context, id, userID int64) (int64, error)
	// LockOwnedForFileRemoval has the contract of LockOwnedForAppend; it is
	// taken before one of the share's files is removed.
	LockOwnedForFileRemoval(ctx context.Context, id, userID int64) (int64, error)
	// LongIDIf returns the share's long id if the share matches f
	// (ErrNotFound otherwise).
	LongIDIf(ctx context.Context, id int64, f ShareFilter) (string, error)
	// Delete removes the share with its files, downloads and pending append
	// uploads; it returns the number of shares removed.
	Delete(ctx context.Context, id int64) (int64, error)

	// BaselineFileChecksum records sum as the file's SHA-256 only while the
	// file has none (a missing file is not an error).
	BaselineFileChecksum(ctx context.Context, fileID int64, sum string) error
	// FileChecksum returns the file's recorded SHA-256 ("" when none;
	// ErrNotFound for an unknown file).
	FileChecksum(ctx context.Context, fileID int64) (string, error)
	// CountFilesByEncryption counts the stored files that are encrypted and
	// those stored plain.
	CountFilesByEncryption(ctx context.Context) (encrypted, plain int64, err error)
	// VerificationFiles returns every stored file with its share's long id and
	// name, ordered by file id (ShareName is set; Type is not). For a
	// database that predates storage locations, every file is reported as
	// local (StorageID 0, no ObjectKey) and locationsKnown is false. A row
	// that cannot be read fails the whole call.
	VerificationFiles(ctx context.Context) (files []ShareFile, locationsKnown bool, err error)
}

// DownloadRecord is one recorded download start. FileID is nil for a
// download of the whole share; FileName is "" then, or when the file no
// longer belongs to the share.
type DownloadRecord struct {
	ID        int64
	FileID    *int64
	FileName  string
	CreatedAt time.Time
}

// DownloadRepository covers the recorded download starts of shares.
type DownloadRepository interface {
	// Record stores a download start of the share (fileID nil: all files).
	Record(ctx context.Context, shareID int64, fileID *int64, ip string, at time.Time) error
	// Count counts the share's recorded downloads.
	Count(ctx context.Context, shareID int64) (int64, error)
	// List returns a page of the share's downloads, newest first (ties:
	// higher id first). Any read error fails the call.
	List(ctx context.Context, shareID int64, limit, offset int) ([]DownloadRecord, error)
	// BlankAddressesUnlessLogged empties the recorded client address of every
	// download unless the setting audit_log_ip is "true" (any letter case);
	// a missing setting counts as off.
	BlankAddressesUnlessLogged(ctx context.Context) error
}

// StorageLocationRepository covers the configured remote storage locations
// (the local data directory is location 0 and has no record).
type StorageLocationRepository interface {
	// IDs returns the ids of the configured locations in ascending order.
	// Unreadable rows are skipped; an error while iterating ends the list
	// without failing it.
	IDs(ctx context.Context) ([]int64, error)
}

// DownloadMailRepository is the outbox of download notification emails. A
// job is reserved when a download is admitted and becomes pending when the
// download actually starts; reserved jobs of downloads that never started
// are released.
type DownloadMailRepository interface {
	// CountQueued counts the jobs that are reserved or pending.
	CountQueued(ctx context.Context) (int, error)
	// Reserve stores a reserved job for share shareID to recipient with the
	// JSON template data and returns its id.
	Reserve(ctx context.Context, shareID int64, recipient, language, data string, nextAttempt time.Time) (int64, error)
	// Activate makes reserved job id pending: its data gains StartedAt
	// (startedAt as RFC 3339 text) and it is due at startedAt. A job that is
	// not reserved is left alone.
	Activate(ctx context.Context, id int64, startedAt time.Time) error
	// Release removes job id if it is still reserved.
	Release(ctx context.Context, id int64) error
	// ReleaseAllReserved removes every reserved job (at startup: no
	// reserved download can still start).
	ReleaseAllReserved(ctx context.Context) error
	// NextDue returns the oldest pending job due at now; ErrNotFound when
	// none is due.
	NextDue(ctx context.Context, now time.Time) (DownloadMailJob, error)
	// Claim leases pending job id until until when it is due at now (its
	// next attempt moves to until) and returns the rows changed (1 or 0).
	// Its clean commit is the replication barrier before the mail is sent
	// (design 4.3); another worker does not see the job before until.
	Claim(ctx context.Context, id int64, now, until time.Time) (int64, error)
	// Delete removes job id.
	Delete(ctx context.Context, id int64) error
	// RecordFailure stores a failed attempt: the attempt count, the new
	// status ("pending" or "failed"), the error text and the next attempt.
	RecordFailure(ctx context.Context, id int64, attempts int, status, lastError string, next time.Time) error
	// PruneFailed keeps only the newest 1000 failed jobs.
	PruneFailed(ctx context.Context) error
}
