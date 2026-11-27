// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"time"
)

// PendingDelete is a queued deletion of a remote object.
type PendingDelete struct {
	ID         int64
	LocationID int64
	ObjectKey  string
	Attempts   int
}

// LocationCount is how many files (and bytes) live in one storage location.
type LocationCount struct {
	ID    int64
	Files int64
	Bytes int64
}

// MigrationFile is the stored state of a file the storage migration moves.
type MigrationFile struct {
	ID, Size, LocationID        int64
	SHA256, EncID, ObjectKey    string
	DiskPath, Name, ShareLongID string
	Encrypted                   bool
}

// MovedFile is the new location of a migrated file.
type MovedFile struct {
	LocationID int64
	ObjectKey  string
	DiskPath   string
	Encrypted  bool
	EncID      string
	SHA256     string
}

// StorageMigration is the record of a storage migration run.
type StorageMigration struct {
	ID, TargetLocation        int64
	Status, Target, StartedBy string
	Total, Done, Failed       int64
	Bytes                     int64
	Error                     string
	StartedAt                 time.Time
	FinishedAt                *time.Time
}

// ObjectStorageRepository covers storage locations, the queue of remote
// objects to delete and the file rows the storage migration moves.
type ObjectStorageRepository interface {
	// EnsureLocation returns the id of the location with identity, creating
	// it or replacing its stored configuration (its update time moves only
	// when the configuration changed).
	EnsureLocation(ctx context.Context, backend, identity, config string) (int64, error)
	// LocationConfig returns the stored configuration of location id;
	// ErrNotFound when unknown.
	LocationConfig(ctx context.Context, id int64) (string, error)
	// LocationConfigs returns the stored configuration of every location in
	// id order. Rows that cannot be read are skipped; an error reported with
	// a partial list means the listing stopped early.
	LocationConfigs(ctx context.Context) ([]string, error)
	// QueueDelete records a remote object for deletion not before notBefore.
	QueueDelete(ctx context.Context, location int64, key string, notBefore time.Time) error
	// CountPendingDeletes counts the queued deletions.
	CountPendingDeletes(ctx context.Context) (int64, error)
	// DuePendingDeletes returns up to limit deletions due at now, oldest
	// first. Unreadable rows are skipped.
	DuePendingDeletes(ctx context.Context, now time.Time, limit int) ([]PendingDelete, error)
	// DeletePendingDelete removes a queued deletion.
	DeletePendingDelete(ctx context.Context, id int64) error
	// DeferPendingDelete counts a failed attempt and moves the deletion to
	// notBefore.
	DeferPendingDelete(ctx context.Context, id int64, notBefore time.Time) error
	// UsageByLocation counts files and bytes per location, ordered by id.
	UsageByLocation(ctx context.Context) ([]LocationCount, error)
	// FilesOutside lists the files that are not in location target, by id.
	FilesOutside(ctx context.Context, target int64) ([]int64, error)
	// CountFilesOutside counts the files that are not in location target.
	CountFilesOutside(ctx context.Context, target int64) (int64, error)
	// MigrationFile returns the stored state of file id; ErrNotFound when
	// it is gone.
	MigrationFile(ctx context.Context, id int64) (MigrationFile, error)
	// ListMigrationFiles returns up to limit files with an id above after, by
	// id (the re-encryption of stored files walks the table with it).
	ListMigrationFiles(ctx context.Context, after int64, limit int) ([]MigrationFile, error)
	// MoveFile switches file f to its new location only while its location,
	// object key, disk path and encryption id are still those of f; it
	// returns the rows changed.
	MoveFile(ctx context.Context, f MigrationFile, to MovedFile) (int64, error)
}

// StorageMigrationRepository covers the records of storage migration runs.
type StorageMigrationRepository interface {
	// Start records a running migration to target and returns its id.
	Start(ctx context.Context, target int64, targetDesc, startedBy string) (int64, error)
	// StartByTool is Start for the command-line tool (started by
	// "sendora-db").
	StartByTool(ctx context.Context, target int64, targetDesc string) (int64, error)
	// Progress stores the counters of migration id.
	Progress(ctx context.Context, id, total, done, failed, bytes int64) error
	// Finish stores the end status and error of migration id; the finish
	// time is the current time.
	Finish(ctx context.Context, id int64, status, errText string) error
	// FinishWithCounters is Finish that also stores the counters.
	FinishWithCounters(ctx context.Context, id int64, status string, total, done, failed, bytes int64, errText string) error
	// FailInterrupted marks running migrations failed (interrupted by a
	// restart).
	FailInterrupted(ctx context.Context) error
	// Latest returns the newest migration; ErrNotFound when there is none.
	Latest(ctx context.Context) (StorageMigration, error)
}
