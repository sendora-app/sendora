// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"time"
)

// Setting is one stored setting.
type Setting struct {
	Key, Value, Group string
}

// SettingsRepository covers the settings table. "Editable" settings are
// those outside the secret and email-template groups.
type SettingsRepository interface {
	// ListEditable returns the editable settings except the JWT secret,
	// ordered by key. A row that cannot be read is returned with the values
	// read so far.
	ListEditable(ctx context.Context) ([]Setting, error)
	// EditableKeys returns the keys of the editable settings. Unreadable rows
	// are skipped.
	EditableKeys(ctx context.Context) ([]string, error)
	// EditableKeysOrdered is EditableKeys ordered by key.
	EditableKeysOrdered(ctx context.Context) ([]string, error)
	// SetApplicationURL changes the stored application_url.
	SetApplicationURL(ctx context.Context, url string) error
	// UpdateEditable changes an existing editable setting; other keys are
	// left alone.
	UpdateEditable(ctx context.Context, key, value string) error
	// Update changes an existing setting (any group); a missing key is left
	// alone.
	Update(ctx context.Context, key, value string) error
	// Clear sets an existing setting to "".
	Clear(ctx context.Context, key string) error
	// Get returns the stored value of key; ErrNotFound when the key is not
	// stored.
	Get(ctx context.Context, key string) (string, error)
	// Set stores value under key, creating the setting (group "system") when
	// it does not exist; an existing setting keeps its group.
	Set(ctx context.Context, key, value string) error
}

// ThemeRecord is a stored UI theme; Data is its JSON colour map.
type ThemeRecord struct {
	ID       int64
	Name     string
	Category string
	Bundled  bool
	Active   bool
	Data     string
}

// ThemeRepository covers UI themes. Lists are ordered bundled first, then by
// name; a row that cannot be read is returned with the values read so far.
type ThemeRepository interface {
	List(ctx context.Context) ([]ThemeRecord, error)
	// ListActive returns the active theme(s).
	ListActive(ctx context.Context) ([]ThemeRecord, error)
	// Create stores a custom theme; a taken name is an error.
	Create(ctx context.Context, name, data string) error
	// UpdateCustom changes a custom (not bundled) theme; a taken name is an
	// error. It returns the rows changed.
	UpdateCustom(ctx context.Context, id int64, name, data string) (int64, error)
	// DeleteCustomInactive removes a custom theme that is not active.
	DeleteCustomInactive(ctx context.Context, id int64) (int64, error)
	// DeactivateAll clears the active flag of every theme.
	DeactivateAll(ctx context.Context) error
	// Activate sets the active flag of theme id.
	Activate(ctx context.Context, id int64) (int64, error)
}

// DayCount is a number of events on one UTC day ("YYYY-MM-DD").
type DayCount struct {
	Day   string
	Count int
}

// StatsRepository answers the administrator dashboard.
type StatsRepository interface {
	CountLocalUsers(ctx context.Context) (int64, error)
	CountShares(ctx context.Context) (int64, error)
	// CountActiveShares counts active shares that do not expire before now.
	CountActiveShares(ctx context.Context, now time.Time) (int64, error)
	CountFiles(ctx context.Context) (int64, error)
	SumFileBytes(ctx context.Context) (int64, error)
	CountDownloads(ctx context.Context) (int64, error)
	// DownloadsPerDay counts downloads after since per day, oldest first. A
	// row that cannot be read is returned with the values read so far.
	DownloadsPerDay(ctx context.Context, since time.Time) ([]DayCount, error)
}

// ExpiringShare is a share that is due for an expiry warning.
type ExpiringShare struct {
	ID         int64
	Name       string
	LongID     string
	ExpiresAt  time.Time
	OwnerEmail string
}

// RemovedAccount is an account removed by a clean-up job.
type RemovedAccount struct {
	ID       int64
	Username string
}

// MaintenanceRepository holds the periodic clean-up statements. Timestamps
// given as text use the form "YYYY-MM-DD HH:MM:SS" in UTC.
type MaintenanceRepository interface {
	// ExpireShares marks active shares expired whose time passed (before
	// now) or whose download limit was reached; it returns how many.
	ExpireShares(ctx context.Context, now time.Time) (int64, error)
	// SharesToWarn lists active, not yet warned shares with an owner
	// address that expire before before. A row that cannot be read is
	// listed with the values read so far.
	SharesToWarn(ctx context.Context, before time.Time) ([]ExpiringShare, error)
	// MarkExpiryWarned records that the share's expiry warning was sent.
	MarkExpiryWarned(ctx context.Context, shareID int64) error
	// RetiredShareIDs lists shares that are not active and expired (or,
	// without expiry, were created) before before. Unreadable rows are listed
	// as 0.
	RetiredShareIDs(ctx context.Context, before time.Time) ([]int64, error)
	// StaleUploadIDs lists upload sessions created before before (UTC
	// text). Unreadable rows are listed as "".
	StaleUploadIDs(ctx context.Context, before string) ([]string, error)
	// CountStaleUpload is 1 when upload session id still exists and was
	// created before before, else 0.
	CountStaleUpload(ctx context.Context, id, before string) (int, error)
	// PruneExpiredCredentials removes expired revoked access tokens,
	// verification attempts, refresh tokens, spent refresh tokens, reset
	// links, verification codes and used or expired MFA reset requests, in
	// that order; every step is attempted and errors are ignored.
	PruneExpiredCredentials(ctx context.Context, now time.Time)
	// PruneDownloads removes download records created before before (UTC
	// text).
	PruneDownloads(ctx context.Context, before string) error
	// RemoveUnverifiedRegistrations deletes pending self-registrations with
	// a password, unverified, created before before (UTC text), without
	// provider links, shares or uploads, and returns them. Unreadable rows
	// are skipped; on an error the accounts read so far are returned with it.
	RemoveUnverifiedRegistrations(ctx context.Context, before string) ([]RemovedAccount, error)
	// RemoveExpiredLinkGuests deletes guest accounts of open-link
	// invitations that expired unused before now and have no uploads, and
	// returns them (as RemoveUnverifiedRegistrations).
	RemoveExpiredLinkGuests(ctx context.Context, now time.Time) ([]RemovedAccount, error)
	// RemoveOrphanedLinkInvites deletes expired, unused open-link
	// invitations whose guest account no longer exists.
	RemoveOrphanedLinkInvites(ctx context.Context, now time.Time) error
}

// ExportSection names one table of the personal data export.
type ExportSection string

const (
	ExportLinkedLogins    ExportSection = "linked_logins"
	ExportShares          ExportSection = "shares"
	ExportShareFiles      ExportSection = "share_files"
	ExportDownloadHistory ExportSection = "download_history"
	ExportInvites         ExportSection = "invites"
	ExportSessions        ExportSection = "sessions"
	ExportAuditRecords    ExportSection = "audit_records"
)

// PersonalDataRepository reads the account data of the personal data export.
type PersonalDataRepository interface {
	// Terms returns the accepted terms version and time (nil when none).
	Terms(ctx context.Context, userID int64) (version string, at *time.Time, err error)
	// TOTPCreated returns when the account's confirmed authenticator app was
	// set up; ErrNotFound when it has none.
	TOTPCreated(ctx context.Context, userID int64) (*time.Time, error)
	// Section returns the rows of one export section as objects with fixed
	// keys (limit bounds ExportAuditRecords). Values are strings, numbers,
	// nil or (times) RFC 3339 UTC text; flags are returned as the database
	// stores them. Unreadable rows are skipped; a failing query gives an
	// empty list.
	Section(ctx context.Context, s ExportSection, userID int64, limit int) []map[string]any
}

// SeedData is the default content of a new tenant database: settings with
// their groups (templates included), bundled themes and built-in mail
// languages. Core produces it (store.DefaultSeed) and every Store adapter
// stores the parts that are missing, so all backends start from the same rows.
type SeedData struct {
	Settings      []Setting
	Themes        []ThemeRecord // ID and Active are kept when > 0 / true
	MailLanguages []MailLanguage
}
