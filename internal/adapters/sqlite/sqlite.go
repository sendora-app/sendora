// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sqlite is the Store adapter of the Community flavours: SQLite with
// SQLCipher, one database per tenant (docs/cluster/DESIGN.md section 2A.2).
// Together with internal/adapters/postgres (phase 2) it is the only place
// where SQL may appear; internal/lint/nosql enforces that.
//
// Opening and keying a database (cipher.go), exports, snapshots and
// verification (backup.go), the base schema and seed (schema.go), the
// per-domain migrations (Migrate*) and the inspection of an imported database
// (import.go) are SQLite-specific and live here; internal/store sequences
// them (directories, key files, migration order) and owns the *sql.DB.
// Repositories (New, NewPlatform) work on that *sql.DB.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
	"github.com/sendora-app/sendora/internal/ports"
)

var (
	_ ports.Store = (*Store)(nil)
	_ ports.Tx    = (*Tx)(nil)
)

// querier is what repositories run on: the database or a transaction.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// repos hands out the repositories bound to one querier.
type repos struct {
	q     querier
	codec ports.ColumnCodec // nil: encrypted columns hold plaintext (see ports.ColumnCodec)
}

func (r repos) AuditChain() ports.AuditChainRepository { return auditRepo{q: r.q, codec: r.codec} }
func (r repos) AuditQuery() ports.AuditQueryRepository { return auditQueryRepo{q: r.q, codec: r.codec} }
func (r repos) System() ports.SystemRepository         { return systemRepo{q: r.q, codec: r.codec} }
func (r repos) Settings() ports.SettingsRepository     { return settingsRepo{q: r.q, codec: r.codec} }
func (r repos) Themes() ports.ThemeRepository          { return themeRepo{q: r.q} }
func (r repos) Stats() ports.StatsRepository           { return statsRepo{q: r.q} }
func (r repos) Maintenance() ports.MaintenanceRepository {
	return maintenanceRepo{q: r.q, codec: r.codec}
}
func (r repos) PersonalData() ports.PersonalDataRepository {
	return personalDataRepo{q: r.q, codec: r.codec}
}
func (r repos) Mail() ports.MailRepository                    { return mailRepo{q: r.q, codec: r.codec} }
func (r repos) UITranslations() ports.UITranslationRepository { return uiTranslationRepo{q: r.q} }
func (r repos) ObjectStorage() ports.ObjectStorageRepository {
	return objectStorageRepo{q: r.q, codec: r.codec}
}
func (r repos) StorageMigrations() ports.StorageMigrationRepository {
	return storageMigrationRepo{q: r.q}
}
func (r repos) IPBans() ports.IPBanRepository     { return ipBanRepo{db: r.q} }
func (r repos) Users() ports.UserRepository       { return userRepo{q: r.q, codec: r.codec} }
func (r repos) Sessions() ports.SessionRepository { return sessionRepo{q: r.q, codec: r.codec} }
func (r repos) PasswordResets() ports.PasswordResetRepository {
	return passwordResetRepo{q: r.q, codec: r.codec}
}
func (r repos) EmailVerifications() ports.EmailVerificationRepository {
	return emailVerificationRepo{q: r.q, codec: r.codec}
}
func (r repos) PasswordHistory() ports.PasswordHistoryRepository {
	return passwordHistoryRepo{q: r.q, codec: r.codec}
}
func (r repos) AuthProviders() ports.AuthProviderRepository {
	return authProviderRepo{q: r.q, codec: r.codec}
}
func (r repos) ReverseInvites() ports.ReverseInviteRepository {
	return reverseInviteRepo{q: r.q, codec: r.codec}
}
func (r repos) MFA() ports.MFARepository                     { return mfaRepo{q: r.q} }
func (r repos) SignInHistory() ports.SignInHistoryRepository { return signInHistoryRepo{q: r.q} }
func (r repos) Quota() ports.QuotaRepository                 { return quotaRepo{q: r.q, codec: r.codec} }
func (r repos) Shares() ports.ShareRepository                { return shareRepo{q: r.q, codec: r.codec} }
func (r repos) Downloads() ports.DownloadRepository {
	return downloadSettingRepo{downloadRepo{q: r.q, codec: r.codec}}
}
func (r repos) StorageLocations() ports.StorageLocationRepository {
	return storageLocationRepo{q: r.q}
}
func (r repos) Uploads() ports.UploadRepository             { return uploadRepo{q: r.q, codec: r.codec} }
func (r repos) DownloadMails() ports.DownloadMailRepository { return downloadMailRepo{q: r.q} }
func (r repos) TenantLimits() ports.TenantLimitRepository   { return tenantLimitRepo{q: r.q} }
func (r repos) Idempotency() ports.IdempotencyRepository    { return idempotencyRepo{q: r.q} }
func (r repos) JobFences() ports.JobFenceRepository         { return jobFenceRepo{q: r.q} }
func (r repos) ControlLog() ports.ControlLogRepository      { return controlLogRepo{q: r.q} }
func (r repos) Keyring() ports.KeyringRepository            { return keyringRepo{q: r.q} }

// Store implements ports.Store on one SQLCipher database.
type Store struct {
	repos
	db *sql.DB
}

// New returns the Store for db. It does not take ownership: closing db stays
// the caller's job.
func New(db *sql.DB) *Store {
	return &Store{repos: repos{q: db}, db: db}
}

// SetCodec makes the adapter encrypt and decrypt the encrypted columns with c
// (design 6.5, D39). Call it before the store is used.
func (s *Store) SetCodec(c ports.ColumnCodec) { s.repos.codec = c }

// Begin starts a (deferred) SQLite transaction on the store's connection.
func (s *Store) Begin(ctx context.Context) (ports.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &Tx{repos: repos{q: tx, codec: s.codec}, tx: tx}, nil
}

// Tx implements ports.Tx.
type Tx struct {
	repos
	tx *sql.Tx
}

// Commit classifies the outcome (ports.OutcomeOf): an I/O error during
// COMMIT leaves the database file's state unknown; every other error means
// the transaction did not commit.
func (t *Tx) Commit() error   { return commitOutcome(t.tx.Commit()) }
func (t *Tx) Rollback() error { return t.tx.Rollback() }

func commitOutcome(err error) error {
	var se sqlite3.Error
	if errors.As(err, &se) && se.Code == sqlite3.ErrIoErr {
		return &classifiedError{kind: ports.ErrOutcomeUnknown, err: err}
	}
	return err
}

// classifiedError keeps the driver's message and adds a ports sentinel for
// errors.Is (so callers and logs see the same text as before).
type classifiedError struct {
	kind error
	err  error
}

func (e *classifiedError) Error() string        { return e.err.Error() }
func (e *classifiedError) Unwrap() []error      { return []error{e.kind, e.err} }
func (e *classifiedError) Is(target error) bool { return target == e.kind }

// userInsertErr types the refusals of an account insert: the tenant user
// limit trigger becomes ports.ErrTenantUserLimit, a taken username or email
// address ports.ErrDuplicate. The message is unchanged.
func userInsertErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "tenant user limit"):
		return &classifiedError{kind: ports.ErrTenantUserLimit, err: err}
	case strings.Contains(msg, "UNIQUE constraint failed"), strings.Contains(msg, "email already in use"):
		return &classifiedError{kind: ports.ErrDuplicate, err: err}
	}
	return err
}

// notFound maps the driver's "no rows" to ports.ErrNotFound and passes other
// errors through.
func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ports.ErrNotFound
	}
	return err
}

// affected returns the rows a statement changed, or its error.
func affected(res sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// changed returns the rows a statement changed, or the statement's error. Like
// the 0.2 callers it was taken from, it reads a failing RowsAffected as 0.
func changed(res sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// nullString and nullTime turn nullable scans into port pointers.
func nullString(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}

func nullTime(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time
	return &t
}
