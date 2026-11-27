// SPDX-License-Identifier: AGPL-3.0-or-later

// Package postgres is the Store adapter of the Cluster flavour: PostgreSQL
// (CloudNativePG), one database per tenant plus the platform database
// (docs/cluster/DESIGN.md sections 2A.2, 4.1 and 5). Together with
// internal/adapters/sqlite it is the only place where SQL may appear;
// internal/lint/nosql enforces that.
//
// The adapter speaks database/sql through pgx/v5's stdlib driver, so the
// repositories mirror the SQLite ones method for method (see
// docs/cluster/REPOSITORY-PATTERN.md, "Adding a method to both adapters").
// Statements are written with '?' placeholders and rebound to $n by the
// querier (rebind), which also turns Go booleans into the 0/1 integers both
// schemas use for flags, so personal-data exports emit the same JSON types
// as Community.
//
// Differences from the SQLite adapter that are not visible through the port:
//   - SQLite's single writer serialised every write transaction. Here the
//     methods documented as taking the "write lock" (Lock*, LockToken, ...)
//     take a transaction-scoped advisory lock per database (lockWrite), and
//     the first read of the audit chain head inside a Tx takes the audit
//     append lock (lockAudit), so the former implicit-lock spots stay
//     serialised across replicas (design 4.1).
//   - Times are timestamptz: instants are equal, but values are returned in
//     UTC with microsecond precision (SQLite keeps the writer's offset and
//     nanoseconds). Defaults that SQLite fills with CURRENT_TIMESTAMP are
//     truncated to whole seconds, so RFC 3339 renderings of created_at match.
//   - Text columns use the "C" collation, so ORDER BY and LIKE behave like
//     SQLite's BINARY collation and ASCII-only case folding.
//   - Unique violations (SQLSTATE 23505) are reported as ports.ErrDuplicate
//     and a refused account insert as ports.ErrTenantUserLimit, with the
//     driver's message kept.
//   - Commit outcomes are classified (Tx.Commit, design 4.1).
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/sendora-app/sendora/internal/ports"
)

var (
	_ ports.Store = (*Store)(nil)
	_ ports.Tx    = (*Tx)(nil)
)

// StatementCacheCapacity is the per-connection prepared statement cache. It
// stays below PgBouncer's max_prepared_statements (200, design 3.2 #16).
const StatementCacheCapacity = 100

// OpenDB returns a database handle for cfg with the settings every Sendora
// connection needs: timestamptz values scanned in UTC, a bounded statement
// cache and the notice hook that detects a cancelled synchronous-replication
// wait (commit outcome classification). The caller owns and closes the
// handle. It does not connect; use Ping or Migrate to find out.
func OpenDB(cfg *pgx.ConnConfig) *sql.DB { return openDB(cfg) }

// openDB is OpenDB running init on every new connection (session setup for
// the provisioner's direct, unpooled connections; never through PgBouncer).
func openDB(cfg *pgx.ConnConfig, init ...string) *sql.DB {
	cfg = cfg.Copy()
	cfg.StatementCacheCapacity = StatementCacheCapacity
	prev := cfg.OnNotice
	cfg.OnNotice = func(c *pgconn.PgConn, n *pgconn.Notice) {
		noticeHook(c, n)
		if prev != nil {
			prev(c, n)
		}
	}
	return stdlib.OpenDB(*cfg, stdlib.OptionAfterConnect(func(ctx context.Context, c *pgx.Conn) error {
		c.TypeMap().RegisterType(&pgtype.Type{Name: "timestamptz", OID: pgtype.TimestamptzOID, Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC}})
		for _, stmt := range init {
			if _, err := c.Exec(ctx, stmt); err != nil {
				return err
			}
		}
		return nil
	}))
}

// ---------- querier ----------

// querier is what repositories run on: the database, a transaction or a
// dedicated connection. Every statement passes through rebind.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// pq wraps a database/sql querier: placeholders are rebound, arguments
// normalised and errors classified (classify).
type pq struct {
	raw querier
	// tx is set when raw is a write transaction (Begin); repositories take
	// row-level and advisory locks only then.
	tx bool
}

func (q pq) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	res, err := q.raw.ExecContext(ctx, rebind(query), normArgs(args)...)
	return res, classify(err)
}

func (q pq) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	rows, err := q.raw.QueryContext(ctx, rebind(query), normArgs(args)...)
	return rows, classify(err)
}

// QueryRowContext returns a row whose Scan error is classified as well.
func (q pq) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return q.raw.QueryRowContext(ctx, rebind(query), normArgs(args)...)
}

// scan runs a single-row query and scans it, classifying the error (the
// returned *sql.Row of QueryRowContext cannot carry a wrapped error).
func (q pq) scan(ctx context.Context, query string, args []any, dest ...any) error {
	return classify(q.QueryRowContext(ctx, query, args...).Scan(dest...))
}

var rebindCache sync.Map // query text -> rebound text

// rebind turns '?' placeholders into $1, $2, ... outside quoted literals and
// identifiers. Statements are constants, so results are cached.
func rebind(query string) string {
	if v, ok := rebindCache.Load(query); ok {
		return v.(string)
	}
	var b strings.Builder
	b.Grow(len(query) + 16)
	n := 0
	var quote byte
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '?':
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	out := b.String()
	rebindCache.Store(query, out)
	return out
}

// normArgs maps Go values onto the schema's column types: booleans become
// 0/1 (flags are integer columns, as in SQLite) and nil pointers NULL.
func normArgs(args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case bool:
			out[i] = b2i(v)
		case *bool:
			if v == nil {
				out[i] = nil
			} else {
				out[i] = b2i(*v)
			}
		case *int64:
			if v == nil {
				out[i] = nil
			} else {
				out[i] = *v
			}
		case *string:
			if v == nil {
				out[i] = nil
			} else {
				out[i] = *v
			}
		case *time.Time:
			if v == nil {
				out[i] = nil
			} else {
				out[i] = *v
			}
		default:
			out[i] = a
		}
	}
	return out
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ---------- errors ----------

// SQLSTATEs raised by the schema's own trigger functions (class "SD" is not
// used by PostgreSQL).
const (
	stateTenantUserLimit = "SD001" // tenant_user_limit
	stateEmailInUse      = "SD002" // users_email_guard
)

// classifiedError keeps the driver's message (callers and logs see the same
// text as before) and adds a ports sentinel for errors.Is.
type classifiedError struct {
	kind error
	err  error
}

func (e *classifiedError) Error() string        { return e.err.Error() }
func (e *classifiedError) Unwrap() []error      { return []error{e.kind, e.err} }
func (e *classifiedError) Is(target error) bool { return target == e.kind }

// classify maps "no rows" to ports.ErrNotFound and the SQLSTATEs the port
// promises to type: unique violations and the schema's email guard become
// ports.ErrDuplicate, the tenant user limit ports.ErrTenantUserLimit.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ports.ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505", stateEmailInUse:
			return &classifiedError{kind: ports.ErrDuplicate, err: err}
		case stateTenantUserLimit:
			return &classifiedError{kind: ports.ErrTenantUserLimit, err: err}
		}
	}
	return err
}

// notFound passes errors through classify (kept for the SQLite adapter's
// spelling, so ported repository code reads the same).
func notFound(err error) error { return classify(err) }

// affected returns the rows a statement changed, or its error.
func affected(res sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// changed is affected, reading a failing RowsAffected as 0 (as the SQLite
// adapter does for the 0.2 callers it was taken from).
func changed(res sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

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

func nullInt64(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

// opt is the statement argument of an optional id: NULL or the value.
func opt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// optTime is the statement argument of an optional time: NULL or the value.
func optTime(p *time.Time) any {
	if p == nil {
		return nil
	}
	return *p
}

// ---------- locks ----------

// lockClass is the first key of every Sendora advisory lock ("Sndr").
const lockClass = 0x536E6472

// lock takes the transaction-scoped advisory lock name, scoped to the current
// database and schema (so tenants sharing a server never contend, and neither
// do the conformance suite's per-test schemas). Outside a transaction it is
// released at once, like SQLite's write lock outside BEGIN.
func (q pq) lock(ctx context.Context, name string) error {
	_, err := q.ExecContext(ctx, `SELECT pg_advisory_xact_lock(`+strconv.Itoa(lockClass)+`, hashtext(current_schema() || ':' || ?::text))`, name)
	return err
}

// lockWrite is the counterpart of SQLite's database write lock: the methods
// whose SQLite version is a no-op UPDATE to obtain that lock take it, so the
// read-check-write sequences after them (quota admission, account removal,
// share appends, invite acceptance) stay serialised.
func (q pq) lockWrite(ctx context.Context) error { return q.lock(ctx, "write") }

// lockAudit serialises audit appends: taken by the first read of the chain
// head inside a write transaction.
func (q pq) lockAudit(ctx context.Context) error {
	if !q.tx {
		return nil
	}
	return q.lock(ctx, "audit")
}

// withTx runs fn in the current transaction, or in a new one when q
// autocommits (for methods that need two statements to be atomic).
func (q pq) withTx(ctx context.Context, db *sql.DB, fn func(pq) error) error {
	if q.tx || db == nil {
		return fn(q)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(pq{raw: tx, tx: true}); err != nil {
		return err
	}
	return classify(tx.Commit())
}

// ---------- store, transactions, snapshots ----------

// repos hands out the repositories bound to one querier.
type repos struct {
	q     pq
	db    *sql.DB           // for methods that open their own transaction (withTx)
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
func (r repos) IPBans() ports.IPBanRepository     { return ipBanRepo{q: r.q} }
func (r repos) Users() ports.UserRepository       { return userRepo{q: r.q, db: r.db, codec: r.codec} }
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

// Store implements ports.Store on one PostgreSQL database (schema on the
// connection's search_path).
type Store struct {
	repos
	db *sql.DB
}

// New returns the Store for db (from OpenDB). It does not take ownership:
// closing db stays the caller's job. The schema must be migrated (Migrate).
func New(db *sql.DB) *Store {
	return &Store{repos: repos{q: pq{raw: db}, db: db}, db: db}
}

// SetCodec makes the adapter encrypt and decrypt the encrypted columns with c
// (design 6.5, D39). Call it before the store is used.
func (s *Store) SetCodec(c ports.ColumnCodec) { s.repos.codec = c }

// Begin starts a READ COMMITTED transaction on a dedicated connection. The
// former SQLite implicit-lock spots take explicit locks (package comment).
func (s *Store) Begin(ctx context.Context) (ports.Tx, error) {
	t, err := begin(ctx, s.db)
	if err != nil {
		return nil, err
	}
	return &Tx{repos: repos{q: pq{raw: t.tx, tx: true}, codec: s.codec}, txState: t}, nil
}

// ReadSnapshot runs fn in a REPEATABLE READ, READ ONLY transaction: every
// query of fn sees the snapshot taken by its first statement.
func (s *Store) ReadSnapshot(ctx context.Context, fn func(ports.Repositories) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return classify(err)
	}
	defer tx.Rollback()
	return fn(repos{q: pq{raw: tx}, codec: s.codec})
}

// Tx implements ports.Tx.
type Tx struct {
	repos
	*txState
}

// txState is a write transaction on its own connection, with what commit
// classification needs.
type txState struct {
	ctx  context.Context
	conn *sql.Conn
	tx   *sql.Tx
	pg   *pgconn.PgConn
	done bool
}

func begin(ctx context.Context, db *sql.DB) (*txState, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	t := &txState{ctx: ctx, conn: conn}
	if err := conn.Raw(func(dc any) error {
		if c, ok := dc.(*stdlib.Conn); ok {
			t.pg = c.Conn().PgConn()
		}
		return nil
	}); err != nil {
		conn.Close()
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		conn.Close()
		return nil, classify(err)
	}
	t.tx = tx
	return t, nil
}

// Commit classifies the outcome (design 4.1): nil means committed; an error
// wrapping ports.ErrOutcomeUnknown means the write may or may not survive
// (any error returned by COMMIT, a connection lost after COMMIT was sent, a
// cancelled context after it was sent, or a COMMIT answered with the
// "canceling wait for synchronous replication" warning); any other error
// means nothing was written.
func (t *txState) Commit() error {
	if t.done {
		return sql.ErrTxDone
	}
	t.done = true
	defer t.conn.Close()
	if err := t.ctx.Err(); err != nil {
		t.tx.Rollback()
		return fmt.Errorf("commit not sent: %w", err)
	}
	watch := watchNotices(t.pg)
	err := t.tx.Commit()
	cancelled := watch.stop()
	return commitOutcome(err, cancelled)
}

// commitOutcome turns the result of COMMIT into the port's classification.
func commitOutcome(err error, syncWaitCancelled bool) error {
	switch {
	case err == nil && !syncWaitCancelled:
		return nil
	case err == nil:
		return fmt.Errorf("%w: COMMIT returned with %q", ports.ErrOutcomeUnknown, syncCancelMessage)
	case errors.Is(err, sql.ErrTxDone):
		// database/sql already rolled back (the context ended before
		// COMMIT could be sent).
		return err
	default:
		return &classifiedError{kind: ports.ErrOutcomeUnknown, err: fmt.Errorf("%w (COMMIT sent, outcome unknown)", err)}
	}
}

// Rollback discards the transaction; after Commit it does nothing.
func (t *txState) Rollback() error {
	if t.done {
		return sql.ErrTxDone
	}
	t.done = true
	defer t.conn.Close()
	return t.tx.Rollback()
}

// syncCancelMessage is the warning PostgreSQL sends when the wait for a
// synchronous standby is cancelled after the commit record was written.
const syncCancelMessage = "canceling wait for synchronous replication"

var notices sync.Map // *pgconn.PgConn -> *noticeWatch

type noticeWatch struct {
	pg        *pgconn.PgConn
	mu        sync.Mutex
	cancelled bool
}

func watchNotices(pg *pgconn.PgConn) *noticeWatch {
	w := &noticeWatch{pg: pg}
	if pg != nil {
		notices.Store(pg, w)
	}
	return w
}

func (w *noticeWatch) stop() bool {
	if w.pg != nil {
		notices.Delete(w.pg)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cancelled
}

// noticeHook records the sync-replication cancel warning for a connection
// that is committing.
func noticeHook(c *pgconn.PgConn, n *pgconn.Notice) {
	if !isSyncCancel(n) {
		return
	}
	if v, ok := notices.Load(c); ok {
		w := v.(*noticeWatch)
		w.mu.Lock()
		w.cancelled = true
		w.mu.Unlock()
	}
}

func isSyncCancel(n *pgconn.Notice) bool {
	return n != nil && strings.Contains(n.Message, syncCancelMessage)
}
