# Repository pattern: moving a domain off direct SQL

How storage access is structured: ports (interfaces) with one adapter per database, held together by a conformance suite.
moves every SQL statement out of `internal/app`, `internal/store`, `internal/platform` and
`internal/dbcli` into repositories behind `internal/ports.Store`. This page is the recipe. The
reference migration is **IP bans** (table `ip_bans`); read its diff alongside this page:

| Piece | File |
|---|---|
| Port: data type + repository interface | `internal/ports/store.go` (`IPBan`, `IPBanRepository`, `Store.IPBans`) |
| SQLite adapter: DDL + queries | `internal/adapters/sqlite/ipbans.go` (`MigrateIPBans`, `ipBanRepo`) |
| Adapter wiring | `internal/adapters/sqlite/sqlite.go` (`Store.IPBans`) |
| Migration hook | `internal/store/ipban.go` (`migrateIPBans` delegates to the adapter) |
| Core code using the port | `internal/app/ipban.go` (`s.St.Repos().IPBans()...`) |
| Contract tests | `internal/conformance/ipbans.go` (`RunIPBans`, registered in `RunStore`) |
| Allowlist | `.nosql-allowlist` (entries for both `ipban.go` files removed: 700 → 695 sites; the list reached 0 and was removed in batch F) |

## Rules

1. **SQL lives only in `internal/adapters/<dialect>`.** Core code (`internal/app`, later
   `internal/core`) calls repository methods; it never sees `*sql.DB`, `*sql.Tx`, `sql.ErrNoRows`
   or SQL text.
2. **The port speaks the domain, not the table.** Methods are named after what the caller needs
   (`Prune(endedBefore, strikeBefore)`, not `DeleteWhere(...)`). Types are plain Go
   (`time.Time`, `int64` IDs, `string`); storage encodings (Unix seconds, `TEXT` timestamps, JSON
   columns) stay inside the adapter.
3. **Behaviour is preserved exactly.** A migration commit is a refactoring: same rows, same
   errors handled the same way (if the old code ignored an `Exec` error, the new code ignores the
   repository error; fixing that is a separate commit), same transaction boundaries, same locking.
4. **Every method has a contract test** in `internal/conformance`, written against the port, so the
   PostgreSQL adapter is held to the same semantics. State precision and ordering in the
   interface comment and test it (for example "one-second precision", "in no particular order").
5. **Context first.** Every repository method takes `ctx context.Context`. Callers without a
   request context pass `context.Background()` until the call chain carries one.
6. **Transactions span repositories through the port, not through `*sql.Tx`.** A unit of work
   inside one repository can be one method. Transactions that interleave core logic with
   several repositories use `Store.Begin(ctx) (Tx, error)`: a `Tx` offers the same repository
   accessors (`tx.Users()`, `tx.Sessions()`, ...) plus `Commit`/`Rollback`, so the 0.2
   transaction boundaries move over unchanged (including early commits). Callers that used
   `DB.Begin()` pass `context.Background()`. Commit-outcome classification (design §4.1) is
   added to `Tx.Commit` with idempotency keys. Never pass `*sql.Tx` around.
7. **No dialect leaks in the port.** `INSERT OR IGNORE`, `ON CONFLICT`, `COLLATE NOCASE`,
   `CURRENT_TIMESTAMP` and `RETURNING` are adapter details. If a caller relies on case-insensitive
   matching or "insert if absent", say so in the method name or comment.

## Steps (one domain per commit)

1. **Find the sites.** `grep -n` the table name across the repository. Include tests that poke
   the table directly;
   they may keep doing so (tests are not linted) but should prefer the repository.
2. **Declare the port.** In `internal/ports` add the data type, the `XxxRepository` interface with
   doc comments stating the contract, and an accessor `Xxx() XxxRepository` on `Store`. One file
   per domain once `store.go` grows (`internal/ports/<domain>.go`).
3. **Implement the SQLite adapter** in `internal/adapters/sqlite/<domain>.go`: move the queries
   verbatim (same SQL text, so behaviour and query plans do not change), and move the domain's
   `CREATE TABLE` / `ALTER TABLE` statements into an exported `MigrateXxx(db *sql.DB) error`. Add
   the field and accessor in `sqlite.go`.
4. **Keep the migration order.** Replace the body of the `internal/store` migration function with
   a call to `sqlite.MigrateXxx(s.DB)` at the same position in the migration sequence. (The whole
   migration sequence moves into the adapter later; until then `internal/store` stays the opener.)
5. **Switch the callers** to `s.St.Repos().Xxx()` (in `internal/app`) or `st.Repos().Xxx()`
   elsewhere. Delete the old `Store` methods once they have no callers.
6. **Write the contract tests** in `internal/conformance/<domain>.go` (`RunXxx`) and register them
   in `RunStore`. Cover: empty state, round trip, replace/update semantics, delete of a missing
   key, boundary conditions of every filter (inclusive or exclusive), and one concurrent case for
   anything that counts, claims or allocates.
7. **Keep the lint green.** There is no allowlist, and
   `go test ./internal/lint/nosql` fails on any SQL call or SQL literal outside
   `internal/adapters`, so a new query outside an adapter is caught in review and in CI.
   Backend-specific work (opening and keying a database, exports, snapshots, migrations, the
   inspection of an imported database) lives in the adapter too, as exported functions that
   `internal/store` sequences. The platform database has its own port, `ports.PlatformStore`
   (contracts in `internal/conformance/platform.go`).
8. **Verify:** `gofmt -l .`, `go vet ./...`, `go test ./internal/conformance ./internal/lint/nosql`,
   the domain's existing tests in `internal/app` / `internal/store`, then `go test ./...`.

## Adding a method to both adapters

Every port method has two implementations, `internal/adapters/sqlite` and
`internal/adapters/postgres`, and the conformance suite runs both
(`SENDORA_TEST_PG_DSN=... go test ./internal/conformance/...`). A new method takes these steps,
in one commit:

1. **Port:** declare the method with its contract (precision, ordering, errors, locking) in
   `internal/ports`.
2. **SQLite:** implement it in the domain's file of `internal/adapters/sqlite`.
3. **PostgreSQL:** implement it in the file of the same name in `internal/adapters/postgres`.
   Write the statement with `?` placeholders (the querier rebinds them to `$n`); booleans are
   passed as Go `bool` (stored as 0/1 like SQLite). Translate the dialect:
   | SQLite | PostgreSQL |
   |---|---|
   | `INSERT OR IGNORE` | `ON CONFLICT DO NOTHING` |
   | `res.LastInsertId()` | `... RETURNING id` with `insertID` |
   | `COLLATE NOCASE` | `lower(col)=lower(?::text COLLATE "C")`, unique index on `lower(col)` |
   | `LIKE` (ASCII case-insensitive) | `ILIKE` (columns are `COLLATE "C"`, so only ASCII folds) |
   | `CURRENT_TIMESTAMP` | `date_trunc('second', now())` (same RFC 3339 text when scanned to a string) |
   | `datetime(col)<?` with UTC text | `col < (?::timestamp AT TIME ZONE 'UTC')` (`utcText`) |
   | `date(col)` | `to_char(col AT TIME ZONE 'UTC','YYYY-MM-DD')` |
   | `SUM(x)` | `COALESCE(SUM(x),0)::bigint` (PostgreSQL returns numeric) |
   | `SUM(a=b)` | `COUNT(*) FILTER (WHERE a=b)` |
   | `json_set` | `jsonb_set(data::jsonb, ...)::text` |
   | no-op `UPDATE t SET id=id` (write lock) | `lockRows`: advisory write lock + `SELECT ... FOR UPDATE` |
   | read-check-insert relying on the single writer | `withTx` + `lockWrite` before the check |
   | `RAISE(ABORT, ...)` trigger | PL/pgSQL trigger with its own SQLSTATE, mapped in `classify` |
   Parameters whose type PostgreSQL cannot infer need a cast: `INSERT ... SELECT ?::text, ...`,
   `?::bigint IS NULL`, `CASE WHEN ?::int<>0`.
4. **Schema:** a new table or column is a **new migration version** in
   `internal/adapters/postgres/schema.go` (never edit a released version) and, for SQLite, an
   additive `Migrate*` step as before.
5. **Contract test:** call the method from `internal/conformance`;
   `TestEveryPortMethodHasConformanceCoverage` fails until you do. Anything that counts, claims
   or allocates also gets a parallel case (see `RunConcurrency`).
6. **Verify:** `go test ./internal/conformance/...` (SQLite) and the same with
   `SENDORA_TEST_PG_DSN` set (each test gets its own scratch schema, `postgres.OpenScratch`).

## Commit checklist

- [ ] No SQL text, `database/sql` type or `sql.ErrNoRows` left in core code for this domain
- [ ] Port methods documented with their contract; conformance tests cover each method
- [ ] Implemented in both adapters; conformance green on SQLite and PostgreSQL
- [ ] Same SQL text in the adapter as before (or a separate, explained commit for changes)
- [ ] Migration called from the same place in the sequence
- [ ] `go test ./internal/lint/nosql` green (no SQL outside `internal/adapters`)
- [ ] All existing tests green without changes to their assertions
