// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/sendora-app/sendora/internal/ports"
)

func TestRebind(t *testing.T) {
	for in, want := range map[string]string{
		`SELECT ? , ?`:                         `SELECT $1 , $2`,
		`x LIKE ? ESCAPE '\' AND y=?`:          `x LIKE $1 ESCAPE '\' AND y=$2`,
		`SELECT '?', "?", ?`:                   `SELECT '?', "?", $1`,
		`jsonb_set(d,'{A}',to_jsonb(?::text))`: `jsonb_set(d,'{A}',to_jsonb($1::text))`,
		`SELECT 1`:                             `SELECT 1`,
	} {
		if got := rebind(in); got != want {
			t.Errorf("rebind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormArgs(t *testing.T) {
	yes := true
	var nilBool *bool
	var nilInt *int64
	n := int64(7)
	got := normArgs([]any{true, false, &yes, nilBool, nilInt, &n, "s"})
	want := []any{int64(1), int64(0), int64(1), nil, nil, int64(7), "s"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("normArgs[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestClassify(t *testing.T) {
	if !errors.Is(classify(sql.ErrNoRows), ports.ErrNotFound) {
		t.Error("no rows is not ErrNotFound")
	}
	dup := classify(&pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"})
	if !errors.Is(dup, ports.ErrDuplicate) || dup.Error() == "" {
		t.Errorf("23505 = %v", dup)
	}
	lim := classify(&pgconn.PgError{Code: stateTenantUserLimit, Message: "tenant user limit reached"})
	if !errors.Is(lim, ports.ErrTenantUserLimit) {
		t.Errorf("tenant limit = %v", lim)
	}
	var pg *pgconn.PgError
	if !errors.As(lim, &pg) {
		t.Error("the driver error is no longer reachable")
	}
	other := errors.New("x")
	if classify(other) != other {
		t.Error("other errors must pass through")
	}
}

func TestCommitOutcome(t *testing.T) {
	cases := []struct {
		err       error
		cancelled bool
		want      ports.CommitOutcome
	}{
		{nil, false, ports.Committed},
		{nil, true, ports.Unknown},                           // sync-replication wait cancelled
		{errors.New("unexpected EOF"), false, ports.Unknown}, // connection lost after COMMIT
		{&pgconn.PgError{Code: "40001"}, false, ports.Unknown},
		{sql.ErrTxDone, false, ports.Failed}, // rolled back before COMMIT was sent
	}
	for _, c := range cases {
		if got := ports.OutcomeOf(commitOutcome(c.err, c.cancelled)); got != c.want {
			t.Errorf("commitOutcome(%v, %v) = %v, want %v", c.err, c.cancelled, got, c.want)
		}
	}
	if !isSyncCancel(&pgconn.Notice{Severity: "WARNING", Message: "canceling wait for synchronous replication due to user request"}) {
		t.Error("sync-cancel warning not recognised")
	}
	if isSyncCancel(&pgconn.Notice{Severity: "NOTICE", Message: "relation exists, skipping"}) {
		t.Error("an unrelated notice counted as sync-cancel")
	}
}

func TestNoticeHookMarksOnlyWatchedConnection(t *testing.T) {
	a, b := &pgconn.PgConn{}, &pgconn.PgConn{}
	w := watchNotices(a)
	n := &pgconn.Notice{Severity: "WARNING", Message: syncCancelMessage}
	noticeHook(b, n)
	if w.cancelled {
		t.Fatal("a notice on another connection marked this commit")
	}
	noticeHook(a, n)
	if !w.stop() {
		t.Fatal("the notice on the committing connection was missed")
	}
	if _, ok := notices.Load(a); ok {
		t.Fatal("stop left the watch registered")
	}
}

// liveScratch opens a scratch schema on SENDORA_TEST_PG_DSN or skips.
func liveScratch(t *testing.T, s Schema) *Scratch {
	t.Helper()
	dsn := os.Getenv("SENDORA_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("SENDORA_TEST_PG_DSN is not set")
	}
	sc, err := OpenScratch(context.Background(), dsn, s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sc.Close() })
	return sc
}

func TestLiveMigrationsAreVersionedAndIdempotent(t *testing.T) {
	for _, s := range []Schema{TenantSchema, PlatformSchema} {
		t.Run(s.String(), func(t *testing.T) {
			sc := liveScratch(t, s)
			ctx := context.Background()
			if err := Migrate(ctx, sc.DB, s); err != nil {
				t.Fatalf("second Migrate: %v", err)
			}
			v, err := AppliedVersions(ctx, sc.DB)
			if err != nil || len(v) != len(Migrations(s)) || v[len(v)-1] != Migrations(s)[len(Migrations(s))-1].Version {
				t.Fatalf("AppliedVersions = %v, %v", v, err)
			}
		})
	}
}

// TestLiveCommitOutcome terminates the transaction's backend before COMMIT
// (the client cannot tell this from a loss after COMMIT was sent) and checks
// the classification, and that a context ended before COMMIT is Failed.
func TestLiveCommitOutcome(t *testing.T) {
	sc := liveScratch(t, TenantSchema)
	ctx := context.Background()
	st := New(sc.DB)

	tx, err := st.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Settings().Set(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := tx.(*Tx).q.scan(ctx, `SELECT pg_backend_pid()`, nil, &pid); err != nil {
		t.Fatal(err)
	}
	var killed bool
	if err := sc.DB.QueryRowContext(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&killed); err != nil || !killed {
		t.Fatalf("pg_terminate_backend = %v, %v", killed, err)
	}
	time.Sleep(100 * time.Millisecond)
	err = tx.Commit()
	if got := ports.OutcomeOf(err); got != ports.Unknown {
		t.Fatalf("commit on a terminated backend: %v (%v), want unknown", got, err)
	}

	cctx, cancel := context.WithCancel(ctx)
	tx, err = st.Begin(cctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Settings().Set(cctx, "k2", "v"); err != nil {
		t.Fatal(err)
	}
	cancel()
	err = tx.Commit()
	if got := ports.OutcomeOf(err); got != ports.Failed {
		t.Fatalf("commit after the context ended: %v (%v), want failed", got, err)
	}
	if _, err := st.Settings().Get(ctx, "k2"); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("a failed commit left its write: %v", err)
	}

	tx, _ = st.Begin(ctx)
	tx.Settings().Set(ctx, "k3", "v")
	if err := tx.Commit(); ports.OutcomeOf(err) != ports.Committed {
		t.Fatalf("clean commit: %v", err)
	}
	if v, _ := st.Settings().Get(ctx, "k3"); v != "v" {
		t.Fatal("committed write missing")
	}
}

// TestLiveCollationAndCase pins the byte order of the sorted listings and the
// full Unicode case folding of the username blind index (NFKC, case-folded).
func TestLiveCollationAndCase(t *testing.T) {
	sc := liveScratch(t, TenantSchema)
	ctx := context.Background()
	st := New(sc.DB)
	for _, name := range []string{"bob", "älva", "Zed", "alice"} {
		if _, err := st.Users().Create(ctx, ports.NewUser{Username: name, Language: "en", UILanguage: "en"}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := st.Users().ListLocal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(func() []string {
		var n []string
		for _, u := range list {
			n = append(n, u.Username)
		}
		return n
	}())
	if got != "[Zed alice bob älva]" {
		t.Fatalf("ListLocal order = %s, want byte order", got)
	}
	if n, _ := st.Users().CountByUsernameFold(ctx, "ÄLVA"); n != 1 {
		t.Fatal("non-ASCII letters were not case-folded")
	}
	if n, _ := st.Users().CountByUsernameFold(ctx, "ZED"); n != 1 {
		t.Fatal("ASCII letters were not case-folded")
	}
}
