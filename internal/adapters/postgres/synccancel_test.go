// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/sendora-app/sendora/internal/ports"
)

// TestLiveSyncCancelWarning checks whether the "canceling wait for
// synchronous replication" WARNING reaches the client directly and through
// PgBouncer in transaction mode (design 4.1, verified in phase 2). It needs
// SENDORA_TEST_PG_SYNC_CANCEL=1 and WAL replay paused on every standby
// (break-glass, pg_wal_replay_pause()), so that a commit with
// synchronous_commit = remote_apply waits until a cancel request (the
// protocol message pgx sends; PgBouncer forwards it to the server) ends the
// wait. statement_timeout cannot do this: PostgreSQL disables it before
// COMMIT. Other sessions (remote flush) are not affected.
func TestLiveSyncCancelWarning(t *testing.T) {
	if os.Getenv("SENDORA_TEST_PG_SYNC_CANCEL") != "1" {
		t.Skip("SENDORA_TEST_PG_SYNC_CANCEL is not set (needs standby replay paused)")
	}
	direct, pooler := liveTenantEnv(t)
	ctx := context.Background()
	p := NewProvisioner(direct)
	a := TenantSpec{ID: randomTenantID(), AppPassword: randomPassword(), ConnectionLimit: ConnectionLimit(2)}
	t.Cleanup(func() {
		if err := p.DropTenant(context.Background(), a.ID); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		p.Close()
	})
	if err := p.CreateTenant(ctx, a); err != nil {
		t.Fatal(err)
	}
	na, _ := TenantNamesFor(a.ID)

	// Raw: which notices does a client see on COMMIT?
	raw := func(name string, cfg *pgx.ConnConfig, setup ...string) []string {
		cfg = cfg.Copy()
		var mu sync.Mutex
		var seen []string
		cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
			mu.Lock()
			seen = append(seen, n.Severity+": "+n.Message)
			mu.Unlock()
		}
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		defer conn.Close(ctx)
		stmts := append([]string{`BEGIN`}, setup...)
		stmts = append(stmts, `SET LOCAL synchronous_commit = remote_apply`,
			`INSERT INTO sendora.settings(key, value) VALUES ('sync-' || pg_backend_pid(), 'x') ON CONFLICT DO NOTHING`)
		for _, s := range stmts {
			if _, err := conn.Exec(ctx, s); err != nil {
				t.Fatalf("%s: %s: %v", name, s, err)
			}
		}
		stop := cancelAfter(conn.PgConn())
		tag, err := conn.Exec(ctx, `COMMIT`)
		stop()
		mu.Lock()
		defer mu.Unlock()
		t.Logf("%s: COMMIT tag=%q err=%v notices=%q", name, tag.String(), err, seen)
		return seen
	}
	ownerDirect := direct.Copy()
	ownerDirect.Database = na.Database
	directSeen := raw("direct (provisioner as owner)", ownerDirect, `SET LOCAL ROLE `+ident(na.Owner))
	app := pooler.Copy()
	app.User, app.Password, app.Database = na.App, a.AppPassword, na.Database
	poolerSeen := raw("pooler (app role)", app)

	has := func(s []string) bool {
		for _, m := range s {
			if strings.Contains(m, syncCancelMessage) {
				return true
			}
		}
		return false
	}
	if !has(directSeen) {
		t.Fatal("no sync-cancel warning on the direct connection: is standby replay paused?")
	}
	t.Logf("RESULT: warning forwarded by PgBouncer = %v", has(poolerSeen))

	// The adapter's classification through the pooler.
	db, _ := OpenTenantApp(pooler, a.ID, a.AppPassword)
	defer db.Close()
	st := New(db)
	tx, err := st.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	q := tx.(*Tx).q
	if _, err := q.ExecContext(ctx, `SET LOCAL synchronous_commit = remote_apply`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Settings().Set(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	stop := cancelAfter(tx.(*Tx).pg)
	err = tx.Commit()
	stop()
	t.Logf("RESULT: Tx.Commit through the pooler: outcome=%v err=%v", ports.OutcomeOf(err), err)
	if has(poolerSeen) && ports.OutcomeOf(err) != ports.Unknown {
		t.Fatalf("warning forwarded but outcome %v", ports.OutcomeOf(err))
	}
}

// cancelAfter sends a cancel request for pg after two seconds unless stop is
// called first.
func cancelAfter(pg *pgconn.PgConn) (stop func()) {
	t := time.AfterFunc(2*time.Second, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pg.CancelRequest(ctx)
	})
	return func() { t.Stop() }
}
