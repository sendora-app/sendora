// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sendora-app/sendora/internal/ports"
)

func TestTenantNames(t *testing.T) {
	n, err := TenantNamesFor("abcdefghijklmnopqrstuvwxyz")
	if err != nil || n.Database != "t_abcdefghijklmnopqrstuvwxyz" || n.Owner != n.Database+"_owner" || n.App != n.Database+"_app" {
		t.Fatalf("TenantNamesFor = %+v, %v", n, err)
	}
	for _, bad := range []string{"", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abc", "abcdefghijklmnopqrstuvwxy1", `abcdefghijklmnopqrstuvwx"y`} {
		if _, err := TenantNamesFor(bad); err == nil {
			t.Errorf("TenantNamesFor(%q) accepted", bad)
		}
	}
	if id, ok := TenantIDFromDatabase(n.Database); !ok || id != "abcdefghijklmnopqrstuvwxyz" {
		t.Fatal("TenantIDFromDatabase does not invert TenantNamesFor")
	}
	if _, ok := TenantIDFromDatabase("t_x"); ok {
		t.Fatal("TenantIDFromDatabase accepted a short name")
	}
	if ConnectionLimit(2) != 8 {
		t.Fatal("ConnectionLimit(2) != 3·2+2")
	}
}

func TestScramVerifierFormat(t *testing.T) {
	v, err := scramVerifier("secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v, "SCRAM-SHA-256$4096:") || strings.Count(v, "$") != 2 || strings.Count(v, ":") != 2 || strings.ContainsAny(v, "' ") {
		t.Fatalf("verifier %q", v)
	}
	w, _ := scramVerifier("secret")
	if v == w {
		t.Fatal("verifiers share a salt")
	}
}

func TestServiceLogin(t *testing.T) {
	for _, ok := range []string{"sendora_provisioner", "sendora_monitor", "streaming_replica", "cnpg_pooler_pgbouncer", "postgres", "t_abcdefghijklmnopqrstuvwxyz_app", "t_abcdefghijklmnopqrstuvwxyz_ro"} {
		if !serviceLogin(ok) {
			t.Errorf("%s is a service role", ok)
		}
	}
	for _, bad := range []string{"app", "sendora", "t_abcdefghijklmnopqrstuvwxyz_owner", "t_abc_app", "dba"} {
		if serviceLogin(bad) {
			t.Errorf("%s is not a service role", bad)
		}
	}
	if maxTenants(200, 2) != 23 {
		t.Errorf("maxTenants(200, 2) = %d", maxTenants(200, 2))
	}
}

// Live tenant tests need a cluster prepared per design 3.2 (#9, #10, #16,
// #20): SENDORA_TEST_PG_PROVISIONER_DSN connects as sendora_provisioner
// directly (database postgres), SENDORA_TEST_PG_POOLER_DSN names the rw
// pooler (host, port, TLS; no user).
const (
	ProvisionerDSNEnv = "SENDORA_TEST_PG_PROVISIONER_DSN"
	PoolerDSNEnv      = "SENDORA_TEST_PG_POOLER_DSN"
)

func liveTenantEnv(t *testing.T) (*pgx.ConnConfig, *pgx.ConnConfig) {
	t.Helper()
	pd, pl := os.Getenv(ProvisionerDSNEnv), os.Getenv(PoolerDSNEnv)
	if pd == "" || pl == "" {
		t.Skip(ProvisionerDSNEnv + " and " + PoolerDSNEnv + " are not set")
	}
	direct, err := pgx.ParseConfig(pd)
	if err != nil {
		t.Fatal(err)
	}
	pooler, err := pgx.ParseConfig(pl)
	if err != nil {
		t.Fatal(err)
	}
	return direct, pooler
}

// TestLiveTenantIsolation creates two tenants, uses one through the pooler
// with its app role, checks that it cannot reach the other tenant's database
// (through the pooler or directly) and that the app role's privileges are
// DML only, migrates both (fan-out), and drops them.
func TestLiveTenantIsolation(t *testing.T) {
	direct, pooler := liveTenantEnv(t)
	ctx := context.Background()
	p := NewProvisioner(direct)
	a := TenantSpec{ID: randomTenantID(), AppPassword: randomPassword(), ConnectionLimit: ConnectionLimit(2)}
	b := TenantSpec{ID: randomTenantID(), AppPassword: randomPassword(), ConnectionLimit: ConnectionLimit(2)}
	t.Cleanup(func() {
		for _, id := range []string{a.ID, b.ID} {
			if err := p.DropTenant(context.Background(), id); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
		p.Close()
	})
	for _, s := range []TenantSpec{a, b} {
		if err := p.CreateTenant(ctx, s); err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
	}
	// Resuming an existing tenant is harmless.
	if err := p.CreateTenant(ctx, a); err != nil {
		t.Fatalf("CreateTenant again: %v", err)
	}
	na, _ := TenantNamesFor(a.ID)
	nb, _ := TenantNamesFor(b.ID)

	dbA, err := OpenTenantApp(pooler, a.ID, a.AppPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer dbA.Close()
	st := New(dbA)
	if err := st.Settings().Set(ctx, "k", "tenant-a"); err != nil {
		t.Fatalf("app write through the pooler: %v", err)
	}
	tx, err := st.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Users().Create(ctx, ports.NewUser{Username: "alice", Language: "en", UILanguage: "en"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); ports.OutcomeOf(err) != ports.Committed {
		t.Fatalf("commit through the pooler: %v", err)
	}
	if v, err := st.Settings().Get(ctx, "k"); err != nil || v != "tenant-a" {
		t.Fatalf("read back = %q, %v", v, err)
	}

	// Isolation: A's role reaches neither B's database through the pooler
	// nor its own database directly.
	cross := pooler.Copy()
	cross.User, cross.Password, cross.Database = na.App, a.AppPassword, nb.Database
	if c, err := connect(ctx, cross); err == nil {
		c.Close(ctx)
		t.Fatalf("%s connected to %s through the pooler", na.App, nb.Database)
	} else {
		t.Logf("cross-database via pooler refused: %s", short(err))
	}
	dir := direct.Copy()
	dir.User, dir.Password, dir.Database = na.App, a.AppPassword, na.Database
	if c, err := connect(ctx, dir); err == nil {
		c.Close(ctx)
		t.Fatalf("%s connected directly", na.App)
	} else if sqlState(err) != "28000" {
		t.Fatalf("direct connect: %v, want 28000", err)
	}
	dir.Database = nb.Database
	if c, err := connect(ctx, dir); err == nil {
		c.Close(ctx)
		t.Fatalf("%s connected directly to %s", na.App, nb.Database)
	}

	// The app role has DML only.
	for stmt, want := range map[string]string{
		`CREATE TABLE sendora.x (a int)`:                            "42501",
		`UPDATE audit_log SET hash = hash`:                          "42501",
		`DELETE FROM schema_migrations`:                             "42501",
		`TRUNCATE settings`:                                         "42501",
		`ALTER TABLE settings ADD COLUMN x int`:                     "42501",
		`CREATE TEMP TABLE x (a int)`:                               "42501", // no TEMP on the database
		`SELECT sendora.audit_log_guard()`:                          "42501", // EXECUTE revoked from PUBLIC
		`SELECT count(*) FROM ` + nb.Database + `.sendora.settings`: "0A000", // cross-database reference
	} {
		_, err := dbA.ExecContext(ctx, stmt)
		if got := sqlState(err); got != want {
			t.Errorf("%s: %v (SQLSTATE %q), want %s", stmt, err, got, want)
		}
	}
	var src, val string
	if err := dbA.QueryRowContext(ctx, `SELECT setting, source FROM pg_settings WHERE name='temp_file_limit'`).Scan(&val, &src); err != nil {
		t.Fatal(err)
	}
	t.Logf("temp_file_limit as %s: %s kB, source=%s", na.App, val, src)
	if val != "1048576" {
		t.Errorf("temp_file_limit = %s kB", val)
	}

	// Fan-out.
	res := p.MigrateTenants(ctx, []string{a.ID, b.ID})
	last := Migrations(TenantSchema)[len(Migrations(TenantSchema))-1].Version
	for _, r := range res {
		if r.Err != nil || len(r.Versions) == 0 || r.Versions[len(r.Versions)-1] != last {
			t.Fatalf("MigrateTenants %s: %v %v", r.ID, r.Versions, r.Err)
		}
	}
	ids, err := p.Tenants(ctx)
	if err != nil || !slices.Contains(ids, a.ID) || !slices.Contains(ids, b.ID) {
		t.Fatalf("Tenants = %v, %v", ids, err)
	}

	// Drop A while its pool may still hold a server connection.
	if err := p.DropTenant(ctx, a.ID); err != nil {
		t.Fatalf("DropTenant: %v", err)
	}
	if ids, _ := p.Tenants(ctx); slices.Contains(ids, a.ID) {
		t.Fatal("dropped tenant still listed")
	}
	if ok, _ := p.roleExists(ctx, na.App); ok {
		t.Fatal("app role survived the drop")
	}
	if _, err := st.Settings().Get(ctx, "k"); err == nil || errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("the dropped tenant still answers: %v", err)
	}
	if err := p.DropTenant(ctx, a.ID); err != nil {
		t.Fatalf("DropTenant of a missing tenant: %v", err)
	}
}

// TestLiveTenantSuspension: SetTenantLogin(false) ends the app role's open
// connections through the pooler and refuses new ones; TenantLogins reports
// it; SetTenantLogin(true) lets the role in again (design 4.6, M11).
func TestLiveTenantSuspension(t *testing.T) {
	direct, pooler := liveTenantEnv(t)
	ctx := context.Background()
	p := NewProvisioner(direct)
	spec := TenantSpec{ID: randomTenantID(), AppPassword: randomPassword(), ConnectionLimit: ConnectionLimit(2)}
	t.Cleanup(func() {
		if err := p.DropTenant(context.Background(), spec.ID); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		p.Close()
	})
	if err := p.CreateTenant(ctx, spec); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	n, _ := TenantNamesFor(spec.ID)
	app := pooler.Copy()
	app.User, app.Password, app.Database = n.App, spec.AppPassword, n.Database
	open, err := connect(ctx, app)
	if err != nil {
		t.Fatalf("app role through the pooler: %v", err)
	}
	defer open.Close(ctx)
	if logins, err := p.TenantLogins(ctx); err != nil || !logins[spec.ID] {
		t.Fatalf("TenantLogins before suspension: %v, %v", logins[spec.ID], err)
	}

	if err := p.SetTenantLogin(ctx, spec.ID, false); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if err := p.SetTenantLogin(ctx, spec.ID, false); err != nil {
		t.Fatalf("suspend again (idempotent): %v", err)
	}
	if logins, _ := p.TenantLogins(ctx); logins[spec.ID] {
		t.Fatal("TenantLogins reports LOGIN after suspension")
	}
	// The open session's server connection was terminated: its next query fails.
	var one int
	if err := open.QueryRow(ctx, "SELECT 1").Scan(&one); err == nil {
		t.Fatal("open connection still served after suspension")
	} else {
		t.Logf("open connection after suspension: %s", short(err))
	}
	if c, err := connect(ctx, app); err == nil {
		var x int
		qerr := c.QueryRow(ctx, "SELECT 1").Scan(&x)
		c.Close(ctx)
		if qerr == nil {
			t.Fatal("new connection served after suspension")
		}
		t.Logf("new connection after suspension: %s", short(qerr))
	} else {
		t.Logf("new connection after suspension: %s", short(err))
	}

	if err := p.SetTenantLogin(ctx, spec.ID, true); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if logins, _ := p.TenantLogins(ctx); !logins[spec.ID] {
		t.Fatal("TenantLogins reports NOLOGIN after resume")
	}
	// The pooler may need a moment for a fresh server connection: after the
	// refused logins of the suspension PgBouncer keeps serving its cached
	// login error until server_login_retry (default 15 s) has passed.
	var c *pgx.Conn
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if c, err = connect(ctx, app); err == nil {
			if err = c.QueryRow(ctx, "SELECT 1").Scan(&one); err == nil {
				break
			}
			c.Close(ctx)
			c = nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	if c == nil {
		t.Fatalf("app role refused after resume: %v", err)
	}
	c.Close(ctx)
	if err := p.SetTenantLogin(ctx, "not-a-tenant-id", true); err == nil {
		t.Fatal("invalid tenant id accepted")
	}
}
