// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Cluster checklist self-test (docs/cluster/DESIGN.md 3.2 "Checked" column,
// 5.2a item 5). The controller runs it at start and after each tenant
// creation; "sendora db cluster-check" runs it on demand. Any FAIL stops the
// controller from serving that cluster.

// Check statuses.
const (
	CheckPass = "PASS"
	CheckWarn = "WARN"
	CheckFail = "FAIL"
	CheckSkip = "SKIP"
)

// CheckResult is one line of the checklist report.
type CheckResult struct {
	ID     string `json:"id"` // checklist number of design 3.2 (or section)
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// CheckConfig is what the self-test connects with. Every connection must use
// sslmode=verify-full.
type CheckConfig struct {
	Direct   *pgx.ConnConfig // sendora_provisioner over the -rw service
	Monitor  *pgx.ConnConfig // sendora_monitor, database postgres (optional)
	Pooler   *pgx.ConnConfig // rw pooler: host, port, TLS (user/db filled in)
	PoolerRO *pgx.ConnConfig // ro pooler (optional)
	Poolers  int             // PgBouncer instances per pooler (P, design 9.3)
	Tenants  int             // tenants planned on this cluster (T)
	// AllowLoginRoles are extra LOGIN roles reported as WARN instead of FAIL
	// (for example the bootstrap owner of a test cluster).
	AllowLoginRoles []string
}

// Failed reports whether any result is a FAIL.
func Failed(rs []CheckResult) bool {
	return slices.ContainsFunc(rs, func(r CheckResult) bool { return r.Status == CheckFail })
}

type checker struct {
	cfg CheckConfig
	out []CheckResult
}

func (c *checker) add(id, name, status, format string, a ...any) {
	c.out = append(c.out, CheckResult{ID: id, Name: name, Status: status, Detail: fmt.Sprintf(format, a...)})
}

func connect(ctx context.Context, cfg *pgx.ConnConfig) (*pgx.Conn, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return pgx.ConnectConfig(cctx, cfg)
}

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

func verifyFull(cfg *pgx.ConnConfig) bool {
	return cfg != nil && cfg.TLSConfig != nil && !cfg.TLSConfig.InsecureSkipVerify && cfg.TLSConfig.ServerName != "" && len(cfg.Fallbacks) == 0
}

// randomTenantID returns a fresh tenant ID for the ephemeral self-test tenants.
func randomTenantID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))[:26]
}

func randomPassword() string {
	b := make([]byte, 24)
	rand.Read(b)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// ClusterCheck runs the checklist against one CNPG cluster. It creates two
// ephemeral tenants (and drops them again) for the two-way pg_hba test.
func ClusterCheck(ctx context.Context, cfg CheckConfig) []CheckResult {
	if cfg.Poolers <= 0 {
		cfg.Poolers = 2
	}
	if cfg.Tenants <= 0 {
		cfg.Tenants = 100
	}
	c := &checker{cfg: cfg}
	if !verifyFull(cfg.Direct) || !verifyFull(cfg.Pooler) {
		c.add("8", "TLS (client side)", CheckFail, "direct and pooler connections must use sslmode=verify-full with a CA")
		return c.out
	}
	conn, err := connect(ctx, cfg.Direct)
	if err != nil {
		c.add("10", "provisioner connects", CheckFail, "%v", err)
		return c.out
	}
	defer conn.Close(context.Background())
	c.checkTLS(ctx, conn)
	c.checkSync(ctx, conn)
	c.checkRoles(ctx, conn)
	c.checkTCP(ctx, conn)
	c.checkMaxConnections(ctx, conn)
	c.checkTemplate(ctx)
	c.checkLoginRoles(ctx, conn)
	c.checkMonitor(ctx)
	c.checkTenants(ctx)
	return c.out
}

func (c *checker) checkTLS(ctx context.Context, conn *pgx.Conn) {
	var ssl bool
	var version string
	err := conn.QueryRow(ctx, `SELECT ssl, COALESCE(version,'') FROM pg_stat_ssl WHERE pid = pg_backend_pid()`).Scan(&ssl, &version)
	switch {
	case err != nil:
		c.add("8", "TLS", CheckFail, "%v", err)
	case !ssl:
		c.add("8", "TLS", CheckFail, "connection is not encrypted")
	case version != "TLSv1.3":
		c.add("8", "TLS", CheckWarn, "verify-full ok, protocol %s (TLSv1.3 expected)", version)
	default:
		c.add("8", "TLS", CheckPass, "verify-full against the cluster CA, %s", version)
	}
	plain := c.cfg.Direct.Copy()
	plain.TLSConfig, plain.Fallbacks = nil, nil
	if pc, err := connect(ctx, plain); err == nil {
		pc.Close(context.Background())
		c.add("8", "plaintext refused", CheckFail, "a connection without TLS was accepted")
	} else {
		c.add("8", "plaintext refused", CheckPass, "SQLSTATE %s", sqlState(err))
	}
}

func (c *checker) checkSync(ctx context.Context, conn *pgx.Conn) {
	var names, commit string
	if err := conn.QueryRow(ctx, `SELECT current_setting('synchronous_standby_names'), current_setting('synchronous_commit')`).Scan(&names, &commit); err != nil {
		c.add("3", "synchronous replication", CheckFail, "%v", err)
		return
	}
	if !strings.HasPrefix(names, "ANY 1 (") || (commit != "on" && commit != "remote_apply") {
		c.add("3", "synchronous replication", CheckFail, "synchronous_standby_names=%q synchronous_commit=%s (want ANY 1 (...), on)", names, commit)
		return
	}
	c.add("3", "synchronous replication", CheckPass, "synchronous_standby_names=%q synchronous_commit=%s", names, commit)
}

func (c *checker) checkRoles(ctx context.Context, conn *pgx.Conn) {
	var createdb, createrole, super, repl, bypass, tfl, wm, mon bool
	err := conn.QueryRow(ctx, `SELECT rolcreatedb, rolcreaterole, rolsuper, rolreplication, rolbypassrls,
		has_parameter_privilege(current_user, 'temp_file_limit', 'SET WITH GRANT OPTION'),
		has_parameter_privilege(current_user, 'work_mem', 'SET WITH GRANT OPTION'),
		COALESCE((SELECT pg_has_role('sendora_monitor', 'pg_monitor', 'MEMBER') WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sendora_monitor')), false)
		FROM pg_roles WHERE rolname = current_user`).Scan(&createdb, &createrole, &super, &repl, &bypass, &tfl, &wm, &mon)
	if err != nil {
		c.add("10", "managed roles", CheckFail, "%v", err)
		return
	}
	var bad []string
	if !createdb || !createrole {
		bad = append(bad, "provisioner lacks CREATEDB/CREATEROLE")
	}
	if super || repl || bypass {
		bad = append(bad, "provisioner is SUPERUSER, REPLICATION or BYPASSRLS")
	}
	if !tfl || !wm {
		bad = append(bad, "provisioner lacks SET ON PARAMETER temp_file_limit, work_mem WITH GRANT OPTION")
	}
	if !mon {
		bad = append(bad, "sendora_monitor is not a member of pg_monitor")
	}
	if len(bad) > 0 {
		c.add("10", "managed roles", CheckFail, "%s", strings.Join(bad, "; "))
		return
	}
	c.add("10", "managed roles", CheckPass, "provisioner CREATEDB CREATEROLE, not superuser/replication, SET ON PARAMETER with grant option; monitor in pg_monitor")
}

func (c *checker) checkTCP(ctx context.Context, conn *pgx.Conn) {
	want := map[string]string{"tcp_keepalives_idle": "30", "tcp_keepalives_interval": "10", "tcp_keepalives_count": "3", "tcp_user_timeout": "30000"}
	rows, err := conn.Query(ctx, `SELECT name, setting FROM pg_settings WHERE name = ANY($1)`, []string{"tcp_keepalives_idle", "tcp_keepalives_interval", "tcp_keepalives_count", "tcp_user_timeout"})
	if err != nil {
		c.add("17", "TCP keepalives", CheckFail, "%v", err)
		return
	}
	got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([2]string, error) {
		var kv [2]string
		return kv, r.Scan(&kv[0], &kv[1])
	})
	if err != nil {
		c.add("17", "TCP keepalives", CheckFail, "%v", err)
		return
	}
	var bad, all []string
	for _, kv := range got {
		all = append(all, kv[0]+"="+kv[1])
		if want[kv[0]] != kv[1] {
			bad = append(bad, fmt.Sprintf("%s=%s (want %s)", kv[0], kv[1], want[kv[0]]))
		}
	}
	slices.Sort(all)
	if len(bad) > 0 || len(got) != len(want) {
		c.add("17", "TCP keepalives", CheckFail, "%s", strings.Join(bad, "; "))
		return
	}
	c.add("17", "TCP keepalives", CheckPass, "%s (this TCP session)", strings.Join(all, " "))
}

func (c *checker) checkMaxConnections(ctx context.Context, conn *pgx.Conn) {
	var maxConn int
	if err := conn.QueryRow(ctx, `SELECT current_setting('max_connections')::int`).Scan(&maxConn); err != nil {
		c.add("12", "max_connections", CheckFail, "%v", err)
		return
	}
	need := int(math.Ceil(1.2 * float64(3*c.cfg.Poolers*c.cfg.Tenants+25)))
	if maxConn < need {
		c.add("12", "max_connections", CheckWarn, "%d < %d needed for P=%d, T=%d (design 9.3); supports up to T=%d", maxConn, need, c.cfg.Poolers, c.cfg.Tenants, maxTenants(maxConn, c.cfg.Poolers))
		return
	}
	c.add("12", "max_connections", CheckPass, "%d >= %d for P=%d, T=%d", maxConn, need, c.cfg.Poolers, c.cfg.Tenants)
}

// maxTenants is the largest T with 1.2·(3·P·T + 25) <= max.
func maxTenants(maxConn, p int) int {
	t := int((float64(maxConn)/1.2 - 25) / float64(3*p))
	return max(t, 0)
}

func extensions(ctx context.Context, cfg *pgx.ConnConfig, init ...string) ([]string, error) {
	conn, err := connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	for _, s := range init {
		if _, err := conn.Exec(ctx, s); err != nil {
			return nil, err
		}
	}
	var ext []string
	err = conn.QueryRow(ctx, `SELECT COALESCE(array_agg(extname::text ORDER BY extname), '{}') FROM pg_extension`).Scan(&ext)
	return ext, err
}

func (c *checker) checkTemplate(ctx context.Context) {
	cfg := c.cfg.Direct.Copy()
	cfg.Database = "template1"
	ext, err := extensions(ctx, cfg)
	switch {
	case err != nil:
		c.add("11", "extensions (template1)", CheckFail, "%v", err)
	case !slices.Equal(ext, []string{"plpgsql"}):
		c.add("11", "extensions (template1)", CheckFail, "template1 has %v (only plpgsql allowed)", ext)
	default:
		c.add("11", "extensions (template1)", CheckPass, "only plpgsql")
	}
}

// serviceLogin reports whether a LOGIN role is one of Sendora's service roles
// or CNPG's internal ones (design 5.1 login policy, 5.2a item 7).
func serviceLogin(name string) bool {
	switch name {
	case "sendora_provisioner", "sendora_monitor", "sendora_platform_app", "sendora_mover",
		"postgres", "streaming_replica", "cnpg_pooler_pgbouncer", "cnpg_metrics_exporter":
		return true
	}
	for _, suffix := range []string{"_app", "_ro"} {
		if base, ok := strings.CutSuffix(name, suffix); ok {
			if _, ok := TenantIDFromDatabase(base); ok {
				return true
			}
		}
	}
	return false
}

func (c *checker) checkLoginRoles(ctx context.Context, conn *pgx.Conn) {
	rows, err := conn.Query(ctx, `SELECT rolname::text FROM pg_roles WHERE rolcanlogin ORDER BY rolname`)
	if err != nil {
		c.add("5.2a", "login roles", CheckFail, "%v", err)
		return
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		c.add("5.2a", "login roles", CheckFail, "%v", err)
		return
	}
	var extra, allowed []string
	for _, n := range names {
		switch {
		case serviceLogin(n):
		case slices.Contains(c.cfg.AllowLoginRoles, n):
			allowed = append(allowed, n)
		default:
			extra = append(extra, n)
		}
	}
	// A superuser must not be reachable over TCP (enableSuperuserAccess:
	// false, final reject): the attempt must be refused by pg_hba, not
	// challenged for a password.
	su := c.cfg.Direct.Copy()
	su.User, su.Password = "postgres", ""
	suConn, suErr := connect(ctx, su)
	if suErr == nil {
		suConn.Close(context.Background())
	}
	switch {
	case suErr == nil || sqlState(suErr) != "28000":
		c.add("7", "superuser over TCP", CheckFail, "postgres over TCP: %v (want SQLSTATE 28000 from pg_hba)", suErr)
	default:
		c.add("7", "superuser over TCP", CheckPass, "refused by pg_hba (28000)")
	}
	switch {
	case len(extra) > 0:
		c.add("5.2a", "login roles", CheckFail, "unexpected LOGIN roles: %s", strings.Join(extra, ", "))
	case len(allowed) > 0:
		c.add("5.2a", "login roles", CheckWarn, "only service roles, plus allowed: %s", strings.Join(allowed, ", "))
	default:
		c.add("5.2a", "login roles", CheckPass, "only Sendora service roles and CNPG internal roles")
	}
}

func (c *checker) checkMonitor(ctx context.Context) {
	if c.cfg.Monitor == nil {
		c.add("1", "instances", CheckSkip, "no monitor credentials")
		return
	}
	conn, err := connect(ctx, c.cfg.Monitor)
	if err != nil {
		c.add("1", "instances", CheckFail, "monitor: %v", err)
		return
	}
	defer conn.Close(context.Background())
	var standbys, quorum, withLSN int
	err = conn.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'streaming'), count(*) FILTER (WHERE sync_state IN ('quorum','sync')), count(flush_lsn) FROM pg_stat_replication`).Scan(&standbys, &quorum, &withLSN)
	switch {
	case err != nil:
		c.add("1", "instances", CheckFail, "%v", err)
	case standbys+1 < 3:
		c.add("1", "instances", CheckWarn, "%d instance(s) streaming (3 recommended)", standbys+1)
	default:
		c.add("1", "instances", CheckPass, "primary + %d streaming standbys (%d quorum)", standbys, quorum)
	}
	if err == nil {
		if withLSN < standbys {
			c.add("10", "monitor sees replication LSNs", CheckFail, "flush_lsn hidden for %d walsender(s) (pg_monitor missing?)", standbys-withLSN)
		} else {
			c.add("10", "monitor sees replication LSNs", CheckPass, "flush_lsn visible for %d walsender(s)", withLSN)
		}
	}
	var archived, failed int64
	var mode string
	if err := conn.QueryRow(ctx, `SELECT current_setting('archive_mode'), archived_count, failed_count FROM pg_stat_archiver`).Scan(&mode, &archived, &failed); err != nil {
		c.add("15", "WAL archiving", CheckFail, "%v", err)
	} else if mode == "off" || archived == 0 {
		c.add("15", "WAL archiving", CheckWarn, "archive_mode=%s, %d archived (backups not configured)", mode, archived)
	} else {
		c.add("15", "WAL archiving", CheckPass, "%d archived, %d failed", archived, failed)
	}
}

// checkTenants is the two-way pg_hba self-test (#9, #20; 5.2a item 5) on two
// ephemeral tenants, plus the checks that need a tenant database.
func (c *checker) checkTenants(ctx context.Context) {
	p := NewProvisioner(c.cfg.Direct)
	defer p.Close()
	x := TenantSpec{ID: randomTenantID(), AppPassword: randomPassword(), ConnectionLimit: ConnectionLimit(c.cfg.Poolers)}
	y := TenantSpec{ID: randomTenantID(), AppPassword: randomPassword(), ConnectionLimit: ConnectionLimit(c.cfg.Poolers)}
	defer func() {
		dctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, s := range []TenantSpec{x, y} {
			if err := p.DropTenant(dctx, s.ID); err != nil {
				c.add("5.2", "drop self-test tenant", CheckFail, "%v", err)
			}
		}
	}()
	for _, s := range []TenantSpec{x, y} {
		if err := p.CreateTenant(ctx, s); err != nil {
			c.add("5.2", "provision self-test tenants", CheckFail, "%v", err)
			return
		}
	}
	nx, _ := TenantNamesFor(x.ID)
	ny, _ := TenantNamesFor(y.ID)
	c.add("5.2", "provision self-test tenants", CheckPass, "%s and %s created (roles, database, schema, migrations, grants)", nx.Database, ny.Database)

	app := func(base *pgx.ConnConfig, s TenantSpec, db string) *pgx.ConnConfig {
		n, _ := TenantNamesFor(s.ID)
		cfg := base.Copy()
		cfg.User, cfg.Password, cfg.Database = n.App, s.AppPassword, db
		return cfg
	}

	// (b) same database through the pooler succeeds.
	same, err := connect(ctx, app(c.cfg.Pooler, x, nx.Database))
	if err != nil {
		c.add("9", "same-database via pooler", CheckFail, "%s to %s: %v", nx.App, nx.Database, err)
	} else {
		var user, db, tfl, src string
		var otherConnect bool
		err = same.QueryRow(ctx, `SELECT current_user::text, current_database()::text, has_database_privilege($1, 'CONNECT')`, ny.Database).Scan(&user, &db, &otherConnect)
		if err == nil {
			// Twice with arguments: protocol-level prepared statements in
			// transaction mode (max_prepared_statements > 0, #16).
			for range 2 {
				if err = same.QueryRow(ctx, `SELECT setting, source FROM pg_settings WHERE name = $1`, "temp_file_limit").Scan(&tfl, &src); err != nil {
					break
				}
			}
		}
		switch {
		case err != nil:
			c.add("9", "same-database via pooler", CheckFail, "%v", err)
		case user != nx.App || db != nx.Database || otherConnect:
			c.add("9", "same-database via pooler", CheckFail, "session %s@%s, CONNECT on other tenant = %v", user, db, otherConnect)
		default:
			c.add("9", "same-database via pooler", CheckPass, "%s@%s through the pooler (verify-full, prepared statements); no CONNECT on %s", user, db, ny.Database)
		}
		if err == nil {
			if tfl == "1048576" {
				c.add("5.2", "temp_file_limit for the app role", CheckPass, "1GB, source=%s", src)
			} else {
				c.add("5.2", "temp_file_limit for the app role", CheckFail, "%s kB, source=%s (want 1GB)", tfl, src)
			}
		}
		c.checkServerTLS(ctx, nx.App)
		same.Close(context.Background())
	}

	// (a) cross-database through the pooler is refused.
	if cross, err := connect(ctx, app(c.cfg.Pooler, x, ny.Database)); err == nil {
		cross.Close(context.Background())
		c.add("9", "cross-database via pooler refused", CheckFail, "%s connected to %s", nx.App, ny.Database)
	} else {
		c.add("9", "cross-database via pooler refused", CheckPass, "%s to %s: %s", nx.App, ny.Database, short(err))
	}
	if c.cfg.PoolerRO != nil {
		if cross, err := connect(ctx, app(c.cfg.PoolerRO, x, ny.Database)); err == nil {
			cross.Close(context.Background())
			c.add("9", "cross-database via ro pooler refused", CheckFail, "%s connected to %s", nx.App, ny.Database)
		} else {
			c.add("9", "cross-database via ro pooler refused", CheckPass, "%s", short(err))
		}
	}

	// (c) the tenant role directly (not from a pooler pod) is refused by
	// pg_hba, for its own database too (#20: only pooler pod addresses).
	if direct, err := connect(ctx, app(c.cfg.Direct, x, nx.Database)); err == nil {
		direct.Close(context.Background())
		c.add("20", "direct tenant connect refused", CheckFail, "%s connected directly to %s", nx.App, nx.Database)
	} else if sqlState(err) != "28000" {
		c.add("20", "direct tenant connect refused", CheckFail, "%s (want SQLSTATE 28000 from pg_hba)", short(err))
	} else {
		c.add("20", "direct tenant connect refused", CheckPass, "%s: pg_hba (28000)", nx.App)
	}

	// (d) an unknown role is refused by pg_hba, not challenged for a password.
	unknown := c.cfg.Direct.Copy()
	unknown.User, unknown.Password, unknown.Database = "sendora_selftest_"+randomTenantID()[:8], "x", nx.Database
	if uc, err := connect(ctx, unknown); err == nil {
		uc.Close(context.Background())
		c.add("9", "unknown role refused", CheckFail, "connected")
	} else if sqlState(err) != "28000" {
		c.add("9", "unknown role refused", CheckFail, "%s (want 28000, not a password challenge)", short(err))
	} else {
		c.add("9", "unknown role refused", CheckPass, "pg_hba (28000), no password challenge")
	}

	// #11 in a tenant database.
	owner := c.cfg.Direct.Copy()
	owner.Database = nx.Database
	if ext, err := extensions(ctx, owner); err != nil {
		c.add("11", "extensions (tenant)", CheckFail, "%v", err)
	} else if !slices.Equal(ext, []string{"plpgsql"}) {
		c.add("11", "extensions (tenant)", CheckFail, "%s has %v", nx.Database, ext)
	} else {
		c.add("11", "extensions (tenant)", CheckPass, "%s: only plpgsql", nx.Database)
	}
}

// checkServerTLS checks, as the monitor, that the pooler's server connection
// for role is encrypted (#16, server side).
func (c *checker) checkServerTLS(ctx context.Context, role string) {
	if c.cfg.Monitor == nil {
		return
	}
	conn, err := connect(ctx, c.cfg.Monitor)
	if err != nil {
		return
	}
	defer conn.Close(context.Background())
	var total, enc int
	if err := conn.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE s.ssl) FROM pg_stat_activity a JOIN pg_stat_ssl s USING (pid) WHERE a.usename = $1`, role).Scan(&total, &enc); err != nil {
		c.add("16", "pooler server-side TLS", CheckFail, "%v", err)
		return
	}
	switch {
	case total == 0:
		c.add("16", "pooler server-side TLS", CheckSkip, "no server connection of %s visible", role)
	case enc < total:
		c.add("16", "pooler server-side TLS", CheckFail, "%d of %d server connections unencrypted", total-enc, total)
	default:
		c.add("16", "pooler server-side TLS", CheckPass, "%d server connection(s) of %s encrypted", total, role)
	}
}

func short(err error) string {
	if s := sqlState(err); s != "" {
		var pg *pgconn.PgError
		errors.As(err, &pg)
		return pg.Severity + " " + s + ": " + pg.Message
	}
	msg := err.Error()
	if len(msg) > 160 {
		msg = msg[:160] + "..."
	}
	return msg
}
