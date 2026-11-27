// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sendora-app/sendora/internal/ports"
)

// Per-tenant databases and roles (docs/cluster/DESIGN.md 5.1, 5.2, 5.2a).
//
// Every tenant gets database t_<id> and three roles:
//
//	t_<id>        NOLOGIN group role named like the database, so the pg_hba
//	              line "hostssl samerole all ${podselector:...}" admits
//	              exactly this tenant's roles to exactly this database;
//	t_<id>_owner  NOLOGIN; owns the database, schema sendora and every
//	              object; assumed by the provisioner with SET ROLE;
//	t_<id>_app    LOGIN, member of t_<id>; DML only; used by the web pods
//	              through PgBouncer.
//
// The Provisioner runs as sendora_provisioner over the direct connection
// (controller only; its credentials are never mounted into web pods).

// tenantIDPattern is store.TenantIDPattern (26 lowercase base32 characters);
// repeated here so the adapter does not import the SQLite store.
var tenantIDPattern = regexp.MustCompile(`^[a-z2-7]{26}$`)

// TenantNames are the PostgreSQL object names of one tenant.
type TenantNames struct {
	Database string // t_<id>, also the group role
	Owner    string // t_<id>_owner
	App      string // t_<id>_app
}

// TenantNamesFor returns the names for tenant id, or an error when id is not
// a tenant ID (the names are built into SQL as identifiers).
func TenantNamesFor(id string) (TenantNames, error) {
	if !tenantIDPattern.MatchString(id) {
		return TenantNames{}, errors.New("invalid tenant id")
	}
	db := "t_" + id
	return TenantNames{Database: db, Owner: db + "_owner", App: db + "_app"}, nil
}

// TenantIDFromDatabase is the inverse of TenantNamesFor: the tenant ID of a
// database name, or false.
func TenantIDFromDatabase(name string) (string, bool) {
	id, ok := strings.CutPrefix(name, "t_")
	return id, ok && tenantIDPattern.MatchString(id)
}

// App role defaults (design 5.2). They are defaults, not limits: the role can
// override them for its own session, except temp_file_limit, which needs
// SET ON PARAMETER (the cluster-wide value is the fallback, 3.4).
// Values are SQL (search_path is a list of identifiers, not one literal).
var appRoleDefaults = [][2]string{
	{"search_path", "sendora, pg_catalog"},
	{"statement_timeout", "'15s'"},
	{"idle_in_transaction_session_timeout", "'30s'"},
	{"lock_timeout", "'5s'"},
	{"temp_file_limit", "'1GB'"},
}

// ConnectionLimit is the app role's CONNECTION LIMIT for poolers PgBouncer
// instances: 3·P + 2 (design 9.3).
func ConnectionLimit(poolers int) int { return 3*poolers + 2 }

// TenantSpec describes a tenant database to create.
type TenantSpec struct {
	ID string
	// AppPassword is the app role's password. Only its SCRAM-SHA-256 verifier
	// is sent to the server (the DDL is logged with log_statement=ddl).
	AppPassword string
	// ConnectionLimit of the app role (ConnectionLimit(P)); 0 = unlimited.
	ConnectionLimit int
	// Seed is stored after the migrations when set.
	Seed *ports.SeedData
	// InitKeys runs as the database owner after the migrations and before the
	// seed (column keys and the control log, which the app role cannot write)
	// and returns the column codec the seed is sealed with. It must be
	// idempotent: a resumed provisioning runs it again. A codec that has a
	// Close method is closed when the provisioning is done.
	InitKeys func(ctx context.Context, db *sql.DB) (ports.ColumnCodec, error)
}

// Provisioner creates, migrates and drops tenant databases.
type Provisioner struct {
	cfg *pgx.ConnConfig // sendora_provisioner, direct; Database is replaced
	db  *sql.DB         // database postgres
}

// NewProvisioner returns a provisioner for cfg (the provisioner role over
// the direct -rw service with sslmode=verify-full). It does not connect.
func NewProvisioner(cfg *pgx.ConnConfig) *Provisioner {
	c := cfg.Copy()
	c.Database = "postgres"
	db := OpenDB(c)
	db.SetMaxOpenConns(2)
	return &Provisioner{cfg: cfg.Copy(), db: db}
}

// Close releases the provisioner's connections.
func (p *Provisioner) Close() error { return p.db.Close() }

func ident(s string) string { return pgx.Identifier{s}.Sanitize() }

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func (p *Provisioner) exists(ctx context.Context, query, name string) (bool, error) {
	var ok bool
	err := p.db.QueryRowContext(ctx, query, name).Scan(&ok)
	return ok, err
}

func (p *Provisioner) roleExists(ctx context.Context, name string) (bool, error) {
	return p.exists(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, name)
}

func (p *Provisioner) databaseExists(ctx context.Context, name string) (bool, error) {
	return p.exists(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name)
}

// CreateTenant creates the roles and the database of spec.ID, prepares the
// schema, migrates and seeds it and grants the app role its privileges. It
// resumes a partly created tenant (every step checks or is idempotent).
func (p *Provisioner) CreateTenant(ctx context.Context, spec TenantSpec) error {
	n, err := TenantNamesFor(spec.ID)
	if err != nil {
		return err
	}
	return p.createDatabase(ctx, n, TenantSchema, spec, false)
}

// platformDBPattern limits the platform database name (built into SQL as an
// identifier, and the base of the role names).
var platformDBPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)

// PlatformNames returns the object names of the platform database (design
// 5.1): database and group role <database>, <database>_owner, <database>_app.
func PlatformNames(database string) (TenantNames, error) {
	if !platformDBPattern.MatchString(database) || strings.HasPrefix(database, "t_") {
		return TenantNames{}, errors.New("invalid platform database name")
	}
	return TenantNames{Database: database, Owner: database + "_owner", App: database + "_app"}, nil
}

// EnsurePlatform creates the platform database and its roles when missing
// (resuming a partial creation), migrates it, renews the app role's grants
// and sets the app role's password to appPassword (so a rotated password
// applies at the next controller start). initKeys (see TenantSpec.InitKeys,
// nil for none) gives the database its column keys.
func (p *Provisioner) EnsurePlatform(ctx context.Context, database, appPassword string, connectionLimit int, initKeys func(context.Context, *sql.DB) (ports.ColumnCodec, error)) error {
	n, err := PlatformNames(database)
	if err != nil {
		return err
	}
	return p.createDatabase(ctx, n, PlatformSchema, TenantSpec{AppPassword: appPassword, ConnectionLimit: connectionLimit, InitKeys: initKeys, Seed: &ports.SeedData{Settings: []ports.Setting{{Key: "platform_schema_version", Value: platformSchemaVersion, Group: "system"}}}}, true)
}

// OpenPlatformApp returns the platform database handle of the web and
// controller pods: the platform app role through the pooler.
func OpenPlatformApp(pooler *pgx.ConnConfig, database, password string) (*sql.DB, error) {
	n, err := PlatformNames(database)
	if err != nil {
		return nil, err
	}
	c := pooler.Copy()
	c.Database, c.User, c.Password = n.Database, n.App, password
	return OpenDB(c), nil
}

// DirectConfig returns cfg (the provisioner's direct connection) aimed at
// database: the controller's LISTEN connection on the platform database.
func (p *Provisioner) DirectConfig(database string) *pgx.ConnConfig {
	c := p.cfg.Copy()
	c.Database = database
	return c
}

// createDatabase is CreateTenant for any database of the cluster: roles,
// database, privileges, schema, migrations of schema s, seed and grants.
// With setPassword an existing app role gets spec.AppPassword again.
func (p *Provisioner) createDatabase(ctx context.Context, n TenantNames, s Schema, spec TenantSpec, setPassword bool) error {
	if spec.AppPassword == "" {
		return errors.New("app password required")
	}
	verifier, err := scramVerifier(spec.AppPassword)
	if err != nil {
		return err
	}
	limit := spec.ConnectionLimit
	if limit <= 0 {
		limit = -1
	}
	step := func(what, stmt string) error {
		if _, err := p.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("provision %s: %s: %w", n.Database, what, err)
		}
		return nil
	}
	ensureRole := func(name, attrs string) error {
		ok, err := p.roleExists(ctx, name)
		if err != nil || ok {
			return err
		}
		return step("create role "+name, `CREATE ROLE `+ident(name)+` `+attrs)
	}
	if err := ensureRole(n.Database, "NOLOGIN"); err != nil {
		return err
	}
	if err := ensureRole(n.Owner, "NOLOGIN"); err != nil {
		return err
	}
	// PG 16+: SET is needed for CREATE DATABASE ... OWNER and SET ROLE,
	// INHERIT for GRANT/DROP on the owner's objects.
	if err := step("grant owner", `GRANT `+ident(n.Owner)+` TO CURRENT_USER WITH SET TRUE, INHERIT TRUE`); err != nil {
		return err
	}
	if err := ensureRole(n.App, `LOGIN CONNECTION LIMIT `+strconv.Itoa(limit)+` PASSWORD `+quoteLiteral(verifier)); err != nil {
		return err
	}
	if setPassword {
		if err := step("app password", `ALTER ROLE `+ident(n.App)+` LOGIN CONNECTION LIMIT `+strconv.Itoa(limit)+` PASSWORD `+quoteLiteral(verifier)); err != nil {
			return err
		}
	}
	// The app role inherits CONNECT from its group (membership with INHERIT).
	if err := step("app membership", `GRANT `+ident(n.Database)+` TO `+ident(n.App)+` WITH INHERIT TRUE`); err != nil {
		return err
	}
	// Privileges of the app role (not SET): lets DROP DATABASE ... FORCE and
	// a suspension terminate the app role's backends.
	if err := step("grant app", `GRANT `+ident(n.App)+` TO CURRENT_USER WITH INHERIT TRUE, SET FALSE`); err != nil {
		return err
	}
	for _, d := range appRoleDefaults {
		if err := step("app default "+d[0], `ALTER ROLE `+ident(n.App)+` SET `+d[0]+` = `+d[1]); err != nil {
			return err
		}
	}
	ok, err := p.databaseExists(ctx, n.Database)
	if err != nil {
		return err
	}
	if !ok {
		if err := step("create database", `CREATE DATABASE `+ident(n.Database)+` OWNER `+ident(n.Owner)+` TEMPLATE template1 ENCODING 'UTF8'`); err != nil {
			return err
		}
	}
	for _, s := range []string{
		`REVOKE ALL ON DATABASE ` + ident(n.Database) + ` FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE ` + ident(n.Database) + ` TO ` + ident(n.Database),
		`GRANT CONNECT ON DATABASE ` + ident(n.Database) + ` TO CURRENT_USER`,
	} {
		if err := step("database privileges", s); err != nil {
			return err
		}
	}
	return p.migrate(ctx, n, s, spec.Seed, spec.InitKeys, true)
}

// MigrateTenant applies the pending tenant migrations of id as its owner and
// renews the app role's grants (design 13.2: the controller migrates; web
// pods never do).
func (p *Provisioner) MigrateTenant(ctx context.Context, id string) error {
	n, err := TenantNamesFor(id)
	if err != nil {
		return err
	}
	return p.migrate(ctx, n, TenantSchema, nil, nil, false)
}

// TenantMigration is the result of one tenant in MigrateTenants.
type TenantMigration struct {
	ID       string
	Versions []int // applied versions after the run
	Err      error
}

// MigrateTenants fans the tenant migrations out over ids, one tenant at a
// time (a connection reaches one database; design 9.3 keeps the controller's
// direct pool small). A failing tenant does not stop the others.
func (p *Provisioner) MigrateTenants(ctx context.Context, ids []string) []TenantMigration {
	out := make([]TenantMigration, 0, len(ids))
	for _, id := range ids {
		r := TenantMigration{ID: id}
		if r.Err = p.MigrateTenant(ctx, id); r.Err == nil {
			r.Versions, r.Err = p.TenantVersions(ctx, id)
		}
		out = append(out, r)
		if ctx.Err() != nil {
			break
		}
	}
	return out
}

// Tenants lists the IDs of the tenant databases on the cluster.
func (p *Provisioner) Tenants(ctx context.Context) ([]string, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT datname FROM pg_database WHERE datname LIKE 't\_%' ORDER BY datname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if id, ok := TenantIDFromDatabase(name); ok {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

// TenantVersions returns the applied migration versions of tenant id.
func (p *Provisioner) TenantVersions(ctx context.Context, id string) ([]int, error) {
	n, err := TenantNamesFor(id)
	if err != nil {
		return nil, err
	}
	db := p.ownerDB(n)
	defer db.Close()
	return AppliedVersions(ctx, db)
}

// ownerDB is a single-connection handle on the tenant database whose session
// runs as the owner role with search_path sendora.
func (p *Provisioner) ownerDB(n TenantNames) *sql.DB {
	c := p.cfg.Copy()
	c.Database = n.Database
	db := openDB(c, `SET ROLE `+ident(n.Owner), `SET search_path = sendora, pg_catalog`)
	db.SetMaxOpenConns(1)
	return db
}

// OwnerDB opens a handle on tenant id's database whose sessions run as the
// owner role: the one role that may write the control log and the keyring.
// Controller only; the caller closes it. Tenant key rotation uses it.
func (p *Provisioner) OwnerDB(id string) (*sql.DB, error) {
	n, err := TenantNamesFor(id)
	if err != nil {
		return nil, err
	}
	db := p.ownerDB(n)
	db.SetMaxOpenConns(2)
	return db, nil
}

func (p *Provisioner) migrate(ctx context.Context, n TenantNames, s Schema, seed *ports.SeedData, initKeys func(context.Context, *sql.DB) (ports.ColumnCodec, error), prepare bool) error {
	db := p.ownerDB(n)
	defer db.Close()
	run := func(what string, stmts ...string) error {
		for _, s := range stmts {
			if _, err := db.ExecContext(ctx, s); err != nil {
				return fmt.Errorf("provision %s: %s: %w", n.Database, what, err)
			}
		}
		return nil
	}
	owner, app := ident(n.Owner), ident(n.App)
	if prepare {
		if err := run("schema",
			`DROP SCHEMA IF EXISTS public`,
			`CREATE SCHEMA IF NOT EXISTS sendora AUTHORIZATION `+owner,
			`GRANT USAGE ON SCHEMA sendora TO `+app,
			// Global form: a per-schema REVOKE cannot remove the global
			// default EXECUTE for PUBLIC (ALTER DEFAULT PRIVILEGES notes).
			`ALTER DEFAULT PRIVILEGES FOR ROLE `+owner+` REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`,
			`ALTER DEFAULT PRIVILEGES FOR ROLE `+owner+` IN SCHEMA sendora GRANT USAGE, SELECT ON SEQUENCES TO `+app,
		); err != nil {
			return err
		}
	}
	if err := Migrate(ctx, db, s); err != nil {
		return fmt.Errorf("provision %s: %w", n.Database, err)
	}
	// The keys come first: the seed's setting values are sealed with them.
	var codec ports.ColumnCodec
	if initKeys != nil {
		c, err := initKeys(ctx, db)
		if err != nil {
			return fmt.Errorf("provision %s: keys: %w", n.Database, err)
		}
		if cl, ok := c.(interface{ Close() }); ok {
			defer cl.Close()
		}
		codec = c
	}
	if seed != nil {
		if err := Seed(ctx, db, codec, *seed); err != nil {
			return fmt.Errorf("provision %s: seed: %w", n.Database, err)
		}
	}
	return run("grants", appGrants(owner, app)...)
}

// appGrants are the app role's privileges on the migrated schema (design
// 5.2), renewed after every migration run. Deviation until phase 6: the
// audit purge still runs as DELETE from the app (audit_purge() as SECURITY
// DEFINER comes with audit v2), so audit_log keeps DELETE but not UPDATE.
func appGrants(owner, app string) []string {
	return []string{
		`REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA sendora FROM PUBLIC`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA sendora TO ` + app,
		`REVOKE UPDATE, TRUNCATE ON sendora.audit_log FROM ` + app,
		`REVOKE INSERT, UPDATE, DELETE ON sendora.schema_migrations FROM ` + app,
		`REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON sendora.control_log, sendora.tenant_keyring FROM ` + app,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sendora TO ` + app,
	}
}

// DropTenant removes tenant id: the app role can no longer log in, its
// backends are terminated with the database, then the roles are dropped. It
// succeeds when the tenant does not exist.
func (p *Provisioner) DropTenant(ctx context.Context, id string) error {
	n, err := TenantNamesFor(id)
	if err != nil {
		return err
	}
	if ok, err := p.roleExists(ctx, n.App); err != nil {
		return err
	} else if ok {
		if _, err := p.db.ExecContext(ctx, `ALTER ROLE `+ident(n.App)+` NOLOGIN`); err != nil {
			return fmt.Errorf("drop %s: %w", n.Database, err)
		}
	}
	if err := p.dropDatabase(ctx, n); err != nil {
		return fmt.Errorf("drop %s: %w", n.Database, err)
	}
	for _, s := range []string{
		`DROP ROLE IF EXISTS ` + ident(n.App),
		`DROP ROLE IF EXISTS ` + ident(n.Owner),
		`DROP ROLE IF EXISTS ` + ident(n.Database),
	} {
		if _, err := p.db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("drop %s: %w", n.Database, err)
		}
	}
	return nil
}

// TenantLogins reports, for every tenant app role of the cluster, whether it
// may log in (tenant ID -> LOGIN). One catalog query; the controller compares
// it with the tenants' statuses (SetTenantLogin).
func (p *Provisioner) TenantLogins(ctx context.Context) (map[string]bool, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname LIKE 't\_%\_app'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		var login bool
		if err := rows.Scan(&name, &login); err != nil {
			return nil, err
		}
		if id, ok := TenantIDFromDatabase(strings.TrimSuffix(name, "_app")); ok {
			out[id] = login
		}
	}
	return out, rows.Err()
}

// SetTenantLogin enforces a tenant's suspension in PostgreSQL (design 4.6,
// M11): without login the app role is NOLOGIN and its backends (also the
// pooler's server connections) are terminated, so no replica can use the
// tenant's database whatever its routing cache says; with login the role may
// log in again. Idempotent; a tenant without an app role is left alone.
func (p *Provisioner) SetTenantLogin(ctx context.Context, id string, login bool) error {
	n, err := TenantNamesFor(id)
	if err != nil {
		return err
	}
	if ok, err := p.roleExists(ctx, n.App); err != nil || !ok {
		return err
	}
	if login {
		_, err := p.db.ExecContext(ctx, `ALTER ROLE `+ident(n.App)+` LOGIN`)
		return err
	}
	if _, err := p.db.ExecContext(ctx, `ALTER ROLE `+ident(n.App)+` NOLOGIN`); err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1`, n.App)
	return err
}

// dropDatabase drops the tenant database. New connections are refused first
// (also CNPG's own short-lived ones, which DROP ... FORCE may not terminate:
// it can only end backends of roles the provisioner has the privileges of),
// the app role's backends are terminated, and the forced drop is retried for a
// few seconds while other backends finish.
func (p *Provisioner) dropDatabase(ctx context.Context, n TenantNames) error {
	ok, err := p.databaseExists(ctx, n.Database)
	if err != nil || !ok {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `ALTER DATABASE `+ident(n.Database)+` WITH ALLOW_CONNECTIONS false`); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND usename = $2`, n.Database, n.App); err != nil {
		return err
	}
	var last error
	for attempt := range 20 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
		_, last = p.db.ExecContext(ctx, `DROP DATABASE IF EXISTS `+ident(n.Database)+` WITH (FORCE)`)
		switch sqlState(last) {
		case "":
			return last
		case "42501", "55006": // a backend we may not terminate, or still in use
			continue
		default:
			return last
		}
	}
	return last
}

// OpenTenantApp returns the handle the web pods use for tenant id: the app
// role through the pooler described by pooler (host, port, TLS; user,
// database and password are filled in). search_path and the timeouts come
// from the role's defaults, so no session SET is needed (transaction pooling).
func OpenTenantApp(pooler *pgx.ConnConfig, id, password string) (*sql.DB, error) {
	n, err := TenantNamesFor(id)
	if err != nil {
		return nil, err
	}
	c := pooler.Copy()
	c.Database, c.User, c.Password = n.Database, n.App, password
	return OpenDB(c), nil
}

// scramVerifier returns the SCRAM-SHA-256 verifier PostgreSQL stores for
// password (RFC 5802/7677, 4096 iterations, as libpq's PQencryptPasswordConn).
// Passwords are generated ASCII, so SASLprep is the identity.
func scramVerifier(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const iter = 4096
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, sha256.Size)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	stored := sha256.Sum256(mac(salted, "Client Key"))
	server := mac(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return "SCRAM-SHA-256$" + strconv.Itoa(iter) + ":" + b64(salt) + "$" + b64(stored[:]) + ":" + b64(server), nil
}
