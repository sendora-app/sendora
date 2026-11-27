// SPDX-License-Identifier: AGPL-3.0-or-later

// Package conformance is the shared contract suite for the ports in
// internal/ports (docs/cluster/DESIGN.md section 2A.4, docs/adr/0003). The same
// tests run against every adapter: the SQLite Store always, a PostgreSQL Store
// when SENDORA_TEST_PG_DSN is set (adapter from phase 2), and the in-process
// Coordinator, Lock and RateLimiter.
//
// Adding a repository method to ports.Store means adding its contract test
// here (a RunXxx function called from RunStore), never only an adapter test.
package conformance

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/sendora-app/sendora/internal/adapters/postgres"
	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// PGDSNEnv names the PostgreSQL connection string for the postgres slot.
const PGDSNEnv = "SENDORA_TEST_PG_DSN"

// StoreBackend is one Store adapter under test. Open returns a fresh, empty
// and fully migrated store; it registers its own cleanup and skips the test
// when the backend is not available.
type StoreBackend struct {
	Name string
	// Unavailable returns why the backend cannot run here ("" = available).
	Unavailable func() string
	Open        func(t testing.TB) ports.Store
}

// StoreBackends lists every Store adapter the suite runs against.
func StoreBackends() []StoreBackend {
	return []StoreBackend{
		{Name: "sqlite", Unavailable: func() string { return "" }, Open: openSQLite},
		{Name: "postgres", Unavailable: postgresUnavailable, Open: openPostgres},
		{Name: "postgres-tenant", Unavailable: tenantUnavailable, Open: openPostgresTenant},
	}
}

// openSQLite opens a new SQLCipher database through the production opener, so
// the tables come from the real migration sequence.
func openSQLite(t testing.TB) ports.Store {
	t.Helper()
	st, err := store.OpenEncrypted(filepath.Join(t.TempDir(), "data"), bytes.Repeat([]byte{0x5a}, 32), true)
	if err != nil {
		t.Fatalf("open sqlite store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	// The server creates this table at startup, after the migration sequence.
	if err := st.MigrateVerificationAttempts(); err != nil {
		t.Fatalf("migrate verification attempts: %v", err)
	}
	// The store's migrations seeded sealed settings: read them with its codec.
	a := sqlite.New(st.DB)
	a.SetCodec(st.ColumnCodec())
	return a
}

// postgresUnavailable gates the PostgreSQL slot: skipped unless
// SENDORA_TEST_PG_DSN is set (a role that may create schemas in its
// database; each test gets its own schema, see postgres.OpenScratch).
func postgresUnavailable() string {
	if os.Getenv(PGDSNEnv) == "" {
		return PGDSNEnv + " is not set"
	}
	return ""
}

// openPostgres opens a fresh, migrated scratch schema on SENDORA_TEST_PG_DSN
// and seeds it with the core default content (store.DefaultSeed), as every
// new tenant database is seeded.
func openPostgres(t testing.TB) ports.Store {
	t.Helper()
	sc := openScratch(t, postgres.TenantSchema)
	if err := postgres.Seed(context.Background(), sc.DB, nil, store.DefaultSeed()); err != nil {
		t.Fatalf("seed postgres store: %v", err)
	}
	return postgres.New(sc.DB)
}

// Environment of the postgres-tenant slot: a cluster prepared per design 3.2
// (#9, #10, #16, #20). The provisioner connects directly (database
// postgres); the pooler DSN names the rw PgBouncer (no user). The slot
// provisions one tenant database per run and resets it between tests; it
// still needs the explicit opt-in SENDORA_TEST_PG_TENANT_SLOT=1, because an
// earlier version that created and dropped a database per test (every DROP
// DATABASE forces a checkpoint) stalled the NFS-backed test cluster's primary
// into a failover.
const (
	PGProvisionerDSNEnv = "SENDORA_TEST_PG_PROVISIONER_DSN"
	PGPoolerDSNEnv      = "SENDORA_TEST_PG_POOLER_DSN"
	PGTenantSlotEnv     = "SENDORA_TEST_PG_TENANT_SLOT"
)

func tenantUnavailable() string {
	if os.Getenv(PGProvisionerDSNEnv) == "" || os.Getenv(PGPoolerDSNEnv) == "" {
		return PGProvisionerDSNEnv + " and " + PGPoolerDSNEnv + " are not set"
	}
	if os.Getenv(PGTenantSlotEnv) != "1" {
		return PGTenantSlotEnv + "=1 is not set (provisions a tenant database)"
	}
	return ""
}

// openPostgresTenant opens the slot's tenant database the way web pods do: as
// the tenant's app role through PgBouncer in transaction mode. One tenant is
// provisioned per test process (roles, schema, migrations, core seed, grants;
// design 5.2) and reset to its freshly seeded state before every test, so a
// run creates and drops exactly one database (CloseTenantSlot drops it).
func openPostgresTenant(t testing.TB) ports.Store {
	t.Helper()
	if reason := tenantUnavailable(); reason != "" {
		t.Skip(reason)
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.inUse {
		t.Fatal("postgres-tenant slot: the shared tenant is already in use by this test")
	}
	ctx := context.Background()
	seed := store.DefaultSeed()
	if slot.p == nil {
		direct, err := pgx.ParseConfig(os.Getenv(PGProvisionerDSNEnv))
		if err != nil {
			t.Fatal(err)
		}
		pooler, err := pgx.ParseConfig(os.Getenv(PGPoolerDSNEnv))
		if err != nil {
			t.Fatal(err)
		}
		p := postgres.NewProvisioner(direct)
		pw := make([]byte, 24)
		rand.Read(pw)
		spec := postgres.TenantSpec{ID: platform.NewTenantID(), AppPassword: hex.EncodeToString(pw), ConnectionLimit: postgres.ConnectionLimit(2), Seed: &seed}
		if err := p.CreateTenant(ctx, spec); err != nil {
			p.DropTenant(ctx, spec.ID)
			p.Close()
			t.Fatalf("provision tenant: %v", err)
		}
		db, err := postgres.OpenTenantApp(pooler, spec.ID, spec.AppPassword)
		if err != nil {
			p.DropTenant(ctx, spec.ID)
			p.Close()
			t.Fatal(err)
		}
		db.SetMaxOpenConns(16)
		slot.p, slot.id, slot.db = p, spec.ID, db
	} else if err := slot.p.ResetTenantForTests(ctx, slot.id, &seed); err != nil {
		t.Fatalf("reset tenant: %v", err)
	}
	slot.inUse = true
	t.Cleanup(func() {
		slot.mu.Lock()
		slot.inUse = false
		slot.mu.Unlock()
	})
	return postgres.New(slot.db)
}

// slot is the postgres-tenant slot's shared tenant.
var slot struct {
	mu    sync.Mutex
	inUse bool
	p     *postgres.Provisioner
	id    string
	db    *sql.DB
}

// CloseTenantSlot drops the postgres-tenant slot's tenant, if one was
// provisioned (TestMain calls it after the run).
func CloseTenantSlot() {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.p == nil {
		return
	}
	slot.db.Close()
	if err := slot.p.DropTenant(context.Background(), slot.id); err != nil {
		fmt.Fprintf(os.Stderr, "drop tenant %s: %v\n", slot.id, err)
	}
	slot.p.Close()
	slot.p = nil
}

func openScratch(t testing.TB, s postgres.Schema) *postgres.Scratch {
	t.Helper()
	if reason := postgresUnavailable(); reason != "" {
		t.Skip(reason)
	}
	sc, err := postgres.OpenScratch(context.Background(), os.Getenv(PGDSNEnv), s)
	if err != nil {
		t.Fatalf("open postgres scratch schema: %v", err)
	}
	t.Cleanup(func() {
		if err := sc.Close(); err != nil {
			t.Logf("drop scratch schema %s: %v", sc.Schema, err)
		}
	})
	return sc
}

// RunStore runs every repository contract against one backend.
func RunStore(t *testing.T, open func(testing.TB) ports.Store) {
	t.Run("Seed", func(t *testing.T) { RunSeed(t, open) })
	t.Run("AuditChain", func(t *testing.T) { RunAuditChain(t, open) })
	t.Run("AuditQuery", func(t *testing.T) { RunAuditQuery(t, open) })
	t.Run("System", func(t *testing.T) { RunSystem(t, open) })
	t.Run("Settings", func(t *testing.T) { RunSettings(t, open) })
	t.Run("Themes", func(t *testing.T) { RunThemes(t, open) })
	t.Run("Stats", func(t *testing.T) { RunStats(t, open) })
	t.Run("Maintenance", func(t *testing.T) { RunMaintenance(t, open) })
	t.Run("PersonalData", func(t *testing.T) { RunPersonalData(t, open) })
	t.Run("Mail", func(t *testing.T) { RunMail(t, open) })
	t.Run("UITranslations", func(t *testing.T) { RunUITranslations(t, open) })
	t.Run("ProviderAdmin", func(t *testing.T) { RunProviderAdmin(t, open) })
	t.Run("ObjectStorage", func(t *testing.T) { RunObjectStorage(t, open) })
	t.Run("StorageMigrations", func(t *testing.T) { RunStorageMigrations(t, open) })
	t.Run("IPBans", func(t *testing.T) { RunIPBans(t, open) })
	t.Run("Tx", func(t *testing.T) { RunTx(t, open) })
	t.Run("Users", func(t *testing.T) { RunUsers(t, open) })
	t.Run("Sessions", func(t *testing.T) { RunSessions(t, open) })
	t.Run("PasswordResets", func(t *testing.T) { RunPasswordResets(t, open) })
	t.Run("EmailVerifications", func(t *testing.T) { RunEmailVerifications(t, open) })
	t.Run("PasswordHistory", func(t *testing.T) { RunPasswordHistory(t, open) })
	t.Run("AuthProviders", func(t *testing.T) { RunAuthProviders(t, open) })
	t.Run("ReverseInvites", func(t *testing.T) { RunReverseInvites(t, open) })
	t.Run("MFA", func(t *testing.T) { RunMFA(t, open) })
	t.Run("AccountState", func(t *testing.T) { RunAccountState(t, open) })
	t.Run("PasswordResetKinds", func(t *testing.T) { RunPasswordResetKinds(t, open) })
	t.Run("SignInHistory", func(t *testing.T) { RunSignInHistory(t, open) })
	t.Run("Quota", func(t *testing.T) { RunQuota(t, open) })
	t.Run("Shares", func(t *testing.T) { RunShares(t, open) })
	t.Run("Downloads", func(t *testing.T) { RunDownloads(t, open) })
	t.Run("StorageLocations", func(t *testing.T) { RunStorageLocations(t, open) })
	t.Run("Uploads", func(t *testing.T) { RunUploads(t, open) })
	t.Run("UploadAdmission", func(t *testing.T) { RunUploadAdmission(t, open) })
	t.Run("ShareManagement", func(t *testing.T) { RunShareManagement(t, open) })
	t.Run("TenantLimits", func(t *testing.T) { RunTenantLimits(t, open) })
	t.Run("Lookups", func(t *testing.T) { RunLookups(t, open) })
	t.Run("Concurrency", func(t *testing.T) { RunConcurrency(t, open) })
	t.Run("Idempotency", func(t *testing.T) { RunIdempotency(t, open) })
	t.Run("ClaimBarrier", func(t *testing.T) { RunClaimBarrier(t, open) })
	t.Run("JobFences", func(t *testing.T) { RunJobFences(t, open) })
	t.Run("ControlLogAndKeyring", func(t *testing.T) { st := open(t); RunControlLogAndKeyring(t, st.ControlLog(), st.Keyring()) })
}
