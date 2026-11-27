// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sendora-app/sendora/internal/adapters/postgres"
	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// PlatformOpener returns a fresh, empty and migrated platform database: the
// PlatformStore and the audit chain repository on the same database (the
// platform audit log is written through it).
type PlatformOpener func(t testing.TB) (ports.PlatformStore, ports.AuditChainRepository)

// PlatformBackend is one PlatformStore adapter under test.
type PlatformBackend struct {
	Name        string
	Unavailable func() string
	Open        PlatformOpener
}

// PlatformBackends lists every PlatformStore adapter the suite runs against.
func PlatformBackends() []PlatformBackend {
	return []PlatformBackend{
		{Name: "sqlite", Unavailable: func() string { return "" }, Open: openSQLitePlatform},
		{Name: "postgres", Unavailable: postgresUnavailable, Open: openPostgresPlatform},
	}
}

// openPostgresPlatform opens a migrated platform scratch schema.
func openPostgresPlatform(t testing.TB) (ports.PlatformStore, ports.AuditChainRepository) {
	t.Helper()
	sc := openScratch(t, postgres.PlatformSchema)
	p := postgres.NewPlatform(sc.DB)
	// The schema version marker is written with the database's keys (here: none).
	if err := p.EnsureSchemaVersion(context.Background()); err != nil {
		t.Fatalf("platform schema version: %v", err)
	}
	return p, postgres.New(sc.DB).AuditChain()
}

// openSQLitePlatform opens a platform database the way platform.Open does
// (OpenPlatform with the platform schema, then MigratePlatform).
func openSQLitePlatform(t testing.TB) (ports.PlatformStore, ports.AuditChainRepository) {
	t.Helper()
	st, err := store.OpenPlatform(filepath.Join(t.TempDir(), "data"), bytes.Repeat([]byte{0x5b}, 32), true, sqlite.PlatformSchema)
	if err != nil {
		t.Fatalf("open platform store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := sqlite.MigratePlatform(st.DB); err != nil {
		t.Fatalf("migrate platform store: %v", err)
	}
	return st.PlatformRepo(), st.Repos().AuditChain()
}

func tenantRec(id, slug, name, status string) ports.TenantRecord {
	return ports.TenantRecord{ID: id, Slug: slug, Name: name, Status: status, CreatedAt: "2026-01-02T03:04:05Z", KeyMode: "derived"}
}

func mustTenant(t *testing.T, r ports.PlatformRepositories, rec ports.TenantRecord) {
	t.Helper()
	if err := r.Tenants().Insert(context.Background(), rec); err != nil {
		t.Fatalf("insert tenant %s: %v", rec.Slug, err)
	}
}

func slugsOf(l []ports.TenantRecord) []string {
	out := []string{}
	for _, t := range l {
		out = append(out, t.Slug)
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RunPlatform runs every PlatformStore contract against one backend.
func RunPlatform(t *testing.T, open PlatformOpener) {
	ctx := context.Background()

	t.Run("ControlLogAndKeyring", func(t *testing.T) { p, _ := open(t); RunControlLogAndKeyring(t, p.ControlLog(), p.Keyring()) })

	t.Run("Tenants", func(t *testing.T) {
		p, _ := open(t)
		tr := p.Tenants()
		if _, err := tr.ByID(ctx, "nope"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ByID of an unknown tenant: %v", err)
		}
		if _, err := tr.BySlug(ctx, "nope"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("BySlug of an unknown tenant: %v", err)
		}
		if l, err := tr.List(ctx, ""); err != nil || l == nil || len(l) != 0 {
			t.Fatalf("List on an empty store = %v, %v (want an empty, non-nil list)", l, err)
		}
		a := tenantRec("aaaa", "zulu", "Acme Corp", "active")
		a.MaxUsers, a.MaxStorageBytes = 5, 1<<20
		mustTenant(t, p, a)
		legacy := tenantRec("bbbb", "alpha", "50%_off", "importing")
		legacy.KeyMode, legacy.LegacyRoot = "legacy", bytes.Repeat([]byte{7}, 32)
		mustTenant(t, p, legacy)
		mustTenant(t, p, tenantRec("cccc", "mike", "Other", "active"))
		if err := tr.Insert(ctx, tenantRec("dddd", "zulu", "dup", "active")); err == nil {
			t.Fatal("duplicate slug accepted")
		}
		if err := tr.Insert(ctx, tenantRec("aaaa", "yankee", "dup", "active")); err == nil {
			t.Fatal("duplicate id accepted")
		}
		got, err := tr.ByID(ctx, "aaaa")
		if err != nil || got.Slug != "zulu" || got.Name != "Acme Corp" || got.Status != "active" || got.CreatedAt != a.CreatedAt ||
			got.MaxUsers != 5 || got.MaxStorageBytes != 1<<20 || got.KeyMode != "derived" || got.LegacyRoot != nil ||
			got.PrimaryDomain != "" || got.StatUsers != 0 || got.StatStorageBytes != 0 || got.StatUpdatedAt != "" || got.AllowPrivateTargets {
			t.Fatalf("ByID = %+v, %v", got, err)
		}
		if got, err := tr.BySlug(ctx, "alpha"); err != nil || got.ID != "bbbb" || !bytes.Equal(got.LegacyRoot, legacy.LegacyRoot) || got.KeyMode != "legacy" {
			t.Fatalf("BySlug = %+v, %v", got, err)
		}
		if n, err := tr.CountBySlug(ctx, "zulu"); err != nil || n != 1 {
			t.Fatalf("CountBySlug = %d, %v", n, err)
		}
		if n, _ := tr.CountBySlug(ctx, "none"); n != 0 {
			t.Fatalf("CountBySlug of a free slug = %d", n)
		}
		if l, _ := tr.List(ctx, ""); !sameStrings(slugsOf(l), []string{"alpha", "mike", "zulu"}) {
			t.Fatalf("List order = %v", slugsOf(l))
		}
		for search, want := range map[string][]string{
			"acme": {"zulu"}, "ul": {"zulu"}, "%": {"alpha"}, "_": {"alpha"}, "o": {"alpha", "mike", "zulu"}, "nothing": {},
		} {
			if l, err := tr.List(ctx, search); err != nil || !sameStrings(slugsOf(l), want) {
				t.Fatalf("List(%q) = %v, %v (want %v)", search, slugsOf(l), err, want)
			}
		}
		if err := p.TenantDomains().AddCustom(ctx, "files.example.org", "cccc", "tok", "2026-01-02T03:04:05Z"); err != nil {
			t.Fatal(err)
		}
		if l, _ := tr.List(ctx, "example.org"); !sameStrings(slugsOf(l), []string{"mike"}) {
			t.Fatalf("List by domain = %v", slugsOf(l))
		}

		if n, err := tr.SetStatus(ctx, "aaaa", "suspended"); err != nil || n != 1 {
			t.Fatalf("SetStatus = %d, %v", n, err)
		}
		if n, _ := tr.SetStatus(ctx, "bbbb", "active"); n != 0 {
			t.Fatal("SetStatus changed an importing tenant")
		}
		if n, _ := tr.SetStatus(ctx, "nope", "active"); n != 0 {
			t.Fatal("SetStatus changed an unknown tenant")
		}
		if err := tr.Activate(ctx, "aaaa"); err != nil {
			t.Fatal(err)
		}
		if got, _ := tr.ByID(ctx, "aaaa"); got.Status != "suspended" {
			t.Fatalf("Activate changed a suspended tenant: %s", got.Status)
		}
		if err := tr.Activate(ctx, "bbbb"); err != nil {
			t.Fatal(err)
		}
		if got, _ := tr.ByID(ctx, "bbbb"); got.Status != "active" {
			t.Fatalf("Activate: status %s", got.Status)
		}
		if n, err := tr.SetQuotas(ctx, "aaaa", 9, 99); err != nil || n != 1 {
			t.Fatalf("SetQuotas = %d, %v", n, err)
		}
		if n, _ := tr.SetQuotas(ctx, "nope", 1, 1); n != 0 {
			t.Fatal("SetQuotas changed an unknown tenant")
		}
		if err := tr.SetName(ctx, "aaaa", "Renamed"); err != nil {
			t.Fatal(err)
		}
		if err := tr.UpdateStats(ctx, "aaaa", 3, 4096, "2026-02-03T04:05:06Z"); err != nil {
			t.Fatal(err)
		}
		if n, err := tr.SetAllowPrivateTargets(ctx, "aaaa", true); err != nil || n != 1 {
			t.Fatalf("SetAllowPrivateTargets = %d, %v", n, err)
		}
		if n, _ := tr.SetAllowPrivateTargets(ctx, "nope", true); n != 0 {
			t.Fatal("SetAllowPrivateTargets changed an unknown tenant")
		}
		got, _ = tr.ByID(ctx, "aaaa")
		if got.MaxUsers != 9 || got.MaxStorageBytes != 99 || got.Name != "Renamed" || got.StatUsers != 3 || got.StatStorageBytes != 4096 ||
			got.StatUpdatedAt != "2026-02-03T04:05:06Z" || !got.AllowPrivateTargets {
			t.Fatalf("after updates = %+v", got)
		}
		if n, _ := tr.SetAllowPrivateTargets(ctx, "aaaa", false); n != 1 {
			t.Fatal("SetAllowPrivateTargets(false)")
		}
		if got, _ := tr.ByID(ctx, "aaaa"); got.AllowPrivateTargets {
			t.Fatal("private targets still allowed")
		}

		// KEK mode (D44): platform-managed by default; the fingerprint only.
		if got, _ := tr.ByID(ctx, "aaaa"); got.KEKMode != "platform" || got.KEKFingerprint != "" {
			t.Fatalf("default KEK mode = %q %q", got.KEKMode, got.KEKFingerprint)
		}
		if n, err := tr.SetKEK(ctx, "aaaa", "tenant", "0123456789abcdef"); n != 1 || err != nil {
			t.Fatalf("SetKEK = %d, %v", n, err)
		}
		if got, _ := tr.ByID(ctx, "aaaa"); got.KEKMode != "tenant" || got.KEKFingerprint != "0123456789abcdef" {
			t.Fatalf("after SetKEK: %q %q", got.KEKMode, got.KEKFingerprint)
		}
		if got, _ := tr.ByID(ctx, "bbbb"); got.KEKMode != "platform" {
			t.Fatalf("another tenant's KEK mode changed: %q", got.KEKMode)
		}
		if list, _ := tr.List(ctx, ""); len(list) == 0 {
			t.Fatal("List")
		} else {
			for _, l := range list {
				if l.ID == "aaaa" && l.KEKMode != "tenant" {
					t.Fatalf("List lacks the KEK mode: %+v", l)
				}
			}
		}
		if n, _ := tr.SetKEK(ctx, "nope", "tenant", "x"); n != 0 {
			t.Fatal("SetKEK changed an unknown tenant")
		}
		if _, err := tr.SetKEK(ctx, "aaaa", "bogus", ""); err == nil {
			t.Fatal("an unknown KEK mode was stored")
		}
		if n, err := tr.SetKEK(ctx, "aaaa", "platform", ""); n != 1 || err != nil {
			t.Fatalf("SetKEK(platform) = %d, %v", n, err)
		}
		if got, _ := tr.ByID(ctx, "aaaa"); got.KEKMode != "platform" || got.KEKFingerprint != "" {
			t.Fatalf("after returning to platform: %q %q", got.KEKMode, got.KEKFingerprint)
		}

		// Master key version (D46): 1 by default, moved by compare-and-swap.
		if got, _ := tr.ByID(ctx, "aaaa"); got.MasterVersion != 1 {
			t.Fatalf("default master version = %d", got.MasterVersion)
		}
		if n, err := tr.SetMasterVersion(ctx, "aaaa", 1, 2); n != 1 || err != nil {
			t.Fatalf("SetMasterVersion 1->2 = %d, %v", n, err)
		}
		if n, _ := tr.SetMasterVersion(ctx, "aaaa", 1, 3); n != 0 {
			t.Fatal("SetMasterVersion moved a tenant that was not at the expected version")
		}
		if n, _ := tr.SetMasterVersion(ctx, "nope", 1, 2); n != 0 {
			t.Fatal("SetMasterVersion changed an unknown tenant")
		}
		if _, err := tr.SetMasterVersion(ctx, "aaaa", 2, 2); err == nil {
			t.Fatal("a move that does not advance was accepted")
		}
		if got, _ := tr.ByID(ctx, "aaaa"); got.MasterVersion != 2 {
			t.Fatalf("master version = %d", got.MasterVersion)
		}
		if got, _ := tr.ByID(ctx, "bbbb"); got.MasterVersion != 1 {
			t.Fatalf("another tenant's master version changed: %d", got.MasterVersion)
		}
		counts, err := tr.CountByMasterVersion(ctx)
		if err != nil || counts[2] != 1 || counts[1] < 1 {
			t.Fatalf("CountByMasterVersion = %v, %v", counts, err)
		}

		if err := tr.SetPrimaryDomain(ctx, "cccc", "files.example.org"); err != nil {
			t.Fatal(err)
		}
		if err := tr.ClearPrimaryDomain(ctx, "cccc", "other.example.org"); err != nil {
			t.Fatal(err)
		}
		if got, _ := tr.ByID(ctx, "cccc"); got.PrimaryDomain != "files.example.org" {
			t.Fatalf("ClearPrimaryDomain of another domain changed it: %q", got.PrimaryDomain)
		}
		if err := tr.ClearPrimaryDomain(ctx, "cccc", "files.example.org"); err != nil {
			t.Fatal(err)
		}
		if got, _ := tr.ByID(ctx, "cccc"); got.PrimaryDomain != "" {
			t.Fatalf("ClearPrimaryDomain: %q", got.PrimaryDomain)
		}
		routes, err := tr.Routes(ctx)
		if err != nil || len(routes) != 3 {
			t.Fatalf("Routes = %+v, %v", routes, err)
		}
		for _, r := range routes {
			if r.ID == "aaaa" && (r.Slug != "zulu" || r.Status != "suspended") {
				t.Fatalf("route = %+v", r)
			}
		}

		mustTenant(t, p, tenantRec("eeee", "echo", "Importing", "importing"))
		if err := tr.DeleteImporting(ctx, "aaaa"); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.ByID(ctx, "aaaa"); err != nil {
			t.Fatal("DeleteImporting removed a tenant that is not importing")
		}
		if err := tr.DeleteImporting(ctx, "eeee"); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.ByID(ctx, "eeee"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteImporting kept an importing tenant")
		}
		if err := p.TenantStorage().CreateDefault(ctx, "cccc", "tenants/cccc/", "t"); err != nil {
			t.Fatal(err)
		}
		if err := tr.Delete(ctx, "cccc"); err != nil {
			t.Fatal(err)
		}
		if err := tr.Delete(ctx, "cccc"); err != nil {
			t.Fatalf("Delete of a missing tenant: %v", err)
		}
		if l, _ := p.TenantDomains().List(ctx, "cccc"); len(l) != 0 {
			t.Fatalf("domains of a deleted tenant remain: %+v", l)
		}
		if _, err := p.TenantStorage().Get(ctx, "cccc"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("storage decision of a deleted tenant remains: %v", err)
		}
	})

	// Insert stores the master key version the caller names (a tenant created
	// after a master rotation derives from the active version, not from 1).
	t.Run("InsertMasterVersion", func(t *testing.T) {
		p, _ := open(t)
		ctx := context.Background()
		rec := tenantRec("mvmv", "mv", "MV", "active")
		rec.MasterVersion = 3
		mustTenant(t, p, rec)
		mustTenant(t, p, tenantRec("mvzero", "mvzero", "Zero", "active")) // unset: version 1
		if got, err := p.Tenants().ByID(ctx, "mvmv"); err != nil || got.MasterVersion != 3 {
			t.Fatalf("master version after insert = %d, %v", got.MasterVersion, err)
		}
		if got, err := p.Tenants().ByID(ctx, "mvzero"); err != nil || got.MasterVersion != 1 {
			t.Fatalf("unset master version after insert = %d, %v", got.MasterVersion, err)
		}
		counts, err := p.Tenants().CountByMasterVersion(ctx)
		if err != nil || counts[3] != 1 || counts[1] != 1 {
			t.Fatalf("CountByMasterVersion = %v, %v", counts, err)
		}
	})

	t.Run("Domains", func(t *testing.T) {
		p, _ := open(t)
		mustTenant(t, p, tenantRec("t1", "one", "One", "active"))
		mustTenant(t, p, tenantRec("t2", "two", "Two", "active"))
		d := p.TenantDomains()
		if m, err := d.VerifiedCustom(ctx); err != nil || len(m) != 0 {
			t.Fatalf("VerifiedCustom on an empty store = %v, %v", m, err)
		}
		for _, dom := range []string{"b.example.org", "a.example.org"} {
			if err := d.AddCustom(ctx, dom, "t1", "tok-"+dom, "2026-01-01T00:00:00Z"); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.AddCustom(ctx, "a.example.org", "t2", "x", "2026-01-01T00:00:00Z"); err == nil {
			t.Fatal("a mapped domain was mapped again")
		}
		l, err := d.List(ctx, "t1")
		if err != nil || len(l) != 2 || l[0].Domain != "a.example.org" || l[0].TenantID != "t1" || l[0].Kind != "custom" || l[0].Verified ||
			l[0].VerifyToken != "tok-a.example.org" || l[0].CreatedAt != "2026-01-01T00:00:00Z" {
			t.Fatalf("List = %+v, %v", l, err)
		}
		if l, err := d.List(ctx, "t2"); err != nil || l == nil || len(l) != 0 {
			t.Fatalf("List of a tenant without domains = %v, %v (want empty, non-nil)", l, err)
		}
		if n, _ := d.CountVerified(ctx, "a.example.org", "t1"); n != 0 {
			t.Fatal("unverified domain counted")
		}
		if n, err := d.MarkVerified(ctx, "a.example.org", "t2"); err != nil || n != 0 {
			t.Fatalf("MarkVerified for another tenant = %d, %v", n, err)
		}
		if n, err := d.MarkVerified(ctx, "a.example.org", "t1"); err != nil || n != 1 {
			t.Fatalf("MarkVerified = %d, %v", n, err)
		}
		if n, err := d.CountVerified(ctx, "a.example.org", "t1"); err != nil || n != 1 {
			t.Fatalf("CountVerified = %d, %v", n, err)
		}
		if m, _ := d.VerifiedCustom(ctx); len(m) != 1 || m["a.example.org"] != "t1" {
			t.Fatalf("VerifiedCustom = %v", m)
		}
		if n, _ := d.RemoveCustom(ctx, "a.example.org", "t2"); n != 0 {
			t.Fatal("RemoveCustom removed another tenant's domain")
		}
		if n, err := d.RemoveCustom(ctx, "a.example.org", "t1"); err != nil || n != 1 {
			t.Fatalf("RemoveCustom = %d, %v", n, err)
		}
		if n, _ := d.RemoveCustom(ctx, "a.example.org", "t1"); n != 0 {
			t.Fatal("RemoveCustom of a removed domain")
		}
		if m, _ := d.VerifiedCustom(ctx); len(m) != 0 {
			t.Fatalf("VerifiedCustom after removal = %v", m)
		}
	})

	t.Run("TenantStorage", func(t *testing.T) {
		p, _ := open(t)
		mustTenant(t, p, tenantRec("t1", "one", "One", "active"))
		mustTenant(t, p, tenantRec("t2", "two", "Two", "active"))
		s := p.TenantStorage()
		if _, err := s.Get(ctx, "t1"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Get without a decision: %v", err)
		}
		if err := s.CreateDefault(ctx, "t1", "tenants/t1/", "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		if d, err := s.Get(ctx, "t1"); err != nil || d.Offer != "none" || !d.TenantManaged || d.UpdatedAt != "2026-01-01T00:00:00Z" {
			t.Fatalf("default decision = %+v, %v", d, err)
		}
		if n, err := s.Set(ctx, "t1", "tenants/t1/", "local", false, "2026-02-01T00:00:00Z"); err != nil || n != 1 {
			t.Fatalf("Set = %d, %v", n, err)
		}
		if d, _ := s.Get(ctx, "t1"); d.Offer != "local" || d.TenantManaged || d.UpdatedAt != "2026-02-01T00:00:00Z" {
			t.Fatalf("after Set = %+v", d)
		}
		if n, err := s.Set(ctx, "t2", "tenants/t2/", "platform", true, "2026-03-01T00:00:00Z"); err != nil || n != 1 {
			t.Fatalf("Set creating a decision = %d, %v", n, err)
		}
		if d, _ := s.Get(ctx, "t2"); d.Offer != "platform" || !d.TenantManaged {
			t.Fatalf("created decision = %+v", d)
		}
		if n, err := s.Set(ctx, "nope", "tenants/nope/", "local", true, "x"); err != nil || n != 0 {
			t.Fatalf("Set for an unknown tenant = %d, %v", n, err)
		}
		if _, err := s.Get(ctx, "nope"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Set stored a decision for an unknown tenant: %v", err)
		}
	})

	t.Run("Admins", func(t *testing.T) {
		p, _ := open(t)
		a := p.PlatformAdmins()
		if n, err := a.Count(ctx); err != nil || n != 0 {
			t.Fatalf("Count = %d, %v", n, err)
		}
		if _, err := a.ByID(ctx, 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ByID of an unknown admin: %v", err)
		}
		if l, err := a.List(ctx); err != nil || l == nil || len(l) != 0 {
			t.Fatalf("List on an empty store = %v, %v", l, err)
		}
		first, created, err := a.CreateFirst(ctx, "Root", "root@example.org", "h1", "2026-01-01T00:00:00Z")
		if err != nil || !created || first == 0 {
			t.Fatalf("CreateFirst = %d, %v, %v", first, created, err)
		}
		if _, created, err := a.CreateFirst(ctx, "second", "s@example.org", "h", "t"); err != nil || created {
			t.Fatalf("CreateFirst with an admin present = %v, %v", created, err)
		}
		if _, err := a.Create(ctx, "ROOT", "x@example.org", "h", "t"); err == nil {
			t.Fatal("username taken ignoring case accepted")
		}
		bob, err := a.Create(ctx, "bob", "bob@example.org", "h2", "2026-01-02T00:00:00Z")
		if err != nil || bob == 0 || bob == first {
			t.Fatalf("Create = %d, %v", bob, err)
		}
		got, err := a.ByName(ctx, "rOOt")
		if err != nil || got.ID != first || got.Username != "Root" || got.Email != "root@example.org" || got.PasswordHash != "h1" ||
			got.CreatedAt != "2026-01-01T00:00:00Z" || got.TOTPEnabled || got.TOTPSecret != "" || got.PendingTOTP != "" ||
			got.LastCounter != 0 || got.Failures != 0 || got.LockedUntil != 0 || got.MustChangePassword {
			t.Fatalf("ByName = %+v, %v", got, err)
		}
		if l, _ := a.List(ctx); len(l) != 2 || l[0].Username != "bob" || l[1].Username != "Root" { // ignoring case
			t.Fatalf("List = %+v", l)
		}
		if n, _ := a.Count(ctx); n != 2 {
			t.Fatalf("Count = %d", n)
		}

		// Lockout.
		for i := 1; i <= 3; i++ {
			if err := a.NoteLoginFailure(ctx, bob, 3, 1_900_000_000); err != nil {
				t.Fatal(err)
			}
			got, _ := a.ByID(ctx, bob)
			wantLock := int64(0)
			if i == 3 {
				wantLock = 1_900_000_000
			}
			if got.Failures != i || got.LockedUntil != wantLock {
				t.Fatalf("after %d failures: failures %d, locked until %d", i, got.Failures, got.LockedUntil)
			}
		}
		if err := a.ClearLoginFailures(ctx, bob); err != nil {
			t.Fatal(err)
		}
		if got, _ := a.ByID(ctx, bob); got.Failures != 0 || got.LockedUntil != 0 {
			t.Fatalf("ClearLoginFailures = %+v", got)
		}

		// Passwords.
		a.NoteLoginFailure(ctx, bob, 1, 1_900_000_000)
		if err := a.SetTemporaryPassword(ctx, bob, "temp"); err != nil {
			t.Fatal(err)
		}
		if got, _ := a.ByID(ctx, bob); got.PasswordHash != "temp" || !got.MustChangePassword || got.Failures != 0 || got.LockedUntil != 0 {
			t.Fatalf("SetTemporaryPassword = %+v", got)
		}
		if err := a.SetPassword(ctx, bob, "final"); err != nil {
			t.Fatal(err)
		}
		if got, _ := a.ByID(ctx, bob); got.PasswordHash != "final" || got.MustChangePassword {
			t.Fatalf("SetPassword = %+v", got)
		}

		// TOTP.
		if err := a.EnableTOTP(ctx, bob, 5); err != nil {
			t.Fatal(err)
		}
		if got, _ := a.ByID(ctx, bob); got.TOTPEnabled || got.LastCounter != 0 {
			t.Fatalf("EnableTOTP without a pending secret = %+v", got)
		}
		if err := a.SetPendingTOTP(ctx, bob, "SECRET"); err != nil {
			t.Fatal(err)
		}
		if err := a.EnableTOTP(ctx, bob, 100); err != nil {
			t.Fatal(err)
		}
		if got, _ := a.ByID(ctx, bob); !got.TOTPEnabled || got.TOTPSecret != "SECRET" || got.PendingTOTP != "" || got.LastCounter != 100 {
			t.Fatalf("EnableTOTP = %+v", got)
		}
		for _, c := range []struct {
			counter, want int64
		}{{100, 0}, {99, 0}, {101, 1}, {101, 0}} {
			if n, err := a.UseTOTPCounter(ctx, bob, c.counter); err != nil || n != c.want {
				t.Fatalf("UseTOTPCounter(%d) = %d, %v (want %d)", c.counter, n, err, c.want)
			}
		}
		if err := a.ResetTOTP(ctx, bob); err != nil {
			t.Fatal(err)
		}
		if got, _ := a.ByID(ctx, bob); got.TOTPEnabled || got.TOTPSecret != "" || got.PendingTOTP != "" || got.LastCounter != 0 {
			t.Fatalf("ResetTOTP = %+v", got)
		}

		// Removal keeps the last administrator.
		if n, err := a.DeleteUnlessLast(ctx, bob); err != nil || n != 1 {
			t.Fatalf("DeleteUnlessLast = %d, %v", n, err)
		}
		if n, err := a.DeleteUnlessLast(ctx, first); err != nil || n != 0 {
			t.Fatalf("DeleteUnlessLast of the last admin = %d, %v", n, err)
		}
		if n, _ := a.DeleteUnlessLast(ctx, 9999); n != 0 {
			t.Fatal("DeleteUnlessLast of an unknown admin")
		}
	})

	t.Run("CreateFirstConcurrent", func(t *testing.T) {
		p, _ := open(t)
		var wg sync.WaitGroup
		var created atomic.Int32
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, ok, err := p.PlatformAdmins().CreateFirst(ctx, "admin"+itoa(int64(i)), "", "h", "t"); err == nil && ok {
					created.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if n, _ := p.PlatformAdmins().Count(ctx); created.Load() != 1 || n != 1 {
			t.Fatalf("concurrent CreateFirst: %d created, %d stored (want exactly one)", created.Load(), n)
		}
	})

	t.Run("Sessions", func(t *testing.T) {
		p, _ := open(t)
		a := p.PlatformAdmins()
		withTOTP, _ := a.Create(ctx, "totp", "", "h", "t")
		a.SetPendingTOTP(ctx, withTOTP, "S")
		a.EnableTOTP(ctx, withTOTP, 1)
		without, _ := a.Create(ctx, "plain", "", "h", "t")
		s := p.PlatformSessions()
		if _, err := s.Get(ctx, "none"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Get of an unknown session: %v", err)
		}
		mk := func(hash string, admin, expires int64) {
			t.Helper()
			if err := s.Create(ctx, ports.PlatformSession{Hash: hash, AdminID: admin, Stage: "mfa", CreatedAt: 1000, LastSeen: 1000, ExpiresAt: expires}); err != nil {
				t.Fatal(err)
			}
		}
		mk("s1", withTOTP, 5000)
		mk("s2", without, 5000)
		mk("s3", without, 2000)
		mk("s4", withTOTP, 1999)
		if err := s.Create(ctx, ports.PlatformSession{Hash: "s1", AdminID: withTOTP, Stage: "mfa"}); err == nil {
			t.Fatal("duplicate session hash accepted")
		}
		if err := s.Create(ctx, ports.PlatformSession{Hash: "bad", AdminID: withTOTP, Stage: "other"}); err == nil {
			t.Fatal("unknown stage accepted")
		}
		got, err := s.Get(ctx, "s1")
		if err != nil || got.Hash != "s1" || got.AdminID != withTOTP || got.Stage != "mfa" || got.CreatedAt != 1000 || got.LastSeen != 1000 || got.ExpiresAt != 5000 || got.MFAAt != 0 {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		if err := s.Touch(ctx, "s1", 1500); err != nil {
			t.Fatal(err)
		}
		if err := s.Promote(ctx, "s1", 1600); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.Get(ctx, "s1"); got.LastSeen != 1500 || got.Stage != "full" || got.MFAAt != 1600 {
			t.Fatalf("after Touch/Promote = %+v", got)
		}
		if err := s.SetMFAAt(ctx, "s1", 1700); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.Get(ctx, "s1"); got.MFAAt != 1700 || got.Stage != "full" {
			t.Fatalf("SetMFAAt = %+v", got)
		}
		if err := s.PruneExpired(ctx, 2000); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, "s4"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("PruneExpired kept an expired session")
		}
		if _, err := s.Get(ctx, "s3"); err != nil {
			t.Fatal("PruneExpired removed a session expiring exactly at the boundary")
		}
		if err := s.DeleteWithoutTOTP(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, "s2"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteWithoutTOTP kept a session of an admin without TOTP")
		}
		if _, err := s.Get(ctx, "s1"); err != nil {
			t.Fatal("DeleteWithoutTOTP removed a session of an admin with TOTP")
		}
		mk("s5", withTOTP, 5000)
		if err := s.Delete(ctx, "s5"); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, "s5"); err != nil {
			t.Fatalf("Delete of a missing session: %v", err)
		}
		if err := s.DeleteForAdmin(ctx, withTOTP); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, "s1"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteForAdmin kept a session")
		}
		mk("s6", without, 5000)
		if n, _ := a.DeleteUnlessLast(ctx, without); n != 1 {
			t.Fatal("DeleteUnlessLast")
		}
		if _, err := s.Get(ctx, "s6"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("a removed administrator's session remains")
		}
	})

	t.Run("Settings", func(t *testing.T) {
		p, _ := open(t)
		s := p.PlatformSettings()
		if _, err := s.Get(ctx, "k"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Get of a missing key: %v", err)
		}
		if v, err := s.Get(ctx, "platform_schema_version"); err != nil || v != "1" {
			t.Fatalf("platform_schema_version = %q, %v", v, err)
		}
		if err := s.Update(ctx, "k", "v"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, "k"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("Update created a setting")
		}
		if err := s.EnsureDefault(ctx, "k", "d1", "system"); err != nil {
			t.Fatal(err)
		}
		if err := s.EnsureDefault(ctx, "k", "d2", "system"); err != nil {
			t.Fatal(err)
		}
		if v, _ := s.Get(ctx, "k"); v != "d1" {
			t.Fatalf("EnsureDefault replaced a stored value: %q", v)
		}
		if err := s.Update(ctx, "k", "v"); err != nil {
			t.Fatal(err)
		}
		if v, _ := s.Get(ctx, "k"); v != "v" {
			t.Fatalf("Update = %q", v)
		}
	})

	t.Run("AuditPage", func(t *testing.T) {
		p, chain := open(t)
		if l, err := p.PlatformAudit().Page(ctx, 0, 10); err != nil || l == nil || len(l) != 0 {
			t.Fatalf("Page on an empty log = %v, %v", l, err)
		}
		for i := int64(1); i <= 5; i++ {
			if err := chain.Insert(ctx, auditRec(i, "2026-01-0"+itoa(i)+"T00:00:00Z", "platform", "act", "root", "ok")); err != nil {
				t.Fatal(err)
			}
		}
		l, err := p.PlatformAudit().Page(ctx, 0, 2)
		if err != nil || len(l) != 2 || l[0].Seq != 5 || l[1].Seq != 4 || l[0] != auditRec(5, "2026-01-05T00:00:00Z", "platform", "act", "root", "ok") {
			t.Fatalf("Page(0, 2) = %+v, %v", l, err)
		}
		if l, _ := p.PlatformAudit().Page(ctx, 4, 10); len(l) != 3 || l[0].Seq != 3 || l[2].Seq != 1 {
			t.Fatalf("Page(4, 10) = %+v", l)
		}
	})

	t.Run("Tx", func(t *testing.T) {
		p, _ := open(t)
		tx, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		mustTenant(t, tx, tenantRec("t1", "one", "One", "active"))
		if n, _ := tx.Tenants().CountBySlug(ctx, "one"); n != 1 {
			t.Fatal("a transaction does not see its own insert")
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Tenants().ByID(ctx, "t1"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("rolled back insert is visible")
		}
		tx, err = p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		mustTenant(t, tx, tenantRec("t1", "one", "One", "active"))
		if err := tx.TenantStorage().CreateDefault(ctx, "t1", "tenants/t1/", "t"); err != nil {
			t.Fatal(err)
		}
		if err := tx.PlatformSettings().Update(ctx, "platform_schema_version", "1"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		tx.Rollback() // no-op after Commit
		if _, err := p.Tenants().ByID(ctx, "t1"); err != nil {
			t.Fatalf("committed insert missing: %v", err)
		}
		if _, err := p.TenantStorage().Get(ctx, "t1"); err != nil {
			t.Fatalf("committed storage decision missing: %v", err)
		}
	})
}
