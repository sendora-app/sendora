// SPDX-License-Identifier: AGPL-3.0-or-later

package platform

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sendora-app/sendora/internal/store"
)

func key32(t *testing.T) []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyDerivationIsDomainSeparated(t *testing.T) {
	master := key32(t)
	a, _ := store.TenantDBKey(master, "aaaaaaaaaaaaaaaaaaaaaaaaaa")
	b, _ := store.TenantDBKey(master, "bbbbbbbbbbbbbbbbbbbbbbbbbb")
	pk, _ := store.PlatformDBKey(master)
	if bytes.Equal(a, b) || bytes.Equal(a, pk) || bytes.Equal(a, master) || bytes.Equal(pk, master) {
		t.Fatal("derived keys must differ from each other and from the master key")
	}
	again, _ := store.TenantDBKey(master, "aaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !bytes.Equal(a, again) {
		t.Fatal("derivation must be deterministic")
	}
	if _, err := store.TenantDBKey(master, "../etc"); err == nil {
		t.Fatal("invalid tenant id accepted")
	}
}

func TestPlatformDatabaseIsEncryptedAndRoutes(t *testing.T) {
	dir := t.TempDir()
	master := key32(t)
	if _, err := Open(dir, master, false); err == nil {
		t.Fatal("platform database created without explicit initialisation")
	}
	p, err := Open(dir, master, true)
	if err != nil {
		t.Fatal(err)
	}
	tn, err := p.CreateTenant("klant1", "Klant 1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateTenant("klant1", "dup", 0, 0); !errors.Is(err, ErrSlugTaken) {
		t.Fatal("duplicate slug:", err)
	}
	for _, bad := range []string{"admin", "www", "-x", "x", "a_b", "UPPER!", "xn--", "a--b"} {
		if ValidSlug(bad) {
			t.Fatal("slug accepted:", bad)
		}
	}
	if id, ok := p.TenantForHost("klant1.example.test", "example.test:9090"); !ok || id != tn.ID {
		t.Fatal("subdomain routing")
	}
	for _, h := range []string{"example.test", "admin.example.test", "x.klant1.example.test", "klant1.example.test.evil.test"} {
		if _, ok := p.TenantForHost(h, "example.test"); ok {
			t.Fatal("routed:", h)
		}
	}
	if _, err := p.AddCustomDomain(tn.ID, "files.example.test", "example.test"); err == nil {
		t.Fatal("subdomain of the base accepted as custom domain")
	}
	d, err := p.AddCustomDomain(tn.ID, "Files.Klant1.NL.", "example.test")
	if err != nil || d.Domain != "files.klant1.nl" {
		t.Fatal(d, err)
	}
	if _, ok := p.TenantForHost("files.klant1.nl", "example.test"); ok {
		t.Fatal("unverified custom domain routed")
	}
	p.MarkDomainVerified(tn.ID, d.Domain)
	if id, ok := p.TenantForHost("files.klant1.nl", "example.test"); !ok || id != tn.ID {
		t.Fatal("verified custom domain not routed")
	}
	p.Close()
	raw, _ := os.ReadFile(filepath.Join(dir, store.PlatformDBFile))
	if bytes.Contains(raw, []byte("klant1")) || bytes.HasPrefix(raw, []byte("SQLite format 3")) {
		t.Fatal("platform database is not encrypted")
	}
	if _, err := Open(dir, key32(t), false); err == nil {
		t.Fatal("platform database opened with another master key")
	}
}

// singleTenantDir creates an encrypted single-tenant data directory with a
// share directory and a backup.
func singleTenantDir(t *testing.T, key []byte) string {
	dir := t.TempDir()
	st, err := store.OpenEncrypted(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "shares", "some-share"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "shares", "some-share", "blob"), []byte("x"), 0o600)
	if err := st.ExportEncryptedBackup(filepath.Join(dir, "backups", "sendora-encrypted-20260101-000000-aaaaaaaaaaaa.db")); err != nil {
		t.Fatal(err)
	}
	st.Close()
	return dir
}

func TestImportAbortAndResume(t *testing.T) {
	master := key32(t)
	dir := singleTenantDir(t, master)
	p, err := Open(dir, master, true)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, phase := range []string{phaseRegistered, phaseDatabase, phaseMoved, phaseVerified} {
		importFailAfter = phase
		_, err := p.ImportSingleTenant(ImportOptions{Slug: "klant1"})
		importFailAfter = ""
		if !errors.Is(err, errImportInjected) {
			t.Fatal(phase, err)
		}
		res, err := p.ImportSingleTenant(ImportOptions{Abort: true})
		if err != nil || !res.Aborted {
			t.Fatal("abort after", phase, err)
		}
		for _, f := range []string{store.DBFile, "shares/some-share/blob", "backups"} {
			if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
				t.Fatal("after abort in", phase, "missing", f)
			}
		}
		if ts, _ := p.Tenants(""); len(ts) != 0 {
			t.Fatal("tenant left after abort")
		}
		ents, _ := os.ReadDir(filepath.Join(dir, "tenants"))
		if len(ents) != 0 {
			t.Fatal("tenant directory left after abort")
		}
	}
	// Interrupted, then resumed to the end.
	importFailAfter = phaseMoved
	if _, err := p.ImportSingleTenant(ImportOptions{Slug: "klant1"}); !errors.Is(err, errImportInjected) {
		t.Fatal(err)
	}
	importFailAfter = ""
	res, err := p.ImportSingleTenant(ImportOptions{})
	if err != nil {
		t.Fatal("resume:", err)
	}
	if res.Backups != 1 {
		t.Fatal("backups", res.Backups)
	}
	tn, _ := p.Tenant(res.TenantID)
	if tn.Status != StatusActive || tn.KeyMode != KeyLegacy {
		t.Fatalf("%+v", tn)
	}
	dbKey, root, _ := p.TenantKeys(tn)
	if !bytes.Equal(root, master) {
		t.Fatal("legacy root must be the master key when the source used it")
	}
	tdir, _ := p.TenantDir(tn.ID)
	if !store.DatabaseReadable(filepath.Join(tdir, "backups", "sendora-encrypted-20260101-000000-aaaaaaaaaaaa.db"), dbKey) {
		t.Fatal("backup not re-encrypted with the tenant key")
	}
	if _, err := os.Stat(filepath.Join(tdir, "shares", "some-share", "blob")); err != nil {
		t.Fatal("shares not moved")
	}
	if _, err := p.ImportSingleTenant(ImportOptions{Abort: true}); err == nil {
		t.Fatal("abort after completion must fail")
	}
}

// TestActivatePending: the Cluster controller activates a tenant created by
// CreatePendingTenant once its database exists. SetStatus refuses that
// transition (it only moves between active and suspended), so the controller
// must use ActivatePending; an active or unknown tenant is not "pending".
func TestActivatePending(t *testing.T) {
	p, err := Open(t.TempDir(), key32(t), true)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	tn, err := p.CreatePendingTenant("pending1", "Pending", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SetStatus(tn.ID, StatusActive); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetStatus on a pending tenant: %v, want ErrNotFound", err)
	}
	if err := p.ActivatePending(tn.ID); err != nil {
		t.Fatal(err)
	}
	got, err := p.Tenant(tn.ID)
	if err != nil || got.Status != StatusActive {
		t.Fatalf("after ActivatePending: %+v, %v", got, err)
	}
	if err := p.ActivatePending(tn.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second ActivatePending: %v, want ErrNotFound", err)
	}
	if err := p.ActivatePending("aaaaaaaaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown tenant: %v, want ErrNotFound", err)
	}
}
