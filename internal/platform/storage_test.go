// SPDX-License-Identifier: AGPL-3.0-or-later

package platform

import (
	"context"
	"testing"

	"github.com/sendora-app/sendora/internal/storage"
)

func ownS3(bucket, prefix string) map[string]string {
	return map[string]string{"storage_backend": "s3", "storage_s3_endpoint": "https://s3.example.com", "storage_s3_region": "eu-west-1",
		"storage_s3_bucket": bucket, "storage_s3_prefix": prefix, "storage_s3_auth": "static", "storage_s3_access_key": "AK", "storage_s3_secret_key": "SECRET"}
}

func TestTenantStorageOffers(t *testing.T) {
	p, err := Open(t.TempDir(), key32(t), true)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	a, err := p.CreateTenant("klanta", "A", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := p.CreateTenant("klantb", "B", 0, 0)
	sc, err := p.Storage(a.ID)
	if err != nil || sc.Offer != OfferNone || !sc.TenantManaged {
		t.Fatalf("default decision %+v %v", sc, err)
	}
	if c := p.Resolve(a.ID, sc); c.Backend != storage.KindNone {
		t.Fatalf("no offer must mean no storage: %+v", c)
	}
	if err := p.SetStorage(a.ID, "own", true); err == nil {
		t.Fatal("invalid offer accepted")
	}
	p.SetStorage(a.ID, OfferLocal, false)
	if sc, _ = p.Storage(a.ID); sc.Offer != OfferLocal || sc.TenantManaged || p.Resolve(a.ID, sc).Backend != storage.KindLocal {
		t.Fatalf("local offer %+v", sc)
	}
	// The platform bucket: the tenant's fixed prefix inside the platform default.
	next, err := MergeStorageSettings(p.StorageSettings(), ownS3("platform-bucket", "sendora/"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.PutStorageSettings(next, nil); err != nil {
		t.Fatal(err)
	}
	offer := &StorageConfig{Offer: OfferPlatform}
	ca, cb := p.Resolve(a.ID, offer), p.Resolve(b.ID, offer)
	if ca.Prefix != "sendora/tenants/"+a.ID+"/" || cb.Prefix != "sendora/tenants/"+b.ID+"/" || ca.S3Bucket != "platform-bucket" || ca.Overlaps(cb) {
		t.Fatalf("tenant prefixes %q %q", ca.Prefix, cb.Prefix)
	}
	if locs := p.StorageLocations(a.ID); len(locs) != 1 || locs[0].Prefix != ca.Prefix {
		t.Fatalf("locations %+v", locs)
	}
	// A blank secret keeps the stored one; changing the endpoint needs it again.
	merged, err := MergeStorageSettings(next, map[string]string{"storage_s3_bucket": "platform-bucket2", "storage_s3_secret_key": ""})
	if err != nil || merged["storage_s3_secret_key"] != "SECRET" {
		t.Fatalf("merge %v %v", merged, err)
	}
	if _, err := MergeStorageSettings(next, map[string]string{"storage_s3_endpoint": "https://evil.example.com"}); err == nil {
		t.Fatal("endpoint changed without retyping the secret")
	}
	if _, err := MergeStorageSettings(next, map[string]string{"backup_remote_enabled": "true"}); err == nil {
		t.Fatal("non-storage key accepted")
	}
}

// Tenants stored before the storage offer existed keep the platform default.
func TestStorageOfferMigration(t *testing.T) {
	dir, master := t.TempDir(), key32(t)
	p, err := Open(dir, master, true)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := p.CreateTenant("klanta", "A", 0, 0)
	if _, err := p.St.DB.Exec(`ALTER TABLE tenant_storage DROP COLUMN offer`); err != nil {
		t.Fatal(err)
	}
	p.Close()
	p, err = Open(dir, master, false)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if sc, _ := p.Storage(a.ID); sc.Offer != OfferPlatform {
		t.Fatalf("existing tenant lost its storage: %+v", sc)
	}
	b, _ := p.CreateTenant("klantb", "B", 0, 0)
	if sc, _ := p.Storage(b.ID); sc.Offer != OfferNone {
		t.Fatalf("new tenant after migration: %+v", sc)
	}
}

func TestPlatformMFASettingAndTemporaryPassword(t *testing.T) {
	p, err := Open(t.TempDir(), key32(t), true)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if !p.MFARequired() {
		t.Fatal("MFA must be required by default")
	}
	if _, err := p.PutSettings(map[string]string{"platform_mfa_required": "maybe"}, nil); err == nil {
		t.Fatal("invalid value accepted")
	}
	if _, err := p.PutSettings(map[string]string{"platform_mfa_required": "false"}, nil); err != nil || p.MFARequired() {
		t.Fatal("not switched off", err)
	}
	if _, err := p.PutSettings(map[string]string{"platform_storage_s3_bucket": "x"}, nil); err == nil {
		t.Fatal("storage setting through the generic settings")
	}
	a, err := p.CreateFirstAdmin("root", "", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SetTemporaryPassword(a.ID, "temp"); err != nil {
		t.Fatal(err)
	}
	a, _ = p.AdminByID(a.ID)
	if !a.MustChangePassword || a.PasswordHash != "temp" {
		t.Fatal("temporary password not marked")
	}
	p.SetPassword(a.ID, "new")
	if a, _ = p.AdminByID(a.ID); a.MustChangePassword {
		t.Fatal("mark not cleared by a new password")
	}
	if n := p.SettingIntRange("max_open_tenants", 50, 1, 10000); n != 50 {
		t.Fatal(n)
	}
	p.repo.PlatformSettings().Update(context.Background(), "max_open_tenants", "99999999999999999999") // a setting value is sealed: write it through the repository
	if n := p.SettingIntRange("max_open_tenants", 50, 1, 10000); n != 50 {
		t.Fatal("unparsable value", n)
	}
	p.repo.PlatformSettings().Update(context.Background(), "max_open_tenants", "-5")
	if n := p.SettingIntRange("max_open_tenants", 50, 1, 10000); n != 1 {
		t.Fatal("clamp", n)
	}
}

// Tenants may configure their own storage by default, also tenants stored
// before the switch existed; an explicit "off" from the console is kept.
func TestTenantManagedDefaultOn(t *testing.T) {
	dir, master := t.TempDir(), key32(t)
	p, err := Open(dir, master, true)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := p.CreateTenant("klanta", "A", 0, 0)
	b, _ := p.CreateTenant("klantb", "B", 0, 0)
	if sc, _ := p.Storage(a.ID); !sc.TenantManaged {
		t.Fatal("new tenant: own storage not allowed by default")
	}
	if err := p.SetStorage(b.ID, OfferNone, false); err != nil {
		t.Fatal(err)
	}
	// A row from an earlier build: off without an explicit choice.
	p.St.DB.Exec(`UPDATE tenant_storage SET tenant_managed=0, tenant_managed_explicit=0 WHERE tenant_id=?`, a.ID)
	p.Close()
	p, err = Open(dir, master, false)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if sc, _ := p.Storage(a.ID); !sc.TenantManaged {
		t.Fatal("existing tenant without a choice not switched on")
	}
	if sc, _ := p.Storage(b.ID); sc.TenantManaged {
		t.Fatal("explicit off was overridden")
	}
}
