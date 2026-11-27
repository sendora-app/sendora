// SPDX-License-Identifier: AGPL-3.0-or-later

package platform

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/sendora-app/sendora/internal/storage"
)

// Object storage in multi-tenant mode (docs/MULTI-TENANT.md, "Storage").
//
// A tenant's storage is the tenant's own business. The platform decides only:
//
//	TenantManaged  whether the tenant's administrators may configure storage
//	               of their own (S3, Azure Blob, GCS) in their Admin -> Storage
//	               (default on). The platform never sees, changes or tests
//	               that configuration; it lives in the tenant's database.
//	Offer          what the platform provides itself, optionally:
//	  none         nothing (the default for new tenants): until the tenant's
//	               administrators set up storage, uploads are refused.
//	  platform     the platform's default bucket (platform settings
//	               platform_storage_*, or SENDORA_PLATFORM_STORAGE_*) under the
//	               tenant's fixed prefix tenants/<tenant id>/ (storage.Config
//	               .WithPrefix); while the platform default is the local data
//	               directory, the tenant's directory.
//	  local        the local disk of the server (the tenant's directory).
//
// Files keep the location they were written to (storage_locations in the
// tenant's database), so changing any of this only affects new files.

// Storage offers.
const (
	OfferNone     = "none"
	OfferPlatform = "platform"
	OfferLocal    = "local"
)

// StorageConfig is the platform's storage decision for one tenant. It holds
// no configuration of the tenant's own storage.
type StorageConfig struct {
	Offer         string `json:"offer"`
	Prefix        string `json:"-"`
	TenantManaged bool   `json:"tenant_managed"`
	UpdatedAt     string `json:"updated_at"`
}

// TenantPrefix is the fixed prefix of a tenant inside the platform default.
func TenantPrefix(tenantID string) string { return "tenants/" + tenantID + "/" }

// storageKeys are the storage_* settings of the platform default (the remote
// backup switch is a setting of each tenant).
func storageKeys() []string {
	var out []string
	for _, s := range storage.Settings {
		if s.Key != "backup_remote_enabled" {
			out = append(out, s.Key)
		}
	}
	return out
}

// ValidOffer reports whether o is a storage offer.
func ValidOffer(o string) bool { return o == OfferNone || o == OfferPlatform || o == OfferLocal }

// Storage returns a tenant's storage decision (no offer, own storage allowed,
// when nothing is stored).
func (p *Platform) Storage(tenantID string) (*StorageConfig, error) {
	c := &StorageConfig{Offer: OfferNone, TenantManaged: true}
	d, err := p.repo.TenantStorage().Get(context.Background(), tenantID)
	if err == nil {
		c.Offer, c.TenantManaged, c.UpdatedAt = d.Offer, d.TenantManaged, d.UpdatedAt
		if !ValidOffer(c.Offer) {
			c.Offer = OfferNone
		}
	} else if _, terr := p.Tenant(tenantID); terr != nil {
		return nil, ErrNotFound
	}
	c.Prefix = TenantPrefix(tenantID)
	return c, nil
}

// PlatformStorage is the platform default backend (platform_storage_* settings).
func (p *Platform) PlatformStorage() storage.Config {
	return storage.FromSettings(func(k string) string { return p.Setting("platform_" + k) })
}

// Resolve returns the backend the platform provides to a tenant (the
// tenant's own storage, when configured, is applied by the tenant's server on
// top of this): KindNone without an offer. LocalRoot is left for the caller.
func (p *Platform) Resolve(tenantID string, c *StorageConfig) storage.Config {
	offer := OfferNone
	if c != nil {
		offer = c.Offer
	}
	switch offer {
	case OfferLocal:
		return storage.Config{Backend: storage.KindLocal}
	case OfferPlatform:
		def := p.PlatformStorage()
		if def.Backend == storage.KindLocal {
			return storage.Config{Backend: storage.KindLocal}
		}
		return def.WithPrefix(TenantPrefix(tenantID))
	}
	return storage.Config{Backend: storage.KindNone}
}

// MergeStorageSettings validates the storage_* settings in (as sent by the
// console's form for the platform default) against the stored ones in prev:
// unknown keys are refused, an empty secret keeps the stored value, and a
// stored secret must be typed again when the place it is sent to changes. It
// returns the complete set.
func MergeStorageSettings(prev map[string]string, in map[string]string) (map[string]string, error) {
	next := map[string]string{}
	for k, v := range prev {
		next[k] = v
	}
	changed := map[string]bool{}
	typed := map[string]bool{}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := in[k]
		if !storage.IsSetting(k) || k == "backup_remote_enabled" {
			return nil, fmt.Errorf("%s: unknown storage setting", k)
		}
		if storage.SettingSecret(k) && v == "" {
			continue
		}
		norm, _, err := storage.NormalizeSetting(k, v)
		if err != nil {
			return nil, err
		}
		if storage.SettingSecret(k) {
			typed[k] = true
		}
		if norm != prev[k] {
			changed[k] = true
		}
		next[k] = norm
	}
	if secret := storage.SecretRetypeNeeded(func(k string) bool { return changed[k] }, func(k string) bool { return typed[k] }, func(k string) bool { return prev[k] != "" }); secret != "" {
		return nil, fmt.Errorf("enter the storage secret again when changing the endpoint, account or access key (%s)", secret)
	}
	return next, nil
}

// NewTenantOffer is the storage offer for new tenants (platform setting
// new_tenant_storage_offer, default none).
func (p *Platform) NewTenantOffer() string {
	if o := p.Setting("new_tenant_storage_offer"); ValidOffer(o) {
		return o
	}
	return OfferNone
}

// CheckOffer refuses an offer the platform cannot provide: the platform
// bucket needs a configured platform default backend.
func (p *Platform) CheckOffer(offer string) error {
	if !ValidOffer(offer) {
		return errors.New("storage offer must be none, platform or local")
	}
	if offer == OfferPlatform && p.PlatformStorage().Backend == storage.KindLocal {
		return errors.New("configure a platform default storage backend (Default storage) before offering the platform bucket")
	}
	return nil
}

// SetStorage stores a tenant's storage decision: the platform's offer and
// whether the tenant may configure storage of its own.
func (p *Platform) SetStorage(tenantID, offer string, tenantManaged bool) error {
	defer p.changed()
	if !ValidOffer(offer) {
		return errors.New("storage offer must be none, platform or local")
	}
	n, err := p.repo.TenantStorage().Set(context.Background(), tenantID, TenantPrefix(tenantID), offer, tenantManaged, now())
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// StorageLocations lists the platform-provided location a tenant's data may
// be in (its fixed prefix in the platform default), for removal when the
// tenant is deleted.
func (p *Platform) StorageLocations(tenantID string) []storage.Config {
	if def := p.PlatformStorage(); def.Backend != storage.KindLocal {
		return []storage.Config{def.WithPrefix(TenantPrefix(tenantID))}
	}
	return nil
}
