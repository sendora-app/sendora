// SPDX-License-Identifier: AGPL-3.0-or-later

// Package platform holds the data of multi-tenant mode: the platform database
// (DATA_DIR/platform.db) with tenants, their domains, quotas and storage
// configuration, the platform administrators and the platform audit log. It
// never opens or reads a tenant's database except in the offline conversion
// (import.go); serving tenants is internal/app's job (mt_*.go).
package platform

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/masterkey"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// Tenant statuses.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	// StatusImporting marks a tenant whose offline conversion has not finished;
	// it is never served.
	StatusImporting = "importing"
)

// Key modes of a tenant (see store/tenant.go).
const (
	KeyDerived = "derived"
	KeyLegacy  = "legacy"
)

// KEK modes of a tenant (D41, D44): who holds the key-encryption key that
// wraps the tenant's data keys.
const (
	KEKPlatform = "platform"
	KEKTenant   = "tenant"
)

// Platform is the open platform database.
type Platform struct {
	St      *store.Store
	DataDir string
	master  []byte
	keys    KeyProvider    // when set, tenant keys come from here and master is unused (web replicas)
	masters *masterkey.Set // when set (controller), tenant keys derive from the tenant's master version (D46)

	repo ports.PlatformStore // repositories on St.DB (internal/adapters/sqlite)

	// OnChange, when set, runs after every change of tenants, domains,
	// tenant storage or platform settings made through this Platform. The
	// Cluster flavour tells the other replicas (design 4.6); nil does nothing.
	OnChange func()

	mu      sync.RWMutex
	domains map[string]string // verified custom domain -> tenant id (lookup cache)
	slugs   map[string]string // slug -> tenant id
	routes  map[string]Route  // tenant id -> routing data
}

// Open opens or (with initialize) creates DATA_DIR/platform.db. The master key
// is kept to derive the tenants' database keys.
func Open(dataDir string, master []byte, initialize bool) (*Platform, error) {
	key, err := store.PlatformDBKey(master)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	st, err := store.OpenPlatform(dataDir, key, initialize, sqlite.PlatformSchema)
	if err != nil {
		return nil, err
	}
	for _, d := range []string{"tenants"} {
		if err := os.MkdirAll(filepath.Join(dataDir, d), 0o700); err != nil {
			st.Close()
			return nil, err
		}
	}
	if err := sqlite.MigratePlatform(st.DB); err != nil {
		st.Close()
		return nil, err
	}
	p := &Platform{St: st, DataDir: dataDir, master: append([]byte(nil), master...), repo: st.PlatformRepo()}
	for _, d := range settingDefaults {
		p.repo.PlatformSettings().EnsureDefault(context.Background(), d.Key, d.Val, d.Grp)
	}
	if err := p.reloadDomains(); err != nil {
		st.Close()
		return nil, err
	}
	return p, nil
}

// OpenOn opens the platform on an already migrated database: st holds the
// settings and the platform audit chain (store.OpenRemote), repo the platform
// repositories (the PostgreSQL adapter in the Cluster flavour). The master
// key is kept to derive the tenants' keys.
func OpenOn(st *store.Store, repo ports.PlatformStore, dataDir string, master []byte) (*Platform, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "tenants"), 0o700); err != nil {
		return nil, err
	}
	p := &Platform{St: st, DataDir: dataDir, master: append([]byte(nil), master...), repo: repo}
	for _, d := range settingDefaults {
		p.repo.PlatformSettings().EnsureDefault(context.Background(), d.Key, d.Val, d.Grp)
	}
	if err := p.reloadDomains(); err != nil {
		return nil, err
	}
	return p, nil
}

// KeyProvider supplies a tenant's keys without the master key (Cluster web
// replicas fetch them from the controller; docs/cluster/DESIGN.md D42). root
// is nil for a native tenant. The caller wipes both after use.
type KeyProvider interface {
	TenantKeys(id string) (dbKey, root []byte, err error)
}

// UseMasters gives the Platform the versions of the master key (controller):
// a tenant's keys are then derived from the version its record names.
func (p *Platform) UseMasters(m *masterkey.Set) { p.masters = m }

// UseKeyProvider makes TenantKeys ask kp instead of deriving from the master
// key; the Platform then does not need a master key at all.
func (p *Platform) UseKeyProvider(kp KeyProvider) { p.keys = kp }

// RemoteKeys is a KeyProvider on top of ports.ClusterKeys (the key client).
type RemoteKeys struct{ Src ports.ClusterKeys }

// TenantKeys implements KeyProvider.
func (r RemoteKeys) TenantKeys(id string) (dbKey, root []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	k, err := r.Src.Tenant(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if dbKey, err = hex.DecodeString(k.DBKey); err != nil || len(dbKey) != 32 {
		return nil, nil, errors.New("key endpoint returned an invalid tenant key")
	}
	if k.Root != "" {
		if root, err = hex.DecodeString(k.Root); err != nil || len(root) != 32 {
			clear(dbKey)
			return nil, nil, errors.New("key endpoint returned an invalid tenant root key")
		}
	}
	return dbKey, root, nil
}

// Reload re-reads the routing data (slugs, domains, statuses) after another
// replica changed it.
func (p *Platform) Reload() error { return p.reloadDomains() }

func (p *Platform) changed() {
	if p.OnChange != nil {
		p.OnChange()
	}
}

// Close closes the platform database and wipes the kept master key.
func (p *Platform) Close() error {
	clear(p.master)
	return p.St.Close()
}

// Tenant is one row of tenants.
type Tenant struct {
	ID              string `json:"id"`
	Slug            string `json:"slug"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	MaxUsers        int64  `json:"max_users"`
	MaxStorageBytes int64  `json:"max_storage_bytes"`
	KeyMode         string `json:"key_mode"`
	// KEKMode is KEKPlatform or KEKTenant; KEKFingerprint identifies the
	// tenant-supplied KEK (never the KEK itself).
	KEKMode        string `json:"kek_mode"`
	KEKFingerprint string `json:"kek_fingerprint,omitempty"`
	// MasterVersion is the master key version the tenant's derived material
	// (its platform KEK root) comes from (D46).
	MasterVersion int    `json:"master_version"`
	PrimaryDomain string `json:"primary_domain"`
	StatUsers     int64  `json:"user_count"`
	StatStorage   int64  `json:"storage_used_bytes"`
	StatUpdatedAt string `json:"stats_updated_at"`
	// AllowPrivateTargets lets the tenant's administrators point SMTP, sign-in
	// providers, audit forwarding and their own storage at private, loopback
	// and link-local addresses (off: the multi-tenant SSRF guard applies).
	AllowPrivateTargets bool `json:"allow_private_targets"`
	legacyRoot          []byte
}

// tenantFrom converts a stored tenant.
func tenantFrom(r ports.TenantRecord) *Tenant {
	return &Tenant{ID: r.ID, Slug: r.Slug, Name: r.Name, Status: r.Status, CreatedAt: r.CreatedAt, MaxUsers: r.MaxUsers,
		MaxStorageBytes: r.MaxStorageBytes, KeyMode: r.KeyMode, KEKMode: kekModeOf(r.KEKMode), KEKFingerprint: r.KEKFingerprint, MasterVersion: max(r.MasterVersion, 1), PrimaryDomain: r.PrimaryDomain, StatUsers: r.StatUsers,
		StatStorage: r.StatStorageBytes, StatUpdatedAt: r.StatUpdatedAt, AllowPrivateTargets: r.AllowPrivateTargets, legacyRoot: r.LegacyRoot}
}

func kekModeOf(m string) string {
	if m == KEKTenant {
		return KEKTenant
	}
	return KEKPlatform
}

// SetKEK records who holds the tenant's KEK and the fingerprint of a
// tenant-supplied one ("" for KEKPlatform), then tells the other replicas.
func (p *Platform) SetKEK(id, mode, fingerprint string) error {
	if mode != KEKPlatform && mode != KEKTenant {
		return fmt.Errorf("invalid KEK mode %q", mode)
	}
	if mode == KEKPlatform {
		fingerprint = ""
	}
	defer p.changed()
	n, err := p.repo.Tenants().SetKEK(context.Background(), id, mode, fingerprint)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// tenantResult maps a repository lookup to the package's result.
func tenantResult(r ports.TenantRecord, err error) (*Tenant, error) {
	if errors.Is(err, ports.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return tenantFrom(r), nil
}

// ErrNotFound is returned for an unknown tenant, domain or administrator.
var ErrNotFound = errors.New("not found")

// Tenant returns one tenant by ID.
func (p *Platform) Tenant(id string) (*Tenant, error) {
	return tenantResult(p.repo.Tenants().ByID(context.Background(), id))
}

// TenantBySlug returns one tenant by slug.
func (p *Platform) TenantBySlug(slug string) (*Tenant, error) {
	return tenantResult(p.repo.Tenants().BySlug(context.Background(), strings.ToLower(slug)))
}

// Tenants lists tenants, optionally filtered by a search over slug, name and
// domains.
func (p *Platform) Tenants(q string) ([]*Tenant, error) {
	rows, err := p.repo.Tenants().List(context.Background(), strings.TrimSpace(strings.ToLower(q)))
	if err != nil {
		return nil, err
	}
	out := make([]*Tenant, 0, len(rows))
	for _, r := range rows {
		out = append(out, tenantFrom(r))
	}
	return out, nil
}

// NewTenantID returns a random tenant ID (26 lowercase base32 characters).
func NewTenantID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

var slugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// reservedSlugs cannot be tenant subdomains: they are the console's host or
// commonly used for other services on the same domain.
var reservedSlugs = map[string]bool{
	"admin": true, "www": true, "api": true, "app": true, "mail": true, "smtp": true, "imap": true, "pop": true,
	"ftp": true, "static": true, "assets": true, "cdn": true, "platform": true, "console": true, "status": true,
	"root": true, "sendora": true, "ns1": true, "ns2": true, "autodiscover": true, "autoconfig": true, "localhost": true,
	"default": true, "system": true, "support": true, "help": true, "docs": true, "auth": true, "login": true, "sso": true,
}

// ValidSlug reports whether s can be a tenant subdomain.
func ValidSlug(s string) bool {
	return len(s) >= 2 && slugPattern.MatchString(s) && !strings.Contains(s, "--") && !reservedSlugs[s]
}

var hostLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain lowercases a host name and checks it is a plausible DNS name
// with at least two labels.
func NormalizeDomain(d string) (string, bool) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if len(d) > 253 || !strings.Contains(d, ".") {
		return "", false
	}
	for _, l := range strings.Split(d, ".") {
		if !hostLabel.MatchString(l) {
			return "", false
		}
	}
	return d, true
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// CreateTenant inserts a new tenant with its subdomain. The caller creates the
// tenant's database afterwards (app.TenantHost.Provision).
func (p *Platform) CreateTenant(slug, name string, maxUsers, maxStorage int64) (*Tenant, error) {
	return p.createTenant(slug, name, maxUsers, maxStorage, StatusActive)
}

// CreatePendingTenant registers a tenant whose database the Cluster
// controller still has to provision: it has status importing (never served)
// until the controller sets it active.
func (p *Platform) CreatePendingTenant(slug, name string, maxUsers, maxStorage int64) (*Tenant, error) {
	return p.createTenant(slug, name, maxUsers, maxStorage, StatusImporting)
}

// ActivatePending sets a pending tenant (status importing, CreatePendingTenant)
// active once its database exists. SetStatus does not do this: it only moves
// between active and suspended. ErrNotFound when no pending tenant has this id.
func (p *Platform) ActivatePending(id string) error {
	defer p.changed()
	t, err := p.Tenant(id)
	if err != nil {
		return err
	}
	if t.Status != StatusImporting {
		return ErrNotFound
	}
	if err := p.repo.Tenants().Activate(context.Background(), id); err != nil {
		return err
	}
	return p.reloadDomains()
}

func (p *Platform) createTenant(slug, name string, maxUsers, maxStorage int64, status string) (*Tenant, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if !ValidSlug(slug) {
		return nil, fmt.Errorf("invalid or reserved subdomain")
	}
	if maxUsers < 0 || maxStorage < 0 {
		return nil, fmt.Errorf("invalid quota")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = slug
	}
	if len(name) > 200 {
		return nil, fmt.Errorf("name too long")
	}
	t := &Tenant{ID: NewTenantID(), Slug: slug, Name: name, Status: status, CreatedAt: now(), MaxUsers: maxUsers, MaxStorageBytes: maxStorage, KeyMode: KeyDerived,
		MasterVersion: int(p.SettingInt("master_active_version", 1))}
	if err := p.insertTenant(t, nil); err != nil {
		return nil, err
	}
	return t, nil
}

// ErrSlugTaken is returned when the subdomain is in use.
var ErrSlugTaken = errors.New("this subdomain is already in use")

func (p *Platform) insertTenant(t *Tenant, legacyRoot []byte) error {
	defer p.changed()
	ctx := context.Background()
	tx, err := p.repo.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	n, _ := tx.Tenants().CountBySlug(ctx, t.Slug)
	if n > 0 {
		return ErrSlugTaken
	}
	if err := tx.Tenants().Insert(ctx, ports.TenantRecord{ID: t.ID, Slug: t.Slug, Name: t.Name, Status: t.Status, CreatedAt: t.CreatedAt,
		MaxUsers: t.MaxUsers, MaxStorageBytes: t.MaxStorageBytes, KeyMode: t.KeyMode, LegacyRoot: legacyRoot, MasterVersion: max(t.MasterVersion, 1)}); err != nil {
		return err
	}
	if err := tx.TenantStorage().CreateDefault(ctx, t.ID, "tenants/"+t.ID+"/", now()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return p.reloadDomains()
}

// baseHost strips an optional port from the base domain.
func baseHost(base string) string {
	base = strings.ToLower(strings.TrimSpace(base))
	if i := strings.LastIndexByte(base, ':'); i >= 0 && !strings.Contains(base[i:], "]") {
		base = base[:i]
	}
	return strings.TrimSuffix(base, ".")
}

// SetStatus changes a tenant's status (active or suspended).
func (p *Platform) SetStatus(id, status string) error {
	defer p.changed()
	if status != StatusActive && status != StatusSuspended {
		return fmt.Errorf("invalid status")
	}
	n, err := p.repo.Tenants().SetStatus(context.Background(), id, status)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return p.reloadDomains()
}

// SetQuotas changes a tenant's limits (0 = unlimited).
func (p *Platform) SetQuotas(id string, maxUsers, maxStorage int64) error {
	defer p.changed()
	if maxUsers < 0 || maxStorage < 0 {
		return fmt.Errorf("invalid quota")
	}
	n, err := p.repo.Tenants().SetQuotas(context.Background(), id, maxUsers, maxStorage)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetName renames a tenant (display name only).
func (p *Platform) SetName(id, name string) error {
	defer p.changed()
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return fmt.Errorf("invalid name")
	}
	return p.repo.Tenants().SetName(context.Background(), id, name)
}

// UpdateStats stores the counts shown in the console (never content).
func (p *Platform) UpdateStats(id string, users, storage int64) {
	p.repo.Tenants().UpdateStats(context.Background(), id, users, storage, now())
}

// SetAllowPrivateTargets switches the SSRF guard of a tenant off (true) or on.
func (p *Platform) SetAllowPrivateTargets(id string, allow bool) error {
	defer p.changed()
	n, err := p.repo.Tenants().SetAllowPrivateTargets(context.Background(), id, allow)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteTenantRow removes the tenant and its domains and storage config from
// the platform database. The caller removes the tenant's directory first.
func (p *Platform) DeleteTenantRow(id string) error {
	defer p.changed()
	if err := p.repo.Tenants().Delete(context.Background(), id); err != nil {
		return err
	}
	return p.reloadDomains()
}

// TenantDir is the tenant's data directory.
func (p *Platform) TenantDir(id string) (string, error) {
	if !store.TenantIDPattern.MatchString(id) {
		return "", fmt.Errorf("invalid tenant id")
	}
	return filepath.Join(p.DataDir, "tenants", id), nil
}

// TenantKeys returns the tenant's database key and its file/audit root (nil
// for a native tenant). The caller wipes both after use. On a controller with
// versioned master keys the material comes from the version the tenant's
// record names.
func (p *Platform) TenantKeys(t *Tenant) (dbKey, root []byte, err error) {
	if p.keys != nil {
		return p.keys.TenantKeys(t.ID)
	}
	return p.TenantKeysAt(t, t.MasterVersion)
}

// TenantKeysAt is TenantKeys derived from master key version v (the master
// rotation derives the old and the new KEK from it).
func (p *Platform) TenantKeysAt(t *Tenant, v int) (dbKey, root []byte, err error) {
	master := p.master
	if p.masters != nil {
		if slices.Contains(parseVersions(p.Setting("master_retired")), max(v, 1)) {
			return nil, nil, fmt.Errorf("master key version %d is retired", v)
		}
		if master, err = p.masters.Key(max(v, 1)); err != nil {
			return nil, nil, err
		}
		defer clear(master)
	}
	dbKey, err = store.TenantDBKey(master, t.ID)
	if err != nil {
		return nil, nil, err
	}
	if t.KeyMode == KeyLegacy {
		if len(t.legacyRoot) == 32 {
			root = append([]byte(nil), t.legacyRoot...)
		} else {
			root = append([]byte(nil), master...)
		}
	}
	return dbKey, root, nil
}

// ---------- domains ----------

// Domain is one row of tenant_domains.
type Domain struct {
	Domain      string `json:"domain"`
	TenantID    string `json:"tenant_id"`
	Kind        string `json:"kind"`
	Verified    bool   `json:"verified"`
	VerifyToken string `json:"verify_token,omitempty"`
	CreatedAt   string `json:"created_at"`
}

func (p *Platform) reloadDomains() error {
	ctx := context.Background()
	domains, err := p.repo.TenantDomains().VerifiedCustom(ctx)
	if err != nil {
		return err
	}
	list, err := p.repo.Tenants().Routes(ctx)
	if err != nil {
		return err
	}
	slugs, routes := map[string]string{}, map[string]Route{}
	for _, t := range list {
		r := Route{ID: t.ID, Slug: t.Slug, Status: t.Status, PrimaryDomain: t.PrimaryDomain}
		slugs[r.Slug], routes[r.ID] = r.ID, r
	}
	p.mu.Lock()
	p.domains, p.slugs, p.routes = domains, slugs, routes
	p.mu.Unlock()
	return nil
}

// Route is the cached routing data of a tenant.
type Route struct {
	ID, Slug, Status, PrimaryDomain string
}

// RouteOf returns the cached routing data of a tenant.
func (p *Platform) RouteOf(id string) (Route, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.routes[id]
	return r, ok
}

// TenantForHost resolves a request host (lowercase, without port) to a tenant
// ID: <slug>.<base domain> or a verified custom domain. ok is false for any
// other host, including the console host and the bare base domain.
func (p *Platform) TenantForHost(host, baseDomain string) (string, bool) {
	base := baseHost(baseDomain)
	p.mu.RLock()
	defer p.mu.RUnlock()
	if label, found := strings.CutSuffix(host, "."+base); found && base != "" {
		if strings.Contains(label, ".") {
			return "", false
		}
		id, ok := p.slugs[label]
		return id, ok
	}
	id, ok := p.domains[host]
	return id, ok
}

// SubdomainHost is the tenant's host under the base domain (without port).
func SubdomainHost(slug, baseDomain string) string { return slug + "." + baseHost(baseDomain) }

// Domains lists a tenant's domains.
func (p *Platform) Domains(tenantID string) ([]Domain, error) {
	list, err := p.repo.TenantDomains().List(context.Background(), tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Domain, 0, len(list))
	for _, d := range list {
		out = append(out, Domain{Domain: d.Domain, TenantID: d.TenantID, Kind: d.Kind, Verified: d.Verified, VerifyToken: d.VerifyToken, CreatedAt: d.CreatedAt})
	}
	return out, nil
}

// VerifyRecordName is the DNS name that must hold the TXT verification record
// of a custom domain.
func VerifyRecordName(domain string) string { return "_sendora-challenge." + domain }

// VerifyRecordValue is the TXT value that proves control of a custom domain.
func VerifyRecordValue(token string) string { return "sendora-verify=" + token }

// ErrDomainTaken is returned when a domain is already mapped.
var ErrDomainTaken = errors.New("this domain is already in use")

// AddCustomDomain maps an unverified custom domain to a tenant and returns its
// verification token.
func (p *Platform) AddCustomDomain(tenantID, domain, baseDomain string) (*Domain, error) {
	defer p.changed()
	d, ok := NormalizeDomain(domain)
	if !ok {
		return nil, fmt.Errorf("invalid domain")
	}
	base := baseHost(baseDomain)
	if d == base || strings.HasSuffix(d, "."+base) {
		return nil, fmt.Errorf("subdomains of the platform's base domain cannot be custom domains")
	}
	if _, err := p.Tenant(tenantID); err != nil {
		return nil, err
	}
	tok := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes(20)))
	if err := p.repo.TenantDomains().AddCustom(context.Background(), d, tenantID, tok, now()); err != nil {
		return nil, ErrDomainTaken
	}
	return &Domain{Domain: d, TenantID: tenantID, Kind: "custom", VerifyToken: tok, CreatedAt: now()}, nil
}

// MarkDomainVerified sets a custom domain verified (after the TXT check).
func (p *Platform) MarkDomainVerified(tenantID, domain string) error {
	defer p.changed()
	n, err := p.repo.TenantDomains().MarkVerified(context.Background(), domain, tenantID)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return p.reloadDomains()
}

// RemoveCustomDomain unmaps a custom domain; the primary domain falls back to
// the subdomain when it was this one.
func (p *Platform) RemoveCustomDomain(tenantID, domain string) error {
	defer p.changed()
	ctx := context.Background()
	n, err := p.repo.TenantDomains().RemoveCustom(ctx, domain, tenantID)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	p.repo.Tenants().ClearPrimaryDomain(ctx, tenantID, domain)
	return p.reloadDomains()
}

// SetPrimaryDomain chooses the domain used for the tenant's links and emails
// ("" = the subdomain).
func (p *Platform) SetPrimaryDomain(tenantID, domain string) error {
	defer p.changed()
	ctx := context.Background()
	n, _ := p.repo.TenantDomains().CountVerified(ctx, domain, tenantID)
	if n == 0 && domain != "" {
		return fmt.Errorf("only a verified domain of this tenant can be the primary domain")
	}
	if err := p.repo.Tenants().SetPrimaryDomain(ctx, tenantID, domain); err != nil {
		return err
	}
	return p.reloadDomains()
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
