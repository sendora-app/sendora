// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/netguard"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/storage"
	"github.com/sendora-app/sendora/internal/storage/storagetest"
	"golang.org/x/crypto/bcrypt"
)

// Multi-tenant object storage, network guard and platform MFA switch.

// memBuckets simulates object stores: one Memory per bucket (identity without
// prefix); a backend sees the bucket through its configuration's prefix, like
// the real backends.
type memBuckets struct {
	mu      sync.Mutex
	buckets map[string]*storagetest.Memory
	opened  []storage.Config
}

func (mb *memBuckets) open(ctx context.Context, cfg storage.Config) (storage.Backend, error) {
	if cfg.Backend == storage.KindLocal || cfg.Backend == "" {
		return storage.Open(ctx, cfg)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.opened = append(mb.opened, cfg)
	bare := cfg
	bare.Prefix = ""
	m := mb.buckets[bare.Identity()]
	if m == nil {
		m = storagetest.NewMemory()
		mb.buckets[bare.Identity()] = m
	}
	return &prefixed{m: m, prefix: cfg.Prefix}, nil
}

// keys lists every object of the bucket of cfg (full keys).
func (mb *memBuckets) keys(cfg storage.Config) []string {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	bare := cfg
	bare.Prefix = ""
	if m := mb.buckets[bare.Identity()]; m != nil {
		k := m.Keys()
		sort.Strings(k)
		return k
	}
	return nil
}

type prefixed struct {
	m      *storagetest.Memory
	prefix string
}

func (p *prefixed) Kind() string { return "s3" }
func (p *prefixed) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	return p.m.Put(ctx, p.prefix+key, r, size)
}
func (p *prefixed) Open(ctx context.Context, key string) (storage.Object, error) {
	return p.m.Open(ctx, p.prefix+key)
}
func (p *prefixed) Stat(ctx context.Context, key string) (storage.Info, error) {
	i, err := p.m.Stat(ctx, p.prefix+key)
	i.Key = strings.TrimPrefix(i.Key, p.prefix)
	return i, err
}
func (p *prefixed) Delete(ctx context.Context, key string) error {
	return p.m.Delete(ctx, p.prefix+key)
}
func (p *prefixed) List(ctx context.Context, prefix string, fn func(storage.Info) error) error {
	return p.m.List(ctx, p.prefix+prefix, func(i storage.Info) error {
		i.Key = strings.TrimPrefix(i.Key, p.prefix)
		return fn(i)
	})
}

// memoryStorage routes every backend of the host (console tests, tenant
// servers, deletion) to in-memory buckets.
func (m *mtEnv) memoryStorage() *memBuckets {
	mb := &memBuckets{buckets: map[string]*storagetest.Memory{}}
	m.h.openBackend = mb.open
	return mb
}

// platformS3 is a platform default storage form (bucket shared by tenants).
func platformS3(bucket, prefix string) map[string]any {
	if ep := os.Getenv("SENDORA_TEST_S3_ENDPOINT"); ep != "" {
		return map[string]any{"storage_backend": "s3", "storage_s3_endpoint": ep, "storage_s3_region": "us-east-1",
			"storage_s3_bucket": envOr("SENDORA_TEST_S3_BUCKET", "sendora-test"), "storage_s3_prefix": prefix, "storage_s3_path_style": "true",
			"storage_s3_auth": "static", "storage_s3_access_key": os.Getenv("SENDORA_TEST_S3_ACCESS_KEY"), "storage_s3_secret_key": os.Getenv("SENDORA_TEST_S3_SECRET_KEY")}
	}
	return map[string]any{"storage_backend": "s3", "storage_s3_endpoint": "https://s3.storage-test.invalid", "storage_s3_region": "us-east-1",
		"storage_s3_bucket": bucket, "storage_s3_prefix": prefix, "storage_s3_auth": "static", "storage_s3_access_key": "AKPLATFORM", "storage_s3_secret_key": "platform-secret"}
}

func formConfig(form map[string]any) storage.Config {
	return storage.FromSettings(func(k string) string { v, _ := form[k].(string); return v })
}

// listAll lists the keys under prefix in cfg's bucket through a backend
// without prefix (the bucket as the operator sees it).
func listAll(t *testing.T, open func(context.Context, storage.Config) (storage.Backend, error), cfg storage.Config, prefix string) []string {
	t.Helper()
	cfg.Prefix = ""
	b, err := open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	if err := b.List(context.Background(), prefix, func(i storage.Info) error { keys = append(keys, i.Key); return nil }); err != nil {
		t.Fatal(err)
	}
	sort.Strings(keys)
	return keys
}

// Two tenants on one bucket: each tenant's objects live under its own prefix
// tenants/<id>/, are encrypted, are not reachable through the other tenant,
// and deleting a tenant removes its prefix only. Runs against MinIO when
// SENDORA_TEST_S3_* is set (CI job "storage"), otherwise in memory.
func TestMTObjectStoragePerTenantOnSharedBucket(t *testing.T) {
	m := newMTEnv(t)
	real := os.Getenv("SENDORA_TEST_S3_ENDPOINT") != ""
	open := storage.Open
	if !real {
		open = m.memoryStorage().open
	} else {
		cfg := formConfig(platformS3("", ""))
		b, err := storage.Open(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.CreateBucket(context.Background(), b); err != nil {
			t.Fatal(err)
		}
	}
	root := "mt-" + randomText(8) + "/"
	form := platformS3("shared-bucket", root)
	c, cookie, secret := m.consoleLogin()
	if real {
		t.Cleanup(func() {
			b, _ := storage.Open(context.Background(), formConfig(form))
			if b != nil {
				storage.DeletePrefix(context.Background(), b, "")
			}
		})
	}
	// Before a default is configured, tenants use their directory.
	a, tokA := m.newTenant("klanta")
	ta, _ := m.p.TenantBySlug("klanta")
	if l, _, err := m.server("klanta").currentStorage(context.Background()); err != nil || l != 0 {
		t.Fatalf("tenant without platform storage: location %d %v", l, err)
	}
	localFiles := map[string]string{"local.txt": "LOCAL-BEFORE-PLATFORM-STORAGE", "local2.txt": "second local file"}
	r := a.share(tokA, localFiles, nil)
	a.want(r, 201, "local share")
	localLID := r.S("long_id")

	// The platform default is tested before it is saved.
	bad := map[string]any{}
	for k, v := range form {
		bad[k] = v
	}
	bad["storage_s3_bucket"] = "Bad_Bucket"
	c.want(c.do("PUT", "/api/platform/storage", "", map[string]any{"settings": bad}, "Cookie", cookie), 400, "invalid platform storage")
	c.want(c.do("PUT", "/api/platform/storage", "", map[string]any{"settings": form}, "Cookie", cookie), 200, "platform storage")
	g := c.do("GET", "/api/platform/storage", "", nil, "Cookie", cookie)
	if strings.Contains(string(g.Body), form["storage_s3_secret_key"].(string)) || !strings.Contains(string(g.Body), `"storage_s3_secret_key":true`) {
		t.Fatalf("platform storage secret shown: %s", g.Body)
	}
	b, tokB := m.newTenant("klantb")
	tb, _ := m.p.TenantBySlug("klantb")
	// The platform offers its bucket to both tenants.
	for _, id := range []string{ta.ID, tb.ID} {
		c.want(c.do("PUT", "/api/platform/tenants/"+id+"/storage", "", map[string]any{"offer": "platform", "tenant_managed": true}, "Cookie", cookie), 200, "offer platform bucket")
		m.h.evict(id, 0)
	}
	sv := c.do("GET", "/api/platform/tenants/"+ta.ID+"/storage", "", nil, "Cookie", cookie)
	if sv.S("kind") != "platform" || sv.S("offer") != "platform" {
		t.Fatalf("console storage view: %s", sv.Body)
	}

	contentA := "TENANT-A-SECRET-" + randomText(filecrypt.ChunkSize/2)
	contentB := "TENANT-B-SECRET-" + randomText(200)
	// klanta was reopened by the change; new files go to the platform bucket.
	m.h.evict(ta.ID, 0)
	filesA := map[string]string{"a.txt": contentA, "a2.txt": "second A"}
	filesB := map[string]string{"b.txt": contentB, "b2.txt": "second B"}
	r = a.share(tokA, filesA, nil)
	a.want(r, 201, "share A")
	lidA := r.S("long_id")
	r = b.share(tokB, filesB, nil)
	b.want(r, 201, "share B")
	lidB := r.S("long_id")
	a.checkDownloads(lidA, filesA)
	b.checkDownloads(lidB, filesB)
	a.checkDownloads(localLID, localFiles)
	// A share is only reachable on its own tenant's host.
	b.want(b.do("GET", "/api/shares/"+lidA+"/download/a.txt", "", nil), 404, "A's share on B's host")

	cfg := formConfig(form)
	keysA := listAll(t, open, cfg, root+"tenants/"+ta.ID+"/")
	keysB := listAll(t, open, cfg, root+"tenants/"+tb.ID+"/")
	all := listAll(t, open, cfg, root)
	if len(keysA) != 2 || len(keysB) != 2 || len(all) != 4 {
		t.Fatalf("objects: A=%v B=%v all=%v", keysA, keysB, all)
	}
	for _, k := range append(keysA, keysB...) {
		rest := k[strings.LastIndex(k, "/files/")+1:]
		if !storage.ValidFileKey(rest) || strings.Contains(k, lidA) || strings.Contains(k, lidB) {
			t.Fatalf("object key %s", k)
		}
	}
	// Ciphertext only.
	bare := cfg
	bare.Prefix = ""
	ob, _ := open(context.Background(), bare)
	raw := objectBytes(t, ob, keysA[0])
	if !strings.HasPrefix(string(raw), "SNDF\x02") || strings.Contains(string(raw), "TENANT-A-SECRET") {
		t.Fatal("tenant object is not ciphertext")
	}
	// Tenant B's backend cannot see tenant A's objects: its view starts at its prefix.
	sB := m.server("klantb")
	_, bb, err := sB.currentStorage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	bb.List(context.Background(), "", func(i storage.Info) error { seen = append(seen, i.Key); return nil })
	if len(seen) != 2 || !strings.HasPrefix(seen[0], "files/") {
		t.Fatalf("tenant B sees %v", seen)
	}
	if _, err := bb.Open(context.Background(), "../"+ta.ID+"/"+keysA[0][strings.LastIndex(keysA[0], "files/"):]); err == nil {
		t.Fatal("tenant B opened an object outside its prefix")
	}

	// Tenants may configure their own storage by default; the platform can
	// switch that off (audited), and then tenant admins see it read-only.
	if st := a.do("GET", "/api/storage", tokA, nil); !strings.Contains(string(st.Body), `"editable":true`) {
		t.Fatalf("own storage not allowed by default: %s", st.Body)
	}
	c.want(c.do("PUT", "/api/platform/tenants/"+ta.ID+"/storage", "", map[string]any{"offer": "platform", "tenant_managed": false}, "Cookie", cookie), 200, "switch tenant storage off")
	m.h.evict(ta.ID, 0)
	st := a.do("GET", "/api/storage", tokA, nil)
	a.want(st, 200, "tenant storage status")
	tn, _ := st.J()["tenant"].(map[string]any)
	if tn == nil || tn["editable"] != false || tn["managed_by"] != "platform" || !strings.Contains(st.S("description"), "tenants/"+ta.ID+"/") {
		t.Fatalf("tenant storage view: %s", st.Body)
	}
	a.want(a.do("PUT", "/api/settings", tokA, map[string]any{"storage_s3_bucket": "other"}), 403, "tenant changes platform-managed storage")
	a.want(a.do("POST", "/api/storage/test", tokA, map[string]any{}), 403, "tenant tests platform-managed storage")

	// The tenant's migration job moves its earlier local file to its prefix.
	oldDelay := migrationDeleteDelay
	migrationDeleteDelay = 0
	t.Cleanup(func() { migrationDeleteDelay = oldDelay })
	a.want(a.do("POST", "/api/storage/migrate", tokA, nil), 202, "tenant migration")
	sA := m.server("klanta")
	sA.stor.migMu.Lock()
	job := sA.stor.mig
	sA.stor.migMu.Unlock()
	<-job.done
	if job.status != "finished" {
		t.Fatalf("migration: %s", job.status)
	}
	if keys := listAll(t, open, cfg, root+"tenants/"+ta.ID+"/"); len(keys) != 4 {
		t.Fatalf("after migration: %v", keys)
	}
	a.checkDownloads(localLID, localFiles)

	// Deleting tenant A removes its prefix; tenant B's objects stay.
	c.want(c.do("POST", "/api/platform/tenants/"+ta.ID+"/delete", "", map[string]any{"confirm": "klanta", "code": m.nextCode(secret)}, "Cookie", cookie), 200, "delete A")
	if keys := listAll(t, open, cfg, root+"tenants/"+ta.ID+"/"); len(keys) != 0 {
		t.Fatalf("tenant A's objects left: %v", keys)
	}
	if keys := listAll(t, open, cfg, root+"tenants/"+tb.ID+"/"); len(keys) != 2 {
		t.Fatalf("tenant B's objects: %v", keys)
	}
	b.checkDownloads(lidB, filesB)
}

// Deleting a tenant whose own bucket is unreachable is refused unless forced.
func TestMTDeleteTenantWithUnreachableBucket(t *testing.T) {
	m := newMTEnv(t)
	mb := m.memoryStorage()
	c, cookie, secret := m.consoleLogin()
	old := netguard.LookupNetIP
	t.Cleanup(func() { netguard.LookupNetIP = old })
	netguard.LookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	x, tok := m.newTenant("klantx")
	tx, _ := m.p.TenantBySlug("klantx")
	own := map[string]any{"storage_backend": "s3", "storage_s3_endpoint": "https://s3.example.com", "storage_s3_region": "eu-west-1", "storage_s3_bucket": "klantx",
		"storage_s3_prefix": "", "storage_s3_auth": "static", "storage_s3_access_key": "AKX", "storage_s3_secret_key": "sx"}
	x.want(x.do("PUT", "/api/settings", tok, own), 200, "tenant's own bucket")
	x.want(x.share(tok, map[string]string{"x.txt": "in the own bucket", "y.txt": "second"}, nil), 201, "share in own bucket")
	m.h.openBackend = func(ctx context.Context, cfg storage.Config) (storage.Backend, error) {
		if cfg.S3Bucket == "klantx" {
			return nil, io.ErrUnexpectedEOF
		}
		return mb.open(ctx, cfg)
	}
	r := c.do("POST", "/api/platform/tenants/"+tx.ID+"/delete", "", map[string]any{"confirm": "klantx", "code": m.nextCode(secret)}, "Cookie", cookie)
	c.want(r, 409, "delete with unreachable bucket")
	if _, err := m.p.Tenant(tx.ID); err != nil {
		t.Fatal("tenant removed although its objects could not be deleted")
	}
	c.want(c.do("POST", "/api/platform/tenants/"+tx.ID+"/delete", "", map[string]any{"confirm": "klantx", "code": m.nextCode(secret), "force": true}, "Cookie", cookie), 200, "forced delete")
	a := c.do("GET", "/api/platform/audit", "", nil, "Cookie", cookie)
	if !strings.Contains(string(a.Body), "NOT removed (forced)") {
		t.Fatalf("forced deletion not audited: %s", a.Body)
	}
}

// With "tenant may configure its own storage", the tenant's administrators
// use the same form, with explicit credentials and the SSRF guard.
func TestMTTenantManagedStorageAndGuard(t *testing.T) {
	m := newMTEnv(t)
	mb := m.memoryStorage()
	old := netguard.LookupNetIP
	t.Cleanup(func() { netguard.LookupNetIP = old })
	netguard.LookupNetIP = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "rebind.example.com" {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	c, cookie, secret := m.consoleLogin()
	a, tok := m.newTenant("klantm")
	tm, _ := m.p.TenantBySlug("klantm")
	mine := map[string]any{"storage_backend": "s3", "storage_s3_endpoint": "https://s3.tenant.example.com", "storage_s3_region": "eu-west-1", "storage_s3_bucket": "klantm-own",
		"storage_s3_prefix": "sendora/", "storage_s3_auth": "static", "storage_s3_access_key": "AKM", "storage_s3_secret_key": "tenant-secret"}
	c.want(c.do("PUT", "/api/platform/tenants/"+tm.ID+"/storage", "", map[string]any{"offer": "local", "tenant_managed": false}, "Cookie", cookie), 200, "switch tenant storage off")
	m.h.evict(tm.ID, 0)
	a.want(a.do("PUT", "/api/settings", tok, mine), 403, "own storage switched off")
	c.want(c.do("PUT", "/api/platform/tenants/"+tm.ID+"/storage", "", map[string]any{"offer": "local", "tenant_managed": true}, "Cookie", cookie), 200, "allow tenant storage")
	m.h.evict(tm.ID, 0)
	st := a.do("GET", "/api/storage", tok, nil)
	if tn, _ := st.J()["tenant"].(map[string]any); tn == nil || tn["editable"] != true {
		t.Fatalf("tenant storage not editable: %s", st.Body)
	}
	// Ambient credentials and internal endpoints are refused.
	amb := map[string]any{}
	for k, v := range mine {
		amb[k] = v
	}
	amb["storage_s3_auth"] = "default"
	a.want(a.do("PUT", "/api/settings", tok, amb), 400, "default credentials")
	for _, ep := range []string{"http://127.0.0.1:9000", "http://10.0.0.5:9000", "https://rebind.example.com", "http://minio:9000"} {
		bad := map[string]any{}
		for k, v := range mine {
			bad[k] = v
		}
		bad["storage_s3_endpoint"] = ep
		a.want(a.do("PUT", "/api/settings", tok, bad), 400, "internal endpoint "+ep)
	}
	a.want(a.do("PUT", "/api/settings", tok, mine), 200, "tenant's own bucket")
	s := m.server("klantm")
	_, _, err := s.currentStorage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.storageFromSettings()
	if !cfg.TenantManaged || cfg.S3Bucket != "klantm-own" {
		t.Fatalf("effective storage %+v", cfg.Public())
	}
	// The backend of a tenant-managed location dials through the guard.
	mb.mu.Lock()
	last := mb.opened[len(mb.opened)-1]
	mb.mu.Unlock()
	if last.DialContext == nil || !last.TenantManaged {
		t.Fatal("tenant-managed backend opened without the network guard")
	}
	// The platform can allow private targets for this tenant (step-up, audited).
	c.want(c.do("PUT", "/api/platform/tenants/"+tm.ID+"/network", "", map[string]any{"allow_private_targets": true, "code": "000000"}, "Cookie", cookie), 403, "network policy without step-up")
	c.want(c.do("PUT", "/api/platform/tenants/"+tm.ID+"/network", "", map[string]any{"allow_private_targets": true, "code": m.nextCode(secret)}, "Cookie", cookie), 200, "allow private targets")
	m.h.evict(tm.ID, 0)
	priv := map[string]any{}
	for k, v := range mine {
		priv[k] = v
	}
	priv["storage_s3_endpoint"] = "http://10.0.0.5:9000"
	priv["storage_s3_secret_key"] = "tenant-secret"
	a.want(a.do("PUT", "/api/settings", tok, priv), 200, "private endpoint when allowed")
	au := c.do("GET", "/api/platform/audit", "", nil, "Cookie", cookie)
	if !strings.Contains(string(au.Body), "tenant_network_policy_changed") {
		t.Fatal("network policy change not audited")
	}
}

// SMTP, OIDC issuer and audit forwarding targets of a tenant are checked at
// save time; single-tenant mode is unchanged.
func TestMTTargetGuardOnSave(t *testing.T) {
	m := newMTEnv(t)
	old := netguard.LookupNetIP
	t.Cleanup(func() { netguard.LookupNetIP = old })
	netguard.LookupNetIP = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if strings.HasPrefix(host, "internal.") {
			return []netip.Addr{netip.MustParseAddr("192.168.1.10")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	a, tok := m.newTenant("klantg")
	for k, v := range map[string]string{"smtp_host": "127.0.0.1", "audit_forward_syslog": "169.254.169.254:514", "audit_forward_webhook_url": "https://internal.example.com/hook"} {
		r := a.do("PUT", "/api/settings", tok, map[string]any{k: v})
		if r.Code != 400 || !strings.Contains(r.S("error"), "not allowed") {
			t.Fatalf("%s=%s: %d %s", k, v, r.Code, r.Body)
		}
	}
	a.want(a.do("PUT", "/api/settings", tok, map[string]any{"smtp_host": "smtp.example.com"}), 200, "public smtp host")
	r := a.do("POST", "/api/auth-providers", tok, map[string]any{"name": "Corp", "type": "oidc", "client_id": "x", "client_secret": "y", "issuer_url": "https://internal.example.com/realms/a", "enabled": true})
	if r.Code != 400 {
		t.Fatalf("internal issuer accepted: %d %s", r.Code, r.Body)
	}
	a.want(a.do("POST", "/api/auth-providers", tok, map[string]any{"name": "Corp", "type": "oidc", "client_id": "x", "client_secret": "y", "issuer_url": "https://login.example.com/realms/a", "enabled": true}), 201, "public issuer")

	// Single-tenant mode: the administrator may use internal targets.
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_host": "127.0.0.1"}), 200, "single-tenant internal smtp")
}

// The platform MFA requirement: switching it needs a step-up and is audited;
// when off, administrators sign in with a password only and may still enrol.
func TestMTPlatformMFASwitch(t *testing.T) {
	m := newMTEnv(t)
	c, cookie, secret := m.consoleLogin()
	c.want(c.do("PUT", "/api/platform/settings", "", map[string]any{"platform_mfa_required": false}, "Cookie", cookie), 403, "switch without step-up")
	if !m.p.MFARequired() {
		t.Fatal("switched without step-up")
	}
	c.want(c.do("PUT", "/api/platform/settings", "", map[string]any{"platform_mfa_required": false, "code": m.nextCode(secret)}, "Cookie", cookie), 200, "switch off")
	if m.p.MFARequired() {
		t.Fatal("not switched off")
	}
	// A second administrator without an authenticator signs in with a password only.
	c.want(c.do("POST", "/api/platform/admins", "", map[string]any{"username": "ops", "email": "ops@platform.test", "password": "Operator-Pass-2026!", "code": m.nextCode(secret)}, "Cookie", cookie), 201, "second admin")
	r := c.do("POST", "/api/platform/login", "", map[string]any{"username": "ops", "password": "Operator-Pass-2026!"})
	c.want(r, 200, "password-only login")
	if r.S("stage") != "full" {
		t.Fatalf("stage %s", r.S("stage"))
	}
	ops := sessionCookie(t, r)
	c.want(c.do("GET", "/api/platform/tenants", "", nil, "Cookie", ops), 200, "console without authenticator")
	// Step-up with the password when there is no authenticator.
	c.want(c.do("PUT", "/api/platform/settings", "", map[string]any{"platform_mfa_required": true, "code": "wrong-password"}, "Cookie", ops), 403, "wrong password step-up")
	// Enrolment stays possible.
	b := c.do("POST", "/api/platform/mfa/begin", "", nil, "Cookie", ops)
	c.want(b, 200, "voluntary enrolment")
	// The administrator with an authenticator also signs in with the password only.
	r = c.do("POST", "/api/platform/login", "", map[string]any{"username": "root", "password": "Platform-Admin-2026!"})
	if r.S("stage") != "full" {
		t.Fatalf("root stage %s", r.S("stage"))
	}
	// Switching back on ends the sessions without a second factor.
	c.want(c.do("PUT", "/api/platform/settings", "", map[string]any{"platform_mfa_required": true, "code": "Operator-Pass-2026!"}, "Cookie", ops), 200, "switch on")
	c.want(c.do("GET", "/api/platform/tenants", "", nil, "Cookie", ops), 401, "session without authenticator ended")
	r = c.do("POST", "/api/platform/login", "", map[string]any{"username": "ops", "password": "Operator-Pass-2026!"})
	if r.S("stage") != "enroll" {
		t.Fatalf("ops stage after switching on: %s", r.S("stage"))
	}
	au := c.do("GET", "/api/platform/audit", "", nil, "Cookie", cookie)
	var recs struct {
		Records []map[string]any `json:"records"`
	}
	json.Unmarshal(au.Body, &recs)
	n := 0
	for _, rec := range recs.Records {
		if rec["action"] == "platform_mfa_requirement_changed" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("platform_mfa_requirement_changed records: %d", n)
	}
}

// A temporary password from the offline reset only allows choosing a new one.
func TestMTTemporaryPasswordMustBeChanged(t *testing.T) {
	m := newMTEnv(t)
	c, cookie, _ := m.consoleLogin()
	a, _ := m.p.AdminByName("root")
	hb, _ := bcrypt.GenerateFromPassword([]byte("Temporary-Pass-123"), bcrypt.MinCost)
	h := string(hb)
	if err := m.p.SetTemporaryPassword(a.ID, h); err != nil {
		t.Fatal(err)
	}
	c.want(c.do("GET", "/api/platform/me", "", nil, "Cookie", cookie), 401, "sessions ended by the reset")
	if err := m.p.ResetTOTP(a.ID); err != nil {
		t.Fatal(err)
	}
	r := c.do("POST", "/api/platform/login", "", map[string]any{"username": "root", "password": "Temporary-Pass-123"})
	c.want(r, 200, "login with temporary password")
	ck := sessionCookie(t, r)
	if r.J()["must_change_password"] != true {
		t.Fatalf("must_change_password missing: %s", r.Body)
	}
	c.want(c.do("POST", "/api/platform/mfa/begin", "", nil, "Cookie", ck), 403, "enrolment before the new password")
	c.want(c.do("POST", "/api/platform/password", "", map[string]any{"current": "wrong", "password": "Brand-New-Pass-2026!"}, "Cookie", ck), 403, "wrong current password")
	r = c.do("POST", "/api/platform/password", "", map[string]any{"current": "Temporary-Pass-123", "password": "Brand-New-Pass-2026!"}, "Cookie", ck)
	c.want(r, 200, "new password")
	ck = sessionCookie(t, r)
	c.want(c.do("POST", "/api/platform/mfa/begin", "", nil, "Cookie", ck), 200, "enrolment after the new password")
	if a, _ := m.p.AdminByName("root"); a.MustChangePassword {
		t.Fatal("mark not cleared")
	}
}

// A tenant created in the console has no storage until its administrator
// sets up its own: uploads, new shares and reverse shares are refused with a
// clear message. Once set up, the console sees only the kind and the usage,
// never the configuration, and no console API returns tenant users, shares,
// audit details or secrets.
func TestMTNewTenantWithoutStorageAndConsolePrivacy(t *testing.T) {
	m := newMTEnv(t)
	m.memoryStorage()
	old := netguard.LookupNetIP
	t.Cleanup(func() { netguard.LookupNetIP = old })
	netguard.LookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	c, cookie, _ := m.consoleLogin()
	r := c.do("POST", "/api/platform/tenants", "", map[string]any{"slug": "klantn", "name": "Klant N", "admin_email": "boss@klantn.test"}, "Cookie", cookie)
	c.want(r, 201, "create tenant")
	tn, _ := m.p.TenantBySlug("klantn")
	if sc, _ := m.p.Storage(tn.ID); sc.Offer != platform.OfferNone || !sc.TenantManaged {
		t.Fatalf("new tenant storage decision: %+v", sc)
	}
	link, _ := r.J()["setup_link"].(string)
	e := m.host("klantn." + mtBase)
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": link[strings.LastIndex(link, "/")+1:], "password": mtPassword}), 200, "first password")
	lr := e.do("POST", "/api/auth/login", "", map[string]any{"username": "boss", "password": mtPassword})
	e.want(lr, 200, "login")
	tok := lr.S("access_token")
	if me := e.do("GET", "/api/users/me", tok, nil); me.J()["storage_ready"] != false {
		t.Fatalf("storage_ready: %s", me.Body)
	}
	up := e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "a.txt", "full_path": "a.txt", "size": 3}}})
	if up.Code != 409 || up.S("error") != msgStorageNotSetUp {
		t.Fatalf("upload without storage: %d %s", up.Code, up.Body)
	}
	if inv := e.do("POST", "/api/reverse-shares/invite", tok, map[string]any{"email": "guest@example.com"}); inv.Code != 409 {
		t.Fatalf("reverse share without storage: %d %s", inv.Code, inv.Body)
	}
	st := e.do("GET", "/api/storage", tok, nil)
	if tnv, _ := st.J()["tenant"].(map[string]any); tnv == nil || tnv["configured"] != false || tnv["offer"] != "none" || tnv["editable"] != true {
		t.Fatalf("tenant storage status: %s", st.Body)
	}
	// "Platform default" is not available without an offer.
	e.want(e.do("PUT", "/api/settings", tok, map[string]any{"storage_backend": "local"}), 400, "no platform storage to choose")
	own := map[string]any{"storage_backend": "azure", "storage_azure_account": "klantnstore", "storage_azure_container": "klantn-files",
		"storage_azure_prefix": "secret-prefix/", "storage_azure_auth": "shared_key", "storage_azure_account_key": "S0VZLVNFQ1JFVA=="}
	e.want(e.do("PUT", "/api/settings", tok, own), 200, "own storage")
	e.want(e.share(tok, map[string]string{"a.txt": "TENANT-CONTENT-1", "b.txt": "TENANT-CONTENT-2"}, map[string]any{"name": "Quarterly secrets"}), 201, "upload after setup")

	// The console sees the kind and the usage only.
	m.h.refreshOpenStats()
	sv := c.do("GET", "/api/platform/tenants/"+tn.ID+"/storage", "", nil, "Cookie", cookie)
	c.want(sv, 200, "console storage view")
	if sv.S("kind") != "own:azure" {
		t.Fatalf("kind: %s", sv.Body)
	}
	var keys []string
	for k := range sv.J() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "kind,limit_applies,max_storage_bytes,offer,platform_backend,tenant_managed,usage_bytes" {
		t.Fatalf("console storage view fields: %v", keys)
	}
	forbidden := []string{"klantnstore", "klantn-files", "secret-prefix", "S0VZLVNFQ1JFVA", "blob.core.windows.net", "boss@klantn.test", "Quarterly secrets",
		"a.txt", "TENANT-CONTENT", "password_hash", mtPassword}
	for _, path := range []string{"/api/platform/tenants", "/api/platform/tenants/" + tn.ID, "/api/platform/tenants/" + tn.ID + "/storage",
		"/api/platform/settings", "/api/platform/storage", "/api/platform/audit", "/api/platform/admins", "/api/platform/me"} {
		g := c.do("GET", path, "", nil, "Cookie", cookie)
		c.want(g, 200, path)
		for _, f := range forbidden {
			if strings.Contains(string(g.Body), f) {
				t.Fatalf("%s exposes %q: %s", path, f, g.Body)
			}
		}
	}
	// The console can neither change nor test a tenant's own storage.
	c.want(c.do("POST", "/api/platform/tenants/"+tn.ID+"/storage/test", "", map[string]any{}, "Cookie", cookie), 404, "no test of tenant storage")
	c.want(c.do("PUT", "/api/platform/tenants/"+tn.ID+"/storage", "", map[string]any{"offer": "none", "tenant_managed": true, "settings": own}, "Cookie", cookie), 200, "decision only")
	if s := m.server("klantn"); s.St.Setting("storage_azure_account") != "klantnstore" {
		t.Fatal("console changed the tenant's storage settings")
	}
}

// "Storage for new tenants": re-authentication and an audit record; the
// platform bucket only while a platform default backend exists; the create
// form uses it unless the administrator picks another offer.
func TestMTNewTenantStorageOfferSetting(t *testing.T) {
	m := newMTEnv(t)
	mb := m.memoryStorage()
	c, cookie, secret := m.consoleLogin()
	if m.p.NewTenantOffer() != platform.OfferNone {
		t.Fatal("default must be none")
	}
	r := c.do("PUT", "/api/platform/settings", "", map[string]any{"new_tenant_storage_offer": "platform", "code": m.nextCode(secret)}, "Cookie", cookie)
	if r.Code != 400 || !strings.Contains(r.S("error"), "platform default storage") {
		t.Fatalf("platform offer without a default backend: %d %s", r.Code, r.Body)
	}
	c.want(c.do("PUT", "/api/platform/storage", "", map[string]any{"settings": platformS3("shared-bucket", "")}, "Cookie", cookie), 200, "platform storage")
	c.want(c.do("PUT", "/api/platform/settings", "", map[string]any{"new_tenant_storage_offer": "platform"}, "Cookie", cookie), 403, "offer change without re-auth")
	c.want(c.do("PUT", "/api/platform/settings", "", map[string]any{"new_tenant_storage_offer": "bogus", "code": m.nextCode(secret)}, "Cookie", cookie), 400, "invalid offer")
	c.want(c.do("PUT", "/api/platform/settings", "", map[string]any{"new_tenant_storage_offer": "platform", "code": m.nextCode(secret)}, "Cookie", cookie), 200, "offer platform to new tenants")
	if g := c.do("GET", "/api/platform/settings", "", nil, "Cookie", cookie); !strings.Contains(string(g.Body), `"new_tenant_storage_offer":"platform"`) {
		t.Fatalf("settings: %s", g.Body)
	}
	// The default backend cannot be removed while new tenants are offered it.
	c.want(c.do("PUT", "/api/platform/storage", "", map[string]any{"settings": map[string]any{"storage_backend": "local"}}, "Cookie", cookie), 400, "remove default while offered")

	r = c.do("POST", "/api/platform/tenants", "", map[string]any{"slug": "klantp", "admin_email": "boss@klantp.test"}, "Cookie", cookie)
	c.want(r, 201, "create with the platform setting")
	tp, _ := m.p.TenantBySlug("klantp")
	if sc, _ := m.p.Storage(tp.ID); sc.Offer != platform.OfferPlatform {
		t.Fatalf("new tenant offer %+v", sc)
	}
	link, _ := r.J()["setup_link"].(string)
	e := m.host("klantp." + mtBase)
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": link[strings.LastIndex(link, "/")+1:], "password": mtPassword}), 200, "first password")
	lr := e.do("POST", "/api/auth/login", "", map[string]any{"username": "boss", "password": mtPassword})
	e.want(e.share(lr.S("access_token"), map[string]string{"a.txt": "straight away", "b.txt": "second"}, nil), 201, "upload straight away")
	if keys := mb.keys(formConfig(platformS3("shared-bucket", ""))); len(keys) != 2 || !strings.HasPrefix(keys[0], "tenants/"+tp.ID+"/files/") {
		t.Fatalf("objects: %v", keys)
	}
	// Another offer can still be chosen per tenant at creation.
	c.want(c.do("POST", "/api/platform/tenants", "", map[string]any{"slug": "klantq", "admin_email": "boss@klantq.test", "storage_offer": "none"}, "Cookie", cookie), 201, "create with none")
	tq, _ := m.p.TenantBySlug("klantq")
	if sc, _ := m.p.Storage(tq.ID); sc.Offer != platform.OfferNone {
		t.Fatalf("explicit offer ignored: %+v", sc)
	}
	au := c.do("GET", "/api/platform/audit", "", nil, "Cookie", cookie)
	if !strings.Contains(string(au.Body), `"action":"platform_new_tenant_storage_changed"`) {
		t.Fatalf("offer change not audited: %s", au.Body)
	}
}

// The platform's storage limit (max_storage_bytes, one source of truth)
// applies to storage the platform provides; changing it needs re-auth and is
// audited; the tenant sees used / limit; storage of the tenant's own has no
// platform limit.
func TestMTStorageLimitForProvidedStorage(t *testing.T) {
	m := newMTEnv(t)
	m.memoryStorage()
	old := netguard.LookupNetIP
	t.Cleanup(func() { netguard.LookupNetIP = old })
	netguard.LookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	c, cookie, secret := m.consoleLogin()
	k, tok := m.newTenant("klantl") // the platform offers local disk
	tl, _ := m.p.TenantBySlug("klantl")
	q := "/api/platform/tenants/" + tl.ID + "/quotas"
	c.want(c.do("PUT", q, "", map[string]any{"max_users": 0, "max_storage_bytes": 50}, "Cookie", cookie), 403, "limit without re-auth")
	c.want(c.do("PUT", q, "", map[string]any{"max_users": 0, "max_storage_bytes": 50, "code": m.nextCode(secret)}, "Cookie", cookie), 200, "limit")
	// The Storage card saves the limit together with the offer (one re-auth).
	sp := "/api/platform/tenants/" + tl.ID + "/storage"
	c.want(c.do("PUT", sp, "", map[string]any{"offer": "local", "tenant_managed": true, "max_storage_bytes": 60}, "Cookie", cookie), 403, "limit on the Storage card without re-auth")
	c.want(c.do("PUT", sp, "", map[string]any{"offer": "local", "tenant_managed": true, "max_storage_bytes": 50, "code": m.nextCode(secret)}, "Cookie", cookie), 200, "same limit: no change")
	c.want(c.do("PUT", sp, "", map[string]any{"offer": "local", "tenant_managed": true, "max_storage_bytes": 60, "code": m.nextCode(secret)}, "Cookie", cookie), 200, "limit on the Storage card")
	c.want(c.do("PUT", sp, "", map[string]any{"offer": "local", "tenant_managed": true, "max_storage_bytes": 50, "code": m.nextCode(secret)}, "Cookie", cookie), 200, "back to 50")
	// Changing only the user quota needs no re-auth and keeps the limit.
	c.want(c.do("PUT", q, "", map[string]any{"max_users": 7}, "Cookie", cookie), 200, "users only")
	if tn, _ := m.p.Tenant(tl.ID); tn.MaxStorageBytes != 50 || tn.MaxUsers != 7 {
		t.Fatalf("quotas %+v", tn)
	}
	k.want(k.share(tok, map[string]string{"a.txt": strings.Repeat("a", 20), "b.txt": strings.Repeat("b", 20)}, nil), 201, "within the limit")
	r := k.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "big.bin", "full_path": "big.bin", "size": 30}}})
	if r.Code != 413 || r.S("error") != msgTenantStorageFull {
		t.Fatalf("over the limit: %d %s", r.Code, r.Body)
	}
	st := k.do("GET", "/api/storage", tok, nil)
	if tn, _ := st.J()["tenant"].(map[string]any); tn == nil || tn["limit_applies"] != true || tn["limit_bytes"] != float64(50) || tn["used_bytes"] != float64(40) {
		t.Fatalf("tenant storage status: %s", st.Body)
	}
	sv := c.do("GET", "/api/platform/tenants/"+tl.ID+"/storage", "", nil, "Cookie", cookie)
	if sv.J()["limit_applies"] != true || sv.J()["max_storage_bytes"] != float64(50) {
		t.Fatalf("console storage view: %s", sv.Body)
	}
	// Storage of the tenant's own: no platform limit.
	own := map[string]any{"storage_backend": "s3", "storage_s3_endpoint": "https://s3.example.com", "storage_s3_region": "eu-west-1", "storage_s3_bucket": "klantl",
		"storage_s3_prefix": "", "storage_s3_auth": "static", "storage_s3_access_key": "AKL", "storage_s3_secret_key": "sl"}
	k.want(k.do("PUT", "/api/settings", tok, own), 200, "own storage")
	k.want(k.share(tok, map[string]string{"c.txt": strings.Repeat("c", 100), "d.txt": "d"}, nil), 201, "own storage has no platform limit")
	if sv := c.do("GET", "/api/platform/tenants/"+tl.ID+"/storage", "", nil, "Cookie", cookie); sv.J()["limit_applies"] != false {
		t.Fatalf("limit shown for own storage: %s", sv.Body)
	}
	au := c.do("GET", "/api/platform/audit", "", nil, "Cookie", cookie)
	if !strings.Contains(string(au.Body), "max_storage_bytes 0-\\u003e50") {
		t.Fatalf("limit change not audited: %s", au.Body)
	}
}
