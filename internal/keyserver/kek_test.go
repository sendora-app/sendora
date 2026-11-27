// SPDX-License-Identifier: AGPL-3.0-or-later

package keyserver_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/keyclient"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/keyserver"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// kekEnv: a platform with one tenant whose database (a SQLite tenant store: the
// same control log, keyring and KEK derivation as a Cluster tenant) holds
// encrypted data, and N controller replicas that share it.
type kekEnv struct {
	t       *testing.T
	master  []byte
	p       *platform.Platform
	tenant  *platform.Tenant
	st      *store.Store
	root    []byte
	log     *logs
	nodes   []*node
	sealed  string // a column value sealed under the tenant's data key
	counter int
}

type node struct {
	kek *keyserver.KEKManager
	srv *httptest.Server
}

func newKEKEnv(t *testing.T, controllers int) *kekEnv {
	return newKEKEnvWith(t, controllers, nil)
}

// newKEKEnvWith is newKEKEnv with a hook that runs on the platform before the
// tenant is created (master versions, settings).
func newKEKEnvWith(t *testing.T, controllers int, before func(p *platform.Platform, master []byte)) *kekEnv {
	t.Helper()
	master := make([]byte, 32)
	rand.Read(master)
	p, err := platform.Open(t.TempDir(), master, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if before != nil {
		before(p, master)
	}
	tn, err := p.CreateTenant("acme", "Acme", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	dbKey, root, err := p.TenantKeys(tn)
	if err != nil {
		t.Fatal(err)
	}
	if root == nil {
		root = append([]byte(nil), dbKey...)
	}
	dir, _ := p.TenantDir(tn.ID)
	st, err := store.OpenTenant(dir, dbKey, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &kekEnv{t: t, master: master, p: p, tenant: tn, st: st, root: root, log: &logs{}}
	e.sealed, err = st.ColumnKeyring().Seal("settings", "value", "k1", "top secret")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < controllers; i++ {
		e.addNode()
	}
	return e
}

func (e *kekEnv) addNode() *node {
	e.t.Helper()
	ring := func(ctx context.Context, id string) (ports.ControlLogRepository, ports.KeyringRepository, func(), error) {
		return e.st.Repos().ControlLog(), e.st.Repos().Keyring(), func() {}, nil
	}
	kek := keyserver.NewKEKManager(e.p, ring, e.master, e.log.logf)
	local := &keyserver.Local{Master: e.master, P: e.p, KEK: kek}
	h := keyserver.Handler(keyserver.Config{Source: local, KEK: kek, AllowedUser: allowed, Logf: e.log.logf,
		Review: fakeReview{"good": {User: allowed, Pod: "web-1"}},
		Status: func(id string) (string, error) {
			tn, err := e.p.Tenant(id)
			if err != nil {
				return "", err
			}
			return tn.Status, nil
		}})
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = false
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	e.t.Cleanup(srv.Close)
	n := &node{kek: kek, srv: srv}
	e.nodes = append(e.nodes, n)
	return n
}

func (e *kekEnv) client() *keyclient.Client {
	e.t.Helper()
	tf := filepath.Join(e.t.TempDir(), "token")
	os.WriteFile(tf, []byte("good\n"), 0o600)
	c, err := keyclient.New(keyclient.Config{URL: e.nodes[0].srv.URL, TokenFile: tf, HTTP: e.nodes[0].srv.Client(),
		Peers: func(context.Context) ([]string, error) {
			var out []string
			for _, n := range e.nodes {
				out = append(out, n.srv.URL)
			}
			return out, nil
		}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.Close() })
	return c
}

func newKEKString(t *testing.T) (string, []byte) {
	raw := make([]byte, 32)
	rand.Read(raw)
	return base64.StdEncoding.EncodeToString(raw), raw
}

// tenantKeys asks controller n for the tenant's keys over its HTTP endpoint.
func (e *kekEnv) tenantKeys(n *node) (int, ports.TenantKeys) {
	e.t.Helper()
	tf := filepath.Join(e.t.TempDir(), "token")
	os.WriteFile(tf, []byte("good\n"), 0o600)
	c, err := keyclient.New(keyclient.Config{URL: n.srv.URL, TokenFile: tf, HTTP: n.srv.Client()})
	if err != nil {
		e.t.Fatal(err)
	}
	defer c.Close()
	k, err := c.Tenant(context.Background(), e.tenant.ID)
	switch {
	case err == nil:
		return 200, k
	case errors.Is(err, ports.ErrLocked):
		return 423, k
	}
	e.t.Fatalf("tenant keys: %v", err)
	return 0, k
}

// operatorCanRead reports whether the platform's own KEK (all the operator has)
// still opens the tenant's keys and the sealed value.
func (e *kekEnv) operatorCanRead() bool {
	svc, err := store.RemoteKeyring(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), e.root)
	if err != nil {
		e.t.Fatal(err)
	}
	c, err := keyring.NewCodec(context.Background(), svc, store.ColumnKeyID)
	if err != nil {
		return false
	}
	defer c.Close()
	v, err := c.Open("settings", "value", "k1", e.sealed)
	return err == nil && v == "top secret"
}

// readerWith opens the keyring with the wrapping key of kek (what a web replica does).
func (e *kekEnv) readerWith(raw []byte) bool {
	w, _ := store.TenantWrapKey(raw)
	defer clear(w)
	svc, err := store.RemoteKeyringWithTenantKEK(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), e.root, w)
	if err != nil {
		e.t.Fatal(err)
	}
	c, err := keyring.NewCodec(context.Background(), svc, store.ColumnKeyID)
	if err != nil {
		return false
	}
	defer c.Close()
	v, err := c.Open("settings", "value", "k1", e.sealed)
	return err == nil && v == "top secret"
}

func TestSwitchToTenantKEKAndLockedUntilUnlocked(t *testing.T) {
	e := newKEKEnv(t, 1)
	c := e.client()
	ctx := context.Background()
	if !e.operatorCanRead() {
		t.Fatal("platform-managed: the operator reads the data")
	}
	kek, raw := newKEKString(t)
	res, err := c.Switch(ctx, e.tenant.ID, kek, "alice")
	if err != nil {
		t.Fatal(err)
	}
	fp := store.TenantKEKFingerprint(raw)
	if res.Fingerprint != fp || len(res.Steps) == 0 {
		t.Fatalf("result %+v", res)
	}
	tn, _ := e.p.Tenant(e.tenant.ID)
	if tn.KEKMode != platform.KEKTenant || tn.KEKFingerprint != fp {
		t.Fatalf("record: %+v", tn)
	}
	// The operator's wrap is destroyed: the platform KEK reads nothing any more.
	if e.operatorCanRead() {
		t.Fatal("the operator can still read the data after the switch")
	}
	if !e.readerWith(raw) {
		t.Fatal("the tenant's KEK does not open the data")
	}
	// Unlocked on this controller: the key endpoint hands the web replica its wrapping key (not the KEK).
	code, keys := e.tenantKeys(e.nodes[0])
	if code != 200 || keys.KEK == "" || keys.KEK == hex.EncodeToString(raw) {
		t.Fatalf("unlocked: %d %+v", code, keys)
	}
	// A controller restart is a fresh manager: locked, 423, until unlocked.
	restarted := e.addNode()
	if code, _ := e.tenantKeys(restarted); code != 423 {
		t.Fatalf("after a restart the tenant is %d, want 423", code)
	}
	wrong, _ := newKEKString(t)
	if _, err := c.Unlock(ctx, e.tenant.ID, wrong); !errors.Is(err, keyclient.ErrKEKRefused) {
		t.Fatalf("wrong key: %v", err)
	}
	if code, _ := e.tenantKeys(restarted); code != 423 {
		t.Fatal("a wrong key unlocked the tenant")
	}
	if _, err := c.Unlock(ctx, e.tenant.ID, kek); err != nil {
		t.Fatalf("unlock with the right key: %v", err)
	}
	if code, keys := e.tenantKeys(restarted); code != 200 || keys.KEK == "" {
		t.Fatalf("after the unlock: %d", code)
	}
	// Neither the KEK nor its derivatives were logged.
	logged := e.log.String()
	w, _ := store.TenantWrapKey(raw)
	for _, secret := range []string{kek, hex.EncodeToString(raw), hex.EncodeToString(w), strings.TrimRight(kek, "=")} {
		if strings.Contains(logged, secret) {
			t.Fatalf("key material in the logs: %s", logged)
		}
	}
	if !strings.Contains(logged, fp) {
		t.Fatal("the fingerprint should be logged")
	}
}

func TestUnlockNeedsEveryController(t *testing.T) {
	e := newKEKEnv(t, 3)
	c := e.client()
	ctx := context.Background()
	kek, _ := newKEKString(t)
	if _, err := c.Switch(ctx, e.tenant.ID, kek, "alice"); err != nil {
		t.Fatal(err)
	}
	for i, n := range e.nodes {
		if code, _ := e.tenantKeys(n); code != 200 {
			t.Fatalf("controller %d: %d after the switch", i, code)
		}
	}
	// Two controllers restart, a third replica is down: unlock fails for the call.
	e.nodes[1].kek.Lock(e.tenant.ID)
	e.nodes[2].kek.Lock(e.tenant.ID)
	e.nodes[2].srv.Close()
	_, err := c.Unlock(ctx, e.tenant.ID, kek)
	var ae *keyclient.AckError
	if !errors.As(err, &ae) || ae.Acked != 2 || ae.Total != 3 {
		t.Fatalf("with one controller down: %v", err)
	}
	if code, _ := e.tenantKeys(e.nodes[1]); code != 200 {
		t.Fatal("the reachable controller took the key")
	}
	// Status reports how many hold the key.
	_, _, unlocked, total, err := c.Status(ctx, e.tenant.ID)
	if err != nil || total != 3 || unlocked != 2 {
		t.Fatalf("status: %d of %d, %v", unlocked, total, err)
	}
	// No controller at all.
	e2 := newKEKEnv(t, 1)
	c2 := e2.client()
	e2.nodes = nil
	if _, err := c2.Unlock(ctx, e2.tenant.ID, kek); !errors.Is(err, keyclient.ErrNoControllers) {
		t.Fatalf("no controllers: %v", err)
	}
}

func TestReplaceAndRelease(t *testing.T) {
	e := newKEKEnv(t, 2)
	c := e.client()
	ctx := context.Background()
	k1, r1 := newKEKString(t)
	k2, r2 := newKEKString(t)
	if _, err := c.Switch(ctx, e.tenant.ID, k1, "alice"); err != nil {
		t.Fatal(err)
	}
	// Replace needs the right old key.
	wrong, _ := newKEKString(t)
	if _, err := c.Replace(ctx, e.tenant.ID, wrong, k2, "alice"); !errors.Is(err, keyclient.ErrKEKRefused) {
		t.Fatalf("replace with a wrong old key: %v", err)
	}
	if _, err := c.Replace(ctx, e.tenant.ID, k1, k1, "alice"); err == nil {
		t.Fatal("replacing a key by itself")
	}
	if _, err := c.Replace(ctx, e.tenant.ID, k1, k2, "alice"); err != nil {
		t.Fatal(err)
	}
	if e.readerWith(r1) || !e.readerWith(r2) {
		t.Fatal("after the replacement only the new key opens the data")
	}
	for i, n := range e.nodes {
		if code, _ := e.tenantKeys(n); code != 200 {
			t.Fatalf("controller %d locked after the replacement", i)
		}
	}
	tn, _ := e.p.Tenant(e.tenant.ID)
	if tn.KEKFingerprint != store.TenantKEKFingerprint(r2) {
		t.Fatal("the record keeps the old fingerprint")
	}
	// Release: wrong key refused; right key returns the tenant to the platform.
	if _, err := c.Release(ctx, e.tenant.ID, k1, "alice"); !errors.Is(err, keyclient.ErrKEKRefused) {
		t.Fatalf("release with the old key: %v", err)
	}
	if _, err := c.Release(ctx, e.tenant.ID, k2, "alice"); err != nil {
		t.Fatal(err)
	}
	if !e.operatorCanRead() {
		t.Fatal("after the release the platform KEK reads the data again")
	}
	w2, _ := store.TenantWrapKey(r2)
	refSvc, _ := store.RemoteKeyringWithTenantKEK(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), e.root, w2)
	if refs, err := refSvc.WrapRefs(ctx, store.ColumnKeyID); err != nil || refs[store.TenantWrapRef(w2)] != 0 {
		t.Fatalf("the tenant's wraps must be gone: %v %v", refs, err)
	}
	tn, _ = e.p.Tenant(e.tenant.ID)
	if tn.KEKMode != platform.KEKPlatform || tn.KEKFingerprint != "" {
		t.Fatalf("record after release: %+v", tn)
	}
	for _, n := range e.nodes {
		if code, k := e.tenantKeys(n); code != 200 || k.KEK != "" {
			t.Fatalf("platform-managed again: %d %+v", code, k)
		}
	}
	// Not tenant-managed any more: release and unlock are conflicts.
	if _, err := c.Release(ctx, e.tenant.ID, k2, "alice"); err == nil {
		t.Fatal("release of a platform-managed tenant")
	}
	if _, err := c.Unlock(ctx, e.tenant.ID, k2); err == nil {
		t.Fatal("unlock of a platform-managed tenant")
	}
	// Control log still verifies and records the hand-overs.
	svc, _ := store.RemoteKeyring(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), e.root)
	if _, err := svc.Verify(ctx, store.ColumnKeyID); err != nil {
		t.Fatal(err)
	}
	evs, _ := e.st.Repos().ControlLog().List(ctx, store.ColumnKeyID, 1, 0)
	handovers := 0
	for _, ev := range evs {
		if ev.Kind == "kek_handover" {
			handovers++
		}
	}
	if handovers != 6 { // begun+complete for switch, replace, release
		t.Fatalf("%d kek_handover events, want 6", handovers)
	}
}

func TestSwitchResumesAfterACrash(t *testing.T) {
	e := newKEKEnv(t, 1)
	ctx := context.Background()
	_, raw := newKEKString(t)
	// Simulate a crash after the new wraps exist but before the old ones were removed:
	// run the keyring hand-over without its last steps via a failing Commit.
	w, _ := store.TenantWrapKey(raw)
	svc, _ := store.RemoteKeyringWithTenantKEK(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), e.root, w)
	from, _ := store.PlatformKEKRef(e.root)
	err := svc.Handover(ctx, store.ColumnKeyID, "x", from, store.TenantWrapRef(w), keyring.HandoverOptions{Commit: func(context.Context) error { return errors.New("crash") }})
	if err == nil {
		t.Fatal("expected the crash")
	}
	if !e.operatorCanRead() || !e.readerWith(raw) {
		t.Fatal("mid-way both KEKs must open the data")
	}
	c := e.client()
	if _, err := c.Switch(ctx, e.tenant.ID, base64.StdEncoding.EncodeToString(raw), "alice"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if e.operatorCanRead() || !e.readerWith(raw) {
		t.Fatal("after the resume only the tenant's KEK opens the data")
	}
}

func TestKEKEndpointsAuthAndInput(t *testing.T) {
	e := newKEKEnv(t, 1)
	n := e.nodes[0]
	post := func(path, token, body string) int {
		req, _ := http.NewRequest("POST", n.srv.URL+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := n.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	good := `{"tenant_id":"` + e.tenant.ID + `","kek":"` + strings.Repeat("A", 43) + `="}`
	for _, p := range []string{"/v1/kek/unlock", "/v1/kek/switch", "/v1/kek/release", "/v1/kek/lock", "/v1/kek/status"} {
		if c := post(p, "", good); c != 401 {
			t.Fatalf("%s without a token: %d", p, c)
		}
		if c := post(p, "nobody", good); c != 401 {
			t.Fatalf("%s with a bad token: %d", p, c)
		}
	}
	// A weak (all-zero) key and malformed bodies are refused before any work.
	if c := post("/v1/kek/switch", "good", good); c != 400 {
		t.Fatalf("weak key: %d", c)
	}
	if c := post("/v1/kek/switch", "good", `{"tenant_id":"x","kek":"y"}`); c != 400 {
		t.Fatalf("bad tenant id: %d", c)
	}
	if c := post("/v1/kek/switch", "good", `{"tenant_id":"`+e.tenant.ID+`","kek":"short"}`); c != 400 {
		t.Fatalf("short key: %d", c)
	}
	if c := post("/v1/kek/switch", "good", `{"tenant_id":"`+e.tenant.ID+`","extra":1}`); c != 400 {
		t.Fatalf("unknown field: %d", c)
	}
	// Unlock of a platform-managed tenant: conflict.
	k, _ := newKEKString(t)
	if c := post("/v1/kek/unlock", "good", `{"tenant_id":"`+e.tenant.ID+`","kek":"`+k+`"}`); c != 409 {
		t.Fatalf("unlock of a platform-managed tenant: %d", c)
	}
}

func TestWrongKeyAttemptsAreLimited(t *testing.T) {
	e := newKEKEnv(t, 1)
	c := e.client()
	ctx := context.Background()
	k, _ := newKEKString(t)
	if _, err := c.Switch(ctx, e.tenant.ID, k, "alice"); err != nil {
		t.Fatal(err)
	}
	var last error
	for i := 0; i < 15; i++ {
		w, _ := newKEKString(t)
		_, last = c.Unlock(ctx, e.tenant.ID, w)
	}
	var ce *keyclient.CallError
	if !errors.As(last, &ce) && !errors.As(last, new(*keyclient.AckError)) {
		t.Fatalf("after many wrong keys: %v", last)
	}
	// The right key is refused too while the limit holds (no oracle by timing out the budget).
	if _, err := c.Unlock(ctx, e.tenant.ID, k); err == nil {
		t.Fatal("the attempt budget did not hold")
	}
}

// The restore procedure of docs/cluster/TENANT-KEY-RESTORE.md: the tenant
// database comes back from a backup into a scratch database, the controllers
// know nothing of the key (locked), a wrong key is refused and the right one
// makes the data readable again.
func TestRestoredTenantStartsLockedAndUnlocksWithTheKEK(t *testing.T) {
	e := newKEKEnv(t, 1)
	ctx := context.Background()
	kek, raw := newKEKString(t)
	if _, err := e.client().Switch(ctx, e.tenant.ID, kek, "alice"); err != nil {
		t.Fatal(err)
	}
	// "Backup": the keyring, the control log and the encrypted data of the live database.
	events, err := e.st.Repos().ControlLog().List(ctx, store.ColumnKeyID, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	var rows []ports.KeyringRow
	for _, p := range keyring.Purposes {
		r, err := e.st.Repos().Keyring().Wraps(ctx, store.ColumnKeyID, p, 1)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r...)
	}
	// Restore into a scratch tenant database (no keys of its own).
	scratchKey := make([]byte, 32)
	rand.Read(scratchKey)
	st2, err := store.OpenTenant(t.TempDir(), scratchKey, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if err := st2.Repos().(*sqlite.Store).DropKeys(ctx); err != nil { // the restore replaces the scratch database's own keys
		t.Fatal(err)
	}
	scratch := st2.Repos()
	for _, ev := range events {
		if err := scratch.ControlLog().Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range rows {
		if err := scratch.Keyring().Add(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// The restored database holds only wrapped keys: the operator cannot read it.
	svc, _ := store.RemoteKeyring(scratch.ControlLog(), scratch.Keyring(), e.root)
	if c, err := keyring.NewCodec(ctx, svc, store.ColumnKeyID); err == nil {
		c.Close()
		t.Fatal("the operator opened a restored tenant-managed database")
	}
	// New controllers (a restored cluster) start locked; the unlock endpoint works on the restored data.
	ring := func(context.Context, string) (ports.ControlLogRepository, ports.KeyringRepository, func(), error) {
		return scratch.ControlLog(), scratch.Keyring(), func() {}, nil
	}
	kekm := keyserver.NewKEKManager(e.p, ring, e.master, e.log.logf)
	if _, ok := kekm.Wrap(e.tenant.ID, store.TenantKEKFingerprint(raw)); ok {
		t.Fatal("a fresh controller holds the key")
	}
	wrong := make([]byte, 32)
	rand.Read(wrong)
	if _, err := kekm.Unlock(ctx, e.tenant.ID, wrong); !errors.Is(err, keyserver.ErrWrongKEK) {
		t.Fatalf("wrong key on the restored database: %v", err)
	}
	if _, err := kekm.Unlock(ctx, e.tenant.ID, raw); err != nil {
		t.Fatalf("unlock of the restored database: %v", err)
	}
	w, ok := kekm.Wrap(e.tenant.ID, store.TenantKEKFingerprint(raw))
	if !ok {
		t.Fatal("not unlocked")
	}
	defer clear(w)
	rsvc, err := store.RemoteKeyringWithTenantKEK(scratch.ControlLog(), scratch.Keyring(), e.root, w)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := keyring.NewCodec(ctx, rsvc, store.ColumnKeyID)
	if err != nil {
		t.Fatalf("codec after the unlock: %v", err)
	}
	defer codec.Close()
	if v, err := codec.Open("settings", "value", "k1", e.sealed); err != nil || v != "top secret" {
		t.Fatalf("data after the restore: %q %v", v, err)
	}
	// A log that was changed in the backup keeps the tenant locked.
	tampered := keyserver.NewKEKManager(e.p, func(context.Context, string) (ports.ControlLogRepository, ports.KeyringRepository, func(), error) {
		return tamperedLog{scratch.ControlLog()}, scratch.Keyring(), func() {}, nil
	}, e.master, e.log.logf)
	if _, err := tampered.Unlock(ctx, e.tenant.ID, raw); err == nil {
		t.Fatal("a changed control log unlocked the tenant")
	}
}

// tamperedLog flips a bit in the MAC of one event.
type tamperedLog struct{ ports.ControlLogRepository }

func (l tamperedLog) List(ctx context.Context, tenant string, from, to int64) ([]ports.ControlLogEvent, error) {
	evs, err := l.ControlLogRepository.List(ctx, tenant, from, to)
	if err == nil && len(evs) > 2 {
		evs[2].MAC = append([]byte(nil), evs[2].MAC...)
		evs[2].MAC[0] ^= 1
	}
	return evs, err
}

// After the switch to the tenant's own KEK nothing the operator holds (the
// master, the root derived from it, the platform KEK, a controller that is
// locked) yields a key that decrypts file content written afterwards or that
// MACs the audit chain: both come from DEKs that only the tenant's wrap opens.
func TestTenantManagedFilesAndAuditMACAreNotOperatorReadable(t *testing.T) {
	e := newKEKEnv(t, 1)
	c := e.client()
	ctx := context.Background()
	kek, raw := newKEKString(t)
	if _, err := c.Switch(ctx, e.tenant.ID, kek, "alice"); err != nil {
		t.Fatal(err)
	}
	// A file written after the switch, by a replica holding the tenant's wrapping key.
	w, _ := store.TenantWrapKey(raw)
	defer clear(w)
	svc, err := store.RemoteKeyringWithTenantKEK(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), e.root, w)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := keyring.NewCodec(ctx, svc, store.ColumnKeyID)
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	master, ver, err := codec.FileMaster(0)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("FILE CONTENT WRITTEN AFTER THE SWITCH")
	var ct bytes.Buffer
	n, id, err := filecrypt.Encrypt(&ct, bytes.NewReader(plain), master, nil)
	if err != nil || n != int64(len(plain)) {
		t.Fatal(n, err)
	}
	open := func(m []byte) error {
		r, err := filecrypt.NewReader(bytesFile{bytes.NewReader(ct.Bytes())}, int64(ct.Len()), int64(len(plain)), m, id)
		if err != nil {
			return err
		}
		_, err = io.ReadAll(r)
		return err
	}
	if err := open(master); err != nil {
		t.Fatalf("the tenant's own key cannot read the file (version %d): %v", ver, err)
	}
	// Everything the operator can derive fails: the master key, the root, the database key.
	dbKey, _, _ := e.p.TenantKeys(e.tenant)
	for name, secret := range map[string][]byte{"master": e.master, "root": e.root, "database key": dbKey} {
		m, err := filecrypt.MasterKey(secret)
		if err != nil {
			t.Fatal(err)
		}
		if err := open(m); err == nil {
			t.Fatalf("a file written after the switch decrypts with the file master derived from the %s", name)
		}
	}
	// The keyring cannot be opened with the platform's KEK, so neither the
	// files DEK nor the audit-mac DEK can be obtained that way.
	psvc, err := store.RemoteKeyring(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), e.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{keyring.PurposeFiles, keyring.PurposeAuditMAC} {
		if k, err := psvc.Load(ctx, store.ColumnKeyID, purpose, 0); err == nil {
			clear(k.DEK)
			t.Fatalf("the platform KEK opened the %s key of a tenant-managed tenant", purpose)
		}
	}
	// A controller that does not have the tenant's KEK (restarted, locked)
	// serves nothing: 423, no keys, no wrapping key.
	locked := e.addNode()
	code, keys := e.tenantKeys(locked)
	if code != 423 || keys.KEK != "" || keys.Root != "" || keys.DBKey != "" {
		t.Fatalf("locked controller answered %d %+v", code, keys)
	}
}

type bytesFile struct{ *bytes.Reader }

func (bytesFile) Close() error { return nil }

// A web replica that cached the tenant's keys before a switch to the tenant's
// own key holds no wrapping key for it: opening the store with that material
// reports ports.ErrUnknownKEK (the replica then fetches the keys again), and
// the fresh material (with the wrapping key) opens it.
func TestStaleKeysAfterASwitchReportUnknownKEK(t *testing.T) {
	e := newKEKEnv(t, 1)
	ctx := context.Background()
	open := func(opts ...store.RemoteOpt) error {
		st, err := store.OpenRemote(e.st.Repos(), t.TempDir(), e.root, nil, append([]store.RemoteOpt{store.WithColumnEncryption()}, opts...)...)
		if err == nil {
			st.Close()
		}
		return err
	}
	if err := open(); err != nil {
		t.Fatalf("before the switch: %v", err)
	}
	kek, raw := newKEKString(t)
	if _, err := e.client().Switch(ctx, e.tenant.ID, kek, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := open(); !errors.Is(err, ports.ErrUnknownKEK) {
		t.Fatalf("stale keys after the switch: %v, want ErrUnknownKEK", err)
	}
	w, _ := store.TenantWrapKey(raw)
	if err := open(store.WithTenantWrapKey(w)); err != nil {
		t.Fatalf("fresh keys after the switch: %v", err)
	}
}
