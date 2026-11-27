// SPDX-License-Identifier: AGPL-3.0-or-later

package keyserver_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/keyserver"
	"github.com/sendora-app/sendora/internal/masterkey"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

type masterEnv struct {
	*kekEnv
	dir string
	set *masterkey.Set
	rot *keyserver.MasterRotator
	m2  []byte
	m3  []byte
}

func writeMaster(t *testing.T, dir string, v int, key []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "master-"+string(rune('0'+v))), key, 0o400); err != nil {
		t.Fatal(err)
	}
}

func newMasterEnv(t *testing.T) *masterEnv {
	t.Helper()
	e := &masterEnv{kekEnv: newKEKEnv(t, 1), dir: t.TempDir(), m2: make([]byte, 32), m3: make([]byte, 32)}
	rand.Read(e.m2)
	rand.Read(e.m3)
	writeMaster(t, e.dir, 1, e.master)
	set, err := masterkey.Load(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	e.set = set
	e.p.UseMasters(set)
	e.rot = &keyserver.MasterRotator{P: e.p, Masters: set, KEK: e.nodes[0].kek, Logf: e.log.logf, Ring: e.ringFunc(nil)}
	return e
}

// ringFunc is the owner connection; wrap lets a test fail mutating calls.
func (e *masterEnv) ringFunc(wrap func(ports.KeyringRepository) ports.KeyringRepository) keyserver.RingFunc {
	return func(ctx context.Context, id string) (ports.ControlLogRepository, ports.KeyringRepository, func(), error) {
		var ring ports.KeyringRepository = e.st.Repos().Keyring()
		if wrap != nil {
			ring = wrap(ring)
		}
		return e.st.Repos().ControlLog(), ring, func() {}, nil
	}
}

// readsWith opens the tenant's keys with only the platform KEK of one master version.
func (e *masterEnv) readsWith(master []byte) bool {
	t, _ := e.p.Tenant(e.tenant.ID)
	dbKey, err := store.TenantDBKey(master, t.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	svc, err := store.RemoteKeyring(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), dbKey)
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

func (e *masterEnv) version() int {
	t, err := e.p.Tenant(e.tenant.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return t.MasterVersion
}

type crashRing struct {
	ports.KeyringRepository
	addAt, removeAt int // fail the n-th call (1-based); 0 never
	adds, removes   int
}

var errBoom = errors.New("crash")

func (c *crashRing) Add(ctx context.Context, r ports.KeyringRow) error {
	c.adds++
	if c.adds == c.addAt {
		return errBoom
	}
	return c.KeyringRepository.Add(ctx, r)
}
func (c *crashRing) Remove(ctx context.Context, tenant, id string) (bool, error) {
	c.removes++
	if c.removes == c.removeAt {
		return false, errBoom
	}
	return c.KeyringRepository.Remove(ctx, tenant, id)
}

func TestMasterRotationPlatformManaged(t *testing.T) {
	e := newMasterEnv(t)
	ctx := context.Background()
	local := &keyserver.Local{Master: e.master, P: e.p}
	before, err := local.Tenant(ctx, e.tenant.ID)
	if err != nil || before.MasterVersion != 1 {
		t.Fatalf("before: %+v %v", before, err)
	}
	// Steps are refused out of order and while the key is not mounted.
	if err := e.rot.Start(3); !errors.Is(err, keyserver.ErrNoSuchStep) {
		t.Fatalf("Start(3): %v", err)
	}
	if err := e.rot.Start(2); err == nil {
		t.Fatal("Start(2) before version 2 is mounted")
	}
	writeMaster(t, e.dir, 2, e.m2) // mounted later: found without a restart
	if err := e.rot.Start(2); err != nil {
		t.Fatal(err)
	}
	if err := e.rot.Start(2); !errors.Is(err, keyserver.ErrRotationBusy) {
		t.Fatalf("second Start: %v", err)
	}
	if !e.readsWith(e.master) {
		t.Fatal("the tenant is not readable under version 1 before the rotation")
	}
	done, err := e.rot.Pass(ctx)
	if err != nil || !done {
		t.Fatalf("Pass: done=%v err=%v", done, err)
	}
	if e.version() != 2 {
		t.Fatalf("tenant version = %d", e.version())
	}
	st, err := e.rot.Status()
	if err != nil || st.InProgress || st.Active != 2 || st.Tenants[2] != 1 || st.Tenants[1] != 0 {
		t.Fatalf("status: %+v %v", st, err)
	}
	// Data unchanged, readable under version 2 only: the old KEK opens nothing.
	if !e.readsWith(e.m2) {
		t.Fatal("the tenant is not readable under version 2")
	}
	if e.readsWith(e.master) {
		t.Fatal("version 1 still opens the keyring")
	}
	// The key endpoint serves material derived from the tenant's version; the
	// database password (infrastructure) is unchanged.
	after, err := local.Tenant(ctx, e.tenant.ID)
	if err != nil || after.MasterVersion != 2 {
		t.Fatalf("after: %+v %v", after, err)
	}
	want, _ := store.TenantDBKey(e.m2, e.tenant.ID)
	if after.DBKey != hex.EncodeToString(want) || after.DBKey == before.DBKey {
		t.Fatal("the served database key is not derived from version 2")
	}
	if after.DBPassword != before.DBPassword {
		t.Fatal("the database password changed")
	}
	// A repeated pass does nothing and appends no events.
	st1, _ := keyringHead(t, e)
	if done, err := e.rot.Pass(ctx); err != nil || !done {
		t.Fatal(err)
	}
	if st2, _ := keyringHead(t, e); st2 != st1 {
		t.Fatal("a finished rotation appended events")
	}
	// Retiring: not the infrastructure version.
	if err := e.rot.Retire(1); err == nil {
		t.Fatal("version 1 was retired while it derives the database passwords")
	}
}

func keyringHead(t *testing.T, e *masterEnv) (int64, string) {
	t.Helper()
	ev, err := e.st.Repos().ControlLog().Latest(context.Background(), store.ColumnKeyID)
	if err != nil {
		t.Fatal(err)
	}
	return ev.Seq, ev.MACKEK
}

// A crash at any mutating call of the keyring, in both directions, is resumed
// by the next pass; the tenant stays readable all along.
func TestMasterRotationResumesAfterCrashes(t *testing.T) {
	for _, kind := range []string{"add", "remove"} {
		for n := 1; n <= 12; n++ {
			e := newMasterEnv(t)
			writeMaster(t, e.dir, 2, e.m2)
			if err := e.rot.Start(2); err != nil {
				t.Fatal(err)
			}
			cr := &crashRing{}
			if kind == "add" {
				cr.addAt = n
			} else {
				cr.removeAt = n
			}
			e.rot.Ring = e.ringFunc(func(r ports.KeyringRepository) ports.KeyringRepository { cr.KeyringRepository = r; return cr })
			done, err := e.rot.Pass(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if done {
				if (kind == "add" && cr.adds < n) || (kind == "remove" && cr.removes < n) {
					break // beyond the last call: every crash point is covered
				}
				t.Fatalf("%s %d: a crash left the rotation done", kind, n)
			}
			// Mid-way: still readable (with both KEKs, as the controller holds them).
			if !e.readsWith(e.master) && !e.readsWith(e.m2) {
				t.Fatalf("%s %d: the tenant is unreadable after a crash", kind, n)
			}
			if st, _ := e.rot.Status(); !st.InProgress {
				t.Fatalf("%s %d: the rotation was forgotten", kind, n)
			}
			e.rot.Ring = e.ringFunc(nil)
			if done, err := e.rot.Pass(context.Background()); err != nil || !done {
				t.Fatalf("%s %d: resume: done=%v err=%v", kind, n, done, err)
			}
			if e.version() != 2 || !e.readsWith(e.m2) || e.readsWith(e.master) {
				t.Fatalf("%s %d: after resume: version %d", kind, n, e.version())
			}
			if _, mac := keyringHead(t, e); mac == "" {
				t.Fatal("no head")
			}
		}
	}
}

// A tenant-managed tenant keeps its own wraps untouched: only the log's MAC
// and the record move, and the tenant's key is neither needed nor used.
func TestMasterRotationTenantManagedIsOnlyAMACMove(t *testing.T) {
	e := newMasterEnv(t)
	ctx := context.Background()
	kekText, kek := newKEKString(t)
	_ = kekText
	if _, err := e.nodes[0].kek.Switch(ctx, e.tenant.ID, kek, "alice"); err != nil {
		t.Fatal(err)
	}
	e.nodes[0].kek.Lock(e.tenant.ID) // locked on the controller: no tenant key is available
	svc, err := store.RemoteKeyring(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), e.root)
	if err != nil {
		t.Fatal(err)
	}
	refsBefore, err := svc.WrapRefs(ctx, store.ColumnKeyID)
	if err != nil {
		t.Fatal(err)
	}
	writeMaster(t, e.dir, 2, e.m2)
	if err := e.rot.Start(2); err != nil {
		t.Fatal(err)
	}
	if done, err := e.rot.Pass(ctx); err != nil || !done {
		t.Fatalf("Pass: done=%v err=%v", done, err)
	}
	if e.version() != 2 {
		t.Fatalf("version %d", e.version())
	}
	// The wraps are exactly as before (under the tenant's KEK); the log is
	// attested by version 2's KEK, so version 2 alone verifies it.
	dbKey2, _ := store.TenantDBKey(e.m2, e.tenant.ID)
	svc2, _ := store.RemoteKeyring(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), dbKey2)
	refsAfter, err := svc2.WrapRefs(ctx, store.ColumnKeyID)
	if err != nil {
		t.Fatalf("version 2 does not verify the log: %v", err)
	}
	for ref, n := range refsBefore {
		if refsAfter[ref] != n {
			t.Fatalf("wraps changed: %v -> %v", refsBefore, refsAfter)
		}
	}
	w, _ := store.TenantWrapKey(kek)
	svc3, err := store.RemoteKeyringWithTenantKEK(e.st.Repos().ControlLog(), e.st.Repos().Keyring(), dbKey2, w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc3.Verify(ctx, store.ColumnKeyID); err != nil {
		t.Fatalf("version 2 plus the tenant's key does not verify: %v", err)
	}
	if _, mac := keyringHead(t, e); mac == "" {
		t.Fatal("no head")
	}
}

// Rotating again, and retiring: refused while a tenant needs the version,
// allowed afterwards.
func TestMasterRetireRules(t *testing.T) {
	e := newMasterEnv(t)
	ctx := context.Background()
	writeMaster(t, e.dir, 2, e.m2)
	writeMaster(t, e.dir, 3, e.m3)
	for _, to := range []int{2, 3} {
		if err := e.rot.Start(to); err != nil {
			t.Fatal(err)
		}
		if err := e.rot.Retire(to - 1); err == nil {
			t.Fatal("retired during a rotation")
		}
		if done, err := e.rot.Pass(ctx); err != nil || !done {
			t.Fatalf("Pass to %d: %v %v", to, done, err)
		}
	}
	if e.version() != 3 || !e.readsWith(e.m3) {
		t.Fatalf("version %d", e.version())
	}
	if err := e.rot.Retire(1); err == nil {
		t.Fatal("version 1 was retired although it derives the database passwords")
	}
	if err := e.rot.Retire(3); err == nil {
		t.Fatal("the active version was retired")
	}
	if err := e.rot.Retire(2); err != nil {
		t.Fatalf("version 2 is unused and must be retirable: %v", err)
	}
	if err := e.rot.Retire(2); err == nil {
		t.Fatal("retired twice")
	}
	st, _ := e.rot.Status()
	if len(st.Retired) != 1 || st.Retired[0] != 2 || len(st.Retirable) != 0 {
		t.Fatalf("status: %+v", st)
	}
	// A retired version is refused for any derivation.
	if _, _, err := e.p.TenantKeysAt(&platform.Tenant{ID: e.tenant.ID}, 2); err == nil {
		t.Fatal("a retired version still derives keys")
	}
}

// lagBehind makes the tenant (on version 1) lag: version 2 becomes active
// without the tenant being moved, as happened to tenants created after a
// rotation while the insert did not record the active version.
func lagBehind(t *testing.T, e *masterEnv) {
	t.Helper()
	writeMaster(t, e.dir, 2, e.m2)
	if err := e.p.SetMasterSetting("master_active_version", "2"); err != nil {
		t.Fatal(err)
	}
	writeMaster(t, e.dir, 3, e.m3)
	if err := e.rot.Start(3); err != nil {
		t.Fatal(err)
	}
}

func (e *masterEnv) onlyReadsWith(want []byte) bool {
	for _, k := range [][]byte{e.master, e.m2, e.m3} {
		if e.readsWith(k) != (string(k) == string(want)) {
			return false
		}
	}
	return true
}

// A tenant two versions behind the target is moved one version at a time;
// afterwards only the target version opens its keyring.
func TestMasterRotationMovesALaggingTenant(t *testing.T) {
	e := newMasterEnv(t)
	lagBehind(t, e)
	if e.version() != 1 {
		t.Fatalf("version %d", e.version())
	}
	if done, err := e.rot.Pass(context.Background()); err != nil || !done {
		t.Fatalf("Pass: done=%v err=%v", done, err)
	}
	if e.version() != 3 || !e.onlyReadsWith(e.m3) {
		t.Fatalf("after the pass: version %d, v1 %v v2 %v v3 %v", e.version(), e.readsWith(e.master), e.readsWith(e.m2), e.readsWith(e.m3))
	}
	st, err := e.rot.Status()
	if err != nil || st.InProgress || st.Tenants[3] != 1 {
		t.Fatalf("status: %+v %v", st, err)
	}
}

// The same, with a crash at every mutating keyring call of both steps: the
// next pass finishes, including the removal of the wraps of a step whose
// commit already happened.
func TestMasterRotationMovesALaggingTenantAfterCrashes(t *testing.T) {
	for _, kind := range []string{"add", "remove"} {
		for n := 1; n <= 30; n++ {
			e := newMasterEnv(t)
			lagBehind(t, e)
			cr := &crashRing{}
			if kind == "add" {
				cr.addAt = n
			} else {
				cr.removeAt = n
			}
			e.rot.Ring = e.ringFunc(func(r ports.KeyringRepository) ports.KeyringRepository { cr.KeyringRepository = r; return cr })
			done, err := e.rot.Pass(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if done {
				if (kind == "add" && cr.adds < n) || (kind == "remove" && cr.removes < n) {
					break // beyond the last call: every crash point is covered
				}
				t.Fatalf("%s %d: a crash left the rotation done", kind, n)
			}
			if !e.readsWith(e.master) && !e.readsWith(e.m2) && !e.readsWith(e.m3) {
				t.Fatalf("%s %d: the tenant is unreadable after a crash", kind, n)
			}
			e.rot.Ring = e.ringFunc(nil)
			if done, err := e.rot.Pass(context.Background()); err != nil || !done {
				t.Fatalf("%s %d: resume: done=%v err=%v", kind, n, done, err)
			}
			if e.version() != 3 || !e.onlyReadsWith(e.m3) {
				t.Fatalf("%s %d: after resume: version %d, v1 %v v2 %v v3 %v", kind, n, e.version(), e.readsWith(e.master), e.readsWith(e.m2), e.readsWith(e.m3))
			}
		}
	}
}

// A tenant created while version 2 is active is recorded on version 2 and
// derives from it; a pass for version 2 has nothing to move and appends
// nothing; the next rotation moves it normally.
func TestMasterRotationTenantCreatedOnTheActiveVersion(t *testing.T) {
	m2, m3 := make([]byte, 32), make([]byte, 32)
	rand.Read(m2)
	rand.Read(m3)
	dir := t.TempDir()
	var set *masterkey.Set
	k := newKEKEnvWith(t, 1, func(p *platform.Platform, master []byte) {
		writeMaster(t, dir, 1, master)
		writeMaster(t, dir, 2, m2)
		var err error
		if set, err = masterkey.Load(dir); err != nil {
			t.Fatal(err)
		}
		p.UseMasters(set)
		if err := p.SetMasterSetting("master_active_version", "2"); err != nil {
			t.Fatal(err)
		}
	})
	e := &masterEnv{kekEnv: k, dir: dir, set: set, m2: m2, m3: m3}
	e.rot = &keyserver.MasterRotator{P: e.p, Masters: set, KEK: e.nodes[0].kek, Logf: e.log.logf, Ring: e.ringFunc(nil)}
	ctx := context.Background()
	if e.version() != 2 {
		t.Fatalf("a tenant created while version 2 is active is recorded on version %d", e.version())
	}
	if !e.onlyReadsWith(e.m2) {
		t.Fatal("the tenant does not derive from version 2 alone")
	}
	seq, mac := keyringHead(t, e)
	if err := e.rot.RotateTenant(ctx, e.tenant.ID, 2); err != nil {
		t.Fatalf("RotateTenant to its own version: %v", err)
	}
	if s2, m2 := keyringHead(t, e); s2 != seq || m2 != mac {
		t.Fatal("a tenant already on the version got a hand-over")
	}
	writeMaster(t, dir, 3, m3)
	if err := e.rot.Start(3); err != nil {
		t.Fatal(err)
	}
	if done, err := e.rot.Pass(ctx); err != nil || !done {
		t.Fatalf("Pass: done=%v err=%v", done, err)
	}
	if e.version() != 3 || !e.onlyReadsWith(e.m3) {
		t.Fatalf("after the rotation: version %d", e.version())
	}
}

func TestMasterRotationNeedsTheKeyOnTheLeader(t *testing.T) {
	e := newMasterEnv(t)
	writeMaster(t, e.dir, 2, e.m2)
	if err := e.rot.Start(2); err != nil {
		t.Fatal(err)
	}
	// Another controller started the rotation; the one that leads now does not have the key.
	d2 := t.TempDir()
	writeMaster(t, d2, 1, e.master)
	set2, err := masterkey.Load(d2)
	if err != nil {
		t.Fatal(err)
	}
	e.p.UseMasters(set2)
	e.rot.Masters = set2
	if done, err := e.rot.Pass(context.Background()); err == nil || done {
		t.Fatalf("Pass without the key: done=%v err=%v", done, err)
	}
	if e.version() != 1 {
		t.Fatal("a tenant moved without the key")
	}
	if st, _ := e.rot.Status(); st.Note == "" {
		t.Fatal("the operator is not told why the rotation waits")
	}
}
