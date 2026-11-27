// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/keyops"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/ports"
)

// RunKeyRotation pins the contract of the online rotation of a tenant's data
// keys (D43): after a rotation old rows still open, new writes use the new
// version, the re-encryption job converges without losing a concurrent
// update, rotating the index key keeps every lookup working, a retired
// version is refused for new writes, and a tampered or unknown version fails
// closed.
func RunKeyRotation(t *testing.T, open func(testing.TB) encStore) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	const tenant = "tenant-1"

	setup := func(t *testing.T) (encStore, *keyops.Engine, *keyring.Service) {
		s := open(t)
		codec, svc := newTestCodec(t, s.Store, tenant)
		s.setCodec(codec)
		return s, &keyops.Engine{KeyID: tenant, Svc: svc, Codec: codec, Store: s.Store, Actor: "conformance", Batch: 3}, svc
	}
	version := func(t *testing.T, s encStore, table, column string, id int64) int {
		t.Helper()
		v, err := s.rawGet(ctx, table, column, strconv.FormatInt(id, 10))
		if err != nil {
			t.Fatal(err)
		}
		n, ok := colenc.TextVersion(v)
		if !ok {
			t.Fatalf("%s.%s of %d holds %q, not ciphertext", table, column, id, v)
		}
		return n
	}
	run := func(t *testing.T, e *keyops.Engine, op, purpose string, v int) keyops.Result {
		t.Helper()
		id, err := e.Store.ColumnKeys().CreateKeyJob(ctx, ports.KeyJob{Op: op, Purpose: purpose, Version: v, Actor: "conformance"})
		if err != nil {
			t.Fatal(err)
		}
		job, err := e.Store.ColumnKeys().NextKeyJob(ctx)
		if err != nil || job.ID != id || job.Status != ports.KeyJobPending {
			t.Fatalf("NextKeyJob = %+v, %v", job, err)
		}
		res, err := e.Execute(ctx, job)
		if err != nil {
			t.Fatalf("%s %s: %v", op, purpose, err)
		}
		return res
	}
	populate := func(t *testing.T, s encStore, n int) (users, shares []int64) {
		for i := 0; i < n; i++ {
			users = append(users, mustCreate(t, s.Users(), newUser(fmt.Sprintf("user%d", i), fmt.Sprintf("user%d@example.org", i))))
			shares = append(shares, mustShare(t, s, ports.NewShare{UserID: users[i], LongID: fmt.Sprintf("long-rot-%d", i), Name: "Plans", Description: fmt.Sprintf("secret %d", i), ExpiresAt: now.Add(time.Hour)}))
		}
		return
	}

	t.Run("Jobs", func(t *testing.T) {
		s, _, _ := setup(t)
		k := s.Store.ColumnKeys()
		if _, err := k.NextKeyJob(ctx); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("NextKeyJob on an empty table = %v, want not found", err)
		}
		if l, err := k.KeyJobs(ctx, 10); err != nil || len(l) != 0 {
			t.Fatalf("KeyJobs = %v, %v", l, err)
		}
		a, err := k.CreateKeyJob(ctx, ports.KeyJob{Op: ports.KeyJobRotate, Purpose: "data", Actor: "ann"})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := k.CreateKeyJob(ctx, ports.KeyJob{Op: ports.KeyJobRetire, Purpose: "data", Version: 1, Actor: "ann"})
		if first, err := k.NextKeyJob(ctx); err != nil || first.ID != a {
			t.Fatalf("NextKeyJob = %+v, %v, want the oldest (%d)", first, err, a)
		}
		if err := k.UpdateKeyJob(ctx, a, ports.KeyJobRunning, 2, "working"); err != nil {
			t.Fatal(err)
		}
		if err := k.UpdateKeyJob(ctx, a, ports.KeyJobDone, 2, "ok"); err != nil {
			t.Fatal(err)
		}
		if err := k.UpdateKeyJob(ctx, a, ports.KeyJobRunning, 2, ""); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("a finished job was updated: %v", err)
		}
		if next, err := k.NextKeyJob(ctx); err != nil || next.ID != b {
			t.Fatalf("NextKeyJob after the first finished = %+v, %v", next, err)
		}
		l, err := k.KeyJobs(ctx, 10)
		if err != nil || len(l) != 2 || l[0].ID != b || l[1].Status != ports.KeyJobDone || l[1].Version != 2 || l[1].Detail != "ok" || l[1].Actor != "ann" {
			t.Fatalf("KeyJobs = %+v, %v", l, err)
		}
	})

	t.Run("Batches", func(t *testing.T) {
		s, e, svc := setup(t)
		users, _ := populate(t, s, 3)
		if _, err := svc.Rotate(ctx, tenant, keyring.PurposeData, "conformance"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Codec.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		// One value is rewritten by someone else (a concurrent update) between
		// the batches: the cursor moves on and the batch never overwrites it.
		var cur ports.ResealCursor
		total, calls := 0, 0
		for {
			tx, err := s.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			next, n, done, err := tx.ColumnKeys().ResealBatch(ctx, e.Codec, 2, cur, 2)
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			total += n
			calls++
			if done {
				break
			}
			if next == cur {
				t.Fatalf("the cursor did not move: %+v", next)
			}
			cur = next
			if calls > 200 {
				t.Fatal("the pass does not end")
			}
		}
		if calls < 3 || total == 0 {
			t.Fatalf("%d values in %d batches of 2: the batches are not bounded", total, calls)
		}
		if counts, _ := s.Store.ColumnKeys().ColumnVersions(ctx); counts.Columns[1] != 0 || counts.Columns[2] != int64(total) {
			t.Fatalf("after one pass: %+v, rewrote %d", counts, total)
		}
		// A second pass changes nothing.
		if _, n, done, err := s.Store.ColumnKeys().ResealBatch(ctx, e.Codec, 2, ports.ResealCursor{}, 1000); err != nil || n != 0 || !done {
			t.Fatalf("second pass: %d, %v, %v", n, done, err)
		}
		// ReindexBlind keeps every index equal to what the codec computes.
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.ColumnKeys().ReindexBlind(ctx, e.Codec); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Users().FindLocalByUniqueEmail(ctx, "user1@example.org"); err != nil || got.ID != users[1] {
			t.Fatalf("lookup after a reindex: %+v, %v", got, err)
		}
	})

	t.Run("DataRotation", func(t *testing.T) {
		s, e, svc := setup(t)
		users, shares := populate(t, s, 4)
		if v := version(t, s, "users", "email", users[0]); v != 1 {
			t.Fatalf("before the rotation: version %d", v)
		}
		before, err := e.Store.ColumnKeys().ColumnVersions(ctx)
		if err != nil || before.Columns[1] == 0 || len(before.Columns) != 1 {
			t.Fatalf("ColumnVersions before = %+v, %v", before, err)
		}

		res := run(t, e, ports.KeyJobRotate, keyring.PurposeData, 0)
		if res.Version != 2 {
			t.Fatalf("rotated to version %d, want 2", res.Version)
		}
		after, _ := e.Store.ColumnKeys().ColumnVersions(ctx)
		if after.Columns[1] != 0 || after.Columns[2] != before.Columns[1] {
			t.Fatalf("after the job: %+v (before %+v): every value must be on version 2", after, before)
		}
		for i, id := range users {
			if v := version(t, s, "users", "email", id); v != 2 {
				t.Fatalf("user %d is on version %d", i, v)
			}
			if got := mustUser(t, s.Users(), id); got.Email != fmt.Sprintf("user%d@example.org", i) {
				t.Fatalf("user %d = %+v after the re-encryption", i, got)
			}
		}
		for i, id := range shares {
			if sh, err := s.Shares().ByID(ctx, id); err != nil || sh.Description != fmt.Sprintf("secret %d", i) {
				t.Fatalf("share %d = %+v, %v", i, sh, err)
			}
		}
		// A write after the rotation is sealed under the new version.
		nu := mustCreate(t, s.Users(), newUser("late", "late@example.org"))
		if v := version(t, s, "users", "email", nu); v != 2 {
			t.Fatalf("a new row is on version %d, want 2", v)
		}
		// A second job finds nothing to rewrite.
		if _, left, err := e.ResealAll(ctx, 2); err != nil || left != 0 {
			t.Fatalf("ResealAll = %d, %v", left, err)
		}

		// Retiring: the active version cannot be, the old one can once nothing
		// uses it, and then it is refused for good.
		if err := e.CheckRetire(ctx, keyring.PurposeData, 2); err == nil {
			t.Fatal("the active version can be retired")
		}
		res = run(t, e, ports.KeyJobRetire, keyring.PurposeData, 1)
		if res.Version != 1 {
			t.Fatalf("retired %d", res.Version)
		}
		st, err := svc.Verify(ctx, tenant)
		if err != nil || st.States[keyring.PurposeData][1] != keyring.StateRetired || st.States[keyring.PurposeData][2] != keyring.StateActive {
			t.Fatalf("states after retiring: %+v, %v", st.States, err)
		}
		if err := e.CheckRetire(ctx, keyring.PurposeData, 1); err == nil {
			t.Fatal("a retired version can be retired again")
		}
		status, err := e.Status(ctx)
		if err != nil || len(status.Jobs) != 2 || status.Jobs[0].Status != ports.KeyJobDone {
			t.Fatalf("Status = %+v, %v", status, err)
		}
	})

	// The audit log's text fields are sealed under "audit-enc", not "data":
	// rotating data (job included) never touches them and a data version that
	// sealed no other value is retirable although audit rows exist; rotating
	// audit-enc only changes what new records use, old ones stay readable, and
	// an audit-enc version with records cannot be retired.
	t.Run("AuditEncPurpose", func(t *testing.T) {
		s, e, _ := setup(t)
		populate(t, s, 2)
		chain := s.AuditChain()
		insert := func(seq int64) {
			t.Helper()
			r := auditRec(seq, "2027-02-01T10:00:00Z", "auth", "login_ok", "Alice Secret", "ok")
			r.Detail = "detail-" + itoa(seq)
			if err := chain.Insert(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		insert(1)
		insert(2)
		counts, err := s.Store.ColumnKeys().ColumnVersions(ctx)
		if err != nil || counts.Audit[1] == 0 || counts.Columns[1] == 0 {
			t.Fatalf("ColumnVersions = %+v, %v", counts, err)
		}
		auditAt1 := counts.Audit[1]

		// Rotate data with the job: audit rows stay on version 1 (audit-enc),
		// every other value moves to data version 2.
		run(t, e, ports.KeyJobRotate, keyring.PurposeData, 0)
		counts, _ = s.Store.ColumnKeys().ColumnVersions(ctx)
		if counts.Columns[1] != 0 || counts.Audit[1] != auditAt1 || len(counts.Audit) != 1 {
			t.Fatalf("after the data rotation: %+v", counts)
		}
		insert(3)
		if v := version(t, s, "audit_log", "detail", 3); v != 1 {
			t.Fatalf("a new audit record is on version %d after a data rotation, want audit-enc 1", v)
		}
		// The data version is retirable although audit rows exist.
		if err := e.CheckRetire(ctx, keyring.PurposeData, 1); err != nil {
			t.Fatalf("data version 1 is not retirable: %v", err)
		}
		run(t, e, ports.KeyJobRetire, keyring.PurposeData, 1)
		if _, err := chain.Walk(ctx, 0, 0, 0, func(r *ports.AuditRecord) {
			if r.Detail != "detail-"+itoa(r.Seq) || r.ActorName != "Alice Secret" {
				t.Fatalf("audit record %d opens as %+v", r.Seq, r)
			}
		}); err != nil {
			t.Fatalf("the audit log after retiring data v1: %v", err)
		}

		// Rotate audit-enc: new records use version 2, old ones still open,
		// version 1 cannot be retired while they exist, the status counts them.
		res := run(t, e, ports.KeyJobRotate, keyring.PurposeAuditEnc, 0)
		if res.Version != 2 {
			t.Fatalf("audit-enc rotated to version %d, want 2", res.Version)
		}
		insert(4)
		if v := version(t, s, "audit_log", "detail", 4); v != 2 {
			t.Fatalf("a new audit record is on version %d, want 2", v)
		}
		if v := version(t, s, "audit_log", "detail", 1); v != 1 {
			t.Fatalf("an old audit record was rewritten to version %d", v)
		}
		n := 0
		if _, err := chain.Walk(ctx, 0, 0, 0, func(r *ports.AuditRecord) {
			n++
			if r.Detail != "detail-"+itoa(r.Seq) {
				t.Fatalf("audit record %d opens as %+v", r.Seq, r)
			}
		}); err != nil || n != 4 {
			t.Fatalf("Walk after the audit-enc rotation: %d, %v", n, err)
		}
		if err := e.CheckRetire(ctx, keyring.PurposeAuditEnc, 1); err == nil || !strings.Contains(err.Error(), "audit") {
			t.Fatalf("CheckRetire(audit-enc 1) = %v, want a refusal naming the audit log", err)
		}
		status, err := e.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range status.Purposes {
			for _, v := range p.Versions {
				switch {
				case p.Purpose == keyring.PurposeAuditEnc && v.Version == 1 && (v.AuditRows == 0 || v.Rows != 0):
					t.Fatalf("audit-enc v1 status: %+v", v)
				case p.Purpose == keyring.PurposeAuditEnc && v.Version == 2 && v.AuditRows == 0:
					t.Fatalf("audit-enc v2 status: %+v", v)
				case p.Purpose == keyring.PurposeData && v.AuditRows != 0:
					t.Fatalf("data v%d counts audit rows: %+v", v.Version, v)
				}
			}
		}
	})

	t.Run("RetireRefusedWhileInUse", func(t *testing.T) {
		s, e, svc := setup(t)
		populate(t, s, 2)
		// Rotate without the job: the values stay on version 1.
		if _, err := svc.Rotate(ctx, tenant, keyring.PurposeData, "conformance"); err != nil {
			t.Fatal(err)
		}
		if err := e.CheckRetire(ctx, keyring.PurposeData, 1); err == nil || !strings.Contains(err.Error(), "still sealed") {
			t.Fatalf("CheckRetire = %v, want a refusal naming the values in use", err)
		}
		if err := svc.Retire(ctx, tenant, keyring.PurposeData, 2, "x"); err == nil {
			t.Fatal("the keyring retired the active version")
		}
	})

	t.Run("ConcurrentUpdateIsNotLost", func(t *testing.T) {
		s, e, _ := setup(t)
		const keys = 12
		for i := 0; i < keys; i++ {
			if err := s.Settings().Set(ctx, fmt.Sprintf("rot_%d", i), "initial"); err != nil {
				t.Fatal(err)
			}
		}
		populate(t, s, 6)
		var stop atomic.Bool
		var wg sync.WaitGroup
		last := make([]string, keys)
		errs := make(chan error, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 1; !stop.Load(); n++ {
				i := n % keys
				v := fmt.Sprintf("write-%d", n)
				if err := s.Settings().Set(ctx, fmt.Sprintf("rot_%d", i), v); err != nil {
					select {
					case errs <- err:
					default:
					}
					return
				}
				last[i] = v
			}
		}()
		run(t, e, ports.KeyJobRotate, keyring.PurposeData, 0)
		stop.Store(true)
		wg.Wait()
		select {
		case err := <-errs:
			t.Fatalf("a concurrent write failed: %v", err)
		default:
		}
		for i := 0; i < keys; i++ {
			want := last[i]
			if want == "" {
				want = "initial"
			}
			if got, err := s.Settings().Get(ctx, fmt.Sprintf("rot_%d", i)); err != nil || got != want {
				t.Fatalf("setting rot_%d = %q, %v, want %q (a concurrent update was lost)", i, got, err, want)
			}
		}
		if counts, _ := e.Store.ColumnKeys().ColumnVersions(ctx); counts.Columns[1] != 0 {
			t.Fatalf("values left on version 1: %+v", counts)
		}
	})

	t.Run("IndexRotation", func(t *testing.T) {
		s, e, svc := setup(t)
		users, shares := populate(t, s, 4)
		c := e.Codec
		old, err := c.BlindIndex("users", "email", "user0@example.org")
		if err != nil {
			t.Fatal(err)
		}
		res := run(t, e, ports.KeyJobRotate, keyring.PurposeIndex, 0)
		if res.Version != 2 {
			t.Fatalf("index version %d, want 2", res.Version)
		}
		if _, iv := c.Versions(); iv != 2 {
			t.Fatalf("the codec's index version is %d, want 2", iv)
		}
		if cur, _ := c.BlindIndex("users", "email", "user0@example.org"); string(cur) == string(old) {
			t.Fatal("the blind index did not change with the key")
		}
		for i, id := range users {
			got, err := s.Users().FindLocalByUniqueEmail(ctx, strings.ToUpper(fmt.Sprintf("user%d@example.org", i)))
			if err != nil || got.ID != id {
				t.Fatalf("lookup of user %d by email after the rotation: %+v, %v", i, got, err)
			}
			if got, err := s.Users().FindLocalByUsername(ctx, fmt.Sprintf("user%d", i)); err != nil || got.ID != id {
				t.Fatalf("lookup of user %d by name: %+v, %v", i, got, err)
			}
		}
		for i, id := range shares {
			if sh, err := s.Shares().ByLongID(ctx, fmt.Sprintf("long-rot-%d", i)); err != nil || sh.ID != id {
				t.Fatalf("share %d by long id: %+v, %v", i, sh, err)
			}
		}
		// Uniqueness holds under the new key, and a new account is found by it.
		if _, err := s.Users().Create(ctx, newUser("dup", "USER1@example.org")); !errors.Is(err, ports.ErrDuplicate) {
			t.Fatalf("a duplicate email after the rotation: %v, want ErrDuplicate", err)
		}
		nu := mustCreate(t, s.Users(), newUser("fresh", "fresh@example.org"))
		if got, err := s.Users().FindLocalByUniqueEmail(ctx, "fresh@example.org"); err != nil || got.ID != nu {
			t.Fatalf("lookup of a new account: %+v, %v", got, err)
		}
		// The old version is decrypt-only and can be retired (no data uses it).
		res = run(t, e, ports.KeyJobRetire, keyring.PurposeIndex, 1)
		if st, err := svc.Verify(ctx, tenant); err != nil || st.States[keyring.PurposeIndex][1] != keyring.StateRetired {
			t.Fatalf("index states: %+v, %v", st.States, err)
		}
		// A second codec (another replica) follows the rotation by refreshing.
		other, err := keyring.NewCodec(ctx, svc, tenant)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		if _, iv := other.Versions(); iv != 2 {
			t.Fatalf("a codec opened after the rotation uses index version %d", iv)
		}
	})

	t.Run("StaleCodecFollows", func(t *testing.T) {
		s, e, svc := setup(t)
		users, _ := populate(t, s, 2)
		// Another process rotates; this codec still seals with version 1 until it
		// meets a value of the newer version or is refreshed.
		stale, err := keyring.NewCodec(ctx, svc, tenant)
		if err != nil {
			t.Fatal(err)
		}
		defer stale.Close()
		if _, err := svc.Rotate(ctx, tenant, keyring.PurposeData, "other"); err != nil {
			t.Fatal(err)
		}
		if d, _ := stale.Versions(); d != 1 {
			t.Fatalf("stale codec on %d", d)
		}
		fresh, _ := keyring.NewCodec(ctx, svc, tenant)
		defer fresh.Close()
		sealed, err := fresh.Seal("users", "name", strconv.FormatInt(users[0], 10), "someone")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := stale.Open("users", "name", strconv.FormatInt(users[0], 10), sealed); err != nil || got != "someone" {
			t.Fatalf("a stale codec opening a newer value: %q, %v", got, err)
		}
		if d, _ := stale.Versions(); d != 2 {
			t.Fatalf("the stale codec did not follow (data version %d)", d)
		}
		_ = e
	})

	t.Run("TamperedAndUnknownVersionFailClosed", func(t *testing.T) {
		s, e, _ := setup(t)
		users, _ := populate(t, s, 2)
		run(t, e, ports.KeyJobRotate, keyring.PurposeData, 0)
		id := strconv.FormatInt(users[0], 10)
		stored, err := s.rawGet(ctx, "users", "name", id)
		if err != nil {
			t.Fatal(err)
		}
		ct, _ := colenc.DecodeText(stored)
		// Claim a version the keyring has never had.
		forged := append([]byte(nil), ct...)
		forged[4] = 99
		if err := s.rawSet(ctx, "users", "name", id, colenc.EncodeText(forged)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Users().ByID(ctx, users[0]); err == nil {
			t.Fatal("a value of an unknown key version opened")
		}
		// Claim the other existing version: the key does not match.
		forged[4] = 1
		if err := s.rawSet(ctx, "users", "name", id, colenc.EncodeText(forged)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Users().ByID(ctx, users[0]); err == nil {
			t.Fatal("a value relabelled to another key version opened")
		}
		// The re-encryption job stops on a value it cannot open instead of
		// rewriting it.
		if _, _, err := e.ResealAll(ctx, 2); err == nil {
			t.Fatal("the re-encryption job went on over a tampered value")
		}
	})
}
