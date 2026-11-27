// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/sendora-app/sendora/internal/ports"
)

func auditRec(seq int64, ts, category, action, actor, outcome string) ports.AuditRecord {
	return ports.AuditRecord{Seq: seq, TS: ts, Category: category, ActorID: seq, ActorName: actor, ActorRole: "admin", Action: action,
		Target: "user#" + itoa(seq), Outcome: outcome, Detail: "d" + itoa(seq), IP: "192.0.2.1", PrevHash: "p" + itoa(seq), Hash: "h" + itoa(seq)}
}

// RunAuditChain pins the contract of ports.AuditChainRepository and
// Store.ReadSnapshot.
func RunAuditChain(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()

	t.Run("EmptyChain", func(t *testing.T) {
		a := open(t).AuditChain()
		if ok, err := a.HasChain(ctx); err != nil || !ok {
			t.Fatalf("HasChain = %v, %v", ok, err)
		}
		if seq, hash, mac, err := a.Checkpoint(ctx); err != nil || seq != 0 || hash != "" || mac != "" {
			t.Fatalf("Checkpoint = %d %q %q %v", seq, hash, mac, err)
		}
		if _, _, err := a.Last(ctx); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Last on empty log: %v", err)
		}
		if n, err := a.Issued(ctx); err != nil || n != 0 {
			t.Fatalf("Issued = %d, %v", n, err)
		}
		if ts, err := a.OldestTS(ctx); err != nil || ts != "" {
			t.Fatalf("OldestTS = %q, %v", ts, err)
		}
		if g, err := a.Guard(ctx); err != nil || g != 0 {
			t.Fatalf("Guard = %d, %v", g, err)
		}
	})

	t.Run("AppendWalkPurge", func(t *testing.T) {
		s := open(t)
		a := s.AuditChain()
		for i := int64(1); i <= 5; i++ {
			if err := a.Insert(ctx, auditRec(i, "2027-01-0"+itoa(i)+"T00:00:00Z", "auth", "login_ok", "ann", "ok")); err != nil {
				t.Fatal(err)
			}
		}
		if g, _ := a.Guard(ctx); g != 0 {
			t.Fatalf("appends at the end moved the guard to %d", g)
		}
		if seq, hash, err := a.Last(ctx); err != nil || seq != 5 || hash != "h5" {
			t.Fatalf("Last = %d %q %v", seq, hash, err)
		}
		if n, err := a.Issued(ctx); err != nil || n != 5 {
			t.Fatalf("Issued = %d, %v", n, err)
		}
		var seen []int64
		n, err := a.Walk(ctx, 1, 4, 0, func(r *ports.AuditRecord) { seen = append(seen, r.Seq) })
		if err != nil || n != 3 || len(seen) != 3 || seen[0] != 2 || seen[2] != 4 {
			t.Fatalf("Walk(1,4) = %d %v %v", n, seen, err)
		}
		seen = nil
		if n, _ := a.Walk(ctx, 0, 0, 2, func(r *ports.AuditRecord) { seen = append(seen, r.Seq) }); n != 2 || seen[1] != 2 {
			t.Fatalf("Walk limit 2 = %d %v", n, seen)
		}
		if seq, _, err := a.LastBefore(ctx, "2027-01-03T00:00:00Z"); err != nil || seq != 2 {
			t.Fatalf("LastBefore = %d, %v (exclusive)", seq, err)
		}
		if _, _, err := a.LastBefore(ctx, "2027-01-01T00:00:00Z"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("LastBefore the first record: %v", err)
		}
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := tx.AuditChain().DeleteThrough(ctx, 2); err != nil || n != 2 {
			t.Fatalf("DeleteThrough = %d, %v", n, err)
		}
		if err := tx.AuditChain().SetCheckpoint(ctx, 2, "h2", "mac"); err != nil {
			t.Fatal(err)
		}
		if ts, _ := tx.AuditChain().OldestTS(ctx); ts != "2027-01-03T00:00:00Z" {
			t.Fatalf("OldestTS after purge = %q", ts)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if g, _ := a.Guard(ctx); g < 1 {
			t.Fatal("a deletion did not move the guard")
		}
		if seq, hash, mac, _ := a.Checkpoint(ctx); seq != 2 || hash != "h2" || mac != "mac" {
			t.Fatalf("Checkpoint after purge = %d %q %q", seq, hash, mac)
		}
		if seq, hash, _ := a.CheckpointHead(ctx); seq != 2 || hash != "h2" {
			t.Fatalf("CheckpointHead = %d %q", seq, hash)
		}
		var all []int64
		if err := a.All(ctx, func(r ports.AuditRecord) error { all = append(all, r.Seq); return nil }); err != nil || len(all) != 3 || all[0] != 3 {
			t.Fatalf("All = %v, %v", all, err)
		}
		stop := errors.New("stop")
		if err := a.All(ctx, func(ports.AuditRecord) error { return stop }); !errors.Is(err, stop) {
			t.Fatalf("All did not return fn's error: %v", err)
		}
		// Removing the tail keeps the issued high-water mark.
		if _, err := a.DeleteThrough(ctx, 5); err != nil {
			t.Fatal(err)
		}
		if n, _ := a.Issued(ctx); n != 5 {
			t.Fatalf("Issued after removing every record = %d, want 5", n)
		}
	})

	t.Run("ClearAndSetIssued", func(t *testing.T) {
		a := open(t).AuditChain()
		if err := a.Insert(ctx, auditRec(1, "2027-01-01T00:00:00Z", "auth", "x", "a", "ok")); err != nil {
			t.Fatal(err)
		}
		if err := a.Clear(ctx); err != nil {
			t.Fatal(err)
		}
		if n, _ := a.Issued(ctx); n != 0 {
			t.Fatalf("Issued after Clear = %d", n)
		}
		if err := a.SetIssued(ctx, 42); err != nil {
			t.Fatal(err)
		}
		if err := a.SetIssued(ctx, 43); err != nil {
			t.Fatal(err)
		}
		if n, _ := a.Issued(ctx); n != 43 {
			t.Fatalf("Issued = %d, want 43", n)
		}
	})

	t.Run("ReadSnapshotIsConsistent", func(t *testing.T) {
		s := open(t)
		if err := s.AuditChain().Insert(ctx, auditRec(1, "2027-01-01T00:00:00Z", "auth", "x", "a", "ok")); err != nil {
			t.Fatal(err)
		}
		err := s.ReadSnapshot(ctx, func(r ports.Repositories) error {
			seq, _, err := r.AuditChain().Last(ctx)
			if err != nil || seq != 1 {
				t.Fatalf("Last in snapshot = %d, %v", seq, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		want := errors.New("fn failed")
		if err := s.ReadSnapshot(ctx, func(ports.Repositories) error { return want }); !errors.Is(err, want) {
			t.Fatalf("ReadSnapshot error = %v", err)
		}
	})
}

// RunAuditQuery pins the contract of ports.AuditQueryRepository.
func RunAuditQuery(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	s := func(t *testing.T) ports.AuditQueryRepository {
		st := open(t)
		for i, r := range []ports.AuditRecord{
			auditRec(1, "2027-01-01T10:00:00Z", "auth", "login_ok", "Alice", "ok"),
			auditRec(2, "2027-01-02T10:00:00Z", "admin", "user_created", "bob", "ok"),
			auditRec(3, "2027-01-03T10:00:00Z", "auth", "login_failed", "alice_2", "denied"),
			auditRec(4, "2027-01-04T10:00:00Z", "share", "share_created", "100%", "ok"),
		} {
			_ = i
			if err := st.AuditChain().Insert(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		return st.AuditQuery()
	}
	seqs := func(recs []ports.AuditRecord) []int64 {
		var out []int64
		for _, r := range recs {
			out = append(out, r.Seq)
		}
		return out
	}
	i64 := func(v int64) *int64 { return &v }

	t.Run("FindOrderAndPaging", func(t *testing.T) {
		q := s(t)
		recs, err := q.Find(ctx, ports.AuditFilter{}, true, 2, 1)
		if err != nil || len(recs) != 2 || recs[0].Seq != 3 || recs[1].Seq != 2 {
			t.Fatalf("newest first, limit 2 offset 1 = %v, %v", seqs(recs), err)
		}
		if recs[0].ActorName != "alice_2" || recs[0].Hash != "h3" || recs[0].IP != "192.0.2.1" {
			t.Fatalf("record fields = %+v", recs[0])
		}
		all, _ := q.Find(ctx, ports.AuditFilter{}, false, 0, 0)
		if got := seqs(all); len(got) != 4 || got[0] != 1 {
			t.Fatalf("oldest first, no limit = %v", got)
		}
		if n, _ := q.MaxSeq(ctx); n != 4 {
			t.Fatalf("MaxSeq = %d", n)
		}
	})

	t.Run("Filters", func(t *testing.T) {
		q := s(t)
		for name, c := range map[string]struct {
			f    ports.AuditFilter
			want int
		}{
			"category":        {ports.AuditFilter{Category: "auth"}, 2},
			"action":          {ports.AuditFilter{Action: "user_created"}, 1},
			"actor substring": {ports.AuditFilter{Actor: "alice"}, 2},
			"actor wildcard":  {ports.AuditFilter{Actor: "_"}, 1}, // literal underscore
			"actor percent":   {ports.AuditFilter{Actor: "%"}, 1},
			"outcome":         {ports.AuditFilter{Outcome: "denied"}, 1},
			"terms all":       {ports.AuditFilter{Terms: []string{"login", "alice"}}, 2},
			"terms none":      {ports.AuditFilter{Terms: []string{"login", "bob"}}, 0},
			"from inclusive":  {ports.AuditFilter{From: "2027-01-03T10:00:00Z"}, 2},
			"to inclusive":    {ports.AuditFilter{To: "2027-01-02T10:00:00Z"}, 2},
			"max seq":         {ports.AuditFilter{MaxSeq: i64(2)}, 2},
			"before seq":      {ports.AuditFilter{BeforeSeq: i64(2)}, 1},
			"after seq":       {ports.AuditFilter{AfterSeq: i64(0)}, 4},
			"max and after":   {ports.AuditFilter{MaxSeq: i64(3), AfterSeq: i64(1)}, 2},
		} {
			recs, err := q.Find(ctx, c.f, true, 0, 0)
			if err != nil || len(recs) != c.want {
				t.Errorf("%s: %v, %v (want %d)", name, seqs(recs), err, c.want)
			}
		}
	})

	t.Run("CountCapped", func(t *testing.T) {
		q := s(t)
		if n, err := q.CountCapped(ctx, ports.AuditFilter{}, 10); err != nil || n != 4 {
			t.Fatalf("CountCapped(10) = %d, %v", n, err)
		}
		if n, _ := q.CountCapped(ctx, ports.AuditFilter{}, 2); n != 3 {
			t.Fatalf("CountCapped(2) = %d, want 3 (limit+1)", n)
		}
		if n, _ := q.CountCapped(ctx, ports.AuditFilter{Category: "share"}, 10); n != 1 {
			t.Fatalf("filtered count = %d", n)
		}
	})
}

// RunSystem pins the contract of ports.SystemRepository and the small
// read methods batch D added to other repositories.
func RunSystem(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	t.Run("Health", func(t *testing.T) {
		sys := open(t).System()
		if ok, err := sys.Ping(ctx); err != nil || !ok {
			t.Fatalf("Ping = %v, %v", ok, err)
		}
		if ro, err := sys.ReadOnly(ctx); err != nil || ro {
			t.Fatalf("ReadOnly = %v, %v", ro, err)
		}
		if err := sys.SetAuditKeyFingerprint(ctx, "fp1"); err != nil {
			t.Fatal(err)
		}
		if err := sys.SetAuditKeyFingerprint(ctx, "fp2"); err != nil {
			t.Fatalf("replacing the fingerprint: %v", err)
		}
		if err := sys.ClassifyJWTSecret(ctx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("AccountReads", func(t *testing.T) {
		s := open(t)
		admin, _, err := s.Users().CreateFirstAdmin(ctx, newUser("root", "root@example.org"))
		if err != nil {
			t.Fatal(err)
		}
		other := mustCreate(t, s.Users(), newUser("Bob", "bob@example.org"))
		if err := s.Users().SetAuditor(ctx, other, true); err != nil {
			t.Fatal(err)
		}
		if a, au, g, err := s.Users().Roles(ctx, admin); err != nil || !a || au || g {
			t.Fatalf("Roles(admin) = %v %v %v %v", a, au, g, err)
		}
		if a, au, _, _ := s.Users().Roles(ctx, other); a || !au {
			t.Fatalf("Roles(auditor) = %v %v", a, au)
		}
		if _, _, _, err := s.Users().Roles(ctx, 999); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Roles of a missing account: %v", err)
		}
		mustGuest(t, s, "guest-x")
		recs, err := s.Users().ListForAccessReview(ctx)
		if err != nil || len(recs) != 2 || recs[0].Username != "Bob" || recs[1].Username != "root" {
			t.Fatalf("ListForAccessReview = %+v, %v (case-insensitive order, no guests)", recs, err)
		}
		if recs[1].Created == nil || recs[1].DisabledAt != nil || recs[1].LastLoginAt != nil {
			t.Fatalf("lifecycle times = %+v", recs[1])
		}
		if l, err := s.AuthProviders().ListLinkNames(ctx); err != nil || len(l) != 0 {
			t.Fatalf("ListLinkNames = %v, %v", l, err)
		}
		if n, err := s.Shares().CountOwnedOrReceived(ctx, admin); err != nil || n != 0 {
			t.Fatalf("CountOwnedOrReceived = %d, %v", n, err)
		}
		mustShare(t, s, ports.NewShare{UserID: admin, LongID: "long-x", Name: "X"})
		if n, _ := s.Shares().CountOwnedOrReceived(ctx, admin); n != 1 {
			t.Fatalf("CountOwnedOrReceived after a share = %d", n)
		}
		if n, err := s.Uploads().CountAll(ctx); err != nil || n != 0 {
			t.Fatalf("CountAll = %d, %v", n, err)
		}
		mustUpload(t, s, ports.NewUpload{ID: "u1", UserID: admin, QuotaOwnerID: admin}, 1)
		if n, _ := s.Uploads().CountAll(ctx); n != 1 {
			t.Fatalf("CountAll after an upload = %d", n)
		}
		if err := s.DownloadMails().ReleaseAllReserved(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
