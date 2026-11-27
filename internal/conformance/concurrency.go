// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunConcurrency pins the serialisation the SQLite adapter got for free from
// its single writer and every other adapter must provide explicitly
// (docs/cluster/DESIGN.md 4.1): audit appends, quota admission, first-account
// creation, counters, the tenant user limit and unique addresses, each under
// parallel load.
func RunConcurrency(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	const workers = 16

	t.Run("AuditAppendsSerialise", func(t *testing.T) {
		s := open(t)
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs <- appendAudit(ctx, s, fmt.Sprintf("w%d", i))
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("parallel append: %v", err)
			}
		}
		var recs []ports.AuditRecord
		if err := s.AuditChain().All(ctx, func(r ports.AuditRecord) error { recs = append(recs, r); return nil }); err != nil {
			t.Fatal(err)
		}
		if len(recs) != workers {
			t.Fatalf("%d records after %d parallel appends", len(recs), workers)
		}
		prev := "genesis"
		for i, r := range recs {
			if r.Seq != int64(i+1) || r.PrevHash != prev {
				t.Fatalf("record %d: seq %d prev %q, want seq %d prev %q (chain forked)", i, r.Seq, r.PrevHash, i+1, prev)
			}
			prev = r.Hash
		}
		if n, _ := s.AuditChain().Issued(ctx); n != workers {
			t.Fatalf("Issued = %d, want %d", n, workers)
		}
	})

	t.Run("QuotaAdmission", func(t *testing.T) {
		// Admission checks the reservations of the whole database (as the
		// tenant storage limit does), so serialising on one account's row
		// would not be enough: the write lock of LockForUpload must cover it.
		s := open(t)
		var users []int64
		for i := 0; i < 4; i++ {
			users = append(users, mustCreate(t, s.Users(), newUser(fmt.Sprintf("q%d", i), fmt.Sprintf("q%d@example.org", i))))
		}
		const limit, size = 1000, 100
		var wg sync.WaitGroup
		var mu sync.Mutex
		admitted, failures := 0, []error{}
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				ok, err := admitUpload(ctx, s, users[i%len(users)], fmt.Sprintf("up%02d", i), limit, size)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					failures = append(failures, err)
				} else if ok {
					admitted++
				}
			}(i)
		}
		wg.Wait()
		if len(failures) > 0 {
			t.Fatalf("admission errors: %v", failures)
		}
		total, err := s.Quota().TotalReservedBytes(ctx)
		if err != nil || admitted != limit/size || total != limit {
			t.Fatalf("admitted %d uploads reserving %d bytes (%v); want %d reserving %d", admitted, total, err, limit/size, limit)
		}
	})

	t.Run("FirstAdminOnce", func(t *testing.T) {
		s := open(t)
		var wg sync.WaitGroup
		var mu sync.Mutex
		created := 0
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, ok, err := s.Users().CreateFirstAdmin(ctx, newUser(fmt.Sprintf("first%d", i), fmt.Sprintf("first%d@example.org", i)))
				if err == nil && ok {
					mu.Lock()
					created++
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()
		if n, _ := s.Users().Count(ctx); created != 1 || n != 1 {
			t.Fatalf("parallel CreateFirstAdmin: %d created, %d stored (want one)", created, n)
		}
	})

	t.Run("Counters", func(t *testing.T) {
		s := open(t)
		id := mustCreate(t, s.Users(), newUser("cnt", "cnt@example.org"))
		now := time.Unix(1_800_000_000, 0).UTC()
		var wg sync.WaitGroup
		var mu sync.Mutex
		seen := map[int]bool{}
		for i := 0; i < workers; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				n, err := s.EmailVerifications().RecordAttempt(ctx, id, now.Add(time.Hour), now)
				if err == nil {
					mu.Lock()
					seen[n] = true
					mu.Unlock()
				}
			}()
			go func() {
				defer wg.Done()
				s.Users().BumpMFAEpoch(ctx, id)
			}()
		}
		wg.Wait()
		if len(seen) != workers || !seen[1] || !seen[workers] {
			t.Fatalf("parallel RecordAttempt returned %d distinct counts, want 1..%d", len(seen), workers)
		}
		if u := mustUser(t, s.Users(), id); u.MFAEpoch != workers {
			t.Fatalf("MFAEpoch after %d parallel bumps = %d", workers, u.MFAEpoch)
		}
	})

	t.Run("TenantUserLimit", func(t *testing.T) {
		s := open(t)
		if err := s.TenantLimits().Enable(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.TenantLimits().Set(ctx, 5, 0); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok, refused := 0, 0
		var other []error
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := s.Users().Create(ctx, newUser(fmt.Sprintf("lim%d", i), fmt.Sprintf("lim%d@example.org", i)))
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ports.ErrTenantUserLimit):
					refused++
				default:
					other = append(other, err)
				}
			}(i)
		}
		wg.Wait()
		if ok != 5 || refused != workers-5 || len(other) > 0 {
			t.Fatalf("parallel creates under a limit of 5: %d stored, %d refused with ErrTenantUserLimit, other errors %v", ok, refused, other)
		}
	})

	t.Run("UniqueAddress", func(t *testing.T) {
		s := open(t)
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok, dup := 0, 0
		var other []error
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				u := newUser(fmt.Sprintf("same%d", i), "Same@Example.org")
				if i%2 == 1 {
					u.Email = " same@example.org"
				}
				_, err := s.Users().CreateRegistered(ctx, u)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ports.ErrDuplicate):
					dup++
				default:
					other = append(other, err)
				}
			}(i)
		}
		wg.Wait()
		if ok != 1 || dup != workers-1 || len(other) > 0 {
			t.Fatalf("parallel registrations with one address: %d stored, %d ErrDuplicate, other errors %v", ok, dup, other)
		}
		mustCreate(t, s.Users(), newUser("taken", ""))
		if _, err := s.Users().Create(ctx, newUser("Taken", "")); !errors.Is(err, ports.ErrDuplicate) {
			t.Fatalf("a taken username: %v, want ErrDuplicate", err)
		}
	})
}

// appendAudit is the core append sequence (internal/store.AuditAppend)
// without the in-process mutex: head, highest issued number, insert, commit.
func appendAudit(ctx context.Context, s ports.Store, actor string) error {
	tx, err := s.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	a := tx.AuditChain()
	seq, hash, err := a.CheckpointHead(ctx)
	if err != nil {
		return err
	}
	if seq == 0 {
		hash = "genesis"
	}
	switch ls, lh, err := a.Last(ctx); {
	case err == nil:
		seq, hash = ls, lh
	case !errors.Is(err, ports.ErrNotFound):
		return err
	}
	issued, err := a.Issued(ctx)
	if err != nil {
		return err
	}
	if issued > seq {
		seq = issued
	}
	rec := auditRec(seq+1, "2027-01-01T00:00:00Z", "auth", "login_ok", actor, "ok")
	rec.PrevHash, rec.Hash = hash, fmt.Sprintf("h%d-%s", seq+1, actor)
	if err := a.Insert(ctx, rec); err != nil {
		return err
	}
	return tx.Commit()
}

// admitUpload is the admission sequence of internal/app's upload start:
// lock, check the database-wide reservations, reserve, commit.
func admitUpload(ctx context.Context, s ports.Store, owner int64, id string, limit, size int64) (bool, error) {
	tx, err := s.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if n, err := tx.Users().LockForUpload(ctx, owner, false); err != nil || n != 1 {
		return false, fmt.Errorf("LockForUpload = %d, %v", n, err)
	}
	reserved, err := tx.Quota().TotalReservedBytes(ctx)
	if err != nil {
		return false, err
	}
	if reserved+size > limit {
		return false, nil
	}
	if err := tx.Uploads().Create(ctx, ports.NewUpload{ID: id, UserID: owner, QuotaOwnerID: owner}); err != nil {
		return false, err
	}
	if err := tx.Uploads().AddFile(ctx, ports.NewUploadFile{SessionID: id, Index: 0, Name: "f", FullPath: "f", Size: size}); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
