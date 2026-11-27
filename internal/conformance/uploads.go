// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// mustUpload creates an upload session with files of the given sizes.
func mustUpload(t *testing.T, s ports.Repositories, u ports.NewUpload, sizes ...int64) {
	t.Helper()
	ctx := context.Background()
	if err := s.Uploads().Create(ctx, u); err != nil {
		t.Fatalf("create upload %s: %v", u.ID, err)
	}
	for i, size := range sizes {
		name := "f" + itoa(int64(i))
		if err := s.Uploads().AddFile(ctx, ports.NewUploadFile{SessionID: u.ID, Index: i, Name: name, FullPath: "dir/" + name, Size: size, Type: "text/plain"}); err != nil {
			t.Fatalf("add upload file: %v", err)
		}
	}
}

// RunUploads pins the contract of ports.UploadRepository.
func RunUploads(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()

	t.Run("Empty", func(t *testing.T) {
		s := open(t)
		up := s.Uploads()
		if _, err := up.Uploader(ctx, "nope"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Uploader of an unknown session: %v", err)
		}
		if _, err := up.AppendTarget(ctx, "nope"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("AppendTarget of an unknown session: %v", err)
		}
		if _, _, err := up.Reservation(ctx, "nope", 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Reservation of an unknown session: %v", err)
		}
		if _, _, err := up.FileState(ctx, "nope", 0); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("FileState of an unknown session: %v", err)
		}
		if _, err := up.ReceivedOfUploader(ctx, "nope", 0, 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ReceivedOfUploader of an unknown session: %v", err)
		}
		if p, err := up.Progress(ctx, "nope"); err != nil || len(p) != 0 {
			t.Fatalf("Progress = %v, %v", p, err)
		}
		if f, err := up.Files(ctx, "nope"); err != nil || len(f) != 0 {
			t.Fatalf("Files = %v, %v", f, err)
		}
		if n, err := up.Delete(ctx, "nope"); err != nil || n != 0 {
			t.Fatalf("Delete of an unknown session = %d, %v", n, err)
		}
		if n, err := up.CountByUploader(ctx, 1); err != nil || n != 0 {
			t.Fatalf("CountByUploader = %d, %v", n, err)
		}
	})

	t.Run("Lifecycle", func(t *testing.T) {
		s := open(t)
		up := s.Uploads()
		owner := mustCreate(t, s.Users(), newUser("hana", "hana@example.org"))
		other := mustCreate(t, s.Users(), newUser("ivo", "ivo@example.org"))
		share := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "u-share", ExpiresAt: time.Unix(1_800_000_000, 0)})
		mustUpload(t, s, ports.NewUpload{ID: "aaaa", UserID: owner, QuotaOwnerID: owner}, 10, 0, 7)
		mustUpload(t, s, ports.NewUpload{ID: "bbbb", UserID: owner, QuotaOwnerID: owner, ShareID: &share}, 3)
		if err := up.Create(ctx, ports.NewUpload{ID: "aaaa", UserID: owner, QuotaOwnerID: owner}); err == nil {
			t.Fatal("a taken session id was accepted")
		}
		if err := up.AddFile(ctx, ports.NewUploadFile{SessionID: "aaaa", Index: 0, Name: "x", FullPath: "x"}); err == nil {
			t.Fatal("a taken file index was accepted")
		}
		if uid, err := up.Uploader(ctx, "aaaa"); err != nil || uid != owner {
			t.Fatalf("Uploader = %d, %v", uid, err)
		}
		if n, _ := up.CountByUploader(ctx, owner); n != 2 {
			t.Fatalf("CountByUploader = %d", n)
		}
		if tgt, err := up.AppendTarget(ctx, "aaaa"); err != nil || tgt != nil {
			t.Fatalf("AppendTarget(new share) = %v, %v", tgt, err)
		}
		if tgt, err := up.AppendTarget(ctx, "bbbb"); err != nil || tgt == nil || *tgt != share {
			t.Fatalf("AppendTarget(append) = %v, %v", tgt, err)
		}
		if q, inv, err := up.Reservation(ctx, "aaaa", owner); err != nil || q != owner || inv != nil {
			t.Fatalf("Reservation = %d, %v, %v", q, inv, err)
		}
		if _, _, err := up.Reservation(ctx, "aaaa", other); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Reservation of another uploader: %v", err)
		}
		files, err := up.Files(ctx, "aaaa")
		if err != nil || len(files) != 3 || files[0].Index != 0 || files[2].Index != 2 || files[0].Size != 10 || files[0].FullPath != "dir/f0" ||
			files[0].Name != "f0" || files[0].Type != "text/plain" || files[0].Received != 0 {
			t.Fatalf("Files = %+v, %v", files, err)
		}
		if err := up.SetReceived(ctx, "aaaa", 0, 4); err != nil {
			t.Fatal(err)
		}
		if size, rec, err := up.FileState(ctx, "aaaa", 0); err != nil || size != 10 || rec != 4 {
			t.Fatalf("FileState = %d, %d, %v", size, rec, err)
		}
		if _, _, err := up.FileState(ctx, "aaaa", 9); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("FileState of an unknown index: %v", err)
		}
		if rec, err := up.ReceivedOfUploader(ctx, "aaaa", 0, owner); err != nil || rec != 4 {
			t.Fatalf("ReceivedOfUploader = %d, %v", rec, err)
		}
		if _, err := up.ReceivedOfUploader(ctx, "aaaa", 0, other); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ReceivedOfUploader of another account: %v", err)
		}
		p, err := up.Progress(ctx, "aaaa")
		if err != nil || len(p) != 3 || p[0] != (ports.UploadProgress{Index: 0, Size: 10, Received: 4}) || p[2] != (ports.UploadProgress{Index: 2, Size: 7}) {
			t.Fatalf("Progress = %+v, %v", p, err)
		}
		ids, err := up.IDsOfUploaderOrQuotaOwner(ctx, owner)
		sort.Strings(ids)
		if err != nil || len(ids) != 2 || ids[0] != "aaaa" || ids[1] != "bbbb" {
			t.Fatalf("IDsOfUploaderOrQuotaOwner = %v, %v", ids, err)
		}
		if ids, _ := up.IDsOfUploaderOrQuotaOwner(ctx, other); len(ids) != 0 {
			t.Fatalf("IDsOfUploaderOrQuotaOwner(other) = %v", ids)
		}

		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := tx.Uploads().LockForCompletion(ctx, "aaaa", owner, owner, true); err != nil || n != 0 {
			t.Fatalf("LockForCompletion with a wrong guest flag = %d, %v", n, err)
		}
		if n, _ := tx.Uploads().LockForCompletion(ctx, "aaaa", owner, other, false); n != 0 {
			t.Fatal("LockForCompletion with another quota owner matched")
		}
		if n, err := tx.Uploads().LockForCompletion(ctx, "aaaa", owner, owner, false); err != nil || n != 1 {
			t.Fatalf("LockForCompletion = %d, %v", n, err)
		}
		if n, _ := tx.Uploads().LockForAppend(ctx, "aaaa", owner, owner, share); n != 0 {
			t.Fatal("LockForAppend matched a session that creates a new share")
		}
		if n, err := tx.Uploads().LockForAppend(ctx, "bbbb", owner, owner, share); err != nil || n != 1 {
			t.Fatalf("LockForAppend = %d, %v", n, err)
		}
		if n, err := tx.Uploads().Delete(ctx, "aaaa"); err != nil || n != 1 {
			t.Fatalf("Delete = %d, %v", n, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if f, _ := up.Files(ctx, "aaaa"); len(f) != 0 {
			t.Fatal("Delete kept the declared files")
		}
		if _, err := up.Uploader(ctx, "aaaa"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("deleted session still readable")
		}
	})

	t.Run("ConcurrentCreate", func(t *testing.T) {
		s := open(t)
		owner := mustCreate(t, s.Users(), newUser("jo", "jo@example.org"))
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- s.Uploads().Create(ctx, ports.NewUpload{ID: "same", UserID: owner, QuotaOwnerID: owner})
			}()
		}
		wg.Wait()
		close(errs)
		ok := 0
		for err := range errs {
			if err == nil {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("%d concurrent creates of one session id succeeded, want 1", ok)
		}
	})
}

// RunUploadAdmission pins the reservation-related methods of the invite,
// share, account and quota repositories.
func RunUploadAdmission(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()

	t.Run("Invites", func(t *testing.T) {
		s := open(t)
		ri := s.ReverseInvites()
		owner := mustCreate(t, s.Users(), newUser("kit", "kit@example.org"))
		g := mustGuest(t, s, "guest-k")
		if n, err := ri.CountForGuest(ctx, g); err != nil || n != 0 {
			t.Fatalf("CountForGuest = %d, %v", n, err)
		}
		if _, _, err := ri.OpenForGuest(ctx, g, now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("OpenForGuest without invite: %v", err)
		}
		if _, _, err := ri.UploadSlot(ctx, 999); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("UploadSlot of an unknown invite: %v", err)
		}
		single := mustInvite(t, s, ports.NewInvite{Token: "s", UserID: owner, ExpiresAt: now.Add(time.Hour)})
		if err := ri.AssignGuest(ctx, single, g); err != nil {
			t.Fatal(err)
		}
		if n, _ := ri.CountForGuest(ctx, g); n != 1 {
			t.Fatalf("CountForGuest = %d", n)
		}
		if iid, o, err := ri.OpenForGuest(ctx, g, now); err != nil || iid != single || o != owner {
			t.Fatalf("OpenForGuest = %d, %d, %v", iid, o, err)
		}
		if _, _, err := ri.OpenForGuest(ctx, g, now.Add(time.Hour)); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("OpenForGuest returned an invite expiring exactly at now")
		}
		if p, m, err := ri.UploadSlot(ctx, single); err != nil || p != nil || m != 1 {
			t.Fatalf("UploadSlot(single) = %v, %d, %v", p, m, err)
		}
		if n, err := ri.CountValidForCompletion(ctx, single, g, owner, now); err != nil || n != 1 {
			t.Fatalf("CountValidForCompletion = %d, %v", n, err)
		}
		if n, _ := ri.CountValidForCompletion(ctx, single, g, owner+100, now); n != 0 {
			t.Fatal("CountValidForCompletion with another owner")
		}
		if n, err := ri.Complete(ctx, single, now, now.Add(2*time.Hour)); err != nil || n != 0 {
			t.Fatalf("Complete of an expired invite = %d, %v", n, err)
		}
		if n, err := ri.Complete(ctx, single, now, now); err != nil || n != 1 {
			t.Fatalf("Complete = %d, %v", n, err)
		}
		if n, _ := ri.Complete(ctx, single, now, now); n != 0 {
			t.Fatal("Complete completed an invite twice")
		}
		if n, _ := ri.CountValidForCompletion(ctx, single, g, owner, now); n != 0 {
			t.Fatal("a completed invite is still valid for completion")
		}
		if _, _, err := ri.OpenForGuest(ctx, g, now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("OpenForGuest returned a completed invite")
		}
		if got, _ := ri.ForAccept(ctx, "s"); got.CompletedAt == nil || !got.CompletedAt.Equal(now) {
			t.Fatalf("CompletedAt after Complete = %v", got.CompletedAt)
		}

		// Open link with three children: completed, uploading, idle.
		wall := time.Now()
		parent := mustInvite(t, s, ports.NewInvite{Token: "p", UserID: owner, ExpiresAt: wall.Add(48 * time.Hour), Reusable: true, MaxUploads: 4})
		var kids []int64
		for i, tok := range []string{"k0", "k1", "k2"} {
			gid := mustGuest(t, s, "guest-"+tok)
			if err := ri.CreateChild(ctx, ports.NewChildInvite{Token: tok, UserID: owner, GuestUserID: gid, ExpiresAt: wall.Add(24 * time.Hour), ParentID: parent}); err != nil {
				t.Fatal(err)
			}
			iid, _, err := ri.OpenForGuest(ctx, gid, wall)
			if err != nil {
				t.Fatal(err)
			}
			kids = append(kids, iid)
			switch i {
			case 0:
				ri.Complete(ctx, iid, wall, wall)
			case 1:
				mustUpload(t, s, ports.NewUpload{ID: "up-k1", UserID: gid, InviteID: &iid, QuotaOwnerID: owner}, 5)
			}
		}
		if p, m, err := ri.UploadSlot(ctx, kids[2]); err != nil || p == nil || *p != parent || m != 4 {
			t.Fatalf("UploadSlot(child) = %v, %d, %v", p, m, err)
		}
		if n, err := ri.CountUsedSiblings(ctx, parent, kids[2]); err != nil || n != 2 {
			t.Fatalf("CountUsedSiblings = %d, %v", n, err)
		}
		if n, _ := ri.CountUsedSiblings(ctx, parent, kids[1]); n != 1 {
			t.Fatalf("CountUsedSiblings excluding the uploading child = %d", n)
		}
		// An older child with an upload in progress still holds a slot.
		if n, _ := ri.CountTakenSlots(ctx, parent, wall, wall.Add(time.Hour)); n != 2 {
			t.Fatalf("CountTakenSlots (no recent accepts) = %d, want completed + uploading", n)
		}
		if n, _ := ri.CountTakenSlots(ctx, parent, wall, wall.Add(-time.Hour)); n != 3 {
			t.Fatalf("CountTakenSlots (recent accepts) = %d", n)
		}
	})

	t.Run("SharesAndAccounts", func(t *testing.T) {
		s := open(t)
		owner := mustCreate(t, s.Users(), newUser("lee", "lee@example.org"))
		other := mustCreate(t, s.Users(), newUser("max", "max@example.org"))
		g := mustGuest(t, s, "guest-l")
		sh := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "a-share", ExpiresAt: now})
		if lid, st, err := s.Shares().OwnedLongIDAndStatus(ctx, sh, owner); err != nil || lid != "a-share" || st != "active" {
			t.Fatalf("OwnedLongIDAndStatus = %q, %q, %v", lid, st, err)
		}
		if _, _, err := s.Shares().OwnedLongIDAndStatus(ctx, sh, other); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("OwnedLongIDAndStatus of another account: %v", err)
		}
		if n, err := s.Shares().FilesTotalSize(ctx, sh); err != nil || n != 0 {
			t.Fatalf("FilesTotalSize without files = %d, %v", n, err)
		}
		mustFile(t, s, localFile(sh, "a", 5))
		mustFile(t, s, localFile(sh, "b", 6))
		if n, _ := s.Shares().FilesTotalSize(ctx, sh); n != 11 {
			t.Fatalf("FilesTotalSize = %d", n)
		}
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		for _, c := range []struct {
			id    int64
			guest bool
			want  int64
		}{{owner, false, 1}, {owner, true, 0}, {g, true, 1}, {g, false, 0}, {owner + 100, false, 0}} {
			if n, err := tx.Users().LockForUpload(ctx, c.id, c.guest); err != nil || n != c.want {
				t.Fatalf("LockForUpload(%d, %v) = %d, %v", c.id, c.guest, n, err)
			}
		}
	})

	t.Run("TenantTotals", func(t *testing.T) {
		s := open(t)
		q := s.Quota()
		if _, err := q.StorageBackendSetting(ctx); err != nil && !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("StorageBackendSetting: %v", err)
		}
		// A single-tenant database keeps no limits: an error or no limit.
		if limit, err := q.TenantStorageLimit(ctx); err == nil && limit > 0 {
			t.Fatalf("TenantStorageLimit on a fresh database = %d", limit)
		}
		if n, err := q.TotalStoredBytes(ctx); err != nil || n != 0 {
			t.Fatalf("TotalStoredBytes = %d, %v", n, err)
		}
		if n, err := q.TotalReservedBytes(ctx); err != nil || n != 0 {
			t.Fatalf("TotalReservedBytes = %d, %v", n, err)
		}
		a := mustCreate(t, s.Users(), newUser("ned", "ned@example.org"))
		b := mustCreate(t, s.Users(), newUser("ola", "ola@example.org"))
		mustFile(t, s, localFile(mustShare(t, s, ports.NewShare{UserID: a, LongID: "t1", ExpiresAt: now}), "x", 100))
		mustFile(t, s, localFile(mustShare(t, s, ports.NewShare{UserID: b, LongID: "t2", ExpiresAt: now}), "y", 20))
		mustUpload(t, s, ports.NewUpload{ID: "t-a", UserID: a, QuotaOwnerID: a}, 3, 4)
		mustUpload(t, s, ports.NewUpload{ID: "t-b", UserID: b, QuotaOwnerID: b}, 5)
		if n, _ := q.TotalStoredBytes(ctx); n != 120 {
			t.Fatalf("TotalStoredBytes = %d", n)
		}
		if n, _ := q.TotalReservedBytes(ctx); n != 12 {
			t.Fatalf("TotalReservedBytes = %d", n)
		}
	})
}
