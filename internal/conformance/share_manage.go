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

// RunShareManagement pins the read, owner-management and removal methods of
// ports.ShareRepository and the download start methods.
func RunShareManagement(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()

	t.Run("Read", func(t *testing.T) {
		s := open(t)
		sr := s.Shares()
		owner := mustCreate(t, s.Users(), newUser("pia", "pia@example.org"))
		other := mustCreate(t, s.Users(), newUser("rob", "rob@example.org"))
		if _, err := sr.ByID(ctx, 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ByID of an unknown share: %v", err)
		}
		if _, err := sr.ByLongID(ctx, "nope"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ByLongID of an unknown share: %v", err)
		}
		limit := int64(9)
		a := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "r-a", Name: "A", Description: "d", PasswordHash: "ph", DownloadLimit: &limit, ExpiresAt: now})
		mustFile(t, s, localFile(a, "b/z.txt", 4))
		mustFile(t, s, localFile(a, "a.txt", 6))
		mustFile(t, s, localFile(a, "a.txt", 1)) // same path: id breaks the tie
		got, err := sr.ByID(ctx, a)
		if err != nil || got.LongID != "r-a" || got.Name != "A" || got.Description != "d" || got.Owner != "pia" || got.PasswordHash != "ph" ||
			got.Status != "active" || got.DownloadLimit == nil || *got.DownloadLimit != 9 || got.DownloadCount != 0 || got.ExpiresAt == nil ||
			!got.ExpiresAt.Equal(now) || got.UserID == nil || *got.UserID != owner || got.Size != 11 || got.FileCount != 3 || got.CreatedAt.IsZero() {
			t.Fatalf("ByID = %+v, %v", got, err)
		}
		if byLong, err := sr.ByLongID(ctx, "r-a"); err != nil || byLong.ID != a {
			t.Fatalf("ByLongID = %+v, %v", byLong, err)
		}
		b := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "r-b", ExpiresAt: now})
		mustShare(t, s, ports.NewShare{UserID: other, LongID: "r-c", ExpiresAt: now})
		if got, _ := sr.ByID(ctx, b); got.DownloadLimit != nil || got.Size != 0 || got.FileCount != 0 || got.PasswordHash != "" {
			t.Fatalf("share without limit or files = %+v", got)
		}
		list, err := sr.ListOwned(ctx, owner)
		if err != nil || len(list) != 2 {
			t.Fatalf("ListOwned = %+v, %v", list, err)
		}
		files, err := sr.Files(ctx, a)
		if err != nil || len(files) != 3 || files[0].FullPath != "a.txt" || files[1].FullPath != "a.txt" || files[0].ID > files[1].ID ||
			files[2].FullPath != "b/z.txt" || files[0].LongID != "r-a" || files[0].Size != 6 || !files[0].Encrypted || files[0].Type != "text/plain" {
			t.Fatalf("Files = %+v, %v", files, err)
		}
		if f, err := sr.Files(ctx, b); err != nil || len(f) != 0 {
			t.Fatalf("Files without files = %v, %v", f, err)
		}
		summaries, err := sr.ListFiles(ctx, a)
		if err != nil || len(summaries) != 3 || summaries[0].ID != files[0].ID || summaries[2].Name != "b/z.txt" || summaries[2].Size != 4 {
			t.Fatalf("ListFiles = %+v, %v", summaries, err)
		}
		paths, err := sr.FilePathsAndSizes(ctx, a)
		sort.Slice(paths, func(i, j int) bool { return paths[i].Size < paths[j].Size })
		if err != nil || len(paths) != 3 || paths[0].Size != 1 || paths[2].FullPath != "a.txt" || paths[2].Size != 6 {
			t.Fatalf("FilePathsAndSizes = %+v, %v", paths, err)
		}
		disk, lid, loc, err := sr.FileLocation(ctx, files[2].ID, a)
		if err != nil || disk != "0_b/z.txt" || lid != "r-a" || loc != 0 {
			t.Fatalf("FileLocation = %q, %q, %d, %v", disk, lid, loc, err)
		}
		if _, _, _, err := sr.FileLocation(ctx, files[2].ID, b); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("FileLocation in another share: %v", err)
		}
		if n, err := sr.CountFiles(ctx, a); err != nil || n != 3 {
			t.Fatalf("CountFiles = %d, %v", n, err)
		}
		if err := sr.DeleteFile(ctx, files[2].ID, b); err != nil {
			t.Fatal(err)
		}
		if n, _ := sr.CountFiles(ctx, a); n != 3 {
			t.Fatal("DeleteFile removed a file of another share")
		}
		if err := sr.DeleteFile(ctx, files[2].ID, a); err != nil {
			t.Fatal(err)
		}
		if n, _ := sr.CountFiles(ctx, a); n != 2 {
			t.Fatal("DeleteFile kept the file")
		}
		if lid, err := sr.OwnedActiveLongID(ctx, a, owner); err != nil || lid != "r-a" {
			t.Fatalf("OwnedActiveLongID = %q, %v", lid, err)
		}
		if _, err := sr.OwnedActiveLongID(ctx, a, other); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("OwnedActiveLongID of another account: %v", err)
		}
		if em, lang, err := s.Users().EmailAndLanguage(ctx, owner); err != nil || em != "pia@example.org" || lang != "en" {
			t.Fatalf("EmailAndLanguage = %q, %q, %v", em, lang, err)
		}
		if _, _, err := s.Users().EmailAndLanguage(ctx, other+100); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("EmailAndLanguage of an unknown account: %v", err)
		}
	})

	t.Run("OwnerChanges", func(t *testing.T) {
		s := open(t)
		sr := s.Shares()
		owner := mustCreate(t, s.Users(), newUser("sol", "sol@example.org"))
		other := mustCreate(t, s.Users(), newUser("tia", "tia@example.org"))
		id := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "o-a", Name: "old", PasswordHash: "h1", ExpiresAt: now.Add(time.Hour)})
		if n, err := sr.ReplacePasswordHash(ctx, id, "h2", "wrong"); err != nil || n != 0 {
			t.Fatalf("ReplacePasswordHash with a stale hash = %d, %v", n, err)
		}
		if n, err := sr.ReplacePasswordHash(ctx, id, "h2", "h1"); err != nil || n != 1 {
			t.Fatalf("ReplacePasswordHash = %d, %v", n, err)
		}
		if err := sr.Expire(ctx, id, now); err != nil {
			t.Fatal(err)
		}
		if got, _ := sr.ByID(ctx, id); got.Status != "expired" || !got.ExpiresAt.Equal(now) {
			t.Fatalf("after Expire: %+v", got)
		}
		if err := sr.Extend(ctx, id, now.Add(48*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if got, _ := sr.ByID(ctx, id); got.Status != "active" || !got.ExpiresAt.Equal(now.Add(48*time.Hour)) {
			t.Fatalf("after Extend: %+v", got)
		}
		if n, err := sr.SetExpiry(ctx, id, other, nil); err != nil || n != 0 {
			t.Fatalf("SetExpiry by another account = %d, %v", n, err)
		}
		if n, err := sr.SetExpiry(ctx, id, owner, nil); err != nil || n != 1 {
			t.Fatalf("SetExpiry(never) = %d, %v", n, err)
		}
		if got, _ := sr.ByID(ctx, id); got.ExpiresAt != nil {
			t.Fatalf("SetExpiry(never) kept %v", got.ExpiresAt)
		}
		at := now.Add(5 * time.Hour)
		if n, _ := sr.SetExpiry(ctx, id, owner, &at); n != 1 {
			t.Fatal("SetExpiry(time) changed nothing")
		}
		if got, _ := sr.ByID(ctx, id); got.ExpiresAt == nil || !got.ExpiresAt.Equal(at) {
			t.Fatalf("SetExpiry(time) stored %v", got.ExpiresAt)
		}

		name, desc, hash := "new", "text", ""
		if n, err := sr.Edit(ctx, id, other, ports.ShareEdit{Name: &name}); err != nil || n != 0 {
			t.Fatalf("Edit by another account = %d, %v", n, err)
		}
		if n, err := sr.Edit(ctx, id, owner, ports.ShareEdit{Name: &name, Description: &desc, PasswordHash: &hash}); err != nil || n != 1 {
			t.Fatalf("Edit = %d, %v", n, err)
		}
		if got, _ := sr.ByID(ctx, id); got.Name != "new" || got.Description != "text" || got.PasswordHash != "" {
			t.Fatalf("after Edit: %+v", got)
		}
		if !(ports.ShareEdit{}).Empty() || (ports.ShareEdit{SetDownloadLimit: true}).Empty() {
			t.Fatal("ShareEdit.Empty")
		}
	})

	t.Run("DownloadLimits", func(t *testing.T) {
		s := open(t)
		sr := s.Shares()
		owner := mustCreate(t, s.Users(), newUser("uma", "uma@example.org"))
		wall := time.Now()
		two := int64(2)
		id := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "d-a", DownloadLimit: &two, ExpiresAt: wall.Add(time.Hour)})
		for want := int64(1); want <= 2; want++ {
			if n, err := sr.CountDownload(ctx, id, wall); err != nil || n != want {
				t.Fatalf("CountDownload = %d, %v; want %d", n, err, want)
			}
		}
		if _, err := sr.CountDownload(ctx, id, wall); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("CountDownload past the limit: %v", err)
		}
		// Maintenance expires a used-up share without moving its expiry.
		sr.Expire(ctx, id, wall.Add(time.Hour))
		if err := sr.SetDownloadLimit(ctx, id, &two, wall); err != nil {
			t.Fatal(err)
		}
		if got, _ := sr.ByID(ctx, id); got.Status != "expired" {
			t.Fatal("SetDownloadLimit revived a share whose new limit is still used up")
		}
		five := int64(5)
		if err := sr.SetDownloadLimit(ctx, id, &five, wall); err != nil {
			t.Fatal(err)
		}
		if got, _ := sr.ByID(ctx, id); got.Status != "active" || *got.DownloadLimit != 5 {
			t.Fatalf("SetDownloadLimit did not revive: %+v", got)
		}
		if n, _ := sr.CountDownload(ctx, id, wall); n != 3 {
			t.Fatal("CountDownload after raising the limit")
		}
		if _, err := sr.CountDownload(ctx, id, wall.Add(2*time.Hour)); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("CountDownload admitted an expired share")
		}
		// Edit with the same rule: back to used up, then no limit.
		sr.Edit(ctx, id, owner, ports.ShareEdit{SetDownloadLimit: true, DownloadLimit: &two, Now: wall})
		sr.Expire(ctx, id, wall.Add(time.Hour))
		if n, err := sr.Edit(ctx, id, owner, ports.ShareEdit{SetDownloadLimit: true, Now: wall}); err != nil || n != 1 {
			t.Fatalf("Edit(no limit) = %d, %v", n, err)
		}
		if got, _ := sr.ByID(ctx, id); got.Status != "active" || got.DownloadLimit != nil {
			t.Fatalf("Edit(no limit) did not revive: %+v", got)
		}
		// A manually expired share is not revived.
		sr.Expire(ctx, id, wall.Add(-time.Minute))
		sr.SetDownloadLimit(ctx, id, &five, wall)
		if got, _ := sr.ByID(ctx, id); got.Status != "expired" {
			t.Fatal("SetDownloadLimit revived a time-expired share")
		}

		// Concurrent downloads never exceed the limit.
		ten := int64(10)
		c := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "d-c", DownloadLimit: &ten, ExpiresAt: wall.Add(time.Hour)})
		var wg sync.WaitGroup
		var mu sync.Mutex
		seen := map[int64]bool{}
		for i := 0; i < 25; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if n, err := sr.CountDownload(ctx, c, wall); err == nil {
					mu.Lock()
					seen[n] = true
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(seen) != 10 || !seen[1] || !seen[10] {
			t.Fatalf("concurrent CountDownload admitted %d distinct counts", len(seen))
		}
	})

	t.Run("Removal", func(t *testing.T) {
		s := open(t)
		owner := mustCreate(t, s.Users(), newUser("vic", "vic@example.org"))
		other := mustCreate(t, s.Users(), newUser("wes", "wes@example.org"))
		active := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "x-active", ExpiresAt: now.Add(time.Hour)})
		lapsed := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "x-lapsed", ExpiresAt: now.Add(-time.Hour)})
		expired := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "x-expired", ExpiresAt: now.Add(time.Hour)})
		s.Shares().Expire(ctx, expired, now.Add(-48*time.Hour))
		foreign := mustShare(t, s, ports.NewShare{UserID: other, LongID: "x-foreign", ExpiresAt: now.Add(-time.Hour)})
		ids, err := s.Shares().PrunableIDs(ctx, owner, now)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		if err != nil || len(ids) != 2 || ids[0] != lapsed || ids[1] != expired {
			t.Fatalf("PrunableIDs = %v, %v", ids, err)
		}
		for _, c := range []struct {
			id   int64
			f    ports.ShareFilter
			want bool
		}{
			{active, ports.ShareFilter{Kind: ports.AnyShare}, true},
			{active, ports.ShareFilter{Kind: ports.SharePrunableByOwner, UserID: owner, At: now}, false},
			{lapsed, ports.ShareFilter{Kind: ports.SharePrunableByOwner, UserID: owner, At: now}, true},
			{foreign, ports.ShareFilter{Kind: ports.SharePrunableByOwner, UserID: owner, At: now}, false},
			{lapsed, ports.ShareFilter{Kind: ports.ShareRetiredBefore, At: now}, false}, // still active
			{expired, ports.ShareFilter{Kind: ports.ShareRetiredBefore, At: now.Add(-24 * time.Hour)}, true},
			{expired, ports.ShareFilter{Kind: ports.ShareRetiredBefore, At: now.Add(-48 * time.Hour)}, false}, // exclusive
		} {
			lid, err := s.Shares().LongIDIf(ctx, c.id, c.f)
			if c.want && (err != nil || lid == "") || !c.want && !errors.Is(err, ports.ErrNotFound) {
				t.Fatalf("LongIDIf(%d, %+v) = %q, %v", c.id, c.f, lid, err)
			}
		}
		mustFile(t, s, localFile(expired, "f", 1))
		mustUpload(t, s, ports.NewUpload{ID: "app-1", UserID: owner, QuotaOwnerID: owner, ShareID: &expired}, 2)
		mustUpload(t, s, ports.NewUpload{ID: "app-2", UserID: owner, QuotaOwnerID: owner, ShareID: &active}, 2)
		if err := s.Downloads().Record(ctx, expired, nil, "", now); err != nil {
			t.Fatal(err)
		}
		if ids, err := s.Uploads().IDsForShare(ctx, expired); err != nil || len(ids) != 1 || ids[0] != "app-1" {
			t.Fatalf("IDsForShare = %v, %v", ids, err)
		}
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := tx.Shares().Lock(ctx, expired); err != nil {
			t.Fatal(err)
		}
		if err := tx.Shares().Lock(ctx, 999); err != nil {
			t.Fatalf("Lock of an unknown share: %v", err)
		}
		if n, err := tx.Shares().LockOwnedForAppend(ctx, active, other); err != nil || n != 0 {
			t.Fatalf("LockOwnedForAppend by another account = %d, %v", n, err)
		}
		if n, err := tx.Shares().LockOwnedForAppend(ctx, active, owner); err != nil || n != 1 {
			t.Fatalf("LockOwnedForAppend = %d, %v", n, err)
		}
		if n, err := tx.Shares().LockOwnedForFileRemoval(ctx, active, owner); err != nil || n != 1 {
			t.Fatalf("LockOwnedForFileRemoval = %d, %v", n, err)
		}
		if n, _ := tx.Shares().LockOwnedForFileRemoval(ctx, active, other); n != 0 {
			t.Fatal("LockOwnedForFileRemoval by another account matched")
		}
		if n, err := tx.Shares().Delete(ctx, expired); err != nil || n != 1 {
			t.Fatalf("Delete = %d, %v", n, err)
		}
		if n, err := tx.Shares().Delete(ctx, expired); err != nil || n != 0 {
			t.Fatalf("Delete again = %d, %v", n, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Uploads().Uploader(ctx, "app-1"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("Delete kept a pending append upload")
		}
		if _, err := s.Uploads().Uploader(ctx, "app-2"); err != nil {
			t.Fatal("Delete removed another share's append upload")
		}
		if n, _ := s.Downloads().Count(ctx, expired); n != 0 {
			t.Fatal("Delete kept the share's downloads")
		}
		if n, _ := s.Quota().TotalStoredBytes(ctx); n != 0 {
			t.Fatal("Delete kept the share's files")
		}
	})

	t.Run("Downloads", func(t *testing.T) {
		s := open(t)
		d := s.Downloads()
		owner := mustCreate(t, s.Users(), newUser("xia", "xia@example.org"))
		a := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "dl-a", ExpiresAt: now})
		b := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "dl-b", ExpiresAt: now})
		f := mustFile(t, s, localFile(a, "named.txt", 1))
		foreign := mustFile(t, s, localFile(b, "other.txt", 1))
		if n, err := d.Count(ctx, a); err != nil || n != 0 {
			t.Fatalf("Count = %d, %v", n, err)
		}
		if l, err := d.List(ctx, a, 10, 0); err != nil || len(l) != 0 {
			t.Fatalf("List = %v, %v", l, err)
		}
		for i, fid := range []*int64{nil, &f, &foreign, &f} {
			if err := d.Record(ctx, a, fid, "192.0.2.1", now.Add(time.Duration(i)*time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
		d.Record(ctx, b, nil, "", now)
		if n, _ := d.Count(ctx, a); n != 4 {
			t.Fatalf("Count = %d", n)
		}
		l, err := d.List(ctx, a, 2, 0)
		if err != nil || len(l) != 2 || l[0].FileID == nil || *l[0].FileID != f || l[0].FileName != "named.txt" || !l[0].CreatedAt.Equal(now.Add(3*time.Minute)) {
			t.Fatalf("List page 1 = %+v, %v", l, err)
		}
		if l[1].FileID == nil || *l[1].FileID != foreign || l[1].FileName != "" {
			t.Fatalf("a file of another share must not be named: %+v", l[1])
		}
		l, _ = d.List(ctx, a, 10, 2)
		if len(l) != 2 || l[1].FileID != nil || l[1].FileName != "" || !l[1].CreatedAt.Equal(now) {
			t.Fatalf("List page 2 = %+v", l)
		}
		if err := d.BlankAddressesUnlessLogged(ctx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("DownloadMails", func(t *testing.T) {
		s := open(t)
		m := s.DownloadMails()
		owner := mustCreate(t, s.Users(), newUser("yan", "yan@example.org"))
		sh := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "m-a", ExpiresAt: now})
		if n, err := m.CountQueued(ctx); err != nil || n != 0 {
			t.Fatalf("CountQueued = %d, %v", n, err)
		}
		j1, err := m.Reserve(ctx, sh, "yan@example.org", "en", `{"ShareName":"A"}`, now)
		if err != nil {
			t.Fatal(err)
		}
		j2, err := m.Reserve(ctx, sh, "yan@example.org", "en", `{}`, now)
		if err != nil || j1 == j2 {
			t.Fatalf("Reserve = %d, %d, %v", j1, j2, err)
		}
		if n, _ := m.CountQueued(ctx); n != 2 {
			t.Fatalf("CountQueued = %d", n)
		}
		if err := m.Activate(ctx, j1, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		// A pending job is not released; a reserved one is.
		if err := m.Release(ctx, j1); err != nil {
			t.Fatal(err)
		}
		if err := m.Release(ctx, j2); err != nil {
			t.Fatal(err)
		}
		if n, _ := m.CountQueued(ctx); n != 1 {
			t.Fatalf("CountQueued after releases = %d, want the pending job", n)
		}
		if err := m.Activate(ctx, j2, now); err != nil {
			t.Fatalf("Activate of a released job: %v", err)
		}
		if err := m.Release(ctx, 999); err != nil {
			t.Fatal(err)
		}
	})
}
