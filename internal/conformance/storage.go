// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunObjectStorage pins the contract of ports.ObjectStorageRepository.
func RunObjectStorage(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("Locations", func(t *testing.T) {
		os := open(t).ObjectStorage()
		id, err := os.EnsureLocation(ctx, "s3", "s3://bucket-a", `{"v":1}`)
		if err != nil || id == 0 {
			t.Fatalf("EnsureLocation = %d, %v", id, err)
		}
		again, err := os.EnsureLocation(ctx, "s3", "s3://bucket-a", `{"v":2}`)
		if err != nil || again != id {
			t.Fatalf("EnsureLocation of a known identity = %d, %v (want %d)", again, err, id)
		}
		if js, err := os.LocationConfig(ctx, id); err != nil || js != `{"v":2}` {
			t.Fatalf("LocationConfig = %q, %v (configuration must be replaced)", js, err)
		}
		if other, _ := os.EnsureLocation(ctx, "s3", "s3://bucket-b", `{}`); other == id {
			t.Fatal("two identities share a location id")
		}
		if _, err := os.LocationConfig(ctx, 9999); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("LocationConfig of an unknown id: %v", err)
		}
	})

	t.Run("PendingDeletes", func(t *testing.T) {
		os := open(t).ObjectStorage()
		if n, err := os.CountPendingDeletes(ctx); err != nil || n != 0 {
			t.Fatalf("CountPendingDeletes = %d, %v", n, err)
		}
		for i, nb := range []time.Time{now.Add(-time.Minute), now.Add(-time.Second), now.Add(time.Hour)} {
			if err := os.QueueDelete(ctx, 1, "obj"+itoa(int64(i)), nb); err != nil {
				t.Fatal(err)
			}
		}
		due, err := os.DuePendingDeletes(ctx, now, 10)
		if err != nil || len(due) != 2 || due[0].ObjectKey != "obj0" || due[0].LocationID != 1 || due[0].Attempts != 0 {
			t.Fatalf("DuePendingDeletes = %+v, %v", due, err)
		}
		if lim, _ := os.DuePendingDeletes(ctx, now, 1); len(lim) != 1 {
			t.Fatalf("limit ignored: %+v", lim)
		}
		if err := os.DeferPendingDelete(ctx, due[0].ID, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := os.DeletePendingDelete(ctx, due[1].ID); err != nil {
			t.Fatal(err)
		}
		if d, _ := os.DuePendingDeletes(ctx, now, 10); len(d) != 0 {
			t.Fatalf("deferred or deleted jobs still due: %+v", d)
		}
		later, _ := os.DuePendingDeletes(ctx, now.Add(2*time.Hour), 10)
		if len(later) != 2 || later[0].Attempts != 1 {
			t.Fatalf("after defer = %+v", later)
		}
		if n, _ := os.CountPendingDeletes(ctx); n != 2 {
			t.Fatalf("CountPendingDeletes = %d", n)
		}
	})

	t.Run("FilesAndMigration", func(t *testing.T) {
		s := open(t)
		os := s.ObjectStorage()
		owner := mustCreate(t, s.Users(), newUser("ivy", "ivy@example.org"))
		share := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-i", Name: "I"})
		f1 := mustFile(t, s, localFile(share, "a.txt", 10))
		mustFile(t, s, localFile(share, "b.txt", 5))
		if u, err := os.UsageByLocation(ctx); err != nil || len(u) != 1 || u[0].ID != 0 || u[0].Files != 2 || u[0].Bytes != 15 {
			t.Fatalf("UsageByLocation = %+v, %v", u, err)
		}
		loc, _ := os.EnsureLocation(ctx, "s3", "s3://x", `{}`)
		ids, err := os.FilesOutside(ctx, loc)
		if err != nil || len(ids) != 2 || ids[0] != f1 {
			t.Fatalf("FilesOutside = %v, %v", ids, err)
		}
		if n, _ := os.CountFilesOutside(ctx, 0); n != 0 {
			t.Fatalf("CountFilesOutside(local) = %d", n)
		}
		f, err := os.MigrationFile(ctx, f1)
		if err != nil || f.ID != f1 || f.Size != 10 || f.LocationID != 0 || f.ShareLongID != "long-i" || f.DiskPath == "" || !f.Encrypted {
			t.Fatalf("MigrationFile = %+v, %v", f, err)
		}
		if _, err := os.MigrationFile(ctx, 9999); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("MigrationFile of a missing file: %v", err)
		}
		// The walk by id: pages of a given size, strictly after the cursor.
		page, err := os.ListMigrationFiles(ctx, 0, 1)
		if err != nil || len(page) != 1 || page[0].ID != f1 || page[0].Name != "a.txt" || page[0].ShareLongID != "long-i" || page[0].Size != 10 {
			t.Fatalf("ListMigrationFiles(0,1) = %+v, %v", page, err)
		}
		rest, err := os.ListMigrationFiles(ctx, f1, 10)
		if err != nil || len(rest) != 1 || rest[0].ID <= f1 || rest[0].Name != "b.txt" {
			t.Fatalf("ListMigrationFiles(after) = %+v, %v", rest, err)
		}
		if end, err := os.ListMigrationFiles(ctx, rest[0].ID, 10); err != nil || len(end) != 0 {
			t.Fatalf("ListMigrationFiles past the end = %+v, %v", end, err)
		}
		to := ports.MovedFile{LocationID: loc, ObjectKey: "key-a", Encrypted: true, EncID: f.EncID, SHA256: f.SHA256}
		stale := f
		stale.DiskPath = "other"
		if n, _ := os.MoveFile(ctx, stale, to); n != 0 {
			t.Fatal("MoveFile ignored a changed source")
		}
		if n, err := os.MoveFile(ctx, f, to); err != nil || n != 1 {
			t.Fatalf("MoveFile = %d, %v", n, err)
		}
		if n, _ := os.CountFilesOutside(ctx, loc); n != 1 {
			t.Fatalf("CountFilesOutside after a move = %d", n)
		}
		if moved, _ := os.MigrationFile(ctx, f1); moved.LocationID != loc || moved.ObjectKey != "key-a" || moved.DiskPath != "" {
			t.Fatalf("moved file = %+v", moved)
		}
	})
}

// RunStorageMigrations pins the contract of ports.StorageMigrationRepository.
func RunStorageMigrations(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	t.Run("Lifecycle", func(t *testing.T) {
		sm := open(t).StorageMigrations()
		if _, err := sm.Latest(ctx); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Latest on an empty store: %v", err)
		}
		id, err := sm.Start(ctx, 3, "S3 bucket", "admin")
		if err != nil {
			t.Fatal(err)
		}
		if err := sm.Progress(ctx, id, 10, 4, 1, 400); err != nil {
			t.Fatal(err)
		}
		m, err := sm.Latest(ctx)
		if err != nil || m.ID != id || m.Status != "running" || m.TargetLocation != 3 || m.Target != "S3 bucket" || m.StartedBy != "admin" ||
			m.Total != 10 || m.Done != 4 || m.Failed != 1 || m.Bytes != 400 || m.FinishedAt != nil || m.StartedAt.IsZero() {
			t.Fatalf("Latest = %+v, %v", m, err)
		}
		if err := sm.FailInterrupted(ctx); err != nil {
			t.Fatal(err)
		}
		if m, _ = sm.Latest(ctx); m.Status != "failed" || m.Error != "interrupted by a restart" || m.FinishedAt == nil {
			t.Fatalf("after FailInterrupted = %+v", m)
		}
		tool, err := sm.StartByTool(ctx, 0, "local")
		if err != nil {
			t.Fatal(err)
		}
		if err := sm.FinishWithCounters(ctx, tool, "finished", 2, 2, 0, 20, ""); err != nil {
			t.Fatal(err)
		}
		if m, _ = sm.Latest(ctx); m.ID != tool || m.StartedBy != "sendora-db" || m.Status != "finished" || m.Done != 2 || m.FinishedAt == nil {
			t.Fatalf("tool run = %+v", m)
		}
		third, _ := sm.Start(ctx, 1, "x", "y")
		if err := sm.Finish(ctx, third, "cancelled", "stop"); err != nil {
			t.Fatal(err)
		}
		if m, _ = sm.Latest(ctx); m.Status != "cancelled" || m.Error != "stop" {
			t.Fatalf("Finish = %+v", m)
		}
	})
}
