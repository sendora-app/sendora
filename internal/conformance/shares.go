// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// mustShare creates a share through the port.
func mustShare(t *testing.T, s ports.Repositories, sh ports.NewShare) int64 {
	t.Helper()
	id, err := s.Shares().Create(context.Background(), sh)
	if err != nil {
		t.Fatalf("create share %s: %v", sh.LongID, err)
	}
	return id
}

// mustFile adds a stored file to a share through the port.
func mustFile(t *testing.T, s ports.Repositories, f ports.NewShareFile) int64 {
	t.Helper()
	id, err := s.Shares().AddFile(context.Background(), f)
	if err != nil {
		t.Fatalf("add file %s: %v", f.FullPath, err)
	}
	return id
}

// localFile is a stored file in the local data directory.
func localFile(shareID int64, path string, size int64) ports.NewShareFile {
	return ports.NewShareFile{ShareID: shareID, Name: path, FullPath: path, Size: size, Type: "text/plain", DiskPath: "0_" + path,
		Integrity: "server_baseline", Encrypted: true, EncID: "00112233445566778899aabbccddeeff"}
}

// RunShares pins the contract of ports.ShareRepository.
func RunShares(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()

	t.Run("Empty", func(t *testing.T) {
		s := open(t)
		if e, p, err := s.Shares().CountFilesByEncryption(ctx); err != nil || e != 0 || p != 0 {
			t.Fatalf("CountFilesByEncryption = %d, %d, %v", e, p, err)
		}
		if f, known, err := s.Shares().VerificationFiles(ctx); err != nil || len(f) != 0 || !known {
			t.Fatalf("VerificationFiles = %v, %v, %v", f, known, err)
		}
		if _, err := s.Shares().FileChecksum(ctx, 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("FileChecksum of an unknown file: %v", err)
		}
		if err := s.Shares().BaselineFileChecksum(ctx, 1, "abc"); err != nil {
			t.Fatalf("BaselineFileChecksum of an unknown file: %v", err)
		}
	})

	t.Run("CreateAndFiles", func(t *testing.T) {
		s := open(t)
		owner := mustCreate(t, s.Users(), newUser("fay", "fay@example.org"))
		limit := int64(3)
		a := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-a", Name: "A", Description: "first", PasswordHash: "h",
			DownloadLimit: &limit, ExpiresAt: now.Add(time.Hour)})
		b := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-b", Name: "B", ExpiresAt: now.Add(time.Hour)})
		if _, err := s.Shares().Create(ctx, ports.NewShare{UserID: owner, LongID: "long-a", ExpiresAt: now}); err == nil {
			t.Fatal("a taken long id was accepted")
		}
		f2 := mustFile(t, s, localFile(b, "z.txt", 7))
		plain := localFile(a, "plain.txt", 5)
		plain.Encrypted, plain.EncID, plain.SHA256 = false, "", "known"
		f1 := mustFile(t, s, plain)
		remote := localFile(a, "dir/remote.bin", 11)
		remote.DiskPath, remote.StorageID, remote.ObjectKey = "", 4, "files/abc"
		f3 := mustFile(t, s, remote)
		if f1 == f2 || f2 == f3 {
			t.Fatal("AddFile returned a duplicate id")
		}
		if e, p, err := s.Shares().CountFilesByEncryption(ctx); err != nil || e != 2 || p != 1 {
			t.Fatalf("CountFilesByEncryption = %d, %d, %v", e, p, err)
		}
		files, known, err := s.Shares().VerificationFiles(ctx)
		if err != nil || !known || len(files) != 3 {
			t.Fatalf("VerificationFiles = %+v, %v, %v", files, known, err)
		}
		if files[0].ID != f2 || files[1].ID != f1 || files[2].ID != f3 {
			t.Fatal("VerificationFiles is not ordered by file id")
		}
		z, p, r := files[0], files[1], files[2]
		if z.LongID != "long-b" || z.ShareName != "B" || z.Size != 7 || !z.Encrypted || z.EncID == "" || z.DiskPath != "0_z.txt" || z.StorageID != 0 {
			t.Fatalf("encrypted local file = %+v", z)
		}
		if p.Encrypted || p.SHA256 != "known" || p.LongID != "long-a" || p.ShareName != "A" || p.FullPath != "plain.txt" {
			t.Fatalf("plain file = %+v", p)
		}
		if r.StorageID != 4 || r.ObjectKey != "files/abc" || r.DiskPath != "" || r.Name != "dir/remote.bin" {
			t.Fatalf("remote file = %+v", r)
		}
	})

	t.Run("Checksums", func(t *testing.T) {
		s := open(t)
		owner := mustCreate(t, s.Users(), newUser("gil", "gil@example.org"))
		sh := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-c", ExpiresAt: now})
		f := mustFile(t, s, localFile(sh, "a.txt", 1))
		if sum, err := s.Shares().FileChecksum(ctx, f); err != nil || sum != "" {
			t.Fatalf("FileChecksum without one = %q, %v", sum, err)
		}
		if err := s.Shares().BaselineFileChecksum(ctx, f, "first"); err != nil {
			t.Fatal(err)
		}
		if err := s.Shares().BaselineFileChecksum(ctx, f, "second"); err != nil {
			t.Fatal(err)
		}
		if sum, _ := s.Shares().FileChecksum(ctx, f); sum != "first" {
			t.Fatalf("BaselineFileChecksum replaced a recorded checksum: %q", sum)
		}
	})
}

// RunDownloads pins the contract of ports.DownloadRepository.
func RunDownloads(t *testing.T, open func(testing.TB) ports.Store) {
	t.Run("Empty", func(t *testing.T) {
		if err := open(t).Downloads().BlankAddressesUnlessLogged(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

// RunStorageLocations pins the contract of ports.StorageLocationRepository
// (empty state until locations can be created through the port).
func RunStorageLocations(t *testing.T, open func(testing.TB) ports.Store) {
	t.Run("Empty", func(t *testing.T) {
		if ids, err := open(t).StorageLocations().IDs(context.Background()); err != nil || len(ids) != 0 {
			t.Fatalf("IDs = %v, %v", ids, err)
		}
	})
}
