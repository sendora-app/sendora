// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunEncryptedLookups pins the contract of the encrypted lookup columns
// (users.username, users.email, users.password_hash, shares.long_id,
// shares.password_hash): the database holds ciphertext, equality lookups and
// uniqueness go through deterministic blind indexes (case-folded), and a
// compare-and-swap on a sealed column still admits exactly one writer.
func RunEncryptedLookups(t *testing.T, open func(testing.TB) encStore) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	fresh := func(t *testing.T) encStore {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		return s
	}
	rawOf := func(t *testing.T, s encStore, table, column string, id int64) string {
		t.Helper()
		v, err := s.rawGet(ctx, table, column, strconv.FormatInt(id, 10))
		if err != nil {
			t.Fatalf("raw %s.%s: %v", table, column, err)
		}
		return v
	}

	t.Run("CiphertextAtRest", func(t *testing.T) {
		s := fresh(t)
		in := newUser("Olivia.Lookup", "olivia.lookup@example.org")
		in.PasswordHash = "$2a$10$secrethashsecrethash"
		id := mustCreate(t, s.Users(), in)
		for col, plain := range map[string]string{"username": "lookup", "email": "olivia.lookup", "password_hash": "secrethash"} {
			if v := rawOf(t, s, "users", col, id); !strings.HasPrefix(v, "e1:") || strings.Contains(strings.ToLower(v), plain) {
				t.Fatalf("users.%s holds %q, want ciphertext", col, v)
			}
		}
		sid := mustShare(t, s, ports.NewShare{UserID: id, LongID: "long-at-rest", Name: "n", PasswordHash: "share-secret-hash", ExpiresAt: now.Add(time.Hour)})
		for col, plain := range map[string]string{"long_id": "at-rest", "password_hash": "share-secret"} {
			if v := rawOf(t, s, "shares", col, sid); !strings.HasPrefix(v, "e1:") || strings.Contains(v, plain) {
				t.Fatalf("shares.%s holds %q, want ciphertext", col, v)
			}
		}
		got := mustUser(t, s.Users(), id)
		if got.Username != in.Username || got.Email != in.Email || got.PasswordHash != in.PasswordHash {
			t.Fatalf("ByID = %+v", got)
		}
		if h, err := s.Users().PasswordHash(ctx, id); err != nil || h != in.PasswordHash {
			t.Fatalf("PasswordHash = %q, %v", h, err)
		}
		if n, err := s.Users().Username(ctx, id); err != nil || n != in.Username {
			t.Fatalf("Username = %q, %v", n, err)
		}
		if e, err := s.Users().Email(ctx, id); err != nil || e != in.Email {
			t.Fatalf("Email = %q, %v", e, err)
		}
		sh, err := s.Shares().ByID(ctx, sid)
		if err != nil || sh.LongID != "long-at-rest" || sh.PasswordHash != "share-secret-hash" || sh.Owner != in.Username {
			t.Fatalf("share ByID = %+v, %v", sh, err)
		}
		// Copied to another row, a sealed value does not open.
		other := mustCreate(t, s.Users(), newUser("other-lookup", "other.lookup@example.org"))
		if err := s.rawSet(ctx, "users", "email", strconv.FormatInt(other, 10), rawOf(t, s, "users", "email", id)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Users().ByID(ctx, other); err == nil {
			t.Fatal("an email copied to another account opened")
		}
	})

	t.Run("UserLookups", func(t *testing.T) {
		s := fresh(t)
		u := s.Users()
		id := mustCreate(t, u, newUser("Piet.Puk", "Piet.Puk@Example.org"))
		unverified, err := u.CreateRegistered(ctx, ports.NewUser{Username: "quinn", Name: "Q", Email: "quinn@example.org", PasswordHash: "h", Language: "en", UILanguage: "en", EmailVerified: false, PendingRegistration: true})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := u.FindLocalByUsername(ctx, "PIET.puk"); err != nil || got.ID != id || got.Username != "Piet.Puk" {
			t.Fatalf("FindLocalByUsername = %+v, %v", got, err)
		}
		if got, err := u.FindLocalByUniqueEmail(ctx, "  piet.PUK@example.ORG "); err != nil || got.ID != id || got.Email != "Piet.Puk@Example.org" {
			t.Fatalf("FindLocalByUniqueEmail = %+v, %v", got, err)
		}
		if got, err := u.FindVerifiedByUniqueEmail(ctx, "piet.puk@example.org"); err != nil || got.ID != id {
			t.Fatalf("FindVerifiedByUniqueEmail = %+v, %v", got, err)
		}
		if _, err := u.FindVerifiedByUniqueEmail(ctx, "quinn@example.org"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("FindVerifiedByUniqueEmail of an unverified account: %v", err)
		}
		if got, err := u.FindUnverifiedByUniqueEmail(ctx, "QUINN@example.org"); err != nil || got.ID != unverified {
			t.Fatalf("FindUnverifiedByUniqueEmail = %+v, %v", got, err)
		}
		if n, err := u.CountByUsernameFold(ctx, "pIET.PUK"); err != nil || n != 1 {
			t.Fatalf("CountByUsernameFold = %d, %v", n, err)
		}
		if n, err := u.CountByUsernameFold(ctx, "nobody"); err != nil || n != 0 {
			t.Fatalf("CountByUsernameFold(nobody) = %d, %v", n, err)
		}
		if got, err := u.LocalIDByUsername(ctx, "PIET.PUK"); err != nil || got != id {
			t.Fatalf("LocalIDByUsername = %d, %v", got, err)
		}
		if n, err := u.CountOtherWithEmail(ctx, "PIET.puk@example.org", 0); err != nil || n != 1 {
			t.Fatalf("CountOtherWithEmail = %d, %v", n, err)
		}
		if n, err := u.CountOtherWithEmail(ctx, "piet.puk@example.org", id); err != nil || n != 0 {
			t.Fatalf("CountOtherWithEmail excluding the owner = %d, %v", n, err)
		}
		if l, err := s.Mail().LanguageOfUniqueEmail(ctx, "PIET.PUK@example.org"); err != nil || l != "en" {
			t.Fatalf("LanguageOfUniqueEmail = %q, %v", l, err)
		}
		if err := s.EmailVerifications().Put(ctx, unverified, "123456", now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if uid, code, _, pending, err := s.EmailVerifications().FindByUniqueEmail(ctx, "Quinn@Example.org"); err != nil || uid != unverified || code != "123456" || !pending {
			t.Fatalf("FindByUniqueEmail = %d, %q, %v, %v", uid, code, pending, err)
		}
		if n, err := u.VerifyEmailWithCode(ctx, unverified, "QUINN@example.org", "123456", now); err != nil || n != 1 {
			t.Fatalf("VerifyEmailWithCode = %d, %v", n, err)
		}
		// An account without an address has no email index: nothing finds it by "".
		noMail := mustCreate(t, u, newUser("no-mail", ""))
		if _, err := u.FindLocalByUniqueEmail(ctx, ""); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("FindLocalByUniqueEmail(\"\") = %v, want not found", err)
		}
		_ = noMail
		// Changing the address moves the index with it.
		cur := mustUser(t, u, id)
		if n, err := u.UpdateProfile(ctx, id, ports.ProfileUpdate{Name: cur.Name, Email: "piet.new@example.org", EmailVerified: true, PasswordHash: cur.PasswordHash, Language: "en"}, guardOf(cur)); err != nil || n != 1 {
			t.Fatalf("UpdateProfile = %d, %v", n, err)
		}
		if _, err := u.FindLocalByUniqueEmail(ctx, "piet.puk@example.org"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("the old address still finds the account: %v", err)
		}
		if got, err := u.FindLocalByUniqueEmail(ctx, "PIET.NEW@example.org"); err != nil || got.ID != id {
			t.Fatalf("the new address: %+v, %v", got, err)
		}
		// Listings come back sorted by the plaintext names.
		mustCreate(t, u, newUser("alice-z", "alice-z@example.org"))
		mustCreate(t, u, newUser("Bert-z", "bert-z@example.org"))
		list, err := u.ListLocal(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(list); i++ {
			if list[i-1].Username > list[i].Username {
				t.Fatalf("ListLocal is not sorted: %q before %q", list[i-1].Username, list[i].Username)
			}
		}
		review, err := u.ListForAccessReview(ctx)
		if err != nil || len(review) != len(list) {
			t.Fatalf("ListForAccessReview = %d rows, %v", len(review), err)
		}
		for i := 1; i < len(review); i++ {
			if strings.ToLower(review[i-1].Username) > strings.ToLower(review[i].Username) {
				t.Fatalf("ListForAccessReview is not sorted: %q before %q", review[i-1].Username, review[i].Username)
			}
		}
		// An erased account keeps a placeholder name that still resolves.
		if err := u.EraseWithOwnedData(ctx, id); err != nil {
			t.Fatal(err)
		}
		if got, err := u.FindLocalByUsername(ctx, "ERASED-"+strconv.FormatInt(id, 10)); err != nil || got.ID != id || got.Email != "" {
			t.Fatalf("erased account = %+v, %v", got, err)
		}
		if _, err := u.FindLocalByUniqueEmail(ctx, "piet.new@example.org"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("an erased address still finds the account: %v", err)
		}
	})

	t.Run("Uniqueness", func(t *testing.T) {
		s := fresh(t)
		u := s.Users()
		a := mustCreate(t, u, newUser("Ursula", "ursula@example.org"))
		for name, in := range map[string]ports.NewUser{
			"username": newUser("URSULA", "other@example.org"),
			"email":    newUser("victor", " URSULA@example.ORG"),
		} {
			if _, err := u.Create(ctx, in); !errors.Is(err, ports.ErrDuplicate) {
				t.Fatalf("a duplicate %s: %v, want ErrDuplicate", name, err)
			}
		}
		b := mustCreate(t, u, newUser("walt", "walt@example.org"))
		cur := mustUser(t, u, b)
		if _, err := u.UpdateProfile(ctx, b, ports.ProfileUpdate{Name: cur.Name, Email: "Ursula@example.org", EmailVerified: true, PasswordHash: cur.PasswordHash, Language: "en"}, guardOf(cur)); !errors.Is(err, ports.ErrDuplicate) {
			t.Fatalf("UpdateProfile to a taken address: %v, want ErrDuplicate", err)
		}
		if got := mustUser(t, u, b); got.Email != "walt@example.org" {
			t.Fatalf("a refused update changed the address to %q", got.Email)
		}
		if _, err := u.AdminUpdate(ctx, b, ports.AdminUserUpdate{Name: cur.Name, Email: "URSULA@example.org", PasswordHash: cur.PasswordHash}, guardOf(cur)); !errors.Is(err, ports.ErrDuplicate) {
			t.Fatalf("AdminUpdate to a taken address: %v, want ErrDuplicate", err)
		}
		// Accounts without an address do not collide with each other.
		mustCreate(t, u, newUser("no-mail-1", ""))
		mustCreate(t, u, newUser("no-mail-2", ""))
		if _, err := u.CreateGuest(ctx, "ursula", "G"); !errors.Is(err, ports.ErrDuplicate) {
			t.Fatalf("a guest with a taken username: %v, want ErrDuplicate", err)
		}
		mustShare(t, s, ports.NewShare{UserID: a, LongID: "dup-link", Name: "x", ExpiresAt: now.Add(time.Hour)})
		if _, err := s.Shares().Create(ctx, ports.NewShare{UserID: a, LongID: "DUP-LINK", Name: "y", ExpiresAt: now.Add(time.Hour)}); err == nil {
			t.Fatal("a second share with the same link id was accepted")
		}
	})

	t.Run("ShareLookups", func(t *testing.T) {
		s := fresh(t)
		owner := mustCreate(t, s.Users(), newUser("xena", "xena@example.org"))
		id := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "link-xena-1", Name: "X", PasswordHash: "ph", ExpiresAt: now.Add(time.Hour)})
		if got, err := s.Shares().ByLongID(ctx, "LINK-XENA-1"); err != nil || got.ID != id || got.LongID != "link-xena-1" || got.Owner != "xena" || got.PasswordHash != "ph" {
			t.Fatalf("ByLongID = %+v, %v", got, err)
		}
		if _, err := s.Shares().ByLongID(ctx, "link-xena-2"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ByLongID of an unknown link: %v", err)
		}
		if ok, err := s.Shares().LongIDExists(ctx, "Link-Xena-1"); err != nil || !ok {
			t.Fatalf("LongIDExists = %v, %v", ok, err)
		}
		if lid, err := s.Shares().OwnedActiveLongID(ctx, id, owner); err != nil || lid != "link-xena-1" {
			t.Fatalf("OwnedActiveLongID = %q, %v", lid, err)
		}
		fid := mustFile(t, s, ports.NewShareFile{ShareID: id, Name: "f.txt", FullPath: "f.txt", Size: 1, DiskPath: "p", SHA256: "abc"})
		if disk, lid, _, err := s.Shares().FileLocation(ctx, fid, id); err != nil || lid != "link-xena-1" || disk != "p" {
			t.Fatalf("FileLocation = %q, %q, %v", disk, lid, err)
		}
		if files, err := s.Shares().Files(ctx, id); err != nil || len(files) != 1 || files[0].LongID != "link-xena-1" {
			t.Fatalf("Files = %+v, %v", files, err)
		}
		if ids, err := s.Users().OwnedShareLongIDs(ctx, owner); err != nil || len(ids) != 1 || ids[0] != "link-xena-1" {
			t.Fatalf("OwnedShareLongIDs = %v, %v", ids, err)
		}
		if lid, err := s.Shares().LongIDIf(ctx, id, ports.ShareFilter{Kind: ports.AnyShare}); err != nil || lid != "link-xena-1" {
			t.Fatalf("LongIDIf = %q, %v", lid, err)
		}
	})

	t.Run("CompareAndSwap", func(t *testing.T) {
		s := fresh(t)
		u := s.Users()
		id := mustCreate(t, u, newUser("yara", "yara@example.org"))
		// Exactly one of the concurrent writers that read the same hash wins.
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				n, err := u.ReplacePasswordHash(ctx, id, "next-"+strconv.Itoa(i), "hash-yara")
				if err != nil {
					t.Errorf("ReplacePasswordHash: %v", err)
				}
				wins.Add(int32(n))
			}(i)
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d writers replaced the same password hash, want exactly 1", wins.Load())
		}
		if h, _ := u.PasswordHash(ctx, id); !strings.HasPrefix(h, "next-") {
			t.Fatalf("the hash after the race is %q", h)
		}
		// A stale guard changes nothing; the current one does.
		cur := mustUser(t, u, id)
		stale := ports.CredentialGuard{PasswordHash: "hash-yara", Email: cur.Email}
		if n, err := u.RecordLoginAttempt(ctx, id, 1, 0, stale); err != nil || n != 0 {
			t.Fatalf("RecordLoginAttempt with a stale guard = %d, %v", n, err)
		}
		if n, err := u.RecordLoginAttempt(ctx, id, 1, 0, guardOf(cur)); err != nil || n != 1 {
			t.Fatalf("RecordLoginAttempt = %d, %v", n, err)
		}
		if n, err := u.UpdateProfile(ctx, id, ports.ProfileUpdate{Name: "Y", Email: cur.Email, EmailVerified: true, PasswordHash: "profile-hash", Language: "en"}, stale); err != nil || n != 0 {
			t.Fatalf("UpdateProfile with a stale guard = %d, %v", n, err)
		}
		if n, err := u.UpdateProfile(ctx, id, ports.ProfileUpdate{Name: "Y", Email: cur.Email, EmailVerified: true, PasswordHash: "profile-hash", Language: "en"}, guardOf(cur)); err != nil || n != 1 {
			t.Fatalf("UpdateProfile = %d, %v", n, err)
		}
		if h, _ := u.PasswordHash(ctx, id); h != "profile-hash" {
			t.Fatalf("hash after UpdateProfile = %q", h)
		}
		// Share password: same rule.
		sid := mustShare(t, s, ports.NewShare{UserID: id, LongID: "cas-share", Name: "c", PasswordHash: "sh-1", ExpiresAt: now.Add(time.Hour)})
		var swaps atomic.Int32
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				n, err := s.Shares().ReplacePasswordHash(ctx, sid, "sh-next-"+strconv.Itoa(i), "sh-1")
				if err != nil {
					t.Errorf("share ReplacePasswordHash: %v", err)
				}
				swaps.Add(int32(n))
			}(i)
		}
		wg.Wait()
		if swaps.Load() != 1 {
			t.Fatalf("%d writers replaced the same share password hash, want exactly 1", swaps.Load())
		}
	})
}
