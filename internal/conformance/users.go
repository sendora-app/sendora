// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// newUser is a valid account for the user contracts.
func newUser(name, email string) ports.NewUser {
	return ports.NewUser{Username: name, Name: name, Email: email, PasswordHash: "hash-" + name, Language: "en", UILanguage: "en",
		PasswordChangedAt: time.Unix(1_800_000_000, 0).UTC()}
}

func mustCreate(t *testing.T, r ports.UserRepository, u ports.NewUser) int64 {
	t.Helper()
	id, err := r.Create(context.Background(), u)
	if err != nil {
		t.Fatalf("create %s: %v", u.Username, err)
	}
	return id
}

func mustUser(t *testing.T, r ports.UserRepository, id int64) ports.UserRecord {
	t.Helper()
	u, err := r.ByID(context.Background(), id)
	if err != nil {
		t.Fatalf("ByID(%d): %v", id, err)
	}
	return u
}

func guardOf(u ports.UserRecord) ports.CredentialGuard {
	return ports.CredentialGuard{PasswordHash: u.PasswordHash, Email: u.Email, MustChangePassword: u.MustChangePassword}
}

// RunUsers pins the contract of ports.UserRepository.
func RunUsers(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()

	t.Run("EmptyStore", func(t *testing.T) {
		r := open(t).Users()
		if n, err := r.Count(ctx); err != nil || n != 0 {
			t.Fatalf("Count = %d, %v", n, err)
		}
		if _, err := r.ByID(ctx, 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ByID on empty store: %v, want ErrNotFound", err)
		}
		if _, err := r.Username(ctx, 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Username on empty store: %v", err)
		}
		if _, err := r.IsGuest(ctx, 1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("IsGuest on empty store: %v", err)
		}
		if l, err := r.ListLocal(ctx); err != nil || len(l) != 0 {
			t.Fatalf("ListLocal = %v, %v", l, err)
		}
		for name, f := range map[string]func() (int64, error){
			"ClearLoginLock":      func() (int64, error) { return r.ClearLoginLock(ctx, 7) },
			"ForcePasswordChange": func() (int64, error) { return r.ForcePasswordChange(ctx, 7) },
			"LockForDelete":       func() (int64, error) { return r.LockForDelete(ctx, 7) },
		} {
			if n, err := f(); err != nil || n != 0 {
				t.Fatalf("%s on a missing account = %d, %v", name, n, err)
			}
		}
	})

	t.Run("CreateFirstAdminOnlyOnce", func(t *testing.T) {
		r := open(t).Users()
		id, created, err := r.CreateFirstAdmin(ctx, newUser("root", "root@example.org"))
		if err != nil || !created || id == 0 {
			t.Fatalf("first CreateFirstAdmin = %d, %v, %v", id, created, err)
		}
		u := mustUser(t, r, id)
		if !u.Admin || u.Username != "root" || u.PasswordHash != "hash-root" || u.PasswordChangedAt == nil {
			t.Fatalf("first admin = %+v", u)
		}
		if _, created, err := r.CreateFirstAdmin(ctx, newUser("second", "s@example.org")); err != nil || created {
			t.Fatalf("second CreateFirstAdmin created=%v err=%v", created, err)
		}
		if n, _ := r.Count(ctx); n != 1 {
			t.Fatalf("Count = %d, want 1", n)
		}
	})

	t.Run("CreateAndRead", func(t *testing.T) {
		r := open(t).Users()
		q := int64(5 << 20)
		nu := newUser("Alice", "alice@example.org")
		nu.QuotaBytes, nu.MustChangePassword = &q, true
		id := mustCreate(t, r, nu)
		u := mustUser(t, r, id)
		// Accounts created by an administrator count as verified.
		if u.Username != "Alice" || u.Email != "alice@example.org" || !u.MustChangePassword || u.Admin || u.IsGuest || u.Disabled || !u.EmailVerified {
			t.Fatalf("record = %+v", u)
		}
		if u.QuotaBytes == nil || *u.QuotaBytes != "5242880" || u.QuotaInheritsDefault == nil || *u.QuotaInheritsDefault != "0" {
			t.Fatalf("own quota = %v/%v", u.QuotaBytes, u.QuotaInheritsDefault)
		}
		if u.DefaultQuota == nil {
			t.Fatal("DefaultQuota is nil on a seeded store")
		}
		if _, err := time.Parse(time.RFC3339Nano, u.CreatedAt); err != nil {
			t.Fatalf("CreatedAt %q is not RFC 3339: %v", u.CreatedAt, err)
		}
		if !u.PasswordChangedAt.Equal(nu.PasswordChangedAt) {
			t.Fatalf("PasswordChangedAt = %v, want %v", u.PasswordChangedAt, nu.PasswordChangedAt)
		}
		inherit := mustUser(t, r, mustCreate(t, r, newUser("bob", "bob@example.org")))
		if inherit.QuotaInheritsDefault == nil || *inherit.QuotaInheritsDefault != "1" {
			t.Fatalf("default account does not inherit the quota: %v", inherit.QuotaInheritsDefault)
		}
		if name, err := r.Username(ctx, id); err != nil || name != "Alice" {
			t.Fatalf("Username = %q, %v", name, err)
		}
		if h, err := r.PasswordHash(ctx, id); err != nil || h != "hash-Alice" {
			t.Fatalf("PasswordHash = %q, %v", h, err)
		}
		if g, err := r.IsGuest(ctx, id); err != nil || g {
			t.Fatalf("IsGuest = %v, %v", g, err)
		}
	})

	t.Run("UsernameIgnoresCase", func(t *testing.T) {
		r := open(t).Users()
		id := mustCreate(t, r, newUser("Carol", "carol@example.org"))
		if _, err := r.Create(ctx, newUser("carol", "other@example.org")); err == nil {
			t.Fatal("a username differing only by case was accepted")
		}
		if n, err := r.CountByUsernameFold(ctx, "CAROL"); err != nil || n != 1 {
			t.Fatalf("CountByUsernameFold = %d, %v", n, err)
		}
		u, err := r.FindLocalByUsername(ctx, "cArOl")
		if err != nil || u.ID != id {
			t.Fatalf("FindLocalByUsername = %+v, %v", u, err)
		}
		if _, err := r.FindLocalByUsername(ctx, "nobody"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("unknown username: %v", err)
		}
	})

	t.Run("FindByUniqueEmail", func(t *testing.T) {
		r := open(t).Users()
		a := newUser("dave", "dave@example.org")
		a.EmailVerified = true
		daveID, err := r.CreateRegistered(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		pending := newUser("erin", "erin@example.org")
		pending.PendingRegistration = true
		erinID, err := r.CreateRegistered(ctx, pending)
		if err != nil {
			t.Fatal(err)
		}
		if u, err := r.FindLocalByUniqueEmail(ctx, "dave@example.org"); err != nil || u.ID != daveID {
			t.Fatalf("FindLocalByUniqueEmail = %+v, %v", u, err)
		}
		if u, err := r.FindVerifiedByUniqueEmail(ctx, "dave@example.org"); err != nil || u.ID != daveID {
			t.Fatalf("FindVerifiedByUniqueEmail = %+v, %v", u, err)
		}
		if _, err := r.FindUnverifiedByUniqueEmail(ctx, "dave@example.org"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("verified account found as unverified: %v", err)
		}
		if u, err := r.FindUnverifiedByUniqueEmail(ctx, "erin@example.org"); err != nil || u.ID != erinID || u.EmailVerified {
			t.Fatalf("FindUnverifiedByUniqueEmail = %+v, %v", u, err)
		}
		// Matching trims and lower-cases the stored address; addresses are
		// unique in that form.
		if _, err := r.Create(ctx, newUser("frank", " Dave@Example.org ")); err == nil {
			t.Fatal("an address differing only by case and spaces was accepted")
		}
		mustCreate(t, r, newUser("heidi", "  Heidi@Example.org"))
		if u, err := r.FindLocalByUniqueEmail(ctx, "heidi@example.org"); err != nil || u.Username != "heidi" {
			t.Fatalf("trim/lower-case match = %+v, %v", u, err)
		}
	})

	t.Run("ListLocalOrdered", func(t *testing.T) {
		r := open(t).Users()
		for _, n := range []string{"zed", "amy", "mia"} {
			mustCreate(t, r, newUser(n, n+"@example.org"))
		}
		l, err := r.ListLocal(ctx)
		if err != nil || len(l) != 3 || l[0].Username != "amy" || l[1].Username != "mia" || l[2].Username != "zed" {
			t.Fatalf("ListLocal = %+v, %v", l, err)
		}
	})

	t.Run("GuardedWrites", func(t *testing.T) {
		r := open(t).Users()
		id := mustCreate(t, r, newUser("ivan", "ivan@example.org"))
		u := mustUser(t, r, id)
		stale := guardOf(u)
		stale.Email = "old@example.org"
		if n, err := r.RecordLoginAttempt(ctx, id, 3, 99, stale); err != nil || n != 0 {
			t.Fatalf("stale guard matched: %d, %v", n, err)
		}
		if n, err := r.RecordLoginAttempt(ctx, id, 3, 99, guardOf(u)); err != nil || n != 1 {
			t.Fatalf("RecordLoginAttempt = %d, %v", n, err)
		}
		if u = mustUser(t, r, id); u.LoginFailures != 3 || u.LoginLockedUntil != 99 {
			t.Fatalf("after attempt: %+v", u)
		}
		if n, err := r.ClearLoginLock(ctx, id); err != nil || n != 1 {
			t.Fatalf("ClearLoginLock = %d, %v", n, err)
		}
		if u = mustUser(t, r, id); u.LoginFailures != 0 || u.LoginLockedUntil != 0 {
			t.Fatalf("after clear: %+v", u)
		}
		if n, _ := r.ReplacePasswordHash(ctx, id, "new", "wrong"); n != 0 {
			t.Fatal("ReplacePasswordHash ignored the old hash")
		}
		if n, err := r.ReplacePasswordHash(ctx, id, "new", "hash-ivan"); err != nil || n != 1 {
			t.Fatalf("ReplacePasswordHash = %d, %v", n, err)
		}
		if n, _ := r.FlagPasswordExpired(ctx, id, "hash-ivan"); n != 0 {
			t.Fatal("FlagPasswordExpired ignored the hash")
		}
		if n, err := r.FlagPasswordExpired(ctx, id, "new"); err != nil || n != 1 {
			t.Fatalf("FlagPasswordExpired = %d, %v", n, err)
		}
		if n, _ := r.FlagPasswordExpired(ctx, id, "new"); n != 0 {
			t.Fatal("FlagPasswordExpired flagged twice")
		}
		if n, err := r.ForcePasswordChange(ctx, id); err != nil || n != 1 {
			t.Fatalf("ForcePasswordChange = %d, %v", n, err)
		}
	})

	t.Run("ProfileAndAdminUpdate", func(t *testing.T) {
		r := open(t).Users()
		id := mustCreate(t, r, newUser("judy", "judy@example.org"))
		u := mustUser(t, r, id)
		if _, err := r.RecordLoginAttempt(ctx, id, 2, 0, guardOf(u)); err != nil {
			t.Fatal(err)
		}
		u = mustUser(t, r, id)
		at := time.Unix(1_900_000_000, 0).UTC()
		ui := "de"
		n, err := r.UpdateProfile(ctx, id, ports.ProfileUpdate{Name: "Judy", Email: "judy@example.net", PasswordHash: "h2", Language: "nl", UILanguage: &ui, PasswordChanged: true, ChangedAt: at}, guardOf(u))
		if err != nil || n != 1 {
			t.Fatalf("UpdateProfile = %d, %v", n, err)
		}
		u = mustUser(t, r, id)
		if u.Name != "Judy" || u.Email != "judy@example.net" || u.PasswordHash != "h2" || u.Language != "nl" || u.UILanguage != "de" || u.LoginFailures != 0 || !u.PasswordChangedAt.Equal(at) {
			t.Fatalf("after UpdateProfile: %+v", u)
		}
		// nil UILanguage keeps the stored value; no password change keeps the time.
		if n, _ := r.UpdateProfile(ctx, id, ports.ProfileUpdate{Name: "J", Email: u.Email, PasswordHash: u.PasswordHash, Language: "en", ChangedAt: at.Add(time.Hour)}, guardOf(u)); n != 1 {
			t.Fatal("second UpdateProfile did not apply")
		}
		u = mustUser(t, r, id)
		if u.UILanguage != "de" || !u.PasswordChangedAt.Equal(at) {
			t.Fatalf("UpdateProfile changed kept fields: %+v", u)
		}
		if n, _ := r.UpdateProfile(ctx, id, ports.ProfileUpdate{Name: "x"}, ports.CredentialGuard{PasswordHash: "other"}); n != 0 {
			t.Fatal("UpdateProfile ignored its guard")
		}
		q, policy := int64(1<<30), "required"
		n, err = r.AdminUpdate(ctx, id, ports.AdminUserUpdate{Name: "J", Email: u.Email, Admin: true, PasswordHash: u.PasswordHash, QuotaBytes: &q, MFAPolicy: &policy, EmailUnverified: true}, guardOf(u))
		if err != nil || n != 1 {
			t.Fatalf("AdminUpdate = %d, %v", n, err)
		}
		u = mustUser(t, r, id)
		if !u.Admin || u.QuotaBytes == nil || *u.QuotaBytes != "1073741824" || u.MFAPolicy != "required" || u.EmailVerified {
			t.Fatalf("after AdminUpdate: %+v", u)
		}
		if err := r.SetAuditorIfNotAdmin(ctx, id); err != nil {
			t.Fatal(err)
		}
		if mustUser(t, r, id).Auditor {
			t.Fatal("SetAuditorIfNotAdmin made an administrator an auditor")
		}
		if err := r.SetAuditor(ctx, id, true); err != nil || !mustUser(t, r, id).Auditor {
			t.Fatalf("SetAuditor: %v", err)
		}
	})

	t.Run("ResetAndVerification", func(t *testing.T) {
		s := open(t)
		r := s.Users()
		nu := newUser("ken", "ken@example.org")
		nu.PendingRegistration = true
		id, err := r.CreateRegistered(ctx, nu)
		if err != nil {
			t.Fatal(err)
		}
		at := time.Unix(1_900_000_000, 0).UTC()
		if n, err := r.SetPasswordAfterReset(ctx, id, "reset", at); err != nil || n != 1 {
			t.Fatalf("SetPasswordAfterReset = %d, %v", n, err)
		}
		u := mustUser(t, r, id)
		if u.PasswordHash != "reset" || u.MustChangePassword || !u.PasswordChangedAt.Equal(at) {
			t.Fatalf("after reset: %+v", u)
		}
		now := time.Unix(1_800_000_000, 0)
		if err := s.EmailVerifications().Put(ctx, id, "12345678", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if n, _ := r.VerifyEmailWithCode(ctx, id, "ken@example.org", "00000000", now); n != 0 {
			t.Fatal("wrong code verified the address")
		}
		if n, _ := r.VerifyEmailWithCode(ctx, id, "ken@example.org", "12345678", now.Add(time.Minute)); n != 0 {
			t.Fatal("expired code verified the address (expiry is exclusive)")
		}
		if n, err := r.VerifyEmailWithCode(ctx, id, "ken@example.org", "12345678", now); err != nil || n != 1 {
			t.Fatalf("VerifyEmailWithCode = %d, %v", n, err)
		}
		if !mustUser(t, r, id).EmailVerified {
			t.Fatal("address not verified")
		}
		other, err := r.CreateRegistered(ctx, newUser("leo", "leo@example.org"))
		if err != nil {
			t.Fatal(err)
		}
		if mustUser(t, r, other).EmailVerified {
			t.Fatal("CreateRegistered ignored EmailVerified=false")
		}
		if err := r.MarkEmailVerified(ctx, other); err != nil || !mustUser(t, r, other).EmailVerified {
			t.Fatalf("MarkEmailVerified: %v", err)
		}
		empty, err := r.CreateRegistered(ctx, newUser("max", ""))
		if err != nil {
			t.Fatal(err)
		}
		if err := r.MarkEmailVerified(ctx, empty); err != nil || mustUser(t, r, empty).EmailVerified {
			t.Fatalf("MarkEmailVerified verified an empty address: %v", err)
		}
	})

	t.Run("PasswordExpiryCandidates", func(t *testing.T) {
		r := open(t).Users()
		reg := newUser("nina", "nina@example.org")
		reg.EmailVerified = true
		id, err := r.CreateRegistered(ctx, reg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.CreateRegistered(ctx, newUser("oscar", "oscar@example.org")); err != nil { // unverified: not a candidate
			t.Fatal(err)
		}
		l, err := r.ListPasswordExpiryCandidates(ctx)
		if err != nil || len(l) != 1 || l[0].ID != id {
			t.Fatalf("candidates = %+v, %v", l, err)
		}
		at := time.Unix(1_900_000_000, 0)
		if n, err := r.MarkPasswordExpiryWarned(ctx, id, "hash-nina", at); err != nil || n != 1 {
			t.Fatalf("MarkPasswordExpiryWarned = %d, %v", n, err)
		}
		if n, _ := r.MarkPasswordExpiryWarned(ctx, id, "hash-nina", at); n != 0 {
			t.Fatal("warning recorded twice")
		}
		if l, _ := r.ListPasswordExpiryCandidates(ctx); len(l) != 0 {
			t.Fatalf("warned account still a candidate: %+v", l)
		}
		if err := r.RecordLastLogin(ctx, id, at); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("DeleteWithOwnedData", func(t *testing.T) {
		s := open(t)
		r := s.Users()
		id := mustCreate(t, r, newUser("pat", "pat@example.org"))
		keep := mustCreate(t, r, newUser("quinn", "quinn@example.org"))
		// Owned: own share and upload, the invite guest's upload and share, a
		// share that arrived through the invite, an upload the account carries.
		guest := mustGuest(t, s, "guest-pat")
		inv := mustInvite(t, s, ports.NewInvite{Token: "pat-inv", UserID: id, ExpiresAt: time.Unix(1_800_000_000, 0)})
		s.ReverseInvites().AssignGuest(ctx, inv, guest)
		mustShare(t, s, ports.NewShare{UserID: id, LongID: "own", ExpiresAt: time.Unix(1_800_000_000, 0)})
		mustShare(t, s, ports.NewShare{UserID: guest, LongID: "guests", ExpiresAt: time.Unix(1_800_000_000, 0)})
		mustShare(t, s, ports.NewShare{UserID: keep, InviteID: &inv, LongID: "arrived", ExpiresAt: time.Unix(1_800_000_000, 0)})
		mustShare(t, s, ports.NewShare{UserID: keep, LongID: "kept", ExpiresAt: time.Unix(1_800_000_000, 0)})
		mustUpload(t, s, ports.NewUpload{ID: "o-1", UserID: id, QuotaOwnerID: id})
		mustUpload(t, s, ports.NewUpload{ID: "o-2", UserID: guest, QuotaOwnerID: id})
		mustUpload(t, s, ports.NewUpload{ID: "o-3", UserID: keep, QuotaOwnerID: id})
		mustUpload(t, s, ports.NewUpload{ID: "o-4", UserID: keep, QuotaOwnerID: keep})
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if n, err := tx.Users().LockForDelete(ctx, id); err != nil || n != 1 {
			t.Fatalf("LockForDelete = %d, %v", n, err)
		}
		if u, err := tx.Users().OwnedUploadIDs(ctx, id); err != nil || len(u) != 3 {
			t.Fatalf("OwnedUploadIDs = %v, %v", u, err)
		}
		if l, err := tx.Users().OwnedShareLongIDs(ctx, id); err != nil || len(l) != 3 {
			t.Fatalf("OwnedShareLongIDs = %v, %v", l, err)
		}
		if err := tx.Users().DeleteWithOwnedData(ctx, id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ByID(ctx, id); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("deleted account still readable: %v", err)
		}
		mustUser(t, r, keep)
		if _, err := r.GuestByID(ctx, guest); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteWithOwnedData kept the invite guest")
		}
		if _, err := s.Uploads().Uploader(ctx, "o-4"); err != nil {
			t.Fatal("DeleteWithOwnedData removed an unrelated upload")
		}
		for _, up := range []string{"o-1", "o-2", "o-3"} {
			if _, err := s.Uploads().Uploader(ctx, up); !errors.Is(err, ports.ErrNotFound) {
				t.Fatalf("DeleteWithOwnedData kept upload %s", up)
			}
		}
		if _, _, err := s.Shares().OwnedLongIDAndStatus(ctx, 4, keep); err != nil {
			t.Fatal("DeleteWithOwnedData removed an unrelated share")
		}
		if _, _, err := s.Shares().OwnedLongIDAndStatus(ctx, 3, keep); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteWithOwnedData kept the share that arrived through the invite")
		}
		if err := r.Delete(ctx, keep); err != nil {
			t.Fatal(err)
		}
		if err := r.Delete(ctx, keep); err != nil {
			t.Fatalf("deleting a missing account must not fail: %v", err)
		}
	})

	t.Run("ConcurrentLoginAttempts", func(t *testing.T) {
		r := open(t).Users()
		id := mustCreate(t, r, newUser("rita", "rita@example.org"))
		g := guardOf(mustUser(t, r, id))
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := r.RecordLoginAttempt(ctx, id, int64(i), 0, g)
				errs <- err
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if f := mustUser(t, r, id).LoginFailures; f < 0 || f > 7 {
			t.Fatalf("LoginFailures = %d after concurrent writes", f)
		}
	})
}
