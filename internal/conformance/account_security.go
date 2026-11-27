// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunAccountState pins the account security, deactivation and terms methods
// of ports.UserRepository.
func RunAccountState(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()

	t.Run("LocalIDByUsername", func(t *testing.T) {
		s := open(t)
		id := mustCreate(t, s.Users(), newUser("Rae", "rae@example.org"))
		for _, name := range []string{"Rae", "rae", "RAE"} {
			if got, err := s.Users().LocalIDByUsername(ctx, name); err != nil || got != id {
				t.Fatalf("LocalIDByUsername(%q) = %d, %v", name, got, err)
			}
		}
		if _, err := s.Users().LocalIDByUsername(ctx, "nobody"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("LocalIDByUsername of an unknown name: %v", err)
		}
	})

	t.Run("LoginFailuresAndEpoch", func(t *testing.T) {
		s := open(t)
		r := s.Users()
		id := mustCreate(t, r, newUser("sam", "sam@example.org"))
		if err := r.SetLoginFailures(ctx, id, 4, 1234); err != nil {
			t.Fatal(err)
		}
		if u := mustUser(t, r, id); u.LoginFailures != 4 || u.LoginLockedUntil != 1234 {
			t.Fatalf("SetLoginFailures stored %d, %d", u.LoginFailures, u.LoginLockedUntil)
		}
		if err := r.ClearLoginFailures(ctx, id); err != nil {
			t.Fatal(err)
		}
		if u := mustUser(t, r, id); u.LoginFailures != 0 || u.LoginLockedUntil != 0 {
			t.Fatal("ClearLoginFailures kept the counter")
		}
		epoch := mustUser(t, r, id).MFAEpoch
		if err := r.BumpMFAEpoch(ctx, id); err != nil {
			t.Fatal(err)
		}
		if u := mustUser(t, r, id); u.MFAEpoch != epoch+1 {
			t.Fatalf("BumpMFAEpoch: %d -> %d", epoch, u.MFAEpoch)
		}
		r.SetLoginFailures(ctx, id, 5, 99)
		if err := r.BumpMFAEpochAndClearLock(ctx, id); err != nil {
			t.Fatal(err)
		}
		if u := mustUser(t, r, id); u.MFAEpoch != epoch+2 || u.LoginFailures != 0 || u.LoginLockedUntil != 0 {
			t.Fatalf("BumpMFAEpochAndClearLock = %+v", u)
		}
		for name, err := range map[string]error{
			"SetLoginFailures":         r.SetLoginFailures(ctx, id+100, 1, 1),
			"ClearLoginFailures":       r.ClearLoginFailures(ctx, id+100),
			"BumpMFAEpoch":             r.BumpMFAEpoch(ctx, id+100),
			"BumpMFAEpochAndClearLock": r.BumpMFAEpochAndClearLock(ctx, id+100),
			"SetCreatedBy":             r.SetCreatedBy(ctx, id, "setup"),
			"NoteRoleChange":           r.NoteRoleChange(ctx, id, now, "user:1"),
			"NoteEmailChange":          r.NoteEmailChange(ctx, id, now, "user:1"),
		} {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	})

	t.Run("DisableEnable", func(t *testing.T) {
		s := open(t)
		r := s.Users()
		admin := newUser("ada", "ada@example.org")
		admin.Admin = true
		a := mustCreate(t, r, admin)
		admin2 := newUser("bob", "bob@example.org")
		admin2.Admin = true
		b := mustCreate(t, r, admin2)
		plain := mustCreate(t, r, newUser("cy", "cy@example.org"))
		if _, err := r.IsDisabled(ctx, plain+100); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("IsDisabled of an unknown account: %v", err)
		}
		if d, err := r.IsDisabled(ctx, plain); err != nil || d {
			t.Fatalf("IsDisabled = %v, %v", d, err)
		}
		if n, err := r.CountActiveAdminsExcept(ctx, a); err != nil || n != 1 {
			t.Fatalf("CountActiveAdminsExcept = %d, %v", n, err)
		}
		if n, _ := r.CountActiveAdminsExcept(ctx, plain); n != 2 {
			t.Fatalf("CountActiveAdminsExcept(non-admin) = %d", n)
		}
		if n, err := r.Disable(ctx, b, now, "user:1", "left"); err != nil || n != 1 {
			t.Fatalf("Disable = %d, %v", n, err)
		}
		if n, _ := r.Disable(ctx, b, now, "user:1", "again"); n != 0 {
			t.Fatal("a disabled account was disabled again")
		}
		if u := mustUser(t, r, b); !u.Disabled || u.DisabledReason != "left" {
			t.Fatalf("after Disable: %+v", u)
		}
		if d, _ := r.IsDisabled(ctx, b); !d {
			t.Fatal("IsDisabled after Disable = false")
		}
		if n, _ := r.CountActiveAdminsExcept(ctx, a); n != 0 {
			t.Fatal("a disabled administrator counts as active")
		}
		if n, err := r.Enable(ctx, b); err != nil || n != 1 {
			t.Fatalf("Enable = %d, %v", n, err)
		}
		if n, _ := r.Enable(ctx, b); n != 0 {
			t.Fatal("an enabled account was enabled again")
		}
		if u := mustUser(t, r, b); u.Disabled || u.DisabledReason != "" {
			t.Fatalf("after Enable: %+v", u)
		}
		if n, _ := r.Disable(ctx, b+100, now, "", ""); n != 0 {
			t.Fatal("Disable of an unknown account")
		}
		if d, err := r.ShareOwnerDisabled(ctx, 1); err != nil || d {
			t.Fatalf("ShareOwnerDisabled of an unknown share = %v, %v", d, err)
		}
		// A share of plain's, and one that arrived through b's invite.
		own := mustShare(t, s, ports.NewShare{UserID: plain, LongID: "own", ExpiresAt: now})
		inv := mustInvite(t, s, ports.NewInvite{Token: "inv", UserID: b, ExpiresAt: now.Add(time.Hour)})
		via := mustShare(t, s, ports.NewShare{UserID: plain, InviteID: &inv, LongID: "via", ExpiresAt: now})
		for _, sh := range []int64{own, via} {
			if d, err := r.ShareOwnerDisabled(ctx, sh); err != nil || d {
				t.Fatalf("ShareOwnerDisabled(%d) with enabled accounts = %v, %v", sh, d, err)
			}
		}
		r.Disable(ctx, b, now, "user:1", "inviter")
		if d, _ := r.ShareOwnerDisabled(ctx, own); d {
			t.Fatal("ShareOwnerDisabled: a disabled inviter affects an unrelated share")
		}
		if d, _ := r.ShareOwnerDisabled(ctx, via); !d {
			t.Fatal("ShareOwnerDisabled ignores the disabled inviter")
		}
		r.Disable(ctx, plain, now, "user:1", "owner")
		if d, _ := r.ShareOwnerDisabled(ctx, own); !d {
			t.Fatal("ShareOwnerDisabled ignores the disabled owner")
		}
	})

	t.Run("RevokeAccess", func(t *testing.T) {
		s := open(t)
		r := s.Users()
		// Unverified accounts, so their verification codes can be looked up.
		id, err := r.CreateRegistered(ctx, newUser("dee", "dee@example.org"))
		if err != nil {
			t.Fatal(err)
		}
		other, err := r.CreateRegistered(ctx, newUser("eli", "eli@example.org"))
		if err != nil {
			t.Fatal(err)
		}
		for _, uid := range []int64{id, other} {
			if err := s.PasswordResets().CreateReset(ctx, "reset-"+itoa(uid), uid, now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if err := s.MFA().CreateResetRequest(ctx, "mfa-"+itoa(uid), uid, 0, now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if err := s.Sessions().Insert(ctx, ports.NewRefreshToken{Hash: "rt-" + itoa(uid), UserID: uid, ExpiresAt: now.Add(time.Hour), IssuedAt: now, Started: now, SessionID: "sid"}); err != nil {
				t.Fatal(err)
			}
			if err := s.EmailVerifications().Put(ctx, uid, "123456", now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		if ups, err := r.UploadsToRevoke(ctx, id); err != nil || len(ups) != 0 {
			t.Fatalf("UploadsToRevoke = %v, %v", ups, err)
		}
		// Uploads of the account, carried by it, and of its invite's guest.
		guest := mustGuest(t, s, "guest-r")
		gi := mustInvite(t, s, ports.NewInvite{Token: "ri-g", UserID: id, ExpiresAt: now.Add(-time.Minute)})
		s.ReverseInvites().AssignGuest(ctx, gi, guest)
		mustUpload(t, s, ports.NewUpload{ID: "rv-1", UserID: id, QuotaOwnerID: id}, 1)
		mustUpload(t, s, ports.NewUpload{ID: "rv-2", UserID: other, QuotaOwnerID: id}, 1)
		mustUpload(t, s, ports.NewUpload{ID: "rv-3", UserID: guest, QuotaOwnerID: id, InviteID: &gi}, 1)
		mustUpload(t, s, ports.NewUpload{ID: "rv-4", UserID: other, QuotaOwnerID: other}, 1)
		if ups, err := r.UploadsToRevoke(ctx, id); err != nil || len(ups) != 3 {
			t.Fatalf("UploadsToRevoke = %v, %v", ups, err)
		}
		// Open invites expire; completed-or-expired ones and other accounts' stay.
		open1 := mustInvite(t, s, ports.NewInvite{Token: "ri-1", UserID: id, ExpiresAt: now.Add(time.Hour)})
		mustInvite(t, s, ports.NewInvite{Token: "ri-2", UserID: id, ExpiresAt: now.Add(time.Hour), Reusable: true, MaxUploads: 2})
		mustInvite(t, s, ports.NewInvite{Token: "ri-3", UserID: id, ExpiresAt: now.Add(-time.Hour)})
		mustInvite(t, s, ports.NewInvite{Token: "ri-4", UserID: other, ExpiresAt: now.Add(time.Hour)})
		invites, err := r.RevokeAccess(ctx, id, now)
		if err != nil || invites != 2 {
			t.Fatalf("RevokeAccess = %d, %v", invites, err)
		}
		if l, _ := s.ReverseInvites().ListOwned(ctx, id, now); len(l) != 4 || (l[0].ID != open1 && l[1].ID != open1 && l[2].ID != open1) {
			t.Fatalf("invites after RevokeAccess: %+v", l)
		} else {
			for _, iv := range l {
				if iv.ExpiresAt.After(now) {
					t.Fatalf("RevokeAccess kept invite %d open", iv.ID)
				}
			}
		}
		if l, _ := s.ReverseInvites().ListOwned(ctx, other, now); len(l) != 1 || !l[0].ExpiresAt.After(now) {
			t.Fatal("RevokeAccess expired another account's invite")
		}
		for _, up := range []string{"rv-1", "rv-2", "rv-3"} {
			if _, err := s.Uploads().Uploader(ctx, up); !errors.Is(err, ports.ErrNotFound) {
				t.Fatalf("RevokeAccess kept upload %s", up)
			}
		}
		if _, err := s.Uploads().Uploader(ctx, "rv-4"); err != nil {
			t.Fatal("RevokeAccess removed another account's upload")
		}
		if _, err := s.PasswordResets().UserFor(ctx, "reset-"+itoa(id), now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("RevokeAccess kept a reset link")
		}
		if n, _ := s.Sessions().CountLive(ctx, "sid", id, now); n != 0 {
			t.Fatal("RevokeAccess kept a session")
		}
		if _, _, _, _, err := s.EmailVerifications().FindByUniqueEmail(ctx, "dee@example.org"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("RevokeAccess kept the verification code")
		}
		if err := s.MFA().CreateResetRequest(ctx, "mfa-"+itoa(id), id, 0, now.Add(time.Hour)); err != nil {
			t.Fatal("RevokeAccess kept the MFA reset request:", err)
		}
		if uid, err := s.PasswordResets().UserFor(ctx, "reset-"+itoa(other), now); err != nil || uid != other {
			t.Fatal("RevokeAccess removed another account's reset link")
		}
		if n, _ := s.Sessions().CountLive(ctx, "sid", other, now); n != 1 {
			t.Fatal("RevokeAccess removed another account's session")
		}
		if _, _, _, _, err := s.EmailVerifications().FindByUniqueEmail(ctx, "eli@example.org"); err != nil {
			t.Fatal("RevokeAccess removed another account's verification code")
		}
	})

	t.Run("Terms", func(t *testing.T) {
		s := open(t)
		r := s.Users()
		id := mustCreate(t, r, newUser("fox", "fox@example.org"))
		if v, err := r.TermsAcceptedVersion(ctx, id); err != nil || v != "" {
			t.Fatalf("TermsAcceptedVersion = %q, %v", v, err)
		}
		if _, err := r.TermsAcceptedVersion(ctx, id+100); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("TermsAcceptedVersion of an unknown account: %v", err)
		}
		if err := r.AcceptTerms(ctx, id, "2026-01", now); err != nil {
			t.Fatal(err)
		}
		if v, _ := r.TermsAcceptedVersion(ctx, id); v != "2026-01" {
			t.Fatalf("TermsAcceptedVersion after AcceptTerms = %q", v)
		}
	})
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// RunPasswordResetKinds pins the kind-specific methods of
// ports.PasswordResetRepository.
func RunPasswordResetKinds(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	s := open(t)
	id := mustCreate(t, s.Users(), newUser("gus", "gus@example.org"))
	pr := s.PasswordResets()
	if n, err := pr.CountWelcomesForUser(ctx, id); err != nil || n != 0 {
		t.Fatalf("CountWelcomesForUser = %d, %v", n, err)
	}
	for _, step := range []error{
		pr.CreateReset(ctx, "r1", id, now.Add(time.Hour)),
		pr.CreateReset(ctx, "r2", id, now.Add(time.Hour)),
		pr.CreateWelcome(ctx, "w1", id, now.Add(time.Hour)),
		pr.CreateWelcome(ctx, "w2", id, now.Add(-time.Hour)), // expired, still counted
	} {
		if step != nil {
			t.Fatal(step)
		}
	}
	if err := pr.CreateReset(ctx, "r1", id, now.Add(time.Hour)); err == nil {
		t.Fatal("a link hash was stored twice")
	}
	if n, _ := pr.CountWelcomesForUser(ctx, id); n != 2 {
		t.Fatalf("CountWelcomesForUser = %d, want 2 (expired included)", n)
	}
	if _, kind, err := pr.Consume(ctx, "w1", now, id); err != nil || kind != "welcome" {
		t.Fatalf("Consume(welcome) kind = %q, %v", kind, err)
	}
	if err := pr.DeleteResetsForUser(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := pr.UserFor(ctx, "r2", now); !errors.Is(err, ports.ErrNotFound) {
		t.Fatal("DeleteResetsForUser kept a reset link")
	}
	if n, _ := pr.CountWelcomesForUser(ctx, id); n != 1 {
		t.Fatal("DeleteResetsForUser removed a welcome link")
	}
	if err := pr.CreateReset(ctx, "r3", id, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := pr.DeleteWelcomesForUser(ctx, id); err != nil {
		t.Fatal(err)
	}
	if n, _ := pr.CountWelcomesForUser(ctx, id); n != 0 {
		t.Fatal("DeleteWelcomesForUser kept a welcome link")
	}
	if _, kind, err := pr.Consume(ctx, "r3", now, id); err != nil || kind != "reset" {
		t.Fatalf("DeleteWelcomesForUser removed a reset link: %q, %v", kind, err)
	}
}

// RunSignInHistory pins the contract of ports.SignInHistoryRepository.
func RunSignInHistory(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	s := open(t)
	id := mustCreate(t, s.Users(), newUser("hal", "hal@example.org"))
	other := mustCreate(t, s.Users(), newUser("ivy", "ivy@example.org"))
	h := s.SignInHistory()
	if hist, known, err := h.Stats(ctx, id, "a"); err != nil || hist != 0 || known != 0 {
		t.Fatalf("Stats on empty history = %d, %d, %v", hist, known, err)
	}
	for i, fp := range []string{"a", "b", "c"} {
		if err := h.Touch(ctx, id, fp, now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Touch(ctx, other, "a", now); err != nil {
		t.Fatal(err)
	}
	if hist, known, _ := h.Stats(ctx, id, "b"); hist != 3 || known != 1 {
		t.Fatalf("Stats = %d, %d", hist, known)
	}
	if hist, known, _ := h.Stats(ctx, id, "z"); hist != 3 || known != 0 {
		t.Fatalf("Stats(unknown) = %d, %d", hist, known)
	}
	// Touch updates: "a" becomes the newest.
	if err := h.Touch(ctx, id, "a", now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if hist, _, _ := h.Stats(ctx, id, "a"); hist != 3 {
		t.Fatal("Touch of a known fingerprint added a record")
	}
	if err := h.KeepNewest(ctx, id, 2); err != nil {
		t.Fatal(err)
	}
	if _, known, _ := h.Stats(ctx, id, "b"); known != 0 {
		t.Fatal("KeepNewest kept the oldest fingerprint")
	}
	if hist, known, _ := h.Stats(ctx, id, "a"); hist != 2 || known != 1 {
		t.Fatalf("after KeepNewest(2): %d, %d", hist, known)
	}
	// PruneBefore is exclusive: "c" was seen at now+2m.
	if err := h.PruneBefore(ctx, id, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if hist, _, _ := h.Stats(ctx, id, "c"); hist != 2 {
		t.Fatal("PruneBefore removed a fingerprint seen exactly at the cutoff")
	}
	if err := h.PruneBefore(ctx, id, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if hist, known, _ := h.Stats(ctx, id, "a"); hist != 1 || known != 1 {
		t.Fatalf("after PruneBefore: %d, %d", hist, known)
	}
	if hist, _, _ := h.Stats(ctx, other, "a"); hist != 1 {
		t.Fatal("pruning touched another account")
	}
}

// RunQuota pins the contract of ports.QuotaRepository.
func RunQuota(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	s := open(t)
	q := s.Quota()
	inherit := mustCreate(t, s.Users(), newUser("jay", "jay@example.org"))
	own := newUser("kai", "kai@example.org")
	limit := int64(12345)
	own.QuotaBytes = &limit
	ownID := mustCreate(t, s.Users(), own)
	if _, _, _, err := q.Policy(ctx, ownID+100); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("Policy of an unknown account: %v", err)
	}
	quota, inh, def, err := q.Policy(ctx, ownID)
	if err != nil || quota == nil || *quota != "12345" || inh == nil || *inh != "0" || def == nil || *def == "" {
		t.Fatalf("Policy(own quota) = %v, %v, %v, %v", quota, inh, def, err)
	}
	if _, inh, _, err := q.Policy(ctx, inherit); err != nil || inh == nil || *inh != "1" {
		t.Fatalf("Policy(inherit) = %v, %v", inh, err)
	}
	if n, err := q.CountUnattributedReservations(ctx); err != nil || n != 0 {
		t.Fatalf("CountUnattributedReservations = %d, %v", n, err)
	}
	if n, err := q.StoredBytes(ctx, ownID); err != nil || n != 0 {
		t.Fatalf("StoredBytes = %d, %v", n, err)
	}
	if n, err := q.ReservedBytes(ctx, ownID); err != nil || n != 0 {
		t.Fatalf("ReservedBytes = %d, %v", n, err)
	}
	// Stored bytes: every file of the account's shares, expired ones included.
	a := mustShare(t, s, ports.NewShare{UserID: ownID, LongID: "q-a", ExpiresAt: time.Unix(1_800_000_000, 0)})
	b := mustShare(t, s, ports.NewShare{UserID: ownID, LongID: "q-b", ExpiresAt: time.Unix(1_000_000_000, 0)})
	c := mustShare(t, s, ports.NewShare{UserID: inherit, LongID: "q-c", ExpiresAt: time.Unix(1_800_000_000, 0)})
	mustFile(t, s, localFile(a, "1", 100))
	mustFile(t, s, localFile(a, "2", 20))
	mustFile(t, s, localFile(b, "3", 3))
	mustFile(t, s, localFile(c, "4", 4000))
	if n, err := q.StoredBytes(ctx, ownID); err != nil || n != 123 {
		t.Fatalf("StoredBytes = %d, %v", n, err)
	}
	if n, _ := q.StoredBytes(ctx, inherit); n != 4000 {
		t.Fatalf("StoredBytes(other account) = %d", n)
	}
	// Reserved bytes: declared sizes of the sessions whose quota the account
	// carries (a guest's upload counts for the inviter).
	g := mustGuest(t, s, "guest-q")
	mustUpload(t, s, ports.NewUpload{ID: "q-1", UserID: ownID, QuotaOwnerID: ownID}, 10, 5)
	mustUpload(t, s, ports.NewUpload{ID: "q-2", UserID: g, QuotaOwnerID: ownID}, 7)
	mustUpload(t, s, ports.NewUpload{ID: "q-3", UserID: inherit, QuotaOwnerID: inherit}, 1000)
	if n, err := q.ReservedBytes(ctx, ownID); err != nil || n != 22 {
		t.Fatalf("ReservedBytes = %d, %v", n, err)
	}
	if n, err := q.CountUnattributedReservations(ctx); err != nil || n != 0 {
		t.Fatalf("CountUnattributedReservations = %d, %v", n, err)
	}
	mustUpload(t, s, ports.NewUpload{ID: "q-4", UserID: ownID, QuotaOwnerID: g}, 1) // a guest carries quota
	if n, _ := q.CountUnattributedReservations(ctx); n != 1 {
		t.Fatalf("CountUnattributedReservations = %d, want 1", n)
	}
	neg := localFile(c, "neg", -1)
	mustFile(t, s, neg)
	if _, err := q.StoredBytes(ctx, inherit); err == nil {
		t.Fatal("StoredBytes accepted a negative size")
	}
}
