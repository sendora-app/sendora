// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// mustInvite creates a top-level invite through the port.
func mustInvite(t *testing.T, s ports.Repositories, in ports.NewInvite) int64 {
	t.Helper()
	id, err := s.ReverseInvites().Create(context.Background(), in)
	if err != nil {
		t.Fatalf("create invite %s: %v", in.Token, err)
	}
	return id
}

// mustGuest creates a guest account through the port.
func mustGuest(t *testing.T, s ports.Repositories, username string) int64 {
	t.Helper()
	id, err := s.Users().CreateGuest(context.Background(), username, "Guest "+username)
	if err != nil {
		t.Fatalf("create guest %s: %v", username, err)
	}
	return id
}

// RunReverseInvites pins the contract of ports.ReverseInviteRepository and
// the guest-account methods of ports.UserRepository.
func RunReverseInvites(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()

	t.Run("Empty", func(t *testing.T) {
		s := open(t)
		if n, err := s.ReverseInvites().CountOpenForGuest(ctx, 1, now); err != nil || n != 0 {
			t.Fatalf("CountOpenForGuest = %d, %v", n, err)
		}
		if l, err := s.ReverseInvites().ListOwned(ctx, 1, now); err != nil || len(l) != 0 {
			t.Fatalf("ListOwned = %v, %v", l, err)
		}
		if _, err := s.ReverseInvites().ForAccept(ctx, "nope"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ForAccept of an unknown token: %v", err)
		}
		if err := s.ReverseInvites().LockToken(ctx, "nope"); err != nil {
			t.Fatalf("LockToken of an unknown token: %v", err)
		}
	})

	t.Run("Guests", func(t *testing.T) {
		s := open(t)
		g := mustGuest(t, s, "guest-a")
		u, err := s.Users().GuestByID(ctx, g)
		if err != nil || !u.IsGuest || u.Username != "guest-a" || u.Name != "Guest guest-a" || u.Email != "" || u.PasswordHash != "" {
			t.Fatalf("GuestByID = %+v, %v", u, err)
		}
		if _, err := s.Users().CreateGuest(ctx, "guest-a", "again"); err == nil {
			t.Fatal("a taken guest username was accepted")
		}
		local := mustCreate(t, s.Users(), newUser("owner", "owner@example.org"))
		if _, err := s.Users().GuestByID(ctx, local); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("GuestByID of a non-guest: %v", err)
		}
		if _, err := s.Users().GuestByID(ctx, g+100); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("GuestByID of an unknown id: %v", err)
		}
	})

	t.Run("CreateListExpire", func(t *testing.T) {
		s := open(t)
		ri := s.ReverseInvites()
		owner := mustCreate(t, s.Users(), newUser("ann", "ann@example.org"))
		other := mustCreate(t, s.Users(), newUser("ben", "ben@example.org"))
		email := mustInvite(t, s, ports.NewInvite{Token: "t-email", UserID: owner, RecipientName: "Rita", RecipientEmail: "rita@example.org",
			Message: "hi", ExpiresAt: now.Add(48 * time.Hour)})
		openID := mustInvite(t, s, ports.NewInvite{Token: "t-open", UserID: owner, RecipientName: "Team", ExpiresAt: now.Add(72 * time.Hour),
			Reusable: true, MaxUploads: 5})
		mustInvite(t, s, ports.NewInvite{Token: "t-other", UserID: other, ExpiresAt: now.Add(time.Hour)})
		if _, err := ri.Create(ctx, ports.NewInvite{Token: "t-email", UserID: owner, ExpiresAt: now}); err == nil {
			t.Fatal("a stored token was accepted again")
		}
		// Two children of the open link: one open, one already expired.
		g1, g2 := mustGuest(t, s, "guest-1"), mustGuest(t, s, "guest-2")
		for _, c := range []ports.NewChildInvite{
			{Token: "c-1", UserID: owner, RecipientName: "Team", GuestUserID: g1, ExpiresAt: now.Add(24 * time.Hour), ParentID: openID},
			{Token: "c-2", UserID: owner, RecipientName: "Team", GuestUserID: g2, ExpiresAt: now.Add(-time.Minute), ParentID: openID},
		} {
			if err := ri.CreateChild(ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := ri.CountOpenForGuest(ctx, g1, now); err != nil || n != 1 {
			t.Fatalf("CountOpenForGuest(open child) = %d, %v", n, err)
		}
		if n, _ := ri.CountOpenForGuest(ctx, g2, now); n != 0 {
			t.Fatalf("CountOpenForGuest(expired child) = %d", n)
		}
		list, err := ri.ListOwned(ctx, owner, now)
		if err != nil || len(list) != 2 {
			t.Fatalf("ListOwned = %+v, %v (children and other owners' invites must not be listed)", list, err)
		}
		// Same creation second: the higher id comes first.
		if list[0].ID != openID || list[1].ID != email {
			t.Fatalf("ListOwned order = %d, %d", list[0].ID, list[1].ID)
		}
		o, e := list[0], list[1]
		if !o.Reusable || o.MaxUploads != 5 || o.Token != "t-open" || o.Used != 0 || o.Pending != 1 || o.CompletedAt != nil {
			t.Fatalf("open link summary = %+v", o)
		}
		if e.Reusable || e.RecipientName != "Rita" || e.RecipientEmail != "rita@example.org" || !e.ExpiresAt.Equal(now.Add(48*time.Hour)) {
			t.Fatalf("email invite summary = %+v", e)
		}
		// ExpireOwned: only the owner's top-level invites.
		if n, err := ri.ExpireOwned(ctx, email, other, now); err != nil || n != 0 {
			t.Fatalf("ExpireOwned by another account = %d, %v", n, err)
		}
		child, err := ri.ForAccept(ctx, "c-1")
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := ri.ExpireOwned(ctx, child.ID, owner, now); n != 0 {
			t.Fatal("ExpireOwned changed a child invite")
		}
		if n, err := ri.ExpireOwned(ctx, openID, owner, now); err != nil || n != 1 {
			t.Fatalf("ExpireOwned = %d, %v", n, err)
		}
		if err := ri.ExpireOpenChildren(ctx, openID, other, now); err != nil {
			t.Fatal(err)
		}
		if n, _ := ri.CountOpenForGuest(ctx, g1, now); n != 1 {
			t.Fatal("ExpireOpenChildren with another owner changed a child")
		}
		if err := ri.ExpireOpenChildren(ctx, openID, owner, now); err != nil {
			t.Fatal(err)
		}
		if n, _ := ri.CountOpenForGuest(ctx, g1, now); n != 0 {
			t.Fatal("ExpireOpenChildren kept a child open")
		}
		if list, _ := ri.ListOwned(ctx, owner, now); len(list) != 2 || list[0].Pending != 0 || !list[0].ExpiresAt.Equal(now) {
			t.Fatalf("after expiry: %+v", list)
		}
	})

	t.Run("Accept", func(t *testing.T) {
		s := open(t)
		ri := s.ReverseInvites()
		named := newUser("cat", "cat@example.org")
		owner := mustCreate(t, s.Users(), named)
		unnamed := newUser("dan", "dan@example.org")
		unnamed.Name = ""
		owner2 := mustCreate(t, s.Users(), unnamed)
		id := mustInvite(t, s, ports.NewInvite{Token: "a-1", UserID: owner, RecipientName: "Rex", Message: "please", ExpiresAt: now.Add(time.Hour)})
		mustInvite(t, s, ports.NewInvite{Token: "a-2", UserID: owner2, ExpiresAt: now.Add(time.Hour), Reusable: true, MaxUploads: 3})
		got, err := ri.ForAccept(ctx, "a-1")
		if err != nil || got.ID != id || got.GuestUserID != nil || got.CompletedAt != nil || got.RecipientName != "Rex" || got.Message != "please" ||
			got.InviterName != "cat" || got.Reusable || got.OwnerID != owner || got.ParentID != nil || !got.ExpiresAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("ForAccept = %+v, %v", got, err)
		}
		if got, _ := ri.ForAccept(ctx, "a-2"); got.InviterName != "dan" || !got.Reusable || got.MaxUploads != 3 {
			t.Fatalf("ForAccept (no display name) = %+v", got)
		}
		g := mustGuest(t, s, "guest-x")
		if err := ri.AssignGuest(ctx, id, g); err != nil {
			t.Fatal(err)
		}
		if got, _ := ri.ForAccept(ctx, "a-1"); got.GuestUserID == nil || *got.GuestUserID != g {
			t.Fatalf("after AssignGuest: %+v", got)
		}
		// An invite owned by a guest is never accepted.
		if _, err := ri.Create(ctx, ports.NewInvite{Token: "a-3", UserID: g, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if _, err := ri.ForAccept(ctx, "a-3"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ForAccept of a guest's invite: %v", err)
		}
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := tx.ReverseInvites().LockToken(ctx, "a-1"); err != nil {
			t.Fatal(err)
		}
		if got, err := tx.ReverseInvites().ForAccept(ctx, "a-1"); err != nil || got.ID != id {
			t.Fatalf("ForAccept inside the transaction = %+v, %v", got, err)
		}
	})

	t.Run("CountTakenSlots", func(t *testing.T) {
		s := open(t)
		ri := s.ReverseInvites()
		owner := mustCreate(t, s.Users(), newUser("eve", "eve@example.org"))
		parent := mustInvite(t, s, ports.NewInvite{Token: "p", UserID: owner, ExpiresAt: time.Now().Add(time.Hour), Reusable: true, MaxUploads: 2})
		// created_at is the database's clock: compare against the wall clock.
		wall := time.Now()
		if n, err := ri.CountTakenSlots(ctx, parent, wall, wall.Add(-time.Hour)); err != nil || n != 0 {
			t.Fatalf("CountTakenSlots without children = %d, %v", n, err)
		}
		g := mustGuest(t, s, "guest-s")
		if err := ri.CreateChild(ctx, ports.NewChildInvite{Token: "c", UserID: owner, GuestUserID: g, ExpiresAt: wall.Add(24 * time.Hour), ParentID: parent}); err != nil {
			t.Fatal(err)
		}
		if n, _ := ri.CountTakenSlots(ctx, parent, wall, wall.Add(-time.Hour)); n != 1 {
			t.Fatalf("a recent open child takes a slot: %d", n)
		}
		if n, _ := ri.CountTakenSlots(ctx, parent, wall, wall.Add(time.Hour)); n != 0 {
			t.Fatalf("an older open child without upload takes no slot: %d", n)
		}
		if n, _ := ri.CountTakenSlots(ctx, parent, wall.Add(48*time.Hour), wall.Add(-time.Hour)); n != 0 {
			t.Fatalf("an expired child takes no slot: %d", n)
		}
		if n, _ := ri.CountTakenSlots(ctx, parent+100, wall, wall.Add(-time.Hour)); n != 0 {
			t.Fatalf("another parent's slots: %d", n)
		}
	})
}
