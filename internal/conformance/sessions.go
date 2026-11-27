// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

func refreshToken(hash string, uid int64, sid string, now time.Time) ports.NewRefreshToken {
	return ports.NewRefreshToken{Hash: hash, UserID: uid, ExpiresAt: now.Add(time.Hour), IssuedAt: now, Started: now.Add(-time.Minute),
		SessionID: sid, UserAgent: "ua", IP: "192.0.2.1", Method: "password"}
}

// RunSessions pins the contract of ports.SessionRepository.
func RunSessions(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)

	t.Run("StartGuarded", func(t *testing.T) {
		s := open(t)
		id := mustCreate(t, s.Users(), newUser("ann", "ann@example.org"))
		u := mustUser(t, s.Users(), id)
		stale := guardOf(u)
		stale.PasswordHash = "other"
		if n, err := s.Sessions().StartGuarded(ctx, refreshToken("h0", id, "s0", now), stale); err != nil || n != 0 {
			t.Fatalf("stale guard stored a token: %d, %v", n, err)
		}
		if n, err := s.Sessions().StartGuarded(ctx, refreshToken("h1", id, "s1", now), guardOf(u)); err != nil || n != 1 {
			t.Fatalf("StartGuarded = %d, %v", n, err)
		}
		if n, err := s.Sessions().StartGuarded(ctx, refreshToken("h2", 999, "s2", now), guardOf(u)); err != nil || n != 0 {
			t.Fatalf("token stored for a missing account: %d, %v", n, err)
		}
		if n, err := s.Sessions().CountLive(ctx, "s1", id, now); err != nil || n != 1 {
			t.Fatalf("CountLive = %d, %v", n, err)
		}
		if n, _ := s.Sessions().CountLive(ctx, "s1", id, now.Add(time.Hour)); n != 0 {
			t.Fatal("a token is live at its expiry (expiry is exclusive)")
		}
	})

	t.Run("ConsumeAndSpent", func(t *testing.T) {
		s := open(t)
		id := mustCreate(t, s.Users(), newUser("ben", "ben@example.org"))
		sr := s.Sessions()
		if _, err := sr.ConsumeLive(ctx, "missing", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ConsumeLive of a missing token: %v", err)
		}
		if _, err := sr.Consume(ctx, "missing"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Consume of a missing token: %v", err)
		}
		rt := refreshToken("live", id, "sid", now)
		if err := sr.Insert(ctx, rt); err != nil {
			t.Fatal(err)
		}
		c, err := sr.ConsumeLive(ctx, "live", now)
		if err != nil || c.UserID != id || c.SessionID == nil || *c.SessionID != "sid" || c.Method == nil || *c.Method != "password" ||
			c.Started == nil || !c.Started.Equal(rt.Started) || c.IssuedAt == nil || !c.IssuedAt.Equal(rt.IssuedAt) {
			t.Fatalf("ConsumeLive = %+v, %v", c, err)
		}
		if _, err := sr.ConsumeLive(ctx, "live", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("a consumed token was consumed twice")
		}
		// Expired tokens are not live but can still be consumed.
		if err := sr.Insert(ctx, refreshToken("old", id, "sid", now.Add(-2*time.Hour))); err != nil {
			t.Fatal(err)
		}
		if _, err := sr.ConsumeLive(ctx, "old", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("an expired token was consumed as live")
		}
		if uid, err := sr.Consume(ctx, "old"); err != nil || uid != id {
			t.Fatalf("Consume = %d, %v", uid, err)
		}
		if err := sr.MarkSpent(ctx, "live", id, now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := sr.MarkSpent(ctx, "live", id, now.Add(time.Minute), now.Add(time.Hour)); err != nil {
			t.Fatalf("MarkSpent of a known hash must not fail: %v", err)
		}
		uid, spentAt, err := sr.FindSpent(ctx, "live", now)
		if err != nil || uid != id || !spentAt.Equal(now) {
			t.Fatalf("FindSpent = %d, %v, %v (the first record must be kept)", uid, spentAt, err)
		}
		if _, _, err := sr.FindSpent(ctx, "live", now.Add(time.Hour)); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("FindSpent at the record's expiry: %v", err)
		}
		if err := sr.DeleteSpentForUser(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, _, err := sr.FindSpent(ctx, "live", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteSpentForUser kept a record")
		}
	})

	t.Run("ListAndRevoke", func(t *testing.T) {
		s := open(t)
		id := mustCreate(t, s.Users(), newUser("cy", "cy@example.org"))
		other := mustCreate(t, s.Users(), newUser("di", "di@example.org"))
		sr := s.Sessions()
		for _, rt := range []ports.NewRefreshToken{
			refreshToken("a", id, "s-a", now), refreshToken("b", id, "s-b", now), refreshToken("c", id, "s-c", now),
			refreshToken("x", other, "s-x", now), refreshToken("gone", id, "s-gone", now.Add(-2*time.Hour)),
		} {
			if err := sr.Insert(ctx, rt); err != nil {
				t.Fatal(err)
			}
		}
		l, err := sr.ListLive(ctx, id, now)
		if err != nil {
			t.Fatal(err)
		}
		var sids []string
		for _, x := range l {
			sids = append(sids, x.SessionID)
			if x.Started == nil || x.IssuedAt == nil || x.UserAgent != "ua" || x.IP != "192.0.2.1" || x.Method != "password" {
				t.Fatalf("session row = %+v", x)
			}
		}
		sort.Strings(sids)
		if len(sids) != 3 || sids[0] != "s-a" || sids[2] != "s-c" {
			t.Fatalf("ListLive sessions = %v", sids)
		}
		if n, err := sr.RevokeSession(ctx, id, "s-x"); err != nil || n != 0 {
			t.Fatalf("revoked another account's session: %d, %v", n, err)
		}
		if n, err := sr.RevokeSession(ctx, id, "s-a"); err != nil || n != 1 {
			t.Fatalf("RevokeSession = %d, %v", n, err)
		}
		if n, err := sr.RevokeOtherSessions(ctx, id, "s-b"); err != nil || n != 2 { // s-c and the expired s-gone
			t.Fatalf("RevokeOtherSessions = %d, %v", n, err)
		}
		if n, err := sr.RevokeAllForUser(ctx, id); err != nil || n != 1 {
			t.Fatalf("RevokeAllForUser = %d, %v", n, err)
		}
		if n, _ := sr.CountLive(ctx, "s-x", other, now); n != 1 {
			t.Fatal("revoking one account touched another")
		}
	})

	t.Run("RevokedAccessTokens", func(t *testing.T) {
		sr := open(t).Sessions()
		if n, err := sr.CountRevokedAccess(ctx, "tok", now); err != nil || n != 0 {
			t.Fatalf("CountRevokedAccess on empty store = %d, %v", n, err)
		}
		if err := sr.RevokeAccessToken(ctx, "tok", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if err := sr.RevokeAccessToken(ctx, "tok", now.Add(time.Hour)); err != nil {
			t.Fatalf("revoking twice must not fail: %v", err)
		}
		if n, _ := sr.CountRevokedAccess(ctx, "tok", now); n != 1 {
			t.Fatalf("CountRevokedAccess = %d, want 1", n)
		}
		if n, _ := sr.CountRevokedAccess(ctx, "tok", now.Add(time.Minute)); n != 0 {
			t.Fatal("the first record must be kept and expire exclusively")
		}
	})
}

// RunPasswordResets pins the contract of ports.PasswordResetRepository.
func RunPasswordResets(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	setup := func(t *testing.T) (ports.Store, int64) {
		s := open(t)
		nu := newUser("eve", "eve@example.org")
		nu.EmailVerified = true
		id, err := s.Users().CreateRegistered(ctx, nu)
		if err != nil {
			t.Fatal(err)
		}
		return s, id
	}

	t.Run("CreateForVerified", func(t *testing.T) {
		s, id := setup(t)
		pr := s.PasswordResets()
		if n, err := pr.CreateForVerified(ctx, "r0", id, now.Add(time.Hour), "eve@example.org", "wrong"); err != nil || n != 0 {
			t.Fatalf("stale hash created a link: %d, %v", n, err)
		}
		if n, err := pr.CreateForVerified(ctx, "r1", id, now.Add(time.Hour), "eve@example.org", "hash-eve"); err != nil || n != 1 {
			t.Fatalf("CreateForVerified = %d, %v", n, err)
		}
		unverified, err := s.Users().CreateRegistered(ctx, newUser("fay", "fay@example.org"))
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := pr.CreateForVerified(ctx, "r2", unverified, now.Add(time.Hour), "fay@example.org", "hash-fay"); n != 0 {
			t.Fatal("link created for an unverified address")
		}
		if uid, err := pr.UserFor(ctx, "r1", now); err != nil || uid != id {
			t.Fatalf("UserFor = %d, %v", uid, err)
		}
		if _, err := pr.UserFor(ctx, "r1", now.Add(time.Hour)); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("UserFor at expiry: %v", err)
		}
	})

	t.Run("ConsumeAndDelete", func(t *testing.T) {
		s, id := setup(t)
		pr := s.PasswordResets()
		for _, h := range []string{"r1", "r2", "r3"} {
			if n, err := pr.CreateForVerified(ctx, h, id, now.Add(time.Hour), "eve@example.org", "hash-eve"); err != nil || n != 1 {
				t.Fatalf("create %s: %d, %v", h, n, err)
			}
		}
		if _, _, err := pr.Consume(ctx, "r1", now, id+1); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Consume for another account: %v", err)
		}
		uid, kind, err := pr.Consume(ctx, "r1", now, id)
		if err != nil || uid != id || kind != "reset" {
			t.Fatalf("Consume = %d, %q, %v", uid, kind, err)
		}
		if _, _, err := pr.Consume(ctx, "r1", now, id); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("a link was consumed twice")
		}
		if err := pr.Delete(ctx, "r2"); err != nil {
			t.Fatal(err)
		}
		if err := pr.Delete(ctx, "missing"); err != nil {
			t.Fatalf("deleting a missing link must not fail: %v", err)
		}
		if _, err := pr.UserFor(ctx, "r2", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("Delete kept the link")
		}
		if err := pr.DeleteForUser(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, err := pr.UserFor(ctx, "r3", now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteForUser kept a link")
		}
	})
}

// RunEmailVerifications pins the contract of ports.EmailVerificationRepository.
func RunEmailVerifications(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)

	t.Run("PutAndFind", func(t *testing.T) {
		s := open(t)
		nu := newUser("gus", "gus@example.org")
		nu.PendingRegistration = true
		id, err := s.Users().CreateRegistered(ctx, nu)
		if err != nil {
			t.Fatal(err)
		}
		ev := s.EmailVerifications()
		if _, _, _, _, err := ev.FindByUniqueEmail(ctx, "gus@example.org"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Find without a code: %v", err)
		}
		if err := ev.Put(ctx, id, "11111111", now); err != nil {
			t.Fatal(err)
		}
		if err := ev.Put(ctx, id, "22222222", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		uid, code, exp, pending, err := ev.FindByUniqueEmail(ctx, "gus@example.org")
		if err != nil || uid != id || code != "22222222" || !exp.Equal(now.Add(time.Minute)) || !pending {
			t.Fatalf("Find = %d %q %v %v %v", uid, code, exp, pending, err)
		}
		if err := ev.DeleteForUser(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := ev.FindByUniqueEmail(ctx, "gus@example.org"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("DeleteForUser kept the code")
		}
	})

	t.Run("RecordAttemptWindow", func(t *testing.T) {
		s := open(t)
		id := mustCreate(t, s.Users(), newUser("hal", "hal@example.org"))
		ev := s.EmailVerifications()
		end := now.Add(30 * time.Minute)
		for want := 1; want <= 3; want++ {
			if n, err := ev.RecordAttempt(ctx, id, end, now); err != nil || n != want {
				t.Fatalf("attempt %d = %d, %v", want, n, err)
			}
		}
		// The window ends at its expiry (inclusive): the count starts again.
		if n, err := ev.RecordAttempt(ctx, id, end.Add(30*time.Minute), end); err != nil || n != 1 {
			t.Fatalf("attempt in a new window = %d, %v", n, err)
		}
		if err := ev.DeleteAttempts(ctx, id); err != nil {
			t.Fatal(err)
		}
		if n, _ := ev.RecordAttempt(ctx, id, end, now); n != 1 {
			t.Fatal("DeleteAttempts kept the counter")
		}
	})
}

// RunPasswordHistory pins the contract of ports.PasswordHistoryRepository.
func RunPasswordHistory(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	at := time.Unix(1_800_000_000, 0).UTC()

	t.Run("RememberAndPrune", func(t *testing.T) {
		s := open(t)
		id := mustCreate(t, s.Users(), newUser("ida", "ida@example.org"))
		ph := s.PasswordHistory()
		if h, err := ph.Recent(ctx, id, 5); err != nil || len(h) != 0 {
			t.Fatalf("Recent on empty history = %v, %v", h, err)
		}
		cur := "hash-ida"
		for _, next := range []string{"p1", "p2", "p3"} {
			if err := ph.Remember(ctx, id, 2, at); err != nil {
				t.Fatal(err)
			}
			if n, err := s.Users().ReplacePasswordHash(ctx, id, next, cur); err != nil || n != 1 {
				t.Fatalf("replace hash: %d, %v", n, err)
			}
			cur = next
		}
		h, err := ph.Recent(ctx, id, 5)
		if err != nil || len(h) != 2 || h[0] != "p2" || h[1] != "p1" {
			t.Fatalf("Recent = %v, %v (want the newest 2, newest first)", h, err)
		}
		if h, _ := ph.Recent(ctx, id, 1); len(h) != 1 || h[0] != "p2" {
			t.Fatalf("Recent(1) = %v", h)
		}
		if err := ph.Remember(ctx, id, 0, at); err != nil {
			t.Fatal(err)
		}
		if h, _ := ph.Recent(ctx, id, 5); len(h) != 0 {
			t.Fatalf("keep=0 left %v", h)
		}
	})
}

// RunAuthProviders pins the contract of ports.AuthProviderRepository. Until
// providers can be created through the port (batch E), it covers the empty
// state.
func RunAuthProviders(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	t.Run("Empty", func(t *testing.T) {
		s := open(t)
		id := mustCreate(t, s.Users(), newUser("jo", "jo@example.org"))
		ap := s.AuthProviders()
		for name, f := range map[string]func() (int, error){
			"CountEnabled":             func() (int, error) { return ap.CountEnabled(ctx) },
			"CountLinks":               func() (int, error) { return ap.CountLinks(ctx, id) },
			"CountEnabledLinks":        func() (int, error) { return ap.CountEnabledLinks(ctx, id) },
			"CountEnabledLinksOfLocal": func() (int, error) { return ap.CountEnabledLinksOfLocal(ctx, id) },
			"CountEnabledLinksExcept":  func() (int, error) { return ap.CountEnabledLinksExcept(ctx, id, 1) },
			"CountEnabledLink":         func() (int, error) { return ap.CountEnabledLink(ctx, id, 1) },
			"CountExternalAdmins":      func() (int, error) { return ap.CountExternalAdmins(ctx, 0, 0, 0, 0) },
		} {
			if n, err := f(); err != nil || n != 0 {
				t.Fatalf("%s = %d, %v", name, n, err)
			}
		}
		if l, err := ap.ListLinked(ctx, id); err != nil || len(l) != 0 {
			t.Fatalf("ListLinked = %v, %v", l, err)
		}
		if l, err := ap.ListLinkTypes(ctx); err != nil || len(l) != 0 {
			t.Fatalf("ListLinkTypes = %v, %v", l, err)
		}
		if err := ap.Unlink(ctx, id, 1); err != nil {
			t.Fatalf("Unlink of a missing link must not fail: %v", err)
		}
	})
}

// RunTx pins the transaction contract of ports.Store.Begin.
func RunTx(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()

	t.Run("CommitPersists", func(t *testing.T) {
		s := open(t)
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		id, err := tx.Users().Create(ctx, newUser("kim", "kim@example.org"))
		if err != nil {
			t.Fatal(err)
		}
		if u, err := tx.Users().ByID(ctx, id); err != nil || u.Username != "kim" {
			t.Fatalf("read inside the transaction = %+v, %v", u, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(); err == nil {
			t.Log("Rollback after Commit returned nil") // allowed: the error is ignored by callers
		}
		mustUser(t, s.Users(), id)
	})

	t.Run("RollbackDiscards", func(t *testing.T) {
		s := open(t)
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Users().Create(ctx, newUser("lou", "lou@example.org")); err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		if n, _ := s.Users().Count(ctx); n != 0 {
			t.Fatalf("rolled back insert is visible: %d accounts", n)
		}
	})
}
