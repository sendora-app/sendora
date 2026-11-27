// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunSettings pins the contract of ports.SettingsRepository.
func RunSettings(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	t.Run("EditableOnly", func(t *testing.T) {
		st := open(t).Settings()
		list, err := st.ListEditable(ctx)
		if err != nil || len(list) == 0 {
			t.Fatalf("ListEditable on a seeded store = %d rows, %v", len(list), err)
		}
		value := map[string]string{}
		for i, x := range list {
			if x.Group == "secret" || x.Group == "email_templates" || x.Key == "jwt_secret" {
				t.Fatalf("ListEditable returned %+v", x)
			}
			if i > 0 && list[i-1].Key > x.Key {
				t.Fatal("ListEditable is not ordered by key")
			}
			value[x.Key] = x.Value
		}
		keys, err := st.EditableKeys(ctx)
		if err != nil || len(keys) < len(list) {
			t.Fatalf("EditableKeys = %d keys, %v", len(keys), err)
		}
		if _, ok := value["application_name"]; !ok {
			t.Fatal("application_name is not editable")
		}
		if err := st.UpdateEditable(ctx, "application_name", "Renamed"); err != nil {
			t.Fatal(err)
		}
		if err := st.UpdateEditable(ctx, "no_such_key", "x"); err != nil {
			t.Fatalf("UpdateEditable of a missing key: %v", err)
		}
		if err := st.Update(ctx, "default_language", "de"); err != nil {
			t.Fatal(err)
		}
		if err := st.Clear(ctx, "ui_logo"); err != nil {
			t.Fatal(err)
		}
		list, _ = st.ListEditable(ctx)
		got := map[string]string{}
		for _, x := range list {
			got[x.Key] = x.Value
		}
		if got["application_name"] != "Renamed" || got["default_language"] != "de" {
			t.Fatalf("updates not stored: %q %q", got["application_name"], got["default_language"])
		}
		if _, ok := got["no_such_key"]; ok {
			t.Fatal("UpdateEditable created a key")
		}
		ordered, err := st.EditableKeysOrdered(ctx)
		if err != nil || len(ordered) != len(keys) {
			t.Fatalf("EditableKeysOrdered = %d keys, %v (EditableKeys: %d)", len(ordered), err, len(keys))
		}
		for i := 1; i < len(ordered); i++ {
			if ordered[i-1] >= ordered[i] {
				t.Fatalf("EditableKeysOrdered not in byte order at %q, %q", ordered[i-1], ordered[i])
			}
		}
		if err := st.SetApplicationURL(ctx, "https://files.example.org"); err != nil {
			t.Fatal(err)
		}
		if v, err := st.Get(ctx, "application_url"); err != nil || v != "https://files.example.org" {
			t.Fatalf("application_url after SetApplicationURL = %q, %v", v, err)
		}
	})
}

// RunThemes pins the contract of ports.ThemeRepository.
func RunThemes(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	t.Run("Lifecycle", func(t *testing.T) {
		s := open(t)
		th := s.Themes()
		before, err := th.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := th.Create(ctx, "zz custom", `{"primary":"#000"}`); err != nil {
			t.Fatal(err)
		}
		if err := th.Create(ctx, "zz custom", `{}`); err == nil {
			t.Fatal("a taken theme name was accepted")
		}
		all, _ := th.List(ctx)
		if len(all) != len(before)+1 {
			t.Fatalf("List = %d themes, want %d", len(all), len(before)+1)
		}
		var custom ports.ThemeRecord
		seenCustom := false
		for _, x := range all {
			if x.Bundled && seenCustom {
				t.Fatal("bundled themes must come first")
			}
			if !x.Bundled {
				seenCustom = true
			}
			if x.Name == "zz custom" {
				custom = x
			}
		}
		if custom.ID == 0 || custom.Data != `{"primary":"#000"}` || custom.Bundled || custom.Active {
			t.Fatalf("custom theme = %+v", custom)
		}
		if n, err := th.UpdateCustom(ctx, custom.ID, "zz renamed", `{}`); err != nil || n != 1 {
			t.Fatalf("UpdateCustom = %d, %v", n, err)
		}
		for _, x := range before {
			if x.Bundled {
				if n, _ := th.UpdateCustom(ctx, x.ID, "hijack", `{}`); n != 0 {
					t.Fatal("UpdateCustom changed a bundled theme")
				}
				break
			}
		}
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Themes().DeactivateAll(ctx); err != nil {
			t.Fatal(err)
		}
		if n, err := tx.Themes().Activate(ctx, custom.ID); err != nil || n != 1 {
			t.Fatalf("Activate = %d, %v", n, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if a, _ := th.ListActive(ctx); len(a) != 1 || a[0].ID != custom.ID {
			t.Fatalf("ListActive = %+v", a)
		}
		if n, _ := th.DeleteCustomInactive(ctx, custom.ID); n != 0 {
			t.Fatal("the active theme was deleted")
		}
		if n, _ := th.Activate(ctx, 99999); n != 0 {
			t.Fatal("Activate of a missing theme reported a change")
		}
		if err := th.DeactivateAll(ctx); err != nil {
			t.Fatal(err)
		}
		if n, err := th.DeleteCustomInactive(ctx, custom.ID); err != nil || n != 1 {
			t.Fatalf("DeleteCustomInactive = %d, %v", n, err)
		}
	})
}

// RunStats pins the contract of ports.StatsRepository.
func RunStats(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Now()
	s := open(t)
	st := s.Stats()
	owner := mustCreate(t, s.Users(), newUser("sam", "sam@example.org"))
	mustGuest(t, s, "guest-s")
	active := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-1", Name: "A", ExpiresAt: now.Add(time.Hour)})
	mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-2", Name: "B", ExpiresAt: now.Add(-time.Hour)})
	mustFile(t, s, localFile(active, "a.txt", 10))
	mustFile(t, s, localFile(active, "b.txt", 5))
	if err := s.Downloads().Record(ctx, active, nil, "", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		f    func() (int64, error)
		want int64
	}{
		"CountLocalUsers":   {func() (int64, error) { return st.CountLocalUsers(ctx) }, 1},
		"CountShares":       {func() (int64, error) { return st.CountShares(ctx) }, 2},
		"CountActiveShares": {func() (int64, error) { return st.CountActiveShares(ctx, now) }, 1},
		"CountFiles":        {func() (int64, error) { return st.CountFiles(ctx) }, 2},
		"SumFileBytes":      {func() (int64, error) { return st.SumFileBytes(ctx) }, 15},
		"CountDownloads":    {func() (int64, error) { return st.CountDownloads(ctx) }, 1},
	} {
		if n, err := c.f(); err != nil || n != c.want {
			t.Errorf("%s = %d, %v (want %d)", name, n, err, c.want)
		}
	}
	days, err := st.DownloadsPerDay(ctx, now.AddDate(0, 0, -14))
	if err != nil || len(days) != 1 || days[0].Count != 1 || len(days[0].Day) != len("2006-01-02") {
		t.Fatalf("DownloadsPerDay = %+v, %v", days, err)
	}
}

// RunMaintenance pins the contract of ports.MaintenanceRepository.
func RunMaintenance(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Now()

	t.Run("Shares", func(t *testing.T) {
		s := open(t)
		m := s.Maintenance()
		owner := mustCreate(t, s.Users(), newUser("una", "una@example.org"))
		soon := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-soon", Name: "Soon", ExpiresAt: now.Add(time.Hour)})
		past := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-past", Name: "Past", ExpiresAt: now.Add(-48 * time.Hour)})
		mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-later", Name: "Later", ExpiresAt: now.Add(30 * 24 * time.Hour)})
		warn, err := m.SharesToWarn(ctx, now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		ids := map[int64]bool{}
		for _, x := range warn {
			ids[x.ID] = true
			if x.OwnerEmail != "una@example.org" || x.LongID == "" {
				t.Fatalf("warning row = %+v", x)
			}
		}
		if !ids[soon] || !ids[past] || len(warn) != 2 {
			t.Fatalf("SharesToWarn = %+v", warn)
		}
		if err := m.MarkExpiryWarned(ctx, soon); err != nil {
			t.Fatal(err)
		}
		if n, err := m.ExpireShares(ctx, now); err != nil || n != 1 {
			t.Fatalf("ExpireShares = %d, %v", n, err)
		}
		if warn, _ := m.SharesToWarn(ctx, now.Add(24*time.Hour)); len(warn) != 0 {
			t.Fatalf("warned or expired shares still listed: %+v", warn)
		}
		if r, err := m.RetiredShareIDs(ctx, now.Add(-24*time.Hour)); err != nil || len(r) != 1 || r[0] != past {
			t.Fatalf("RetiredShareIDs = %v, %v", r, err)
		}
		if r, _ := m.RetiredShareIDs(ctx, now.Add(-72*time.Hour)); len(r) != 0 {
			t.Fatalf("RetiredShareIDs before expiry = %v", r)
		}
	})

	t.Run("UploadsAndCredentials", func(t *testing.T) {
		s := open(t)
		m := s.Maintenance()
		owner := mustCreate(t, s.Users(), newUser("vic", "vic@example.org"))
		mustUpload(t, s, ports.NewUpload{ID: "u-stale", UserID: owner, QuotaOwnerID: owner})
		future := now.UTC().Add(time.Hour).Format("2006-01-02 15:04:05")
		pastTS := now.UTC().Add(-time.Hour).Format("2006-01-02 15:04:05")
		if ids, err := m.StaleUploadIDs(ctx, future); err != nil || len(ids) != 1 || ids[0] != "u-stale" {
			t.Fatalf("StaleUploadIDs = %v, %v", ids, err)
		}
		if ids, _ := m.StaleUploadIDs(ctx, pastTS); len(ids) != 0 {
			t.Fatalf("fresh upload listed as stale: %v", ids)
		}
		if n, _ := m.CountStaleUpload(ctx, "u-stale", future); n != 1 {
			t.Fatal("CountStaleUpload missed the session")
		}
		if n, _ := m.CountStaleUpload(ctx, "nope", future); n != 0 {
			t.Fatal("CountStaleUpload found a missing session")
		}
		if err := s.Sessions().Insert(ctx, refreshToken("old", owner, "s", now.Add(-2*time.Hour))); err != nil {
			t.Fatal(err)
		}
		if err := s.Sessions().Insert(ctx, refreshToken("live", owner, "s2", now)); err != nil {
			t.Fatal(err)
		}
		m.PruneExpiredCredentials(ctx, now)
		if _, err := s.Sessions().Consume(ctx, "old"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("an expired refresh token survived")
		}
		if _, err := s.Sessions().Consume(ctx, "live"); err != nil {
			t.Fatalf("a live refresh token was pruned: %v", err)
		}
		if err := m.PruneDownloads(ctx, future); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("RemoveAccounts", func(t *testing.T) {
		s := open(t)
		m := s.Maintenance()
		pending := newUser("wes", "wes@example.org")
		pending.PendingRegistration = true
		id, err := s.Users().CreateRegistered(ctx, pending)
		if err != nil {
			t.Fatal(err)
		}
		keep := mustCreate(t, s.Users(), newUser("xia", "xia@example.org"))
		if gone, err := m.RemoveUnverifiedRegistrations(ctx, "2000-01-01 00:00:00"); err != nil || len(gone) != 0 {
			t.Fatalf("young registration removed: %v, %v", gone, err)
		}
		gone, err := m.RemoveUnverifiedRegistrations(ctx, "2999-01-01 00:00:00")
		if err != nil || len(gone) != 1 || gone[0].ID != id || gone[0].Username != "wes" {
			t.Fatalf("RemoveUnverifiedRegistrations = %+v, %v", gone, err)
		}
		mustUser(t, s.Users(), keep)
		if g, err := m.RemoveExpiredLinkGuests(ctx, now); err != nil || len(g) != 0 {
			t.Fatalf("RemoveExpiredLinkGuests = %v, %v", g, err)
		}
		if err := m.RemoveOrphanedLinkInvites(ctx, now); err != nil {
			t.Fatal(err)
		}
	})
}

// RunPersonalData pins the contract of ports.PersonalDataRepository and the
// erasure methods of ports.UserRepository.
func RunPersonalData(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	now := time.Now()

	t.Run("Export", func(t *testing.T) {
		s := open(t)
		pd := s.PersonalData()
		id := mustCreate(t, s.Users(), newUser("yan", "yan@example.org"))
		if v, at, err := pd.Terms(ctx, id); err != nil || v != "" || at != nil {
			t.Fatalf("Terms = %q %v %v", v, at, err)
		}
		if _, err := pd.TOTPCreated(ctx, id); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("TOTPCreated without a factor: %v", err)
		}
		share := mustShare(t, s, ports.NewShare{UserID: id, LongID: "long-y", Name: "Mine", ExpiresAt: now.Add(time.Hour)})
		mustFile(t, s, localFile(share, "y.txt", 3))
		if err := s.Sessions().Insert(ctx, refreshToken("tok", id, "sid", now)); err != nil {
			t.Fatal(err)
		}
		shares := pd.Section(ctx, ports.ExportShares, id, 10)
		if len(shares) != 1 || shares[0]["name"] != "Mine" || shares[0]["file_count"] != int64(1) || shares[0]["total_bytes"] != int64(3) {
			t.Fatalf("shares section = %+v", shares)
		}
		if exp, ok := shares[0]["expires_at"].(string); !ok || exp == "" {
			t.Fatalf("expires_at = %#v, want RFC 3339 text", shares[0]["expires_at"])
		}
		if f := pd.Section(ctx, ports.ExportShareFiles, id, 10); len(f) != 1 || f[0]["path"] != "y.txt" {
			t.Fatalf("share_files section = %+v", f)
		}
		if ses := pd.Section(ctx, ports.ExportSessions, id, 10); len(ses) != 1 {
			t.Fatalf("sessions section = %+v", ses)
		}
		for _, sec := range []ports.ExportSection{ports.ExportLinkedLogins, ports.ExportDownloadHistory, ports.ExportInvites, ports.ExportAuditRecords, "unknown"} {
			if rows := pd.Section(ctx, sec, id, 10); rows == nil || len(rows) != 0 {
				t.Fatalf("%s section = %#v, want an empty list", sec, rows)
			}
		}
	})

	t.Run("Erasure", func(t *testing.T) {
		s := open(t)
		u := s.Users()
		admin, _, err := u.CreateFirstAdmin(ctx, newUser("root", "root@example.org"))
		if err != nil {
			t.Fatal(err)
		}
		id := mustCreate(t, u, newUser("zoe", "zoe@example.org"))
		mustShare(t, s, ports.NewShare{UserID: id, LongID: "long-z", Name: "Z"})
		if a, err := u.IsAdmin(ctx, admin); err != nil || !a {
			t.Fatalf("IsAdmin = %v, %v", a, err)
		}
		if _, err := u.IsAdmin(ctx, 999); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("IsAdmin of a missing account: %v", err)
		}
		if n, _ := u.CountOtherUnerasedAdmins(ctx, admin); n != 0 {
			t.Fatalf("CountOtherUnerasedAdmins = %d", n)
		}
		if at, err := u.ErasedAt(ctx, id); err != nil || at != nil {
			t.Fatalf("ErasedAt before erasure = %v, %v", at, err)
		}
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := tx.Users().LockForErasure(ctx, id); err != nil || n != 1 {
			t.Fatalf("LockForErasure = %d, %v", n, err)
		}
		if err := tx.Users().EraseWithOwnedData(ctx, id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		rec := mustUser(t, u, id)
		if rec.Username != "erased-"+itoa(id) || rec.Email != "" || rec.PasswordHash != "" {
			t.Fatalf("erased account = %+v", rec)
		}
		if at, err := u.ErasedAt(ctx, id); err != nil || at == nil {
			t.Fatalf("ErasedAt after erasure = %v, %v", at, err)
		}
		if n, _ := u.LockForErasure(ctx, id); n != 0 {
			t.Fatal("an erased account can be erased again")
		}
		if n, _ := s.Shares().CountOwnedOrReceived(ctx, id); n != 0 {
			t.Fatal("erasure kept the account's shares")
		}
	})

	t.Run("ResetIdentityAndCopy", func(t *testing.T) {
		s := open(t)
		nu := newUser("abe", "abe@example.org")
		nu.EmailVerified = true
		id, err := s.Users().CreateRegistered(ctx, nu)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.PasswordResets().CreateForVerified(ctx, "rh", id, now.Add(time.Hour), "abe@example.org", "hash-abe"); err != nil {
			t.Fatal(err)
		}
		if name, email, err := s.PasswordResets().Identity(ctx, "rh", now); err != nil || name != "abe" || email != "abe@example.org" {
			t.Fatalf("Identity = %q %q %v", name, email, err)
		}
		if _, _, err := s.PasswordResets().Identity(ctx, "rh", now.Add(time.Hour)); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Identity at expiry: %v", err)
		}
		p := filepath.Join(t.TempDir(), "copy.db")
		switch err := s.System().CopyTo(ctx, p); {
		case errors.Is(err, ports.ErrUnsupported):
			// allowed: only file-based backends can copy themselves to a path
		case err != nil:
			t.Fatal(err)
		default:
			if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
				t.Fatalf("copy = %v, %v", fi, err)
			}
		}
	})
}
