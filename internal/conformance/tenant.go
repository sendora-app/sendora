// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunTenantLimits pins the contract of ports.TenantLimitRepository and the
// account creation of a provisioned tenant administrator.
func RunTenantLimits(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()

	t.Run("Limits", func(t *testing.T) {
		s := open(t)
		tl := s.TenantLimits()
		if _, err := tl.MaxUsers(ctx); err == nil {
			t.Fatal("MaxUsers before Enable must fail")
		}
		for i := 0; i < 2; i++ { // idempotent
			if err := tl.Enable(ctx); err != nil {
				t.Fatalf("Enable #%d: %v", i, err)
			}
		}
		if n, err := tl.MaxUsers(ctx); err != nil || n != 0 {
			t.Fatalf("MaxUsers = %d, %v (want unlimited)", n, err)
		}
		if n, err := s.Quota().TenantStorageLimit(ctx); err != nil || n != 0 {
			t.Fatalf("TenantStorageLimit = %d, %v", n, err)
		}
		if err := tl.Set(ctx, 2, 1<<30); err != nil {
			t.Fatal(err)
		}
		if err := tl.Enable(ctx); err != nil { // keeps stored limits
			t.Fatal(err)
		}
		if n, _ := tl.MaxUsers(ctx); n != 2 {
			t.Fatalf("MaxUsers after Set = %d", n)
		}
		if n, _ := s.Quota().TenantStorageLimit(ctx); n != 1<<30 {
			t.Fatalf("TenantStorageLimit after Set = %d", n)
		}
		mustCreate(t, s.Users(), newUser("ann", "ann@example.org"))
		mustGuest(t, s, "guest-1") // guests do not count
		if _, err := s.Users().CreateProvisionedAdmin(ctx, "bob", "bob@example.org", "h", time.Now().UTC()); err != nil {
			t.Fatalf("second account: %v", err)
		}
		_, err := s.Users().Create(ctx, newUser("cid", "cid@example.org"))
		if err == nil || !strings.Contains(err.Error(), "tenant user limit") {
			t.Fatalf("third account: %v (want the tenant user limit)", err)
		}
		_, err = s.Users().CreateProvisionedAdmin(ctx, "dan", "dan@example.org", "h", time.Now().UTC())
		if err == nil || !strings.Contains(err.Error(), "tenant user limit") {
			t.Fatalf("provisioned admin over the limit: %v", err)
		}
		mustGuest(t, s, "guest-2")
		if err := tl.Set(ctx, 0, 0); err != nil {
			t.Fatal(err)
		}
		mustCreate(t, s.Users(), newUser("cid", "cid@example.org"))
	})

	t.Run("ProvisionedAdmin", func(t *testing.T) {
		s := open(t)
		at := time.Unix(1_800_000_000, 0).UTC()
		id, err := s.Users().CreateProvisionedAdmin(ctx, "eve", "eve@example.org", "hash-eve", at)
		if err != nil || id == 0 {
			t.Fatalf("CreateProvisionedAdmin = %d, %v", id, err)
		}
		u := mustUser(t, s.Users(), id)
		if u.Username != "eve" || u.Name != "eve" || u.Email != "eve@example.org" || !u.Admin || u.EmailVerified || u.IsGuest ||
			u.Language != "en" || u.UILanguage != "en" || u.PasswordHash != "hash-eve" || u.PasswordChangedAt == nil || !u.PasswordChangedAt.Equal(at) {
			t.Fatalf("stored account = %+v", u)
		}
		if _, err := s.Users().CreateProvisionedAdmin(ctx, "eve", "other@example.org", "h", at); err == nil {
			t.Fatal("duplicate username accepted")
		}
		if _, err := s.Users().CreateProvisionedAdmin(ctx, "fay", "EVE@example.org", "h", at); err == nil {
			t.Fatal("duplicate email accepted")
		}
	})
}

// RunLookups pins small lookups used by core code: Settings.Get and Set,
// Users.CountOtherWithEmail, Shares.LongIDExists and
// ObjectStorage.LocationConfigs.
func RunLookups(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()

	t.Run("SettingsGet", func(t *testing.T) {
		s := open(t)
		if _, err := s.Settings().Get(ctx, "no_such_key"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Get of a missing key: %v", err)
		}
		if v, err := s.Settings().Get(ctx, "application_name"); err != nil || v != "Sendora" {
			t.Fatalf("Get(application_name) = %q, %v", v, err)
		}
		if err := s.Settings().Clear(ctx, "application_name"); err != nil {
			t.Fatal(err)
		}
		if v, err := s.Settings().Get(ctx, "application_name"); err != nil || v != "" {
			t.Fatalf("Get of an empty value = %q, %v", v, err)
		}
	})

	t.Run("SettingsSet", func(t *testing.T) {
		s := open(t)
		st := s.Settings()
		for _, v := range []string{"one", "two"} {
			if err := st.Set(ctx, "conformance_new_key", v); err != nil {
				t.Fatal(err)
			}
			if got, err := st.Get(ctx, "conformance_new_key"); err != nil || got != v {
				t.Fatalf("Get after Set(%q) = %q, %v", v, got, err)
			}
		}
		if err := st.Set(ctx, "smtp_host", "mail.example.org"); err != nil {
			t.Fatal(err)
		}
		groups := map[string]string{}
		for _, row := range mustSettings(t, s) {
			groups[row.Key] = row.Group
		}
		if groups["conformance_new_key"] != "system" || groups["smtp_host"] != "email" {
			t.Fatalf("groups after Set: new key %q, existing key %q (want system, email)", groups["conformance_new_key"], groups["smtp_host"])
		}
	})

	t.Run("CountOtherWithEmail", func(t *testing.T) {
		s := open(t)
		u := s.Users()
		a := mustCreate(t, u, newUser("gil", "  Gil@Example.org "))
		b := mustCreate(t, u, newUser("hal", "hal@example.org"))
		for _, c := range []struct {
			email  string
			except int64
			want   int
		}{{"gil@example.org", 0, 1}, {"gil@example.org", a, 0}, {"gil@example.org", b, 1}, {"Gil@Example.org", 0, 1}, {"nobody@example.org", 0, 0}} {
			if n, err := u.CountOtherWithEmail(ctx, c.email, c.except); err != nil || n != c.want {
				t.Fatalf("CountOtherWithEmail(%q, %d) = %d, %v (want %d)", c.email, c.except, n, err, c.want)
			}
		}
	})

	t.Run("LongIDExists", func(t *testing.T) {
		s := open(t)
		if ok, err := s.Shares().LongIDExists(ctx, "lid-1"); err != nil || ok {
			t.Fatalf("LongIDExists on an empty store = %v, %v", ok, err)
		}
		owner := mustCreate(t, s.Users(), newUser("ida", "ida@example.org"))
		id := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "lid-1", Name: "x"})
		if ok, err := s.Shares().LongIDExists(ctx, "lid-1"); err != nil || !ok {
			t.Fatalf("LongIDExists = %v, %v", ok, err)
		}
		if ok, _ := s.Shares().LongIDExists(ctx, "LID-1"); !ok {
			t.Fatal("LongIDExists compares through the case-folded blind index")
		}
		if err := s.Shares().Expire(ctx, id, time.Now()); err != nil {
			t.Fatal(err)
		}
		if ok, _ := s.Shares().LongIDExists(ctx, "lid-1"); !ok {
			t.Fatal("an expired share still holds its long id")
		}
	})

	t.Run("LocationConfigs", func(t *testing.T) {
		s := open(t)
		os := s.ObjectStorage()
		if c, err := os.LocationConfigs(ctx); err != nil || len(c) != 0 {
			t.Fatalf("LocationConfigs on an empty store = %v, %v", c, err)
		}
		if _, err := os.EnsureLocation(ctx, "s3", "s3://b", `{"b":1}`); err != nil {
			t.Fatal(err)
		}
		if _, err := os.EnsureLocation(ctx, "s3", "s3://a", `{"a":1}`); err != nil {
			t.Fatal(err)
		}
		if c, err := os.LocationConfigs(ctx); err != nil || len(c) != 2 || c[0] != `{"b":1}` || c[1] != `{"a":1}` {
			t.Fatalf("LocationConfigs = %v, %v (want id order)", c, err)
		}
	})
}
