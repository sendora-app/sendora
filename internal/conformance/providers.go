// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/sendora-app/sendora/internal/ports"
)

func oidcProvider(name string, enabled bool) ports.ProviderSettings {
	return ports.ProviderSettings{Name: name, Type: "oidc", Enabled: enabled, ClientID: "client-" + name, ClientSecret: "secret-" + name,
		IssuerURL: "https://idp.example.org/" + name, Icon: "key", TrustEmail: true, AllowRegistration: true}
}

// RunProviderAdmin pins the provider management and linking methods of
// ports.AuthProviderRepository, with real fixtures for the counting methods.
func RunProviderAdmin(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		ap := open(t).AuthProviders()
		if _, err := ap.ByUUID(ctx, "nope"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ByUUID of an unknown provider: %v", err)
		}
		id, err := ap.Create(ctx, "uuid-b", oidcProvider("beta", true))
		if err != nil || id == 0 {
			t.Fatalf("Create = %d, %v", id, err)
		}
		if _, err := ap.Create(ctx, "uuid-a", oidcProvider("alpha", false)); err != nil {
			t.Fatal(err)
		}
		p, err := ap.ByUUID(ctx, "uuid-b")
		if err != nil || p.ID != id || p.Name != "beta" || p.ClientSecret != "secret-beta" || !p.Enabled || p.Managed || !p.TrustEmail {
			t.Fatalf("ByUUID = %+v, %v", p, err)
		}
		all, _ := ap.List(ctx, false)
		if len(all) != 2 || all[0].Name != "alpha" {
			t.Fatalf("List = %+v (ordered by name)", all)
		}
		if en, _ := ap.List(ctx, true); len(en) != 1 || en[0].UUID != "uuid-b" {
			t.Fatalf("List enabled = %+v", en)
		}
		if typ, client, issuer, err := ap.Identity(ctx, id); err != nil || typ != "oidc" || client != "client-beta" || issuer != "https://idp.example.org/beta" {
			t.Fatalf("Identity = %q %q %q %v", typ, client, issuer, err)
		}
		if _, _, _, err := ap.Identity(ctx, 9999); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Identity of a missing provider: %v", err)
		}
		upd := oidcProvider("beta2", false)
		upd.ClientSecret = "ignored"
		if err := ap.Update(ctx, id, upd); err != nil {
			t.Fatal(err)
		}
		if p, _ = ap.ByUUID(ctx, "uuid-b"); p.Name != "beta2" || p.Enabled || p.ClientSecret != "secret-beta" {
			t.Fatalf("Update changed the secret or missed fields: %+v", p)
		}
		if err := ap.SetClientSecret(ctx, id, "new"); err != nil {
			t.Fatal(err)
		}
		if p, _ = ap.ByUUID(ctx, "uuid-b"); p.ClientSecret != "new" {
			t.Fatal("SetClientSecret not stored")
		}
		if m, _ := ap.IsManaged(ctx, id); m {
			t.Fatal("an administrator-made provider is managed")
		}
		if err := ap.Delete(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, err := ap.ByUUID(ctx, "uuid-b"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("Delete kept the provider")
		}
	})

	t.Run("Managed", func(t *testing.T) {
		ap := open(t).AuthProviders()
		if err := ap.CreateManaged(ctx, "m1", oidcProvider("m1", true)); err != nil {
			t.Fatal(err)
		}
		if err := ap.CreateManaged(ctx, "m2", oidcProvider("m2", true)); err != nil {
			t.Fatal(err)
		}
		id, typ, client, issuer, secret, err := ap.ManagedConfig(ctx, "m1")
		if err != nil || typ != "oidc" || client != "client-m1" || issuer == "" || secret != "secret-m1" {
			t.Fatalf("ManagedConfig = %d %q %q %q %q %v", id, typ, client, issuer, secret, err)
		}
		if _, _, _, _, _, err := ap.ManagedConfig(ctx, "zz"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ManagedConfig of an unknown uuid: %v", err)
		}
		if m, _ := ap.IsManaged(ctx, id); !m {
			t.Fatal("CreateManaged did not mark the provider managed")
		}
		if err := ap.UpdateManaged(ctx, id, oidcProvider("m1b", false)); err != nil {
			t.Fatal(err)
		}
		if err := ap.ReleaseUnconfigured(ctx, []string{"m1"}); err != nil {
			t.Fatal(err)
		}
		p1, _ := ap.ByUUID(ctx, "m1")
		p2, _ := ap.ByUUID(ctx, "m2")
		if !p1.Managed || p1.Name != "m1b" || p2.Managed {
			t.Fatalf("after ReleaseUnconfigured: %+v / %+v", p1, p2)
		}
		if err := ap.ReleaseUnconfigured(ctx, nil); err != nil {
			t.Fatal(err)
		}
		if p1, _ = ap.ByUUID(ctx, "m1"); p1.Managed {
			t.Fatal("ReleaseUnconfigured(nil) kept a managed provider")
		}
	})

	t.Run("LinksAndCounts", func(t *testing.T) {
		s := open(t)
		ap := s.AuthProviders()
		on, _ := ap.Create(ctx, "on", oidcProvider("on", true))
		off, _ := ap.Create(ctx, "off", oidcProvider("off", false))
		admin, _, err := s.Users().CreateFirstAdmin(ctx, newUser("root", "root@example.org"))
		if err != nil {
			t.Fatal(err)
		}
		ext, err := s.Users().CreateExternal(ctx, "ext", "Ext", "", 0)
		if err != nil {
			t.Fatal(err)
		}
		if u := mustUser(t, s.Users(), ext); u.PasswordHash != "" || u.EmailVerified {
			t.Fatalf("external account = %+v", u)
		}
		if n, err := s.Users().FillEmptyEmail(ctx, ext, "ext@example.org"); err != nil || n != 1 {
			t.Fatalf("FillEmptyEmail = %d, %v", n, err)
		}
		if n, _ := s.Users().FillEmptyEmail(ctx, ext, "other@example.org"); n != 0 {
			t.Fatal("FillEmptyEmail overwrote an address")
		}
		for _, l := range []struct {
			uid, pid int64
			sub      string
		}{{admin, on, "s-admin-on"}, {admin, off, "s-admin-off"}, {ext, on, "s-ext"}} {
			if err := ap.Link(ctx, l.uid, l.pid, l.sub); err != nil {
				t.Fatal(err)
			}
		}
		if uid, err := ap.LinkedUser(ctx, on, "s-ext"); err != nil || uid != ext {
			t.Fatalf("LinkedUser = %d, %v", uid, err)
		}
		if _, err := ap.LinkedUser(ctx, on, "nobody"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("LinkedUser of an unknown subject: %v", err)
		}
		for name, c := range map[string]struct {
			f    func() (int, error)
			want int
		}{
			"CountEnabled":             {func() (int, error) { return ap.CountEnabled(ctx) }, 1},
			"CountLinks":               {func() (int, error) { return ap.CountLinks(ctx, admin) }, 2},
			"CountEnabledLinks":        {func() (int, error) { return ap.CountEnabledLinks(ctx, admin) }, 1},
			"CountEnabledLinksOfLocal": {func() (int, error) { return ap.CountEnabledLinksOfLocal(ctx, admin) }, 1},
			"CountEnabledLinksExcept":  {func() (int, error) { return ap.CountEnabledLinksExcept(ctx, admin, on) }, 0},
			"CountEnabledLink":         {func() (int, error) { return ap.CountEnabledLink(ctx, admin, on) }, 1},
			"CountExternalAdmins":      {func() (int, error) { return ap.CountExternalAdmins(ctx, 0, 0, 0, 0) }, 1},
			"CountExternalAdminsExcl":  {func() (int, error) { return ap.CountExternalAdmins(ctx, 0, on, 0, 0) }, 0},
			"CountProviderLinks":       {func() (int, error) { return ap.CountProviderLinks(ctx, on) }, 2},
		} {
			if n, err := c.f(); err != nil || n != c.want {
				t.Errorf("%s = %d, %v (want %d)", name, n, err, c.want)
			}
		}
		if l, _ := ap.ListLinked(ctx, admin); len(l) != 2 {
			t.Fatalf("ListLinked = %+v", l)
		}
		if l, _ := ap.ListLinkTypes(ctx); len(l) != 3 {
			t.Fatalf("ListLinkTypes = %+v", l)
		}
		if l, _ := ap.ListLinkNames(ctx); len(l) != 3 || l[0].Type != "off" {
			t.Fatalf("ListLinkNames = %+v (ordered by provider name)", l)
		}
		if err := ap.Unlink(ctx, admin, off); err != nil {
			t.Fatal(err)
		}
		if n, _ := ap.CountLinks(ctx, admin); n != 1 {
			t.Fatal("Unlink kept the link")
		}
	})
}
