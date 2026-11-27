// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/adapters/keysource"
	"github.com/sendora-app/sendora/internal/adapters/postgres"
	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// encStore is a store whose adapter can be given a column codec, with direct
// access to the database behind it (what a DBA sees).
type encStore struct {
	ports.Store
	setCodec func(ports.ColumnCodec)
	// rawGet and rawSet read and overwrite an encrypted column as the database
	// holds it (RawColumn, RawSetColumn of the adapters).
	rawGet func(ctx context.Context, table, column, key string) (string, error)
	rawSet func(ctx context.Context, table, column, key, v string) error
}

// EncryptedBackend opens a fresh store for the encrypted-column contracts.
type EncryptedBackend struct {
	Name        string
	Unavailable func() string
	Open        func(testing.TB) encStore
}

// EncryptedBackends lists the adapters that implement column encryption.
func EncryptedBackends() []EncryptedBackend {
	return []EncryptedBackend{
		{Name: "sqlite", Unavailable: func() string { return "" }, Open: func(t testing.TB) encStore {
			st, err := store.OpenEncrypted(filepath.Join(t.TempDir(), "data"), bytes.Repeat([]byte{0x5a}, 32), true)
			if err != nil {
				t.Fatalf("open sqlite store: %v", err)
			}
			t.Cleanup(func() { st.Close() })
			if err := st.MigrateVerificationAttempts(); err != nil {
				t.Fatalf("migrate verification attempts: %v", err)
			}
			a := sqlite.New(st.DB)
			// The contracts install their own codec; what the store's own keys
			// sealed while opening (settings, audit records) could not be read
			// with it, so they start from empty tables, as on the PostgreSQL slot.
			if err := a.ClearSealedTables(context.Background()); err != nil {
				t.Fatalf("clear the sealed tables: %v", err)
			}
			return encStore{Store: a, setCodec: a.SetCodec, rawGet: a.RawColumn, rawSet: a.RawSetColumn}
		}},
		{Name: "postgres", Unavailable: postgresUnavailable, Open: func(t testing.TB) encStore {
			sc := openScratch(t, postgres.TenantSchema)
			a := postgres.New(sc.DB)
			return encStore{Store: a, setCodec: a.SetCodec, rawGet: a.RawColumn, rawSet: a.RawSetColumn}
		}},
	}
}

// newTestCodec creates a tenant's keys in the store's own control log and
// keyring and returns the codec over them.
func newTestCodec(t testing.TB, st interface {
	ControlLog() ports.ControlLogRepository
	Keyring() ports.KeyringRepository
}, tenant string) (*keyring.Codec, *keyring.Service) {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	ks, err := keysource.NewFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	svc := &keyring.Service{KS: ks, Log: st.ControlLog(), Ring: st.Keyring()}
	ctx := context.Background()
	if err := svc.Init(ctx, tenant, "conformance"); err != nil {
		t.Fatalf("init keys: %v", err)
	}
	c, err := keyring.NewCodec(ctx, svc, tenant)
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	t.Cleanup(c.Close)
	return c, svc
}

// RunEncryptedColumns pins the contract of an encrypted column through the
// first one that uses it, shares.description: what the port returns is the
// plaintext, what the database holds is ciphertext bound to its row, and a
// plaintext value in an encrypted database is refused.
func RunEncryptedColumns(t *testing.T, open func(testing.TB) encStore) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	const secret = "salary review: Q4 layoffs list"

	raw := func(s encStore, id int64) string {
		v, err := s.rawGet(ctx, "shares", "description", strconv.FormatInt(id, 10))
		if err != nil {
			t.Fatalf("raw read: %v", err)
		}
		return v
	}

	t.Run("Description", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		owner := mustCreate(t, s.Users(), newUser("gina", "gina@example.org"))
		id := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-enc", Name: "Plans", Description: secret, ExpiresAt: now.Add(time.Hour)})

		stored := raw(s, id)
		if strings.Contains(stored, "salary") || !strings.HasPrefix(stored, "e1:") {
			t.Fatalf("the database holds %q, want ciphertext", stored)
		}
		for name, get := range map[string]func() (ports.ShareRecord, error){
			"ByID":     func() (ports.ShareRecord, error) { return s.Shares().ByID(ctx, id) },
			"ByLongID": func() (ports.ShareRecord, error) { return s.Shares().ByLongID(ctx, "long-enc") },
		} {
			if got, err := get(); err != nil || got.Description != secret {
				t.Fatalf("%s = %q, %v", name, got.Description, err)
			}
		}
		if l, err := s.Shares().ListOwned(ctx, owner); err != nil || len(l) != 1 || l[0].Description != secret {
			t.Fatalf("ListOwned = %+v, %v", l, err)
		}
		// Inside a transaction the same codec applies.
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		tid := mustShare(t, tx, ports.NewShare{UserID: owner, LongID: "long-tx", Name: "T", Description: "tx secret", ExpiresAt: now.Add(time.Hour)})
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw(s, tid), "tx secret") {
			t.Fatal("a transaction stored plaintext")
		}
		if got, _ := s.Shares().ByID(ctx, tid); got.Description != "tx secret" {
			t.Fatalf("transaction share description = %q", got.Description)
		}
		// Editing re-encrypts; an empty description stays empty.
		edited := "now: public"
		if _, err := s.Shares().Edit(ctx, id, owner, ports.ShareEdit{Description: &edited}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw(s, id), "public") {
			t.Fatal("an edit stored plaintext")
		}
		if got, _ := s.Shares().ByID(ctx, id); got.Description != edited {
			t.Fatalf("edited description = %q", got.Description)
		}
		empty := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-empty", Name: "E", ExpiresAt: now.Add(time.Hour)})
		if raw(s, empty) != "" {
			t.Fatal("an empty description is not stored empty")
		}
		if got, _ := s.Shares().ByID(ctx, empty); got.Description != "" {
			t.Fatalf("empty description reads back %q", got.Description)
		}
		// The personal-data export shows the clear text.
		found := false
		for _, row := range s.PersonalData().Section(ctx, ports.ExportShares, owner, 100) {
			if row["description"] == edited {
				found = true
			}
			if d, _ := row["description"].(string); strings.HasPrefix(d, "e1:") {
				t.Fatal("the export shows ciphertext")
			}
		}
		if !found {
			t.Fatal("the export lacks the description")
		}
	})

	isCipher := func(label, stored, plain string) {
		t.Helper()
		if !strings.HasPrefix(stored, "e1:") || strings.Contains(stored, plain) {
			t.Fatalf("%s holds %q, want ciphertext without %q", label, stored, plain)
		}
	}

	t.Run("Invites", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		owner := mustCreate(t, s.Users(), newUser("jane", "jane@example.org"))
		id, err := s.ReverseInvites().Create(ctx, ports.NewInvite{Token: "tok-enc", UserID: owner, RecipientName: "Bob Recipient",
			RecipientEmail: "bob@secret.example", Message: "please upload the signed contracts", ExpiresAt: now.Add(time.Hour), Reusable: true, MaxUploads: 5})
		if err != nil {
			t.Fatal(err)
		}
		key := strconv.FormatInt(id, 10)
		for col, plain := range map[string]string{"recipient_name": "Bob", "recipient_email": "secret.example", "message": "contracts"} {
			v, err := s.rawGet(ctx, "reverse_invites", col, key)
			if err != nil {
				t.Fatal(err)
			}
			isCipher("reverse_invites."+col, v, plain)
		}
		list, err := s.ReverseInvites().ListOwned(ctx, owner, now)
		if err != nil || len(list) != 1 || list[0].RecipientName != "Bob Recipient" || list[0].RecipientEmail != "bob@secret.example" {
			t.Fatalf("ListOwned = %+v, %v", list, err)
		}
		acc, err := s.ReverseInvites().ForAccept(ctx, "tok-enc")
		if err != nil || acc.RecipientName != "Bob Recipient" || acc.Message != "please upload the signed contracts" {
			t.Fatalf("ForAccept = %+v, %v", acc, err)
		}
		// A child invite (the open link's guest) is sealed as well.
		guest := mustCreate(t, s.Users(), newUser("guest-one", "guest-one@example.org"))
		if err := s.ReverseInvites().CreateChild(ctx, ports.NewChildInvite{Token: "tok-child", UserID: owner, RecipientName: "Carol Guest",
			Message: "welcome carol", GuestUserID: guest, ExpiresAt: now.Add(time.Hour), ParentID: id}); err != nil {
			t.Fatal(err)
		}
		child, err := s.ReverseInvites().ForAccept(ctx, "tok-child")
		if err != nil || child.RecipientName != "Carol Guest" || child.Message != "welcome carol" {
			t.Fatalf("child ForAccept = %+v, %v", child, err)
		}
		for col, plain := range map[string]string{"recipient_name": "Carol", "message": "welcome"} {
			v, _ := s.rawGet(ctx, "reverse_invites", col, strconv.FormatInt(child.ID, 10))
			isCipher("child reverse_invites."+col, v, plain)
		}
		found := false
		for _, row := range s.PersonalData().Section(ctx, ports.ExportInvites, owner, 100) {
			if row["recipient_email"] == "bob@secret.example" && row["message"] == "please upload the signed contracts" {
				found = true
			}
		}
		if !found {
			t.Fatal("the personal-data export lacks the invite in the clear")
		}
		// An invite moved to another row's place does not open.
		other, _ := s.ReverseInvites().Create(ctx, ports.NewInvite{Token: "tok-other", UserID: owner, RecipientName: "Dan", ExpiresAt: now.Add(time.Hour)})
		v, _ := s.rawGet(ctx, "reverse_invites", "message", key)
		if err := s.rawSet(ctx, "reverse_invites", "message", strconv.FormatInt(other, 10), v); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReverseInvites().ForAccept(ctx, "tok-other"); err == nil {
			t.Fatal("a message copied to another invite opened")
		}
	})

	t.Run("RefreshTokens", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		owner := mustCreate(t, s.Users(), newUser("kim", "kim@example.org"))
		u := mustUser(t, s.Users(), owner)
		started := now.Add(-time.Minute)
		tok := func(hash, sid string) ports.NewRefreshToken {
			return ports.NewRefreshToken{Hash: hash, UserID: owner, ExpiresAt: now.Add(time.Hour), IssuedAt: now, Started: started,
				SessionID: sid, UserAgent: "Mozilla/5.0 (secret laptop)", IP: "203.0.113.77", Method: "password"}
		}
		if err := s.Sessions().Insert(ctx, tok("hash-a", "sid-a")); err != nil {
			t.Fatal(err)
		}
		if n, err := s.Sessions().StartGuarded(ctx, tok("hash-b", "sid-b"), ports.CredentialGuard{PasswordHash: u.PasswordHash, Email: u.Email, MustChangePassword: u.MustChangePassword}); err != nil || n != 1 {
			t.Fatalf("StartGuarded = %d, %v", n, err)
		}
		for _, h := range []string{"hash-a", "hash-b"} {
			ua, _ := s.rawGet(ctx, "refresh_tokens", "user_agent", h)
			ip, _ := s.rawGet(ctx, "refresh_tokens", "ip", h)
			isCipher(h+" user_agent", ua, "laptop")
			isCipher(h+" ip", ip, "203.0.113")
		}
		list, err := s.Sessions().ListLive(ctx, owner, now)
		if err != nil || len(list) != 2 {
			t.Fatalf("ListLive = %d sessions, %v", len(list), err)
		}
		for _, sess := range list {
			if sess.UserAgent != "Mozilla/5.0 (secret laptop)" || sess.IP != "203.0.113.77" {
				t.Fatalf("session %s reads %q %q", sess.SessionID, sess.UserAgent, sess.IP)
			}
		}
		// The address of one session copied onto the other does not open.
		ip, _ := s.rawGet(ctx, "refresh_tokens", "ip", "hash-a")
		if err := s.rawSet(ctx, "refresh_tokens", "ip", "hash-b", ip); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Sessions().ListLive(ctx, owner, now); err == nil {
			t.Fatal("an address copied to another session opened")
		}
	})

	t.Run("ProviderSecrets", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		pv := ports.ProviderSettings{Name: "Corp SSO", Type: "oidc", Enabled: true, ClientID: "client-1", ClientSecret: "s3cr3t-oidc-client-secret", IssuerURL: "https://sso.example.org"}
		id, err := s.AuthProviders().Create(ctx, "uuid-1", pv)
		if err != nil {
			t.Fatal(err)
		}
		key := strconv.FormatInt(id, 10)
		v, _ := s.rawGet(ctx, "auth_providers", "client_secret", key)
		isCipher("auth_providers.client_secret", v, "s3cr3t")
		if got, err := s.AuthProviders().ByUUID(ctx, "uuid-1"); err != nil || got.ClientSecret != pv.ClientSecret || got.ClientID != "client-1" {
			t.Fatalf("ByUUID = %+v, %v", got, err)
		}
		if l, err := s.AuthProviders().List(ctx, false); err != nil || len(l) != 1 || l[0].ClientSecret != pv.ClientSecret {
			t.Fatalf("List = %+v, %v", l, err)
		}
		if err := s.AuthProviders().SetClientSecret(ctx, id, "rotated-secret"); err != nil {
			t.Fatal(err)
		}
		v, _ = s.rawGet(ctx, "auth_providers", "client_secret", key)
		isCipher("rotated client_secret", v, "rotated")
		if got, _ := s.AuthProviders().ByUUID(ctx, "uuid-1"); got.ClientSecret != "rotated-secret" {
			t.Fatalf("after SetClientSecret: %q", got.ClientSecret)
		}
		// Providers defined by the environment (managed) are sealed as well.
		mp := ports.ProviderSettings{Name: "Env IdP", Type: "oidc", Enabled: true, ClientID: "env-1", ClientSecret: "env-secret-value", IssuerURL: "https://env.example.org"}
		if err := s.AuthProviders().CreateManaged(ctx, "uuid-env", mp); err != nil {
			t.Fatal(err)
		}
		mid, _, _, _, msec, err := s.AuthProviders().ManagedConfig(ctx, "uuid-env")
		if err != nil || msec != "env-secret-value" {
			t.Fatalf("ManagedConfig = %d %q, %v", mid, msec, err)
		}
		raw, _ := s.rawGet(ctx, "auth_providers", "client_secret", strconv.FormatInt(mid, 10))
		isCipher("managed client_secret", raw, "env-secret")
		mp.ClientSecret = "env-secret-2"
		if err := s.AuthProviders().UpdateManaged(ctx, mid, mp); err != nil {
			t.Fatal(err)
		}
		raw, _ = s.rawGet(ctx, "auth_providers", "client_secret", strconv.FormatInt(mid, 10))
		isCipher("updated managed client_secret", raw, "env-secret")
		if _, _, _, _, got, _ := s.AuthProviders().ManagedConfig(ctx, "uuid-env"); got != "env-secret-2" {
			t.Fatalf("after UpdateManaged: %q", got)
		}
		// A secret copied from one provider to another does not open.
		if err := s.rawSet(ctx, "auth_providers", "client_secret", strconv.FormatInt(mid, 10), v); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, _, err := s.AuthProviders().ManagedConfig(ctx, "uuid-env"); err == nil {
			t.Fatal("a secret copied to another provider opened")
		}
	})

	t.Run("StorageLocations", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		cfg := `{"backend":"s3","bucket":"files","access_key":"AKIAEXAMPLE","secret_key":"wJalrXUtnFEMI"}`
		id, err := s.ObjectStorage().EnsureLocation(ctx, "s3", "identity-1", cfg)
		if err != nil || id == 0 {
			t.Fatalf("EnsureLocation = %d, %v", id, err)
		}
		key := strconv.FormatInt(id, 10)
		v, _ := s.rawGet(ctx, "storage_locations", "config", key)
		isCipher("storage_locations.config", v, "AKIAEXAMPLE")
		if got, err := s.ObjectStorage().LocationConfig(ctx, id); err != nil || got != cfg {
			t.Fatalf("LocationConfig = %q, %v", got, err)
		}
		if again, err := s.ObjectStorage().EnsureLocation(ctx, "s3", "identity-1", cfg); err != nil || again != id {
			t.Fatalf("EnsureLocation again = %d, %v (want %d)", again, err, id)
		}
		changed := `{"backend":"s3","bucket":"files2","access_key":"AKIAOTHER","secret_key":"x"}`
		if again, err := s.ObjectStorage().EnsureLocation(ctx, "s3", "identity-1", changed); err != nil || again != id {
			t.Fatalf("EnsureLocation with a new config = %d, %v (want %d)", again, err, id)
		}
		v, _ = s.rawGet(ctx, "storage_locations", "config", key)
		isCipher("changed storage_locations.config", v, "AKIAOTHER")
		if got, _ := s.ObjectStorage().LocationConfig(ctx, id); got != changed {
			t.Fatalf("after a change: %q", got)
		}
		second, err := s.ObjectStorage().EnsureLocation(ctx, "azure", "identity-2", `{"backend":"azure","key":"k2"}`)
		if err != nil || second == id {
			t.Fatalf("second location = %d, %v", second, err)
		}
		all, err := s.ObjectStorage().LocationConfigs(ctx)
		if err != nil || len(all) != 2 || all[0] != changed || all[1] != `{"backend":"azure","key":"k2"}` {
			t.Fatalf("LocationConfigs = %v, %v", all, err)
		}
		// A configuration copied to another location does not open.
		if err := s.rawSet(ctx, "storage_locations", "config", strconv.FormatInt(second, 10), v); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ObjectStorage().LocationConfig(ctx, second); err == nil {
			t.Fatal("a configuration copied to another location opened")
		}
	})

	t.Run("UserNames", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		in := newUser("nora", "nora@example.org")
		in.Name = "Nora Privatename"
		id := mustCreate(t, s.Users(), in)
		key := strconv.FormatInt(id, 10)
		v, err := s.rawGet(ctx, "users", "name", key)
		if err != nil {
			t.Fatal(err)
		}
		isCipher("users.name", v, "Privatename")
		if got := mustUser(t, s.Users(), id); got.Name != in.Name {
			t.Fatalf("ByID name = %q", got.Name)
		}
		if l, err := s.Users().ListLocal(ctx); err != nil || len(l) != 1 || l[0].Name != in.Name {
			t.Fatalf("ListLocal = %+v, %v", l, err)
		}
		u := mustUser(t, s.Users(), id)
		if n, err := s.Users().UpdateProfile(ctx, id, ports.ProfileUpdate{Name: "Nora Renamed", Email: u.Email, EmailVerified: u.EmailVerified,
			PasswordHash: u.PasswordHash, MustChangePassword: u.MustChangePassword, Language: "en"}, guardOf(u)); err != nil || n != 1 {
			t.Fatalf("UpdateProfile = %d, %v", n, err)
		}
		v, _ = s.rawGet(ctx, "users", "name", key)
		isCipher("updated users.name", v, "Renamed")
		if got := mustUser(t, s.Users(), id); got.Name != "Nora Renamed" {
			t.Fatalf("name after UpdateProfile = %q", got.Name)
		}
		// The inviter's name reaches the invite page through a join: it is
		// opened with the users row, not the invite.
		if _, err := s.ReverseInvites().Create(ctx, ports.NewInvite{Token: "tok-name", UserID: id, RecipientName: "R", ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if acc, err := s.ReverseInvites().ForAccept(ctx, "tok-name"); err != nil || acc.InviterName != "Nora Renamed" {
			t.Fatalf("ForAccept inviter = %q, %v", acc.InviterName, err)
		}
		guest, err := s.Users().CreateGuest(ctx, "guest-nm", "Guest Secretname")
		if err != nil {
			t.Fatal(err)
		}
		v, _ = s.rawGet(ctx, "users", "name", strconv.FormatInt(guest, 10))
		isCipher("guest users.name", v, "Secretname")
		// A name copied to another account does not open.
		if err := s.rawSet(ctx, "users", "name", strconv.FormatInt(guest, 10), copyOf(t, s, "users", "name", key)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Users().ByID(ctx, guest); err == nil {
			t.Fatal("a name copied to another account opened")
		}
	})

	t.Run("ShareAndFileNames", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		owner := mustCreate(t, s.Users(), newUser("olga", "olga@example.org"))
		sid := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-fn", Name: "Merger Documents", ExpiresAt: now.Add(time.Hour)})
		v, _ := s.rawGet(ctx, "shares", "name", strconv.FormatInt(sid, 10))
		isCipher("shares.name", v, "Merger")
		if got, err := s.Shares().ByID(ctx, sid); err != nil || got.Name != "Merger Documents" {
			t.Fatalf("ByID name = %q, %v", got.Name, err)
		}
		newName := "Renamed Deal"
		if _, err := s.Shares().Edit(ctx, sid, owner, ports.ShareEdit{Name: &newName}); err != nil {
			t.Fatal(err)
		}
		v, _ = s.rawGet(ctx, "shares", "name", strconv.FormatInt(sid, 10))
		isCipher("edited shares.name", v, "Deal")
		sum := strings.Repeat("ab", 32)
		fid := mustFile(t, s, ports.NewShareFile{ShareID: sid, Name: "acquisition-plan.pdf", FullPath: "acquisition-plan.pdf", Size: 5, SHA256: sum})
		bare := mustFile(t, s, ports.NewShareFile{ShareID: sid, Name: "bare.txt", FullPath: "bare.txt", Size: 1})
		for col, plain := range map[string]string{"name": "acquisition", "sha256": "abab", "full_path": "acquisition"} {
			v, _ := s.rawGet(ctx, "files", col, strconv.FormatInt(fid, 10))
			isCipher("files."+col, v, plain)
		}
		if v, _ := s.rawGet(ctx, "files", "sha256", strconv.FormatInt(bare, 10)); v != "" {
			t.Fatalf("an empty checksum is stored as %q", v)
		}
		files, err := s.Shares().Files(ctx, sid)
		if err != nil || len(files) != 2 || files[0].Name != "acquisition-plan.pdf" || files[0].SHA256 != sum {
			t.Fatalf("Files = %+v, %v", files, err)
		}
		if l, err := s.Shares().ListFiles(ctx, sid); err != nil || len(l) != 2 || l[0].Name != "acquisition-plan.pdf" || l[0].FullPath != "acquisition-plan.pdf" || l[1].FullPath != "bare.txt" {
			t.Fatalf("ListFiles = %+v, %v", l, err)
		}
		if l, err := s.Shares().FilePathsAndSizes(ctx, sid); err != nil || len(l) != 2 || l[0].FullPath != "acquisition-plan.pdf" || l[1].FullPath != "bare.txt" {
			t.Fatalf("FilePathsAndSizes = %+v, %v", l, err)
		}
		// The order by path is the plaintext order although the column is sealed.
		z := mustFile(t, s, ports.NewShareFile{ShareID: sid, Name: "a.txt", FullPath: "Aaa/a.txt", Size: 1})
		if l, err := s.Shares().Files(ctx, sid); err != nil || len(l) != 3 || l[0].FullPath != "Aaa/a.txt" || l[1].FullPath != "acquisition-plan.pdf" || l[2].FullPath != "bare.txt" {
			t.Fatalf("Files order = %+v, %v", l, err)
		}
		if err := s.Shares().DeleteFile(ctx, z, sid); err != nil {
			t.Fatal(err)
		}
		all, _, err := s.Shares().VerificationFiles(ctx)
		if err != nil || len(all) != 2 || all[0].Name != "acquisition-plan.pdf" || all[0].SHA256 != sum || all[0].ShareName != newName {
			t.Fatalf("VerificationFiles = %+v, %v", all, err)
		}
		// The baseline checksum of a file without one is sealed with its row.
		base := strings.Repeat("cd", 32)
		if err := s.Shares().BaselineFileChecksum(ctx, bare, base); err != nil {
			t.Fatal(err)
		}
		v, _ = s.rawGet(ctx, "files", "sha256", strconv.FormatInt(bare, 10))
		isCipher("baseline files.sha256", v, "cdcd")
		if got, err := s.Shares().FileChecksum(ctx, bare); err != nil || got != base {
			t.Fatalf("FileChecksum = %q, %v", got, err)
		}
		// The storage migration reads and rewrites the checksum.
		mf, err := s.ObjectStorage().MigrationFile(ctx, fid)
		if err != nil || mf.Name != "acquisition-plan.pdf" || mf.SHA256 != sum {
			t.Fatalf("MigrationFile = %+v, %v", mf, err)
		}
		moved := strings.Repeat("ef", 32)
		if n, err := s.ObjectStorage().MoveFile(ctx, mf, ports.MovedFile{LocationID: mf.LocationID, ObjectKey: mf.ObjectKey, DiskPath: mf.DiskPath, EncID: mf.EncID, SHA256: moved}); err != nil || n != 1 {
			t.Fatalf("MoveFile = %d, %v", n, err)
		}
		v, _ = s.rawGet(ctx, "files", "sha256", strconv.FormatInt(fid, 10))
		isCipher("moved files.sha256", v, "efef")
		if got, _ := s.Shares().FileChecksum(ctx, fid); got != moved {
			t.Fatalf("checksum after MoveFile = %q", got)
		}
		// The download list joins the file name: it opens with the file's row.
		if err := s.Downloads().Record(ctx, sid, &fid, "203.0.113.5", now); err != nil {
			t.Fatal(err)
		}
		if l, err := s.Downloads().List(ctx, sid, 10, 0); err != nil || len(l) != 1 || l[0].FileName != "acquisition-plan.pdf" {
			t.Fatalf("Downloads.List = %+v, %v", l, err)
		}
		found := false
		for _, row := range s.PersonalData().Section(ctx, ports.ExportDownloadHistory, owner, 100) {
			if row["file"] == "acquisition-plan.pdf" {
				found = true
			}
		}
		for _, row := range s.PersonalData().Section(ctx, ports.ExportShares, owner, 100) {
			if row["name"] != newName {
				t.Fatalf("export share name = %v", row["name"])
			}
		}
		if !found {
			t.Fatal("the download-history export lacks the file name in the clear")
		}
		for _, row := range s.PersonalData().Section(ctx, ports.ExportShareFiles, owner, 100) {
			if p, _ := row["path"].(string); p != "acquisition-plan.pdf" && p != "bare.txt" {
				t.Fatalf("export file path = %v", row["path"])
			}
			if _, leaked := row["file_id"]; leaked {
				t.Fatal("the export carries the internal file id")
			}
		}
		// A path copied to another file does not open (and is put back).
		origPath, _ := s.rawGet(ctx, "files", "full_path", strconv.FormatInt(bare, 10))
		v, _ = s.rawGet(ctx, "files", "full_path", strconv.FormatInt(fid, 10))
		if err := s.rawSet(ctx, "files", "full_path", strconv.FormatInt(bare, 10), v); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Shares().Files(ctx, sid); err == nil {
			t.Fatal("a file path copied to another file opened")
		}
		if err := s.rawSet(ctx, "files", "full_path", strconv.FormatInt(bare, 10), origPath); err != nil {
			t.Fatal(err)
		}
		// A file name copied to another file does not open.
		v, _ = s.rawGet(ctx, "files", "name", strconv.FormatInt(fid, 10))
		if err := s.rawSet(ctx, "files", "name", strconv.FormatInt(bare, 10), v); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Shares().Files(ctx, sid); err == nil {
			t.Fatal("a file name copied to another file opened")
		}
	})

	t.Run("UploadFileColumns", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		owner := mustCreate(t, s.Users(), newUser("uma", "uma@example.org"))
		if err := s.Uploads().Create(ctx, ports.NewUpload{ID: "up-enc", UserID: owner, QuotaOwnerID: owner}); err != nil {
			t.Fatal(err)
		}
		sum := strings.Repeat("12", 32)
		for i, name := range []string{"secret-plan.docx", "other.txt"} {
			f := ports.NewUploadFile{SessionID: "up-enc", Index: i, Name: name, FullPath: "dir/" + name, Size: int64(10 + i)}
			if i == 0 {
				f.SHA256 = sum
			}
			if err := s.Uploads().AddFile(ctx, f); err != nil {
				t.Fatal(err)
			}
		}
		for col, plain := range map[string]string{"name": "secret", "full_path": "secret", "sha256": "1212"} {
			v, err := s.rawGet(ctx, "upload_files", col, "1")
			if err != nil {
				t.Fatal(err)
			}
			isCipher("upload_files."+col, v, plain)
		}
		if v, _ := s.rawGet(ctx, "upload_files", "sha256", "2"); v != "" {
			t.Fatalf("an empty checksum is stored as %q", v)
		}
		files, err := s.Uploads().Files(ctx, "up-enc")
		if err != nil || len(files) != 2 || files[0].Name != "secret-plan.docx" || files[0].FullPath != "dir/secret-plan.docx" || files[0].SHA256 != sum || files[1].Name != "other.txt" || files[1].SHA256 != "" {
			t.Fatalf("Files = %+v, %v", files, err)
		}
		for _, col := range []string{"name", "full_path", "sha256"} {
			v, _ := s.rawGet(ctx, "upload_files", col, "1")
			if err := s.rawSet(ctx, "upload_files", col, "2", v); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Uploads().Files(ctx, "up-enc"); err == nil {
				t.Fatalf("an upload %s copied to another row opened", col)
			}
			if col != "sha256" {
				orig := map[string]string{"name": "other.txt", "full_path": "dir/other.txt"}[col]
				sealed, _ := codec.Seal("upload_files", col, "2", orig)
				if err := s.rawSet(ctx, "upload_files", col, "2", sealed); err != nil {
					t.Fatal(err)
				}
			} else if err := s.rawSet(ctx, "upload_files", col, "2", ""); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("PasswordHistory", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		id := mustCreate(t, s.Users(), newUser("pete", "pete@example.org"))
		ph := s.PasswordHistory()
		if err := ph.Remember(ctx, id, 5, now); err != nil {
			t.Fatal(err)
		}
		if n, err := s.Users().ReplacePasswordHash(ctx, id, "hash-pete-2", "hash-pete"); err != nil || n != 1 {
			t.Fatalf("ReplacePasswordHash = %d, %v", n, err)
		}
		if err := ph.Remember(ctx, id, 5, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		recent, err := ph.Recent(ctx, id, 5)
		if err != nil || len(recent) != 2 || recent[0] != "hash-pete-2" || recent[1] != "hash-pete" {
			t.Fatalf("Recent = %v, %v", recent, err)
		}
		for _, key := range []string{"1", "2"} {
			v, err := s.rawGet(ctx, "password_history", "hash", key)
			if err != nil {
				t.Fatal(err)
			}
			isCipher("password_history.hash "+key, v, "hash-pete")
		}
		// A hash copied to another history row does not open.
		v, _ := s.rawGet(ctx, "password_history", "hash", "1")
		if err := s.rawSet(ctx, "password_history", "hash", "2", v); err != nil {
			t.Fatal(err)
		}
		if _, err := ph.Recent(ctx, id, 5); err == nil {
			t.Fatal("a hash copied to another history row opened")
		}
	})

	t.Run("BoundToTheRow", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		owner := mustCreate(t, s.Users(), newUser("hank", "hank@example.org"))
		a := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-a", Name: "A", Description: "for A", ExpiresAt: now.Add(time.Hour)})
		b := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-b", Name: "B", Description: "for B", ExpiresAt: now.Add(time.Hour)})
		// A DBA copies A's ciphertext into B: it must not decrypt there.
		if err := s.rawSet(ctx, "shares", "description", strconv.FormatInt(b, 10), raw(s, a)); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Shares().ByID(ctx, b); err == nil {
			t.Fatalf("a value moved to another row opened as %q", got.Description)
		}
		// A flipped bit is refused too.
		if err := s.rawSet(ctx, "shares", "description", strconv.FormatInt(a, 10), flipChar(raw(s, a))); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Shares().ByID(ctx, a); err == nil {
			t.Fatal("a modified ciphertext was accepted")
		}
	})

	// The audit log: actor_name, target and detail are sealed bound to the
	// record's sequence number; the chain's hashes are computed by the caller
	// over the plaintext, so the port hands out and takes plaintext only.
	t.Run("AuditLog", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		chain, query := s.AuditChain(), s.AuditQuery()
		for i := int64(1); i <= 12; i++ {
			r := auditRec(i, "2027-02-01T10:00:00Z", "auth", "login_ok", "Alice Secret", "ok")
			r.Target, r.Detail = "target-"+itoa(i), "detail-"+itoa(i)
			if i%3 == 0 {
				r.ActorName, r.Detail = "Bob Hidden", "found-the-needle"
			}
			if err := chain.Insert(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		for _, c := range []struct{ col, plain string }{{"actor_name", "Alice"}, {"target", "target-1"}, {"detail", "detail-1"}} {
			v, err := s.rawGet(ctx, "audit_log", c.col, "1")
			if err != nil {
				t.Fatal(err)
			}
			isCipher("audit_log."+c.col, v, c.plain)
		}
		// The columns of the chain and the filters stay plaintext.
		if v, _ := s.rawGet(ctx, "audit_log", "target", "1"); v == "" {
			t.Fatal("the target is stored empty")
		}
		// Reads hand out plaintext: the walk the verifier hashes, the stream
		// that carries the log, the query behind the API.
		var walked []ports.AuditRecord
		if n, err := chain.Walk(ctx, 0, 0, 0, func(r *ports.AuditRecord) { walked = append(walked, *r) }); err != nil || n != 12 {
			t.Fatalf("Walk = %d, %v", n, err)
		}
		if walked[0].ActorName != "Alice Secret" || walked[0].Target != "target-1" || walked[2].Detail != "found-the-needle" || walked[0].Hash != "h1" {
			t.Fatalf("Walk hands out %+v", walked[0])
		}
		all := 0
		if err := chain.All(ctx, func(r ports.AuditRecord) error {
			all++
			if strings.HasPrefix(r.Target, "e1:") || strings.HasPrefix(r.ActorName, "e1:") || strings.HasPrefix(r.Detail, "e1:") {
				t.Fatalf("All hands out ciphertext: %+v", r)
			}
			return nil
		}); err != nil || all != 12 {
			t.Fatalf("All = %d, %v", all, err)
		}
		seqs := func(l []ports.AuditRecord) []int64 {
			var out []int64
			for _, r := range l {
				out = append(out, r.Seq)
			}
			return out
		}
		same := func(got []int64, want ...int64) bool {
			if len(got) != len(want) {
				return false
			}
			for i := range got {
				if got[i] != want[i] {
					return false
				}
			}
			return true
		}
		// Search by actor, target and detail happens on the opened values, with
		// the paging of the SQL filters.
		for name, c := range map[string]struct {
			f      ports.AuditFilter
			newest bool
			limit  int
			offset int
			want   []int64
		}{
			"actor":                    {ports.AuditFilter{Actor: "bob"}, false, 0, 0, []int64{3, 6, 9, 12}},
			"actor, case folded":       {ports.AuditFilter{Actor: "ALICE"}, false, 3, 0, []int64{1, 2, 4}},
			"target term":              {ports.AuditFilter{Terms: []string{"target-7"}}, true, 0, 0, []int64{7}},
			"detail term":              {ports.AuditFilter{Terms: []string{"NEEDLE"}}, true, 0, 0, []int64{12, 9, 6, 3}},
			"terms all":                {ports.AuditFilter{Terms: []string{"needle", "hidden"}}, false, 0, 0, []int64{3, 6, 9, 12}},
			"terms none":               {ports.AuditFilter{Terms: []string{"needle", "alice"}}, false, 0, 0, nil},
			"term in a plain column":   {ports.AuditFilter{Terms: []string{"login_ok", "target-12"}}, false, 0, 0, []int64{12}},
			"paging newest first":      {ports.AuditFilter{Terms: []string{"needle"}}, true, 2, 1, []int64{9, 6}},
			"paging past the matches":  {ports.AuditFilter{Terms: []string{"needle"}}, true, 2, 3, []int64{3}},
			"offset beyond":            {ports.AuditFilter{Terms: []string{"needle"}}, true, 2, 9, nil},
			"with a plaintext filter":  {ports.AuditFilter{Terms: []string{"needle"}, Category: "auth", AfterSeq: i64p(3), BeforeSeq: i64p(12)}, false, 0, 0, []int64{6, 9}},
			"SQL filters only, paging": {ports.AuditFilter{Category: "auth"}, true, 3, 2, []int64{10, 9, 8}},
		} {
			got, err := query.Find(ctx, c.f, c.newest, c.limit, c.offset)
			if err != nil || !same(seqs(got), c.want...) {
				t.Errorf("%s: %v, %v (want %v)", name, seqs(got), err, c.want)
			}
			if len(got) > 0 && (strings.HasPrefix(got[0].Target, "e1:") || strings.HasPrefix(got[0].Detail, "e1:") || strings.HasPrefix(got[0].ActorName, "e1:")) {
				t.Errorf("%s: Find hands out ciphertext", name)
			}
		}
		if n, err := query.CountCapped(ctx, ports.AuditFilter{Terms: []string{"needle"}}, 10); err != nil || n != 4 {
			t.Fatalf("CountCapped = %d, %v", n, err)
		}
		if n, err := query.CountCapped(ctx, ports.AuditFilter{Actor: "alice"}, 5); err != nil || n != 6 {
			t.Fatalf("CountCapped above the cap = %d, %v (it counts one past the cap)", n, err)
		}
		// More matches than one read window, so the windows chain up correctly.
		for i := int64(13); i <= 700; i++ {
			r := auditRec(i, "2027-02-02T10:00:00Z", "admin", "user_created", "Carol", "ok")
			r.Detail = "bulk"
			if err := chain.Insert(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := query.Find(ctx, ports.AuditFilter{Terms: []string{"bulk"}}, false, 5, 600); err != nil || !same(seqs(got), 613, 614, 615, 616, 617) {
			t.Fatalf("a page after several windows = %v, %v", seqs(got), err)
		}
		if n, err := query.CountCapped(ctx, ports.AuditFilter{Actor: "carol"}, 1000); err != nil || n != 688 {
			t.Fatalf("CountCapped over several windows = %d, %v", n, err)
		}
		// The personal-data export shows the clear text.
		if err := chain.Insert(ctx, ports.AuditRecord{Seq: 701, TS: "2027-02-03T10:00:00Z", Category: "auth", ActorID: 4242, ActorName: "Dora", ActorRole: "admin", Action: "login_ok", Target: "export-target", Outcome: "ok", Detail: "export-detail", PrevHash: "p701", Hash: "h701"}); err != nil {
			t.Fatal(err)
		}
		rows := s.PersonalData().Section(ctx, ports.ExportAuditRecords, 4242, 10)
		if len(rows) != 1 || rows[0]["target"] != "export-target" || rows[0]["details"] != "export-detail" {
			t.Fatalf("the export shows %v", rows)
		}
		// Bound to the sequence number: a ciphertext moved to another record, a
		// flipped bit and a plaintext value are refused. Walking marks the record
		// (it then fails its hash, so verification reports it); reading it
		// through the API or the stream fails.
		five, _ := s.rawGet(ctx, "audit_log", "target", "5")
		if err := s.rawSet(ctx, "audit_log", "target", "4", five); err != nil {
			t.Fatal(err)
		}
		if err := s.rawSet(ctx, "audit_log", "detail", "6", flipChar(copyOf(t, s, "audit_log", "detail", "6"))); err != nil {
			t.Fatal(err)
		}
		if err := s.rawSet(ctx, "audit_log", "actor_name", "7", "plain forged name"); err != nil {
			t.Fatal(err)
		}
		bad := map[int64]bool{}
		if _, err := chain.Walk(ctx, 0, 12, 0, func(r *ports.AuditRecord) {
			if strings.Contains(r.Target+r.Detail+r.ActorName, "\x00") {
				bad[r.Seq] = true
			}
			if r.Seq == 4 && r.Target == "target-5" {
				t.Error("a moved ciphertext opened on another record")
			}
		}); err != nil {
			t.Fatalf("Walk of a tampered log: %v", err)
		}
		if !bad[4] || !bad[6] || !bad[7] || len(bad) != 3 {
			t.Fatalf("Walk marked %v, want 4, 6 and 7", bad)
		}
		if err := chain.All(ctx, func(ports.AuditRecord) error { return nil }); err == nil {
			t.Fatal("All streamed a tampered log")
		}
		if _, err := query.Find(ctx, ports.AuditFilter{Actor: "alice"}, false, 0, 0); err == nil {
			t.Fatal("a text search read a tampered log")
		}
		if _, err := query.Find(ctx, ports.AuditFilter{BeforeSeq: i64p(5)}, false, 0, 0); err == nil {
			t.Fatal("a listing read a tampered log")
		}
	})

	// Every setting value is sealed bound to its key, whatever the group.
	t.Run("Settings", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		st := s.Settings()
		rawValue := func(key string) string {
			v, err := s.rawGet(ctx, "settings", "value", key)
			if err != nil {
				t.Fatalf("raw read of %s: %v", key, err)
			}
			return v
		}
		if err := st.Set(ctx, "application_name", "Acme Secret Files"); err != nil {
			t.Fatal(err)
		}
		if err := st.Set(ctx, "smtp_pass", "hunter2-smtp"); err != nil {
			t.Fatal(err)
		}
		if err := s.System().SetAuditKeyFingerprint(ctx, "0123456789abcdef"); err != nil {
			t.Fatal(err)
		}
		if err := st.Set(ctx, "jwt_secret", "jwt-signing-secret"); err != nil {
			t.Fatal(err)
		}
		if err := s.System().ClassifyJWTSecret(ctx); err != nil {
			t.Fatal(err)
		}
		for key, plain := range map[string]string{"application_name": "Acme", "smtp_pass": "hunter2", "audit_key_fingerprint": "0123456789", "jwt_secret": "jwt-signing"} {
			isCipher("settings."+key, rawValue(key), plain)
		}
		for key, want := range map[string]string{"application_name": "Acme Secret Files", "smtp_pass": "hunter2-smtp", "audit_key_fingerprint": "0123456789abcdef", "jwt_secret": "jwt-signing-secret"} {
			if got, err := st.Get(ctx, key); err != nil || got != want {
				t.Fatalf("Get(%s) = %q, %v", key, got, err)
			}
		}
		// Updating keeps the group and re-seals; an empty value stays empty.
		if err := st.Set(ctx, "application_name", "Acme Renamed"); err != nil {
			t.Fatal(err)
		}
		if err := st.Update(ctx, "smtp_pass", "hunter3"); err != nil {
			t.Fatal(err)
		}
		if err := st.UpdateEditable(ctx, "application_name", "Acme Edited"); err != nil {
			t.Fatal(err)
		}
		if err := st.SetApplicationURL(ctx, "https://files.acme.example"); err != nil {
			t.Fatal(err)
		}
		isCipher("settings.application_name", rawValue("application_name"), "Acme")
		if got, _ := st.Get(ctx, "application_name"); got != "Acme Edited" {
			t.Fatalf("application_name = %q", got)
		}
		if got, _ := st.Get(ctx, "smtp_pass"); got != "hunter3" {
			t.Fatalf("smtp_pass = %q", got)
		}
		if err := st.Update(ctx, "no_such_setting", "x"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, "no_such_setting"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("an update created a setting: %v", err)
		}
		if err := st.Clear(ctx, "smtp_pass"); err != nil {
			t.Fatal(err)
		}
		if rawValue("smtp_pass") != "" {
			t.Fatal("a cleared value is not stored empty")
		}
		if got, err := st.Get(ctx, "smtp_pass"); err != nil || got != "" {
			t.Fatalf("cleared = %q, %v", got, err)
		}
		// The listing and the secret group: the editable settings open, the
		// secrets stay out of the listing.
		list, err := st.ListEditable(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sawName := false
		for _, x := range list {
			if x.Key == "application_name" && x.Value == "Acme Edited" {
				sawName = true
			}
			if x.Key == "jwt_secret" || x.Key == "audit_key_fingerprint" || strings.HasPrefix(x.Value, "e1:") {
				t.Fatalf("the listing holds %+v", x)
			}
		}
		if !sawName {
			t.Fatalf("the listing lacks the edited setting: %+v", list)
		}
		// Mail templates are settings: sealed too, and a replacement only takes
		// a template that exists in the group.
		if err := s.Mail().PutTemplate(ctx, "tpl_probe", "Dear {{.Name}}, secret text"); err != nil {
			t.Fatal(err)
		}
		isCipher("settings.tpl_probe", rawValue("tpl_probe"), "secret text")
		if err := s.Mail().SetTemplate(ctx, "tpl_probe", "second secret text"); err != nil {
			t.Fatal(err)
		}
		found := false
		tpls, err := s.Mail().Templates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range tpls {
			if x.Key == "tpl_probe" && x.Value == "second secret text" {
				found = true
			}
			if strings.HasPrefix(x.Value, "e1:") {
				t.Fatalf("a template reads back as ciphertext: %+v", x)
			}
		}
		if !found {
			t.Fatal("the template does not read back")
		}
		// Settings read inside SQL before are read in Go now: the default quota
		// and the storage backend.
		owner := mustCreate(t, s.Users(), newUser("quota", "quota@example.org"))
		if err := st.Set(ctx, "default_storage_quota_bytes", "123456"); err != nil {
			t.Fatal(err)
		}
		if _, _, def, err := s.Quota().Policy(ctx, owner); err != nil || def == nil || *def != "123456" {
			t.Fatalf("Policy default quota = %v, %v", def, err)
		}
		if err := st.Set(ctx, "storage_backend", "local"); err != nil {
			t.Fatal(err)
		}
		if b, err := s.Quota().StorageBackendSetting(ctx); err != nil || b != "local" {
			t.Fatalf("StorageBackendSetting = %q, %v", b, err)
		}
		// Inside a transaction the same codec applies.
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Settings().Set(ctx, "tx_probe", "tx secret"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		isCipher("settings.tx_probe", rawValue("tx_probe"), "tx secret")
		// Bound to the key: a value copied to another setting does not open, a
		// flipped bit and a plaintext value are refused.
		if err := s.rawSet(ctx, "settings", "value", "tx_probe", rawValue("jwt_secret")); err != nil {
			t.Fatal(err)
		}
		if got, err := st.Get(ctx, "tx_probe"); err == nil {
			t.Fatalf("a value moved to another key opened as %q", got)
		}
		if err := s.rawSet(ctx, "settings", "value", "application_name", flipChar(rawValue("application_name"))); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, "application_name"); err == nil {
			t.Fatal("a modified ciphertext was accepted")
		}
		if err := s.rawSet(ctx, "settings", "value", "application_name", "plaintext name"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, "application_name"); !errors.Is(err, ports.ErrNotEncrypted) {
			t.Fatalf("a plaintext setting in an encrypted database: %v, want ErrNotEncrypted", err)
		}
	})

	t.Run("PlaintextRefused", func(t *testing.T) {
		s := open(t)
		owner := mustCreate(t, s.Users(), newUser("ivy", "ivy@example.org"))
		id := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-plain", Name: "P", Description: "legacy plaintext", ExpiresAt: now.Add(time.Hour)})
		if got, err := s.Shares().ByID(ctx, id); err != nil || got.Description != "legacy plaintext" {
			t.Fatalf("without a codec the column is plaintext: %q, %v", got.Description, err)
		}
		codec, _ := newTestCodec(t, s.Store, "tenant-1")
		s.setCodec(codec)
		if _, err := s.Shares().ByID(ctx, id); !errors.Is(err, ports.ErrNotEncrypted) {
			t.Fatalf("a plaintext value in an encrypted database: %v, want ErrNotEncrypted", err)
		}
	})
}

// copyOf reads the stored value of an encrypted column (for copying it onto
// another row).
func copyOf(t *testing.T, s encStore, table, column, key string) string {
	t.Helper()
	v, err := s.rawGet(context.Background(), table, column, key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// flipChar returns s with one character in the middle replaced by another
// base64 character (a change that always alters the decoded bytes, unlike the
// unused trailing bits of the last character).
func flipChar(s string) string {
	i := len(s) / 2
	repl := "A"
	if s[i] == 'A' {
		repl = "B"
	}
	return s[:i] + repl + s[i+1:]
}

// RunColumnCodec pins the ports.ColumnCodec contract: values round-trip, are
// bound to table, column and row, differ per encryption, refuse tampering and
// plaintext, and values written before a key rotation stay readable.
func RunColumnCodec(t *testing.T, open func(testing.TB) encStore) {
	ctx := context.Background()
	s := open(t)
	codec, svc := newTestCodec(t, s.Store, "tenant-1")
	var c ports.ColumnCodec = codec

	a, err := c.Seal("users", "email", "7", "alice@example.org")
	if err != nil || !strings.HasPrefix(a, "e1:") || strings.Contains(a, "alice") {
		t.Fatalf("Seal = %q, %v", a, err)
	}
	if b, _ := c.Seal("users", "email", "7", "alice@example.org"); a == b {
		t.Fatal("two encryptions of the same value are identical (nonce reuse)")
	}
	if got, err := c.Open("users", "email", "7", a); err != nil || got != "alice@example.org" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	for name, args := range map[string][3]string{"table": {"shares", "email", "7"}, "column": {"users", "name", "7"}, "row": {"users", "email", "8"}} {
		if _, err := c.Open(args[0], args[1], args[2], a); err == nil {
			t.Fatalf("a value opened for another %s", name)
		}
	}
	if _, err := c.Open("users", "email", "7", flipChar(a)); err == nil {
		t.Fatal("a modified ciphertext was accepted")
	}
	if _, err := c.Open("users", "email", "7", "alice@example.org"); !errors.Is(err, ports.ErrNotEncrypted) {
		t.Fatalf("plaintext: %v, want ErrNotEncrypted", err)
	}
	if _, err := c.Open("users", "email", "7", "e1:!!!"); !errors.Is(err, ports.ErrNotEncrypted) {
		t.Fatalf("garbage after the prefix: %v, want ErrNotEncrypted", err)
	}
	// Blind indexes: deterministic, normalised (NFKC, case-folded, trimmed),
	// bound to table and column, 16 bytes.
	bi, err := c.BlindIndex("users", "email", "Alice@Example.org")
	if err != nil || len(bi) != 16 {
		t.Fatalf("BlindIndex = %x, %v", bi, err)
	}
	if again, _ := c.BlindIndex("users", "email", "  alice@EXAMPLE.org "); !bytes.Equal(bi, again) {
		t.Fatal("blind indexes of the same address differ")
	}
	if other, _ := c.BlindIndex("users", "username", "Alice@Example.org"); bytes.Equal(bi, other) {
		t.Fatal("blind indexes of two columns are equal")
	}
	if other, _ := c.BlindIndex("users", "email", "bob@example.org"); bytes.Equal(bi, other) {
		t.Fatal("blind indexes of two values are equal")
	}
	// After a rotation new values use the new key and old values still open.
	if _, err := svc.Rotate(ctx, "tenant-1", keyring.PurposeData, "conformance"); err != nil {
		t.Fatal(err)
	}
	rotated, err := keyring.NewCodec(ctx, svc, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Close()
	if got, err := rotated.Open("users", "email", "7", a); err != nil || got != "alice@example.org" {
		t.Fatalf("a value from before the rotation: %q, %v", got, err)
	}
	n, err := rotated.Seal("users", "email", "7", "alice@example.org")
	if err != nil || n == a {
		t.Fatalf("Seal after rotation: %v", err)
	}
	if got, err := codec.Open("users", "email", "7", n); err != nil || got != "alice@example.org" {
		t.Fatalf("a value of the new key opened by the older codec: %q, %v", got, err)
	}
}

// encPlatform is a platform store whose adapter can be given a column codec,
// with direct access to the database behind it.
type encPlatform struct {
	ports.PlatformStore
	setCodec func(ports.ColumnCodec)
	rawGet   func(ctx context.Context, table, column, key string) (string, error)
	rawSet   func(ctx context.Context, table, column, key, v string) error
}

// EncryptedPlatformBackend opens a fresh platform store for the
// encrypted-column contracts of the platform database.
type EncryptedPlatformBackend struct {
	Name        string
	Unavailable func() string
	Open        func(testing.TB) encPlatform
}

// EncryptedPlatformBackends lists the platform adapters that implement column
// encryption. The stores start without a codec (as a database without keys).
func EncryptedPlatformBackends() []EncryptedPlatformBackend {
	return []EncryptedPlatformBackend{
		{Name: "sqlite", Unavailable: func() string { return "" }, Open: func(t testing.TB) encPlatform {
			st, err := store.OpenPlatform(filepath.Join(t.TempDir(), "data"), bytes.Repeat([]byte{0x5c}, 32), true, sqlite.PlatformSchema)
			if err != nil {
				t.Fatalf("open platform store: %v", err)
			}
			t.Cleanup(func() { st.Close() })
			a := sqlite.NewPlatform(st.DB)
			return encPlatform{PlatformStore: a, setCodec: a.SetCodec, rawGet: a.RawColumn, rawSet: a.RawSetColumn}
		}},
		{Name: "postgres", Unavailable: postgresUnavailable, Open: func(t testing.TB) encPlatform {
			sc := openScratch(t, postgres.PlatformSchema)
			a := postgres.NewPlatform(sc.DB)
			return encPlatform{PlatformStore: a, setCodec: a.SetCodec, rawGet: a.RawColumn, rawSet: a.RawSetColumn}
		}},
	}
}

// RunEncryptedPlatformColumns pins the contract of the platform database's
// encrypted columns: administrators' TOTP secrets and legacy tenant roots.
func RunEncryptedPlatformColumns(t *testing.T, open func(testing.TB) encPlatform) {
	ctx := context.Background()
	const secret = "JBSWY3DPEHPK3PXP"
	isCipher := func(what, stored string, leaks ...string) {
		t.Helper()
		if !strings.HasPrefix(stored, "e1:") {
			t.Fatalf("%s holds %q, want ciphertext", what, stored)
		}
		for _, l := range leaks {
			if strings.Contains(stored, l) {
				t.Fatalf("%s leaks %q", what, l)
			}
		}
	}

	// The platform's settings are sealed bound to their key, like a tenant's.
	t.Run("Settings", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.PlatformStore, "conformance")
		s.setCodec(codec)
		set := s.PlatformSettings()
		if err := set.EnsureDefault(ctx, "probe_setting", "platform secret value", "system"); err != nil {
			t.Fatal(err)
		}
		if err := set.EnsureDefault(ctx, "probe_setting", "ignored", "system"); err != nil {
			t.Fatal(err)
		}
		v, err := s.rawGet(ctx, "settings", "value", "probe_setting")
		if err != nil {
			t.Fatal(err)
		}
		isCipher("settings.probe_setting", v, "platform secret")
		if got, err := set.Get(ctx, "probe_setting"); err != nil || got != "platform secret value" {
			t.Fatalf("Get = %q, %v", got, err)
		}
		if err := set.Update(ctx, "probe_setting", "second value"); err != nil {
			t.Fatal(err)
		}
		if got, _ := set.Get(ctx, "probe_setting"); got != "second value" {
			t.Fatalf("after Update = %q", got)
		}
		if err := s.rawSet(ctx, "settings", "value", "probe_setting", "plaintext"); err != nil {
			t.Fatal(err)
		}
		if _, err := set.Get(ctx, "probe_setting"); !errors.Is(err, ports.ErrNotEncrypted) {
			t.Fatalf("a plaintext setting: %v, want ErrNotEncrypted", err)
		}
	})

	t.Run("TOTP", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.PlatformStore, "conformance")
		s.setCodec(codec)
		a := s.PlatformAdmins()
		id, err := a.Create(ctx, "root", "", "hash", "2026-01-01T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		key := strconv.FormatInt(id, 10)
		if err := a.SetPendingTOTP(ctx, id, secret); err != nil {
			t.Fatal(err)
		}
		v, _ := s.rawGet(ctx, "platform_admins", "pending_totp_secret", key)
		isCipher("pending_totp_secret", v, secret)
		if got, err := a.ByID(ctx, id); err != nil || got.PendingTOTP != secret || got.TOTPSecret != "" {
			t.Fatalf("ByID = %+v, %v", got, err)
		}
		if err := a.EnableTOTP(ctx, id, 7); err != nil {
			t.Fatal(err)
		}
		v, _ = s.rawGet(ctx, "platform_admins", "totp_secret", key)
		isCipher("totp_secret", v, secret)
		if p, _ := s.rawGet(ctx, "platform_admins", "pending_totp_secret", key); p != "" {
			t.Fatalf("pending_totp_secret after enabling = %q", p)
		}
		for name, get := range map[string]func() (ports.PlatformAdmin, error){
			"ByID":   func() (ports.PlatformAdmin, error) { return a.ByID(ctx, id) },
			"ByName": func() (ports.PlatformAdmin, error) { return a.ByName(ctx, "root") },
		} {
			if got, err := get(); err != nil || got.TOTPSecret != secret || !got.TOTPEnabled || got.LastCounter != 7 {
				t.Fatalf("%s = %+v, %v", name, got, err)
			}
		}
		if l, err := a.List(ctx); err != nil || len(l) != 1 || l[0].TOTPSecret != secret {
			t.Fatalf("List = %+v, %v", l, err)
		}
		// Enabling without a pending secret changes nothing.
		if err := a.EnableTOTP(ctx, id, 9); err != nil {
			t.Fatal(err)
		}
		if got, _ := a.ByID(ctx, id); got.TOTPSecret != secret || got.LastCounter != 7 {
			t.Fatalf("EnableTOTP without a pending secret: %+v", got)
		}
		// Inside a transaction the same codec applies.
		tx, err := s.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		id2, err := tx.PlatformAdmins().Create(ctx, "second", "", "hash", "2026-01-01T00:00:00Z")
		if err == nil {
			err = tx.PlatformAdmins().SetPendingTOTP(ctx, id2, "tx-secret")
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		v, _ = s.rawGet(ctx, "platform_admins", "pending_totp_secret", strconv.FormatInt(id2, 10))
		isCipher("transaction pending_totp_secret", v, "tx-secret")
		// A secret copied to another administrator, or to the other column,
		// does not open; neither does a flipped bit.
		if err := s.rawSet(ctx, "platform_admins", "totp_secret", strconv.FormatInt(id2, 10), v); err != nil {
			t.Fatal(err)
		}
		if _, err := a.ByID(ctx, id2); err == nil {
			t.Fatal("a secret moved to another column opened")
		}
		v, _ = s.rawGet(ctx, "platform_admins", "totp_secret", key)
		if err := s.rawSet(ctx, "platform_admins", "totp_secret", strconv.FormatInt(id2, 10), v); err != nil {
			t.Fatal(err)
		}
		if _, err := a.ByID(ctx, id2); err == nil {
			t.Fatal("a secret moved to another administrator opened")
		}
		if err := s.rawSet(ctx, "platform_admins", "totp_secret", key, flipChar(v)); err != nil {
			t.Fatal(err)
		}
		if _, err := a.ByID(ctx, id); err == nil {
			t.Fatal("a modified ciphertext was accepted")
		}
		// Resetting clears both.
		if err := s.rawSet(ctx, "platform_admins", "totp_secret", key, ""); err != nil {
			t.Fatal(err)
		}
		if err := a.ResetTOTP(ctx, id); err != nil {
			t.Fatal(err)
		}
		if got, err := a.ByID(ctx, id); err != nil || got.TOTPSecret != "" || got.PendingTOTP != "" || got.TOTPEnabled {
			t.Fatalf("after ResetTOTP: %+v, %v", got, err)
		}
	})

	t.Run("LegacyRoot", func(t *testing.T) {
		s := open(t)
		codec, _ := newTestCodec(t, s.PlatformStore, "conformance")
		s.setCodec(codec)
		root := bytes.Repeat([]byte{0x7e}, 32)
		for _, id := range []string{"aaaa", "bbbb"} {
			rec := tenantRec(id, "t-"+id, "T", "active")
			rec.KeyMode, rec.LegacyRoot = "legacy", root
			mustTenant(t, s, rec)
		}
		mustTenant(t, s, tenantRec("cccc", "t-cccc", "T", "active"))
		v, err := s.rawGet(ctx, "tenants", "legacy_root", "aaaa")
		if err != nil {
			t.Fatal(err)
		}
		isCipher("tenants.legacy_root", v, string(root))
		if got, err := s.Tenants().ByID(ctx, "aaaa"); err != nil || !bytes.Equal(got.LegacyRoot, root) {
			t.Fatalf("ByID = %x, %v", got.LegacyRoot, err)
		}
		if got, err := s.Tenants().BySlug(ctx, "t-bbbb"); err != nil || !bytes.Equal(got.LegacyRoot, root) {
			t.Fatalf("BySlug = %x, %v", got.LegacyRoot, err)
		}
		if got, err := s.Tenants().ByID(ctx, "cccc"); err != nil || got.LegacyRoot != nil {
			t.Fatalf("a derived tenant has a root: %x, %v", got.LegacyRoot, err)
		}
		if l, err := s.Tenants().List(ctx, ""); err != nil || len(l) != 3 || !bytes.Equal(l[0].LegacyRoot, root) {
			t.Fatalf("List = %+v, %v", l, err)
		}
		// A root copied to another tenant does not open.
		if err := s.rawSet(ctx, "tenants", "legacy_root", "bbbb", v); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Tenants().ByID(ctx, "bbbb"); err == nil {
			t.Fatal("a root moved to another tenant opened")
		}
	})

	t.Run("PlaintextRefused", func(t *testing.T) {
		s := open(t)
		id, err := s.PlatformAdmins().Create(ctx, "legacy", "", "hash", "2026-01-01T00:00:00Z")
		if err == nil {
			err = s.PlatformAdmins().SetPendingTOTP(ctx, id, secret)
		}
		if err != nil {
			t.Fatal(err)
		}
		rec := tenantRec("dddd", "t-dddd", "T", "active")
		rec.KeyMode, rec.LegacyRoot = "legacy", bytes.Repeat([]byte{9}, 32)
		mustTenant(t, s, rec)
		codec, _ := newTestCodec(t, s.PlatformStore, "conformance")
		s.setCodec(codec)
		if _, err := s.PlatformAdmins().ByID(ctx, id); !errors.Is(err, ports.ErrNotEncrypted) {
			t.Fatalf("a plaintext secret in an encrypted database: %v, want ErrNotEncrypted", err)
		}
		if _, err := s.Tenants().ByID(ctx, "dddd"); !errors.Is(err, ports.ErrNotEncrypted) {
			t.Fatalf("a plaintext root in an encrypted database: %v, want ErrNotEncrypted", err)
		}
	})
}

func i64p(v int64) *int64 { return &v }
