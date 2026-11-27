// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import "context"

// LinkedProvider is a sign-in provider linked to an account.
type LinkedProvider struct {
	ID   int64
	Name string
	Type string
}

// ProviderLinkType is one (account, provider type) link.
type ProviderLinkType struct {
	UserID int64
	Type   string
}

// ProviderRecord is a stored external sign-in provider.
type ProviderRecord struct {
	ID                int64
	UUID              string
	Name              string
	Type              string
	Enabled           bool
	ClientID          string
	ClientSecret      string
	IssuerURL         string
	Icon              string
	TrustEmail        bool
	AllowRegistration bool
	Managed           bool
}

// ProviderSettings are the editable fields of a provider.
type ProviderSettings struct {
	Name              string
	Type              string
	Enabled           bool
	ClientID          string
	ClientSecret      string
	IssuerURL         string
	Icon              string
	TrustEmail        bool
	AllowRegistration bool
}

// AuthProviderRepository covers the external sign-in providers
// (auth_providers) and their links to accounts (user_auth_providers).
type AuthProviderRepository interface {
	// CountEnabled counts the enabled providers.
	CountEnabled(ctx context.Context) (int, error)
	// CountLinks counts the providers linked to the account.
	CountLinks(ctx context.Context, userID int64) (int, error)
	// CountEnabledLinks counts the enabled providers linked to the account.
	CountEnabledLinks(ctx context.Context, userID int64) (int, error)
	// CountEnabledLinksOfLocal is CountEnabledLinks for a non-guest account
	// (0 for guests and unknown accounts).
	CountEnabledLinksOfLocal(ctx context.Context, userID int64) (int, error)
	// CountEnabledLinksExcept counts the account's enabled linked providers
	// other than providerID.
	CountEnabledLinksExcept(ctx context.Context, userID, providerID int64) (int, error)
	// CountEnabledLink is 1 when the account is linked to providerID and
	// that provider is enabled, else 0.
	CountEnabledLink(ctx context.Context, userID, providerID int64) (int, error)
	// CountExternalAdmins counts the distinct non-guest administrators linked
	// to an enabled provider, leaving out account exclUser, provider
	// exclProvider and the single link (exclLinkUser, exclLinkProvider);
	// 0 excludes nothing.
	CountExternalAdmins(ctx context.Context, exclUser, exclProvider, exclLinkUser, exclLinkProvider int64) (int, error)
	// ListLinked returns the providers linked to the account, in no
	// particular order. A row that cannot be read is returned with zero
	// values; on an error the rows read so far are returned with it.
	ListLinked(ctx context.Context, userID int64) ([]LinkedProvider, error)
	// ListLinkTypes returns every (account, provider type) link ordered by
	// type. Unreadable rows are skipped.
	ListLinkTypes(ctx context.Context) ([]ProviderLinkType, error)
	// ListLinkNames returns every (account, provider name) link ordered by
	// provider name (the Type field carries the name). An unreadable row is
	// an error.
	ListLinkNames(ctx context.Context) ([]ProviderLinkType, error)
	// ByUUID returns the provider with uuid; ErrNotFound when unknown. On a
	// read error the fields read so far are returned with it.
	ByUUID(ctx context.Context, uuid string) (ProviderRecord, error)
	// List returns every provider (only the enabled ones when enabledOnly),
	// ordered by sort position, then name. A row that cannot be read is
	// listed with the fields read so far.
	List(ctx context.Context, enabledOnly bool) ([]ProviderRecord, error)
	// Create stores an administrator-made provider and returns its id.
	Create(ctx context.Context, uuid string, p ProviderSettings) (int64, error)
	// IsManaged reports whether the provider comes from the server
	// configuration (false when unknown).
	IsManaged(ctx context.Context, id int64) (bool, error)
	// Identity returns the provider's type, client id and issuer;
	// ErrNotFound when unknown.
	Identity(ctx context.Context, id int64) (typ, clientID, issuer string, err error)
	// CountProviderLinks counts the accounts linked to the provider.
	CountProviderLinks(ctx context.Context, providerID int64) (int, error)
	// Update changes the provider's settings except the client secret.
	Update(ctx context.Context, id int64, p ProviderSettings) error
	// SetClientSecret replaces the provider's client secret.
	SetClientSecret(ctx context.Context, id int64, secret string) error
	// Delete removes the provider (and its links).
	Delete(ctx context.Context, id int64) error
	// LinkedUser returns the account linked to the provider's subject;
	// ErrNotFound when there is none.
	LinkedUser(ctx context.Context, providerID int64, subject string) (int64, error)
	// Link links the account to the provider's subject.
	Link(ctx context.Context, userID, providerID int64, subject string) error
	// ManagedConfig returns the id, type, client id, issuer and secret of the
	// provider with uuid; ErrNotFound when unknown.
	ManagedConfig(ctx context.Context, uuid string) (id int64, typ, clientID, issuer, secret string, err error)
	// UpdateManaged changes a provider from the server configuration and
	// marks it managed.
	UpdateManaged(ctx context.Context, id int64, p ProviderSettings) error
	// CreateManaged stores a provider from the server configuration.
	CreateManaged(ctx context.Context, uuid string, p ProviderSettings) error
	// ReleaseUnconfigured makes managed providers whose uuid is not in
	// configured editable again.
	ReleaseUnconfigured(ctx context.Context, configured []string) error
	// Unlink removes the account's link to providerID.
	Unlink(ctx context.Context, userID, providerID int64) error
}
