// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
)

const entraAuthority = "https://login.microsoftonline.com/"

func entraTenant(issuer string) (string, error) {
	if !strings.HasPrefix(issuer, entraAuthority) || !strings.HasSuffix(issuer, "/v2.0") {
		return "", fmt.Errorf("invalid Entra issuer")
	}
	tenant := strings.TrimSuffix(strings.TrimPrefix(issuer, entraAuthority), "/v2.0")
	id, err := uuid.Parse(tenant)
	if err != nil || id == uuid.Nil || tenant != id.String() || tenant == "9188040d-6c67-4c5b-b112-36a304b66dad" {
		return "", fmt.Errorf("explicit organization tenant GUID required")
	}
	return tenant, nil
}

func normalizeEntra(p *Provider) string {
	if p.TenantID != "" {
		id, err := uuid.Parse(strings.TrimSpace(p.TenantID))
		if err != nil {
			return "valid organization tenant ID required"
		}
		p.IssuerURL = entraAuthority + id.String() + "/v2.0"
	}
	tenant, err := entraTenant(p.IssuerURL)
	if err != nil {
		return "valid organization tenant ID required"
	}
	p.TenantID = tenant
	// Microsoft email/UPN claims are mutable hints, not verified ownership.
	p.TrustEmail = false
	return ""
}

type externalClaims struct {
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	TenantID          string `json:"tid"`
	ObjectID          string `json:"oid"`
	Version           string `json:"ver"`
}

// Called only after signature, issuer, audience, expiry and nonce verification.
func oidcIdentity(p *Provider, token *oidc.IDToken) (extIdentity, error) {
	var c externalClaims
	if err := token.Claims(&c); err != nil {
		return extIdentity{}, err
	}
	id := extIdentity{Sub: token.Subject, Email: c.Email, EmailVerified: c.EmailVerified, Name: c.Name, Username: c.PreferredUsername}
	if p.Type == "entra" {
		tenant, err := entraTenant(p.IssuerURL)
		object, objectErr := uuid.Parse(c.ObjectID)
		if err != nil || token.Issuer != p.IssuerURL || c.TenantID != tenant || c.Version != "2.0" || objectErr != nil || object == uuid.Nil || token.Subject == "" {
			return extIdentity{}, fmt.Errorf("invalid Entra identity")
		}
		id.Sub = tenant + ":" + object.String()
		id.Email, id.EmailVerified = "", false
	}
	return id, nil
}
