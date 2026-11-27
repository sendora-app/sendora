// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const testTenant = "11111111-2222-3333-4444-555555555555"
const testObject = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

type entraTransport struct {
	next   http.RoundTripper
	target *url.URL
}

func (t entraTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "login.microsoftonline.com" {
		return nil, fmt.Errorf("unexpected external request %s", r.URL.Host)
	}
	c := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.target.Scheme
	u.Host = t.target.Host
	c.URL = &u
	c.Host = t.target.Host
	return t.next.RoundTrip(c)
}

func TestEntraValidationAndPersistence(t *testing.T) {
	for _, tenant := range []string{"common", "organizations", "consumers", "../common", "00000000-0000-0000-0000-000000000000", "9188040d-6c67-4c5b-b112-36a304b66dad"} {
		if validProvider(&Provider{Type: "entra", Name: "Microsoft", ClientID: "client", TenantID: tenant}) == "" {
			t.Fatalf("accepted %s", tenant)
		}
	}
	for _, issuer := range []string{"http://login.microsoftonline.com/" + testTenant + "/v2.0", "https://evil.example/" + testTenant + "/v2.0", entraAuthority + testTenant + "/v2.0?x=y", entraAuthority + "common/v2.0"} {
		if validProvider(&Provider{Type: "entra", Name: "Microsoft", ClientID: "client", IssuerURL: issuer}) == "" {
			t.Fatalf("accepted %s", issuer)
		}
	}
	e := newEnv(t)
	admin := e.setup()
	body := map[string]any{"name": "Microsoft Entra ID", "type": "entra", "tenant_id": testTenant, "client_id": "client", "client_secret": "secret", "enabled": true, "allow_registration": true, "trust_email": true}
	created := e.do("POST", "/api/auth-providers", admin, body)
	e.want(created, 201, "create Entra")
	p, err := e.s.providerByUUID(created.S("uuid"))
	if err != nil {
		t.Fatal(err)
	}
	if p.TenantID != testTenant || p.IssuerURL != entraAuthority+testTenant+"/v2.0" || p.TrustEmail {
		t.Fatalf("unsafe persisted provider %+v", p)
	}
	listed := e.do("GET", "/api/auth-providers", admin, nil)
	if strings.Contains(string(listed.Body), `"client_secret":"secret"`) {
		t.Fatal("secret exposed")
	}
	public := e.do("GET", "/api/auth/providers", "", nil)
	e.want(public, 200, "public provider list")
	if strings.Contains(string(public.Body), "secret") || strings.Contains(string(public.Body), "tenant_id") {
		t.Fatal("provider config exposed")
	}
	u, msg := e.s.resolveExternalUser(p, extIdentity{Sub: testTenant + ":" + testObject, Name: "Microsoft user", Email: "admin@x.io", EmailVerified: true})
	if u == nil {
		t.Fatal(msg)
	}
	// Even direct callers must not trust Entra email.
	if u.Admin || u.ID == 1 || u.Email != "" {
		t.Fatal("external account received local identity or privileges")
	}
	body["tenant_id"] = "99999999-2222-3333-4444-555555555555"
	e.want(e.do("PUT", fmt.Sprintf("/api/auth-providers/%d", p.ID), admin, body), 409, "linked identity cannot change tenant")
	body["tenant_id"] = testTenant
	body["client_secret"] = "rotated"
	e.want(e.do("PUT", fmt.Sprintf("/api/auth-providers/%d", p.ID), admin, body), 200, "rotate secret")
}

// Signed mock tokens and discovery stay entirely local, including the Microsoft authority.
func TestEntraOIDCFlowSecurity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := entraAuthority + testTenant + "/v2.0"
	for _, scenario := range []string{"valid", "wrong-tenant", "wrong-issuer", "wrong-audience", "expired", "wrong-nonce", "bad-signature", "missing-object", "unverified-email"} {
		t.Run(scenario, func(t *testing.T) {
			e := newEnv(t)
			e.setup()
			e.s.BaseURL = "https://sendora.example"
			_, err := e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES(?,?,?,?,?,?,?,?,?)`, "entra-test", "Entra", "entra", true, "client", "secret", issuer, true, true)
			if err != nil {
				t.Fatal(err)
			}
			nonce, verifier := "", ""
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
					json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": entraAuthority + testTenant + "/oauth2/v2.0/authorize", "token_endpoint": entraAuthority + testTenant + "/oauth2/v2.0/token", "jwks_uri": entraAuthority + testTenant + "/discovery/v2.0/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
				case strings.HasSuffix(r.URL.Path, "/keys"):
					json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
				case strings.HasSuffix(r.URL.Path, "/token"):
					r.ParseForm()
					if r.Form.Get("code_verifier") != verifier || verifier == "" {
						t.Error("missing PKCE verifier")
						http.Error(w, "bad verifier", 400)
						return
					}
					claims := jwt.MapClaims{"iss": issuer, "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "sub": "pairwise-subject", "nonce": nonce, "tid": testTenant, "oid": testObject, "ver": "2.0", "email": "admin@x.io", "email_verified": true, "name": "Tenant user", "preferred_username": "tenant-user"}
					switch scenario {
					case "wrong-tenant":
						claims["tid"] = "99999999-2222-3333-4444-555555555555"
					case "wrong-issuer":
						claims["iss"] = "https://evil.example"
					case "wrong-audience":
						claims["aud"] = "other-app"
					case "expired":
						claims["exp"] = time.Now().Add(-time.Hour).Unix()
					case "wrong-nonce":
						claims["nonce"] = "attacker"
					case "missing-object":
						delete(claims, "oid")
					case "unverified-email":
						delete(claims, "email_verified")
					}
					token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
					token.Header["kid"] = "test"
					signingKey := key
					if scenario == "bad-signature" {
						signingKey, _ = rsa.GenerateKey(rand.Reader, 2048)
					}
					raw, _ := token.SignedString(signingKey)
					json.NewEncoder(w).Encode(map[string]any{"access_token": "mock", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
				default:
					t.Errorf("unexpected mock path %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer mock.Close()
			target, _ := url.Parse(mock.URL)
			client := &http.Client{Transport: entraTransport{http.DefaultTransport, target}}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
			req := httptest.NewRequest("GET", "https://sendora.example/api/auth/oidc/entra-test/start", nil).WithContext(ctx)
			start := httptest.NewRecorder()
			e.s.Router().ServeHTTP(start, req)
			if start.Code != 302 {
				t.Fatalf("start %d %s", start.Code, start.Body)
			}
			auth, _ := url.Parse(start.Header().Get("Location"))
			nonce = auth.Query().Get("nonce")
			if auth.Query().Get("code_challenge_method") != "S256" || auth.Query().Get("code_challenge") == "" || nonce == "" {
				t.Fatal("missing PKCE or nonce")
			}
			cookies := start.Result().Cookies()
			for _, c := range cookies {
				if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
					t.Fatal("unsafe OAuth cookie")
				}
				if c.Name == "oidc_pkce" {
					verifier = c.Value
				}
			}
			callback := httptest.NewRequest("GET", "https://sendora.example/api/auth/oidc/entra-test/callback?code=mock&state="+url.QueryEscape(auth.Query().Get("state")), nil).WithContext(ctx)
			for _, c := range cookies {
				callback.AddCookie(c)
			}
			result := httptest.NewRecorder()
			e.s.Router().ServeHTTP(result, callback)
			success := scenario == "valid" || scenario == "unverified-email"
			if (result.Header().Get("Location") == "/?oidc=1") != success {
				t.Fatalf("unexpected callback %s", result.Header().Get("Location"))
			}
			var count int
			e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM user_auth_providers`).Scan(&count)
			if success {
				if count != 1 {
					t.Fatal("no identity link")
				}
				var email, sub string
				var admin bool
				e.s.St.DB.QueryRow(`SELECT u.email,u.admin,p.provider_user_id FROM users u JOIN user_auth_providers p ON p.user_id=u.id`).Scan(&email, &admin, &sub)
				if email != "" || admin || sub != testTenant+":"+testObject {
					t.Fatal("unsafe identity mapping")
				}
			} else if count != 0 {
				t.Fatal("rejected token created identity")
			}
			badState := httptest.NewRequest("GET", "https://sendora.example/api/auth/oidc/entra-test/callback?state=attacker&code=mock", nil).WithContext(ctx)
			for _, c := range cookies {
				badState.AddCookie(c)
			}
			rejected := httptest.NewRecorder()
			e.s.Router().ServeHTTP(rejected, badState)
			if !strings.Contains(rejected.Header().Get("Location"), "invalid+state") {
				t.Fatal("state bypass")
			}
		})
	}
}
