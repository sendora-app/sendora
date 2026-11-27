// SPDX-License-Identifier: AGPL-3.0-or-later

package app

// ROUTE ACCESS MATRIX
//
// Every route of the real router must be listed in routeTable with the access
// policy it is meant to have. TestRouteAccessTableIsComplete fails when a route
// exists without an entry (a new route must declare its policy) or an entry has
// no route (stale). TestRouteAccessMatrix then calls every route as every
// principal and checks the outcome the policy implies. The privacy rules have
// dedicated tests below.

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

type accessPolicy string

const (
	// polPublic: no credentials involved; every principal gets the same answer.
	polPublic accessPolicy = "public"
	// polPublicToken: reachable without a session but the request must carry a
	// share link, invite, reset, MFA or setup token. A bogus token is refused.
	polPublicToken accessPolicy = "public-token"
	// polUser: any signed-in full account (user, administrator). Not guests,
	// not auditors.
	polUser accessPolicy = "user"
	// polSelf: any signed-in non-guest account including auditors (own profile).
	polSelf accessPolicy = "self"
	// polOwner: a signed-in account, and only the owner of the addressed
	// resource. Everyone else (other users, administrators) gets 404.
	polOwner accessPolicy = "owner"
	// polAdmin: administrators only.
	polAdmin accessPolicy = "admin"
	// polAuditor: the audit log: auditors and administrators read the same log.
	polAuditor accessPolicy = "auditor"
	// polGuestAllowed: every signed-in principal including guests and auditors.
	polGuestAllowed accessPolicy = "guest-allowed"
	// polUserOrGuest: users and guests (reverse-share invite sessions), not auditors.
	polUserOrGuest accessPolicy = "user-or-guest"
)

type principal string

const (
	pAnon    principal = "anonymous"
	pOwnerA  principal = "owner-A"
	pUserB   principal = "user-B"
	pGuest   principal = "guest"
	pAdmin   principal = "admin"
	pAuditor principal = "auditor"
)

var allPrincipals = []principal{pAnon, pOwnerA, pUserB, pGuest, pAdmin, pAuditor}

// routeSpec is one row of the table.
type routeSpec struct {
	key    string // "METHOD /pattern" exactly as chi.Walk reports it
	policy accessPolicy
	// soft lists extra status codes an allowed principal may legitimately get
	// (the minimal fixture cannot satisfy the handler); never 401, and 403/404
	// only where documented in why.
	soft []int
	why  string // required whenever soft or noBogus is used
	// noBogus: the "bogus token must be refused" check is skipped (why says why).
	noBogus bool
	body    any // request body for every principal (nil = empty)
}

func rs(key string, p accessPolicy) routeSpec { return routeSpec{key: key, policy: p} }

func (r routeSpec) withSoft(why string, codes ...int) routeSpec {
	r.soft, r.why = codes, why
	return r
}

func (r routeSpec) bogusOK(why string) routeSpec {
	r.noBogus, r.why = true, why
	return r
}

func (r routeSpec) withBody(b any) routeSpec { r.body = b; return r }

var bogusToken = map[string]any{"token": "bogus-token-value"}

var routeTable = []routeSpec{
	// ---- public ----
	rs("GET /api/health", polPublic),
	rs("GET /api/health/ready", polPublic),
	// Off (404) unless SENDORA_METRICS_TOKEN_FILE is set; then its own bearer token, never a session.
	rs("GET /api/metrics", polPublic),
	rs("GET /api/bootstrap", polPublic),
	rs("GET /api/capabilities", polPublic),
	rs("GET /api/i18n/languages", polPublic),
	rs("GET /api/i18n/{code}", polPublic),
	rs("GET /api/themes/active", polPublic),
	rs("GET /api/backgrounds", polPublic),
	rs("GET /api/backgrounds/{file}", polPublic).withSoft("fixture has no such background", 404),
	rs("GET /api/branding/{kind}", polPublic).withSoft("no logo configured in the fixture", 404),
	rs("GET /api/auth/providers", polPublic),
	rs("GET /api/auth/email-languages", polPublic),
	rs("POST /api/auth/login", polPublic),
	rs("POST /api/auth/refresh", polPublic),
	rs("POST /api/auth/logout", polPublic),
	rs("POST /api/auth/forgot-password", polPublic),
	rs("POST /api/auth/register", polPublic),
	rs("POST /api/auth/resend-verification", polPublic),
	rs("GET /api/auth/oidc/{uuid}/start", polPublic).withSoft("unknown provider", 404),

	// ---- public, but only with a token ----
	rs("POST /api/setup", polPublicToken).withBody(bogusToken).bogusOK("setup is already done in the fixture: 403 for everyone, see the dedicated setup test"),
	rs("POST /api/auth/reset-password", polPublicToken).withBody(bogusToken),
	rs("POST /api/auth/verify-email", polPublicToken).withBody(bogusToken),
	rs("POST /api/auth/mfa-reset/confirm", polPublicToken).withBody(bogusToken),
	rs("POST /api/auth/mfa/totp", polPublicToken).withBody(bogusToken),
	rs("POST /api/auth/mfa/recovery", polPublicToken).withBody(bogusToken),
	rs("POST /api/auth/mfa/webauthn/begin", polPublicToken).withBody(bogusToken),
	rs("POST /api/auth/mfa/webauthn/finish", polPublicToken).withBody(bogusToken),
	rs("GET /api/auth/oidc/{uuid}/callback", polPublicToken).bogusOK("an unknown provider redirects to the SPA, which the client follows"),
	rs("POST /api/reverse-shares/accept", polPublicToken).withBody(bogusToken),
	// share links: "anyone with the link"; {id} is the unguessable link id
	rs("GET /api/shares/{id}", polPublicToken),
	rs("POST /api/shares/{id}/unlock", polPublicToken),
	rs("GET /api/shares/{id}/download", polPublicToken),
	rs("POST /api/shares/{id}/download", polPublicToken),
	rs("GET /api/shares/{id}/download/*", polPublicToken),
	rs("GET /api/shares/{id}/preview/*", polPublicToken).withSoft("previews are off by default", 403, 404),

	// ---- own profile ----
	rs("GET /api/users/me", polGuestAllowed),
	rs("PUT /api/users/me", polSelf),
	rs("DELETE /api/users/me/providers/{id}", polUser).withSoft("{id} is a linked sign-in of the caller; the fixture has none", 404),
	rs("GET /api/users/me/mfa", polSelf),
	rs("POST /api/users/me/mfa/totp/begin", polSelf).withSoft("needs the current password in the body", 400, 403),
	rs("POST /api/users/me/mfa/totp/confirm", polSelf).withSoft("needs a started enrolment", 400, 403),
	rs("POST /api/users/me/mfa/totp/remove", polSelf).withSoft("needs the password / a code", 400, 403),
	rs("POST /api/users/me/mfa/recovery/regenerate", polSelf).withSoft("needs the password / a code", 400, 403),
	rs("POST /api/users/me/mfa/webauthn/begin", polSelf).withSoft("needs the password", 400, 403),
	rs("POST /api/users/me/mfa/webauthn/finish", polSelf).withSoft("needs a begun ceremony", 400, 403),
	rs("PUT /api/users/me/mfa/webauthn/{id}", polSelf).withSoft("{id} is a security key of the caller; the fixture has none", 404),
	rs("POST /api/users/me/mfa/webauthn/{id}/remove", polSelf).withSoft("{id} is a security key of the caller; the fixture has none", 400, 403, 404),
	rs("GET /api/users/me/sessions", polSelf),
	rs("POST /api/users/me/sessions/revoke-others", polSelf),
	rs("DELETE /api/users/me/sessions/{id}", polSelf).withSoft("{id} is a session of the caller; the fixture uses an unknown id", 404),
	rs("GET /api/users/me/export", polSelf),
	rs("POST /api/users/me/erase", polSelf).withSoft("needs the current password in the body", 400),
	rs("POST /api/users/me/terms", polSelf).withSoft("terms acceptance is off in the fixture", 400, 409),
	rs("POST /api/auth/step-up", polAdmin).withSoft("needs the password or a code in the body", 400),
	rs("POST /api/auth/step-up/webauthn/begin", polAdmin).withSoft("the fixture administrator has no security key", 409),

	// ---- shares: owner only ----
	rs("GET /api/shares", polUser), // lists the caller's own shares
	rs("POST /api/shares/prune-expired", polUser),
	rs("GET /api/shares/{id}/downloads", polOwner),
	rs("POST /api/shares/{id}/expire", polOwner),
	rs("POST /api/shares/{id}/extend", polOwner),
	rs("PUT /api/shares/{id}/expiry", polOwner),
	rs("POST /api/shares/{id}/download-limit", polOwner),
	rs("PUT /api/shares/{id}", polOwner),
	rs("DELETE /api/shares/{id}", polOwner),
	rs("GET /api/shares/{id}/files", polOwner),
	rs("DELETE /api/shares/{id}/files/{fileId}", polOwner),

	// ---- upload sessions ----
	rs("POST /api/uploads", polUserOrGuest),
	rs("GET /api/uploads/{id}", polOwner),
	rs("PATCH /api/uploads/{id}/files/{idx}", polOwner),
	rs("POST /api/uploads/{id}/complete", polOwner),
	rs("DELETE /api/uploads/{id}", polOwner),

	// ---- reverse shares ----
	rs("POST /api/reverse-shares/invite", polUser),
	rs("GET /api/reverse-shares/invites", polUser),
	rs("POST /api/reverse-shares/invites/{id}/revoke", polOwner),

	// ---- audit log: auditors only ----
	rs("GET /api/audit", polAuditor),
	rs("GET /api/audit/export", polAuditor),
	rs("GET /api/audit/status", polAuditor),
	rs("GET /api/access-review", polAuditor),
	rs("GET /api/access-review/export", polAuditor),

	// ---- administration ----
	rs("GET /api/users", polAdmin),
	rs("POST /api/users", polAdmin),
	rs("PUT /api/users/{id}", polAdmin),
	rs("DELETE /api/users/{id}", polAdmin),
	rs("POST /api/users/{id}/erase", polAdmin),
	rs("POST /api/users/{id}/force-reset-password", polAdmin),
	rs("POST /api/users/{id}/unlock-login", polAdmin),
	rs("POST /api/users/{id}/mfa/reset", polAdmin),
	rs("POST /api/users/{id}/welcome", polAdmin),
	rs("POST /api/users/{id}/disable", polAdmin),
	rs("POST /api/users/{id}/enable", polAdmin),
	rs("POST /api/users/{id}/sessions/revoke", polAdmin),
	rs("GET /api/settings", polAdmin),
	rs("PUT /api/settings", polAdmin),
	rs("POST /api/settings/branding/{kind}", polAdmin),
	rs("DELETE /api/settings/branding/{kind}", polAdmin),
	rs("POST /api/backgrounds", polAdmin),
	rs("DELETE /api/backgrounds/{file}", polAdmin).withSoft("fixture has no such background", 404),
	rs("GET /api/stats", polAdmin),
	rs("GET /api/ip-bans", polAdmin),
	rs("DELETE /api/ip-bans", polAdmin).withSoft("no such banned address", 404),
	rs("GET /api/logs", polAdmin),
	rs("GET /api/logs/export", polAdmin),
	rs("GET /api/logs/status", polAdmin),
	rs("GET /api/themes", polAdmin),
	rs("POST /api/themes", polAdmin),
	rs("DELETE /api/themes/{id}", polAdmin).withSoft("fixture has no such theme", 404),
	rs("POST /api/themes/{id}/activate", polAdmin).withSoft("fixture has no such theme", 404),
	rs("GET /api/auth-providers", polAdmin),
	rs("POST /api/auth-providers", polAdmin),
	rs("PUT /api/auth-providers/{id}", polAdmin).withSoft("fixture has no such provider", 404),
	rs("DELETE /api/auth-providers/{id}", polAdmin).withSoft("fixture has no such provider", 404),
	rs("GET /api/ui-languages", polAdmin).withSoft("translation key list is not built into the test binary", 503),
	rs("GET /api/ui-languages/{code}/export", polAdmin).withSoft("fixture has no such language", 404),
	rs("POST /api/ui-languages", polAdmin).withSoft("translation key list is not built into the test binary", 503),
	rs("DELETE /api/ui-languages/{code}", polAdmin).withSoft("fixture has no such language", 404),
	rs("POST /api/email-languages", polAdmin),
	rs("GET /api/email-templates", polAdmin),
	rs("PUT /api/email-templates", polAdmin),
	rs("POST /api/email-templates/test", polAdmin),
	rs("POST /api/email-templates/preview", polAdmin),
	rs("GET /api/email-templates/export", polAdmin).withSoft("needs a language parameter", 404),
	rs("POST /api/email-templates/import", polAdmin),
	rs("GET /api/admin/keys", polAdmin).withSoft("the fixture database has no column keys", 400, 404, 409),
	rs("POST /api/admin/keys/rotate", polAdmin).withSoft("the fixture database has no column keys", 400, 404, 409),
	rs("POST /api/admin/keys/retire", polAdmin).withSoft("the fixture database has no column keys", 400, 404, 409),
	rs("POST /api/admin/keys/reencrypt-files", polAdmin).withSoft("the fixture database has no column keys", 400, 404, 409),
	rs("GET /api/admin/kek", polAdmin),
	rs("POST /api/admin/kek/upload", polAdmin).withSoft("the Cluster flavour is not in use", 400, 501),
	rs("POST /api/admin/kek/replace", polAdmin).withSoft("the Cluster flavour is not in use", 400, 501),
	rs("POST /api/admin/kek/release", polAdmin).withSoft("the Cluster flavour is not in use", 400, 501),
	rs("GET /api/backups", polAdmin),
	rs("POST /api/backups", polAdmin),
	rs("GET /api/backups/{name}", polAdmin).withSoft("fixture has no such backup", 404),
	rs("DELETE /api/backups/{name}", polAdmin).withSoft("fixture has no such backup", 404),
	rs("POST /api/backups/import", polAdmin),
	rs("POST /api/backups/import/apply", polAdmin),
	rs("GET /api/storage", polAdmin),
	rs("POST /api/storage/test", polAdmin),
	rs("POST /api/storage/migrate", polAdmin).withSoft("every file is already in the current location", 409),
	rs("POST /api/storage/migrate/cancel", polAdmin).withSoft("no migration is running", 409),
	rs("GET /api/multitenant", polAdmin),
	rs("POST /api/multitenant", polAdmin).withSoft("fixture sends no conversion request", 400),
	rs("DELETE /api/multitenant", polAdmin),
	rs("POST /api/multitenant/restart", polAdmin).withSoft("no conversion is scheduled", 409),
}

// allows reports whether the principal is meant to get past the access checks.
func (p accessPolicy) allows(who principal) bool {
	switch p {
	case polPublic, polPublicToken:
		return true
	case polUser:
		return who == pOwnerA || who == pUserB || who == pAdmin
	case polSelf:
		return who == pOwnerA || who == pUserB || who == pAdmin || who == pAuditor
	case polOwner:
		return who == pOwnerA
	case polAdmin:
		return who == pAdmin
	case polAuditor:
		return who == pAuditor || who == pAdmin
	case polGuestAllowed:
		return who != pAnon
	case polUserOrGuest:
		return who == pOwnerA || who == pUserB || who == pAdmin || who == pGuest
	}
	return false
}

// deniedCode is the exact status a refused principal must get.
func deniedCode(spec routeSpec, method, route string, who principal) int {
	if who == pAnon {
		return 401
	}
	if spec.policy == polOwner && (who == pUserB || who == pAdmin) {
		return 404 // existence of other people's resources is not revealed
	}
	if spec.policy == polOwner && who == pGuest && strings.HasPrefix(route, "/api/uploads/") {
		return 404 // guests may use the upload routes, but only see their own sessions
	}
	return 403
}

func splitKey(key string) (method, route string) {
	i := strings.Index(key, " ")
	return key[:i], key[i+1:]
}

func walkRoutes(t *testing.T, s *Server) []string {
	t.Helper()
	var keys []string
	err := chi.Walk(s.Router().(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if route == "/*" {
			return nil // SPA fallback
		}
		keys = append(keys, method+" "+route)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(keys)
	return keys
}

func TestRouteAccessTableIsComplete(t *testing.T) {
	e := newEnv(t)
	routes := walkRoutes(t, e.s)
	have := map[string]bool{}
	for _, k := range routes {
		have[k] = true
	}
	declared := map[string]bool{}
	var missing, stale, dup, noWhy []string
	for _, spec := range routeTable {
		if declared[spec.key] {
			dup = append(dup, spec.key)
		}
		declared[spec.key] = true
		if !have[spec.key] {
			stale = append(stale, spec.key)
		}
		if (len(spec.soft) > 0 || spec.noBogus) && strings.TrimSpace(spec.why) == "" {
			noWhy = append(noWhy, spec.key)
		}
	}
	for _, k := range routes {
		if !declared[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		t.Errorf("routes without a declared access policy (add them to routeTable): %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("routeTable entries without a route (stale): %v", stale)
	}
	if len(dup) > 0 {
		t.Errorf("duplicate routeTable entries: %v", dup)
	}
	if len(noWhy) > 0 {
		t.Errorf("exceptions without a reason: %v", noWhy)
	}
	if len(routes) < 100 {
		t.Fatalf("walk found only %d routes", len(routes))
	}
}

// ---- fixtures ----

type accessEnv struct {
	*env
	ids map[principal]int64
}

func newAccessEnv(t *testing.T) *accessEnv {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "usera", false)
	e.mkUser(admin, "userb", false)
	e.mkAuditor(admin, "auditor1")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_reverse_shares": "true"}), 200, "enable reverse shares")
	ae := &accessEnv{env: e, ids: map[principal]int64{}}
	for who, name := range map[principal]string{pOwnerA: "usera", pUserB: "userb", pAdmin: "admin", pAuditor: "auditor1"} {
		var id int64
		if err := qByName(e.s.St, `SELECT id FROM users WHERE username=?`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ae.ids[who] = id
	}
	return ae
}

// token returns a fresh access token so that routes such as logout cannot
// disturb later requests.
func (a *accessEnv) token(who principal) string {
	a.t.Helper()
	u, err := a.s.userByID(a.ids[who])
	if err != nil {
		a.t.Fatal(err)
	}
	return a.s.accessToken(u)
}

// resetBudgets clears the per-address request budgets (many requests come
// from the one test address).
func (a *accessEnv) resetBudgets() {
	a.s.securityMu.Lock()
	a.s.securityBuckets = nil
	a.s.securityMu.Unlock()
}

// newGuest returns a fresh guest (reverse-share invite session) of user A.
func (a *accessEnv) newGuest() string {
	a.t.Helper()
	r := a.do("POST", "/api/reverse-shares/invite", a.token(pOwnerA), map[string]any{"open": true, "max_uploads": 5, "days": 1, "name": "Drop"})
	a.want(r, 201, "invite")
	u := r.S("url")
	acc := a.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": u[strings.LastIndex(u, "/")+1:]})
	a.want(acc, 200, "accept invite")
	return acc.S("access_token")
}

// fixture is one set of objects owned by user A, created per route so that
// destructive routes cannot affect other cases.
type fixture struct {
	a        *accessEnv
	shareID  int64
	longID   string
	fileID   int64
	uploadID string
	inviteID int64
	userID   int64
	haveSh   bool
}

func (f *fixture) share() {
	if f.haveSh {
		return
	}
	r := f.a.share(f.a.token(pOwnerA), map[string]string{"one.txt": "111", "two.txt": "222"}, map[string]any{"name": "Fixture share"})
	f.a.want(r, 201, "fixture share")
	f.shareID, f.longID = f.a.sid(r), r.S("long_id")
	files := f.a.listFiles(f.a.token(pOwnerA), f.shareID)
	f.fileID = files[0].ID
	f.haveSh = true
}

func (f *fixture) path(spec routeSpec, route string, bogus bool) string {
	pub := spec.policy == polPublic || spec.policy == polPublicToken
	p := route
	if strings.Contains(p, "{id}") {
		switch {
		case bogus && pub:
			p = strings.ReplaceAll(p, "{id}", "nonexistent-link-id")
		case strings.HasPrefix(route, "/api/shares/") && pub:
			f.share()
			p = strings.ReplaceAll(p, "{id}", f.longID)
		case strings.HasPrefix(route, "/api/shares/"):
			f.share()
			p = strings.ReplaceAll(p, "{id}", fmt.Sprint(f.shareID))
		case strings.HasPrefix(route, "/api/uploads/"):
			if f.uploadID == "" {
				r := f.a.do("POST", "/api/uploads", f.a.token(pOwnerA), map[string]any{"files": []map[string]any{{"name": "u.txt", "full_path": "u.txt", "size": 3}}})
				f.a.want(r, 201, "fixture upload")
				f.uploadID = r.S("id")
			}
			p = strings.ReplaceAll(p, "{id}", f.uploadID)
		case strings.HasPrefix(route, "/api/reverse-shares/invites/"):
			if f.inviteID == 0 {
				r := f.a.do("POST", "/api/reverse-shares/invite", f.a.token(pOwnerA), map[string]any{"open": true, "max_uploads": 3, "days": 1, "name": "Inv"})
				f.a.want(r, 201, "fixture invite")
				f.inviteID = int64(r.J()["id"].(float64))
			}
			p = strings.ReplaceAll(p, "{id}", fmt.Sprint(f.inviteID))
		case strings.HasPrefix(route, "/api/users/{id}"):
			if f.userID == 0 {
				name := "tgt" + randHex(4)
				f.a.want(f.a.do("POST", "/api/users", f.a.token(pAdmin), map[string]any{"username": name, "password": "password123", "email": name + "@x.io"}), 201, "fixture user")
				qByName(f.a.s.St, `SELECT id FROM users WHERE username=?`, name).Scan(&f.userID)
			}
			p = strings.ReplaceAll(p, "{id}", fmt.Sprint(f.userID))
		default:
			p = strings.ReplaceAll(p, "{id}", "1")
		}
	}
	if strings.Contains(p, "{fileId}") {
		f.share()
		p = strings.ReplaceAll(p, "{fileId}", fmt.Sprint(f.fileID))
	}
	if bogus && pub && strings.HasSuffix(p, "/*") {
		p = strings.TrimSuffix(p, "*") + "one.txt"
	}
	return strings.NewReplacer("{idx}", "0", "{name}", "sendora-plain-20200101-000000.db", "{file}", "x.png", "{kind}", "logo",
		"{code}", "en", "{uuid}", "00000000-0000-0000-0000-000000000000", "/*", "/one.txt").Replace(p)
}

var middlewareMessages = []string{"unauthorized", "guest session is upload-only", "auditor accounts are read-only", "forbidden"}

func isGateMessage(r resp) bool {
	m := r.S("error")
	for _, g := range middlewareMessages {
		if m == g {
			return true
		}
	}
	return false
}

func inCodes(c int, list []int) bool {
	for _, x := range list {
		if x == c {
			return true
		}
	}
	return false
}

// TestRouteAccessMatrix calls every route as every principal.
func TestRouteAccessMatrix(t *testing.T) {
	a := newAccessEnv(t)
	cases, failures := 0, 0
	byPolicy := map[accessPolicy]int{}
	for _, spec := range routeTable {
		spec := spec
		method, route := splitKey(spec.key)
		byPolicy[spec.policy]++
		a.resetBudgets()
		fx := &fixture{a: a}
		guest := a.newGuest()
		tokens := map[principal]string{pAnon: "", pOwnerA: a.token(pOwnerA), pUserB: a.token(pUserB), pGuest: guest, pAdmin: a.token(pAdmin), pAuditor: a.token(pAuditor)}
		path := fx.path(spec, route, false)
		fail := func(who principal, f string, args ...any) {
			failures++
			t.Errorf("%s as %s (%s): %s", spec.key, who, spec.policy, fmt.Sprintf(f, args...))
		}
		// Refused principals first: an allowed principal may consume the fixture.
		order := append([]principal{}, allPrincipals...)
		sort.SliceStable(order, func(i, j int) bool {
			return !spec.policy.allows(order[i]) && spec.policy.allows(order[j])
		})
		got := map[principal]resp{}
		for _, who := range order {
			r := a.do(method, path, tokens[who], spec.body)
			got[who] = r
			cases++
			if spec.policy == polPublic || spec.policy == polPublicToken {
				continue // compared below
			}
			if spec.policy.allows(who) {
				switch {
				case r.Code == 401:
					fail(who, "allowed principal refused with 401: %s", r.Body)
				case r.Code >= 500 && !inCodes(r.Code, spec.soft):
					fail(who, "server error %d: %s", r.Code, r.Body)
				case isGateMessage(r):
					fail(who, "allowed principal stopped by an access check: %d %s", r.Code, r.Body)
				case (r.Code == 403 || r.Code == 404) && !inCodes(r.Code, spec.soft):
					fail(who, "allowed principal got %d: %s", r.Code, r.Body)
				}
				continue
			}
			if want := deniedCode(spec, method, route, who); r.Code != want {
				fail(who, "want %d got %d: %s", want, r.Code, r.Body)
			}
		}
		if spec.policy == polPublic || spec.policy == polPublicToken {
			anon := got[pAnon]
			if anon.Code >= 500 {
				fail(pAnon, "server error %d: %s", anon.Code, anon.Body)
			}
			if isGateMessage(anon) {
				fail(pAnon, "public route stopped by an access check: %d %s", anon.Code, anon.Body)
			}
			for _, who := range allPrincipals {
				if got[who].Code != anon.Code {
					fail(who, "public route answers %d, anonymous gets %d (credentials must not matter)", got[who].Code, anon.Code)
				}
			}
		}
		if spec.policy == polPublicToken && !spec.noBogus {
			bp := fx.path(spec, route, true)
			r := a.do(method, bp, "", spec.body)
			cases++
			if r.Code < 400 {
				fail(pAnon, "bogus token/link accepted: %d %s (%s)", r.Code, r.Body, bp)
			}
		}
	}
	t.Logf("route access matrix: %d routes x %d principals = %d requests, %d failures; policies: %v", len(routeTable), len(allPrincipals), cases, failures, byPolicy)
	t.Logf("skips: none. Documented per-route exceptions (soft status codes / no bogus-token probe): %d", countExceptions())
}

func countExceptions() int {
	n := 0
	for _, s := range routeTable {
		if len(s.soft) > 0 || s.noBogus {
			n++
		}
	}
	return n
}

// ---- dedicated privacy rules ----

func sameAnswer(a, b resp) bool { return a.Code == b.Code && string(a.Body) == string(b.Body) }

// Administrators and other users learn nothing about a share that is not theirs:
// the answer for a real share is the same 404 as for one that does not exist.
// Auditors are stopped by the read-only gate before any lookup, which is
// existence-blind as well.
func TestRouteAccessOtherUsersSharesAreInvisible(t *testing.T) {
	a := newAccessEnv(t)
	fx := &fixture{a: a}
	fx.share()
	files := a.listFiles(a.token(pOwnerA), fx.shareID)
	type call struct {
		method, tmpl string
		body         any
	}
	calls := []call{
		{"GET", "/api/shares/%d/downloads", nil},
		{"GET", "/api/shares/%d/files", nil},
		{"PUT", "/api/shares/%d", map[string]any{"name": "hijacked"}},
		{"POST", "/api/shares/%d/expire", nil},
		{"POST", "/api/shares/%d/extend", map[string]any{"days": 5}},
		{"PUT", "/api/shares/%d/expiry", map[string]any{"days": 5}},
		{"POST", "/api/shares/%d/download-limit", map[string]any{"limit": 1}},
		{"DELETE", "/api/shares/%d", nil},
		{"DELETE", fmt.Sprintf("/api/shares/%%d/files/%d", files[0].ID), nil},
	}
	const missingID = 987654
	for _, c := range calls {
		real, missing := fmt.Sprintf(c.tmpl, fx.shareID), fmt.Sprintf(c.tmpl, missingID)
		for _, who := range []principal{pUserB, pAdmin, pAuditor, pGuest, pAnon} {
			tok := ""
			switch who {
			case pGuest:
				tok = a.newGuest()
			case pAnon:
			default:
				tok = a.token(who)
			}
			got, none := a.do(c.method, real, tok, c.body), a.do(c.method, missing, tok, c.body)
			if !sameAnswer(got, none) {
				t.Errorf("%s %s as %s: real share answers %d %s, missing share %d %s (existence leak)", c.method, real, who, got.Code, got.Body, none.Code, none.Body)
			}
			switch who {
			case pUserB, pAdmin:
				if got.Code != 404 {
					t.Errorf("%s %s as %s: want 404 got %d", c.method, real, who, got.Code)
				}
			case pAuditor, pGuest:
				if got.Code != 403 && got.Code != 404 {
					t.Errorf("%s %s as %s: want 403/404 got %d", c.method, real, who, got.Code)
				}
			case pAnon:
				if got.Code != 401 {
					t.Errorf("%s %s anonymous: want 401 got %d", c.method, real, got.Code)
				}
			}
		}
	}
	// Appending to somebody else's share through an upload session.
	body := map[string]any{"share_id": fx.shareID, "files": []map[string]any{{"name": "x.txt", "full_path": "x.txt", "size": 1}}}
	missingBody := map[string]any{"share_id": missingID, "files": body["files"]}
	for _, who := range []principal{pUserB, pAdmin, pAuditor} {
		got, none := a.do("POST", "/api/uploads", a.token(who), body), a.do("POST", "/api/uploads", a.token(who), missingBody)
		if !sameAnswer(got, none) || (got.Code != 404 && got.Code != 403) {
			t.Errorf("append upload to foreign share as %s: %d %s vs missing %d %s", who, got.Code, got.Body, none.Code, none.Body)
		}
		if who != pAuditor && got.Code != 404 {
			t.Errorf("append upload to foreign share as %s: want 404 got %d", who, got.Code)
		}
	}
	// An upload session of A cannot be driven by anybody else, and the answer
	// matches a session that does not exist.
	fx.path(routeSpec{policy: polOwner}, "/api/uploads/{id}", false)
	for _, c := range []struct{ method, tmpl string }{
		{"GET", "/api/uploads/%s"}, {"PATCH", "/api/uploads/%s/files/0"}, {"POST", "/api/uploads/%s/complete"}, {"DELETE", "/api/uploads/%s"},
	} {
		for _, who := range []principal{pUserB, pAdmin} {
			got := a.do(c.method, fmt.Sprintf(c.tmpl, fx.uploadID), a.token(who), []byte("zzz"))
			none := a.do(c.method, fmt.Sprintf(c.tmpl, "does-not-exist"), a.token(who), []byte("zzz"))
			if got.Code != 404 || !sameAnswer(got, none) {
				t.Errorf("%s upload session as %s: %d %s vs missing %d %s", c.method, who, got.Code, got.Body, none.Code, none.Body)
			}
		}
	}
	// The share survived every attempt, unchanged.
	sh := a.shareRow(fmt.Sprint(fx.shareID))
	if sh == nil || sh.Name != "Fixture share" || sh.Status != "active" || len(a.listFiles(a.token(pOwnerA), fx.shareID)) != 2 {
		t.Fatalf("share was modified by a foreign principal: %+v", sh)
	}
	// And an administrator's own list does not include it.
	var mine []map[string]any
	if r := a.do("GET", "/api/shares", a.token(pAdmin), nil); r.Code != 200 || strings.Contains(string(r.Body), fx.longID) || strings.Contains(string(r.Body), "Fixture share") {
		t.Fatalf("admin share list leaks: %d %s", r.Code, r.Body)
	}
	_ = mine
}

// Neither the administrator pages nor the plain log expose share names, link
// ids or file names. Share events appear for administrators and auditors alike, by number only.
func TestRouteAccessAdminSeesNoShareIdentifiers(t *testing.T) {
	a := newAccessEnv(t)
	r := a.share(a.token(pOwnerA), map[string]string{"secret-report-final.pdf": "x"}, map[string]any{"name": "Quarterly Takeover Plan", "description": "hush-hush"})
	a.want(r, 201, "share")
	longID := r.S("long_id")
	a.do("GET", "/api/shares/"+longID+"/download", "", nil) // produce a download event
	if len(longID) < 8 {
		t.Fatalf("no link id: %s", r.Body)
	}
	needles := []string{"Quarterly Takeover Plan", longID, "secret-report-final.pdf", "hush-hush"}
	admin := a.token(pAdmin)
	for _, p := range []string{"/api/stats", "/api/users", "/api/logs", "/api/logs/export", "/api/logs/status", "/api/settings", "/api/ip-bans", "/api/backups", "/api/shares", "/api/reverse-shares/invites"} {
		got := a.do("GET", p, admin, nil)
		a.want(got, 200, "admin "+p)
		for _, n := range needles {
			if strings.Contains(string(got.Body), n) {
				t.Errorf("administrator GET %s leaks %q", p, n)
			}
		}
	}
	// Administrators and auditors read the same audit log. It names shares only by
	// number (share#N), never by name, link ID or file name (checked above).
	if got := a.do("GET", "/api/logs?category=share", admin, nil); got.Code != 200 || got.J()["total"].(float64) == 0 {
		t.Errorf("admin log must show share events too: %d %s", got.Code, got.Body)
	}
	aud := a.do("GET", "/api/audit?category=share", a.token(pAuditor), nil)
	a.want(aud, 200, "auditor audit log")
	if aud.J()["total"].(float64) == 0 {
		t.Errorf("auditor sees no share events: %s", aud.Body)
	}
}

func TestRouteAccessAuditorAndAdminAreSeparated(t *testing.T) {
	a := newAccessEnv(t)
	fx := &fixture{a: a}
	adminRoutes, auditRoutes, auditorOK := 0, 0, 0
	for _, spec := range routeTable {
		method, route := splitKey(spec.key)
		switch spec.policy {
		case polAdmin:
			adminRoutes++
			a.resetBudgets()
			if r := a.do(method, fx.path(spec, route, false), a.token(pAuditor), spec.body); r.Code != 403 {
				t.Errorf("auditor reached admin route %s: %d %s", spec.key, r.Code, r.Body)
			}
		case polAuditor:
			auditRoutes++
			// Administrators read the same audit log as auditors.
			if r := a.do(method, fx.path(spec, route, false), a.token(pAdmin), spec.body); r.Code != 200 {
				t.Errorf("administrator cannot read audit route %s: %d %s", spec.key, r.Code, r.Body)
			}
		}
		// The auditor may only use its allowlist (plus the public routes).
		if spec.policy != polPublic && spec.policy != polPublicToken && spec.policy != polAuditor {
			if spec.policy.allows(pAuditor) {
				auditorOK++
			}
		}
	}
	// Exactly the own-profile routes: GET/PUT /api/users/me, the nine
	// self-service routes of the caller's own second factors, the three routes of
	// the caller's own sessions, and the own personal data export, erasure and
	// terms acceptance.
	if auditorOK != 17 {
		t.Errorf("auditor is allowed on %d non-audit routes, want 17 (GET/PUT /api/users/me, /api/users/me/mfa*, /api/users/me/sessions*, export, erase, terms)", auditorOK)
	}
	// The audit log (3 routes) and the read-only access review (2 routes).
	if adminRoutes < 40 || auditRoutes != 5 {
		t.Errorf("walked %d admin and %d audit routes", adminRoutes, auditRoutes)
	}
	// Auditors are read-only everywhere else, whatever the method and path.
	aud := a.token(pAuditor)
	for _, c := range []struct{ m, p string }{
		{"POST", "/api/uploads"}, {"GET", "/api/shares"}, {"POST", "/api/reverse-shares/invite"}, {"GET", "/api/users"},
		{"PUT", "/api/settings"}, {"POST", "/api/audit"}, {"DELETE", "/api/audit"}, {"PUT", "/api/audit"}, {"DELETE", "/api/users/me"},
	} {
		if r := a.do(c.m, c.p, aud, nil); r.Code != 403 && r.Code != 405 {
			t.Errorf("auditor %s %s: %d", c.m, c.p, r.Code)
		}
	}
	for _, p := range []string{"/api/audit", "/api/audit/status", "/api/audit/export"} {
		a.want(a.do("GET", p, aud, nil), 200, "auditor "+p)
	}
	a.want(a.do("GET", "/api/users/me", aud, nil), 200, "auditor profile")
}

func TestRouteAccessGuestOnlyReachesItsAllowlist(t *testing.T) {
	a := newAccessEnv(t)
	allowed := map[string]bool{"GET /api/users/me": true, "POST /api/uploads": true, "GET /api/uploads/{id}": true,
		"PATCH /api/uploads/{id}/files/{idx}": true, "POST /api/uploads/{id}/complete": true, "DELETE /api/uploads/{id}": true}
	fx := &fixture{a: a}
	guest := a.newGuest()
	checked := 0
	for _, spec := range routeTable {
		if spec.policy == polPublic || spec.policy == polPublicToken || allowed[spec.key] {
			continue
		}
		method, route := splitKey(spec.key)
		a.resetBudgets()
		r := a.do(method, fx.path(spec, route, false), guest, spec.body)
		if r.Code != 403 || !isGateMessage(r) {
			t.Errorf("guest reached %s: %d %s", spec.key, r.Code, r.Body)
		}
		checked++
	}
	if checked < 70 {
		t.Fatalf("only %d guest-forbidden routes checked", checked)
	}
	// The allowlist: own profile and own upload session.
	a.want(a.do("GET", "/api/users/me", guest, nil), 200, "guest profile")
	up := a.do("POST", "/api/uploads", guest, map[string]any{"files": []map[string]any{{"name": "g.txt", "full_path": "g.txt", "size": 2}}})
	a.want(up, 201, "guest upload session")
	id := up.S("id")
	a.want(a.do("GET", "/api/uploads/"+id, guest, nil), 200, "guest own session")
	a.want(a.do("PATCH", "/api/uploads/"+id+"/files/0", guest, []byte("hi"), "Upload-Offset", "0"), 200, "guest own chunk")
	// ...but never another account's session.
	fx.path(routeSpec{policy: polOwner}, "/api/uploads/{id}", false)
	a.want(a.do("GET", "/api/uploads/"+fx.uploadID, guest, nil), 404, "guest foreign session")
	a.want(a.do("DELETE", "/api/uploads/"+fx.uploadID, guest, nil), 404, "guest foreign abort")
	// Guests cannot append to an existing share either.
	fx.share()
	a.want(a.do("POST", "/api/uploads", guest, map[string]any{"share_id": fx.shareID, "files": []map[string]any{{"name": "x", "full_path": "x", "size": 1}}}), 404, "guest append")
}
