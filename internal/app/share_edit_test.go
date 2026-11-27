// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"testing"
	"time"
)

func editShareSetup(t *testing.T, opts map[string]any) (*env, string, resp, string) {
	e := newEnv(t)
	admin := e.setup()
	sh := e.share(admin, map[string]string{"a.txt": "abc"}, opts)
	e.want(sh, 201, "share")
	return e, admin, sh, fmt.Sprintf("/api/shares/%v", sh.J()["id"])
}

func (e *env) shareRow(id string) *Share {
	var n int64
	fmt.Sscan(id, &n)
	sh, err := e.s.shareByID(n)
	if err != nil {
		e.t.Fatal(err)
	}
	return sh
}

func TestEditShareFieldsAlone(t *testing.T) {
	e, admin, sh, p := editShareSetup(t, map[string]any{"name": "orig", "description": "d0"})
	id := fmt.Sprint(sh.J()["id"])
	r := e.do("PUT", p, admin, map[string]any{"name": "  new name  "})
	e.want(r, 200, "name")
	if r.J()["ok"] != true {
		t.Fatal(string(r.Body))
	}
	if s := e.shareRow(id); s.Name != "new name" || s.Description != "d0" {
		t.Fatalf("%+v", s)
	}
	e.want(e.do("PUT", p, admin, map[string]any{"description": "hello"}), 200, "desc")
	if s := e.shareRow(id); s.Name != "new name" || s.Description != "hello" {
		t.Fatalf("%+v", s)
	}
	e.want(e.do("PUT", p, admin, map[string]any{"description": ""}), 200, "clear desc")
	if e.shareRow(id).Description != "" {
		t.Fatal("desc not cleared")
	}
	e.want(e.do("PUT", p, admin, map[string]any{}), 200, "empty no-op")
	// combined
	e.want(e.do("PUT", p, admin, map[string]any{"name": "c", "description": "cd", "download_limit": 5, "password": "pw-combined"}), 200, "combined")
	s := e.shareRow(id)
	if s.Name != "c" || s.Description != "cd" || s.DownloadLimit == nil || *s.DownloadLimit != 5 || !s.Protected {
		t.Fatalf("%+v", s)
	}
}

func TestEditShareValidation(t *testing.T) {
	e, admin, _, p := editShareSetup(t, nil)
	for _, c := range []struct {
		n    string
		body any
	}{
		{"empty name", map[string]any{"name": "   "}},
		{"long name", map[string]any{"name": strings.Repeat("x", 121)}},
		{"long desc", map[string]any{"description": strings.Repeat("x", 2001)}},
		{"name type", map[string]any{"name": 5}},
		{"null", map[string]any{"name": nil}},
		{"limit string", map[string]any{"download_limit": "3"}},
		{"limit fraction", map[string]any{"download_limit": 1.5}},
		{"limit negative", map[string]any{"download_limit": -1}},
		{"pw type", map[string]any{"password": 12345678}},
		{"pw empty", map[string]any{"password": ""}},
		{"remove type", map[string]any{"remove_password": "yes"}},
		{"unknown", map[string]any{"owner": "x"}},
		{"both", map[string]any{"password": "abcdefgh", "remove_password": true}},
		{"garbage", []byte("[1]")},
	} {
		if r := e.do("PUT", p, admin, c.body); r.Code != 400 {
			t.Errorf("%s: want 400 got %d %s", c.n, r.Code, r.Body)
		}
	}
	e.want(e.do("PUT", p, admin, map[string]any{"name": strings.Repeat("é", 120), "description": strings.Repeat("é", 2000)}), 200, "limits ok")
	e.want(e.do("PUT", p, admin, map[string]any{"password": "abcdefgh", "remove_password": false}), 200, "remove false ok")
}

func TestEditSharePasswordPolicy(t *testing.T) {
	e, admin, sh, p := editShareSetup(t, nil)
	id := fmt.Sprint(sh.J()["id"])
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"share_password_require_upper": true, "share_password_require_digit": true, "share_password_min_length": 8}), 200, "policy")
	for _, pw := range []string{"short1A", "alllower1x", "NoDigitsHere"} {
		r := e.do("PUT", p, admin, map[string]any{"password": pw})
		e.want(r, 400, pw)
		if r.S("error") == "" {
			t.Fatal("no message")
		}
	}
	if e.shareRow(id).Protected {
		t.Fatal("rejected password stored")
	}
	e.want(e.do("PUT", p, admin, map[string]any{"password": "GoodPass1"}), 200, "good")
	if !e.shareRow(id).Protected {
		t.Fatal("not protected")
	}
	// require_share_password blocks removal
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"require_share_password": true}), 200, "require")
	e.want(e.do("PUT", p, admin, map[string]any{"remove_password": true}), 400, "remove when required")
	if !e.shareRow(id).Protected {
		t.Fatal("removed despite policy")
	}
	e.want(e.do("PUT", p, admin, map[string]any{"password": "OtherPass2"}), 200, "change allowed")
	// corrupt policy
	e.s.St.DB.Exec(`UPDATE settings SET value='bogus' WHERE key='share_password_min_length'`)
	e.want(e.do("PUT", p, admin, map[string]any{"password": "OtherPass3"}), 500, "corrupt")
	e.want(e.do("PUT", p, admin, map[string]any{"name": "still fine"}), 200, "name unaffected by corrupt policy")
}

func TestEditShareTokens(t *testing.T) {
	e, admin, sh, p := editShareSetup(t, map[string]any{"password": "firstpass"})
	id := fmt.Sprint(sh.J()["id"])
	u := "/api/shares/" + sh.S("long_id")
	unlock := func(pw string) string {
		r := e.do("POST", u+"/unlock", "", map[string]any{"password": pw})
		e.want(r, 200, "unlock")
		return r.S("token")
	}
	ok := func(tok string) bool { return e.do("GET", u+"/download", "", nil, "X-Share-Token", tok).Code == 200 }
	tok := unlock("firstpass")
	if !ok(tok) {
		t.Fatal("token should work")
	}
	e.want(e.do("PUT", p, admin, map[string]any{"name": "renamed", "description": "x", "download_limit": 50}), 200, "unrelated")
	if !ok(tok) {
		t.Fatal("token should survive unrelated edit")
	}
	e.want(e.do("PUT", p, admin, map[string]any{"password": "secondpass"}), 200, "change")
	if ok(tok) {
		t.Fatal("old token valid after password change")
	}
	e.want(e.do("POST", u+"/unlock", "", map[string]any{"password": "firstpass"}), 401, "old pw")
	tok2 := unlock("secondpass")
	if !ok(tok2) {
		t.Fatal("new token should work")
	}
	// token without claim is invalid for protected share
	s := e.shareRow(id)
	_ = s
	e.want(e.do("PUT", p, admin, map[string]any{"remove_password": true}), 200, "remove")
	if e.shareRow(id).Protected {
		t.Fatal("still protected")
	}
	if !ok("") {
		t.Fatal("unprotected share needs no token")
	}
	e.want(e.do("PUT", p, admin, map[string]any{"password": "thirdpass"}), 200, "re-add")
	if ok(tok2) {
		t.Fatal("token from before removal valid after re-adding")
	}
	if !ok(unlock("thirdpass")) {
		t.Fatal("fresh token should work")
	}
}

func TestEditShareLegacyTokenWithoutClaim(t *testing.T) {
	e, _, sh, _ := editShareSetup(t, map[string]any{"password": "firstpass"})
	u := "/api/shares/" + sh.S("long_id")
	s, err := e.s.shareByLongID(sh.S("long_id"))
	if err != nil {
		t.Fatal(err)
	}
	// forge an old-format token (valid signature, no pv claim)
	old := e.s.legacyShareTokenForTest(s)
	if e.do("GET", u+"/download", "", nil, "X-Share-Token", old).Code != 401 {
		t.Fatal("legacy token must be rejected")
	}
	if e.do("GET", u+"/download", "", nil, "X-Share-Token", e.s.shareToken(s)).Code != 200 {
		t.Fatal("current token must work")
	}
}

func TestEditShareDownloadLimit(t *testing.T) {
	e, admin, sh, p := editShareSetup(t, nil)
	id := fmt.Sprint(sh.J()["id"])
	e.want(e.do("PUT", p, admin, map[string]any{"download_limit": 1}), 200, "set")
	if l := e.shareRow(id).DownloadLimit; l == nil || *l != 1 {
		t.Fatal("limit not set")
	}
	e.want(e.do("GET", "/api/shares/"+sh.S("long_id")+"/download", "", nil), 200, "download")
	// maintenance marks exhausted share expired
	e.s.St.DB.Exec(`UPDATE shares SET status='expired' WHERE id=?`, id)
	e.want(e.do("PUT", p, admin, map[string]any{"download_limit": 5}), 200, "raise")
	if s := e.shareRow(id); s.Status != "active" || s.Expired {
		t.Fatalf("not revived: %+v", s)
	}
	// manually expired share is not revived by a limit edit
	e.s.St.DB.Exec(`UPDATE shares SET status='expired' WHERE id=?`, id)
	e.want(e.do("PUT", p, admin, map[string]any{"download_limit": 9}), 200, "raise2")
	if e.shareRow(id).Status != "expired" {
		t.Fatal("manually expired share revived")
	}
	// time-expired exhausted share not revived
	e.s.St.DB.Exec(`UPDATE shares SET status='expired', download_limit=1, expires_at=? WHERE id=?`, time.Now().Add(-time.Hour), id)
	e.want(e.do("PUT", p, admin, map[string]any{"download_limit": 50}), 200, "raise3")
	if e.shareRow(id).Status != "expired" {
		t.Fatal("time-expired revived")
	}
	e.s.St.DB.Exec(`UPDATE shares SET expires_at=NULL WHERE id=?`, id)
	e.want(e.do("PUT", p, admin, map[string]any{"download_limit": 0}), 200, "clear")
	if s := e.shareRow(id); s.DownloadLimit != nil || s.Status != "expired" {
		t.Fatalf("clear: %+v", s)
	}
	// clearing the limit of an exhausted, maintenance-expired share revives it
	e.s.St.DB.Exec(`UPDATE shares SET status='expired', download_limit=1 WHERE id=?`, id)
	e.want(e.do("PUT", p, admin, map[string]any{"download_limit": 0}), 200, "clear exhausted")
	if s := e.shareRow(id); s.DownloadLimit != nil || s.Status != "active" {
		t.Fatalf("clear exhausted: %+v", s)
	}
}

func TestEditShareOwnership(t *testing.T) {
	e, admin, _, _ := editShareSetup(t, nil)
	alice := e.mkUser(admin, "alice", false)
	bob := e.mkUser(admin, "bob", false)
	sh := e.share(alice, map[string]string{"a.txt": "abc"}, map[string]any{"name": "alices"})
	e.want(sh, 201, "alice share")
	id := fmt.Sprint(sh.J()["id"])
	p := "/api/shares/" + id
	e.want(e.do("PUT", p, bob, map[string]any{"name": "hijack"}), 404, "other user")
	e.want(e.do("PUT", p, "", map[string]any{"name": "anon"}), 401, "anon")
	e.want(e.do("PUT", "/api/shares/99999", alice, map[string]any{"name": "x"}), 404, "missing")
	e.want(e.do("PUT", "/api/shares/abc", alice, map[string]any{"name": "x"}), 404, "bad id")
	if e.shareRow(id).Name != "alices" {
		t.Fatal("modified by non-owner")
	}
	e.want(e.do("PUT", p, alice, map[string]any{"name": "mine"}), 200, "owner")
	// Administrators have no access to other users' shares.
	e.want(e.do("PUT", p, admin, map[string]any{"name": "by admin", "password": "adminset"}), 404, "admin")
	if s := e.shareRow(id); s.Name != "mine" || s.Protected || !s.userID.Valid {
		t.Fatalf("%+v", s)
	}
}

// legacyShareTokenForTest mints a token in the pre-claim format.
func (s *Server) legacyShareTokenForTest(sh *Share) string {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"purpose": "share", "share": sh.LongID, "exp": time.Now().Add(time.Hour).Unix()})
	str, _ := t.SignedString(s.key(keyShareUnlock))
	return str
}
