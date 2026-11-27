// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func openInvite(e *env, tok string, max, days int) (resp, string) {
	r := e.do("POST", "/api/reverse-shares/invite", tok, map[string]any{"open": true, "max_uploads": max, "days": days, "name": "Dropbox"})
	if r.Code != 201 {
		return r, ""
	}
	u := r.S("url")
	return r, u[strings.LastIndex(u, "/")+1:]
}

func listOwnInvites(e *env, tok string) []map[string]any {
	var l []map[string]any
	json.Unmarshal(e.do("GET", "/api/reverse-shares/invites", tok, nil).Body, &l)
	return l
}

func TestOpenInviteValidationAndPermissions(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	for _, m := range []int{0, -1, 101} {
		r, _ := openInvite(e, tok, m, 7)
		e.want(r, 400, "bad max")
	}
	e.want(e.do("POST", "/api/reverse-shares/invite", tok, map[string]any{"open": true, "max_uploads": 2, "email": "a@x.io"}), 400, "open+email")
	r, itok := openInvite(e, tok, 100, 99)
	e.want(r, 201, "create open")
	if r.J()["kind"] != "open" || r.J()["max_uploads"].(float64) != 100 {
		t.Fatal(string(r.Body))
	}
	exp, _ := time.Parse(time.RFC3339, r.S("expires_at"))
	if d := time.Until(exp); d < 6*24*time.Hour || d > 7*24*time.Hour+time.Minute {
		t.Fatalf("days clamp to 7: %v", d)
	}
	acc := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok})
	e.want(acc, 200, "accept")
	g := acc.S("access_token")
	e.want(openOnly(e, g), 403, "guest cannot create open")
	e.s.St.SetSetting("allow_reverse_shares", "false")
	r, _ = openInvite(e, tok, 2, 1)
	e.want(r, 403, "disabled")
}

func openOnly(e *env, g string) resp {
	return e.do("POST", "/api/reverse-shares/invite", g, map[string]any{"open": true, "max_uploads": 2})
}

func TestOpenInviteTwoUploadersAndLimit(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	_, itok := openInvite(e, tok, 2, 3)
	a1 := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok})
	e.want(a1, 200, "accept 1")
	a2 := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok})
	e.want(a2, 200, "accept 2")
	if a1.J()["user"].(map[string]any)["id"] == a2.J()["user"].(map[string]any)["id"] {
		t.Fatal("distinct guests expected")
	}
	// both slots active: third refused
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 410, "full")
	e.want(e.share(a1.S("access_token"), map[string]string{"a.txt": "one"}, nil), 201, "upload 1")
	e.want(e.share(a2.S("access_token"), map[string]string{"b.txt": "two"}, nil), 201, "upload 2")
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 410, "full after completion")
	// completed guest cannot upload again
	e.want(e.do("POST", "/api/uploads", a1.S("access_token"), map[string]any{"files": []map[string]any{{"name": "a", "full_path": "a", "size": 1}}}), 403, "reuse")
	var shares []map[string]any
	json.Unmarshal(e.do("GET", "/api/shares", tok, nil).Body, &shares)
	if len(shares) != 2 {
		t.Fatalf("owner shares %d", len(shares))
	}
	l := listOwnInvites(e, tok)
	if len(l) != 1 || l[0]["kind"] != "open" || l[0]["used"].(float64) != 2 || l[0]["max_uploads"].(float64) != 2 || !strings.HasSuffix(l[0]["url"].(string), itok) {
		t.Fatalf("list %v", l)
	}
	// guest tokens carry no upload through the parent token's guest; parent has no guest user
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM reverse_invites WHERE parent_id IS NULL AND guest_user_id IS NOT NULL`).Scan(&n)
	if n != 0 {
		t.Fatal("parent must never bind a guest")
	}
}

func TestOpenInviteExpiredChildFreesSlotAndExpiryCap(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	_, itok := openInvite(e, tok, 1, 1)
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 200, "accept")
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 410, "full")
	var cexp, pexp time.Time
	e.s.St.DB.QueryRow(`SELECT expires_at FROM reverse_invites WHERE parent_id IS NOT NULL`).Scan(&cexp)
	e.s.St.DB.QueryRow(`SELECT expires_at FROM reverse_invites WHERE token=?`, itok).Scan(&pexp)
	if cexp.After(pexp) || cexp.After(time.Now().Add(24*time.Hour+time.Minute)) {
		t.Fatalf("child expiry %v parent %v", cexp, pexp)
	}
	e.s.St.DB.Exec(`UPDATE reverse_invites SET expires_at=? WHERE parent_id IS NOT NULL`, time.Now().Add(-time.Minute))
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 200, "slot freed")
	// parent shorter than 24h caps child
	e.s.St.DB.Exec(`UPDATE reverse_invites SET expires_at=? WHERE token=?`, time.Now().Add(time.Hour), itok)
	e.s.St.DB.Exec(`UPDATE reverse_invites SET expires_at=? WHERE parent_id IS NOT NULL`, time.Now().Add(-time.Minute))
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 200, "accept")
	e.s.St.DB.QueryRow(`SELECT expires_at FROM reverse_invites WHERE parent_id IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&cexp)
	if cexp.After(time.Now().Add(time.Hour + time.Minute)) {
		t.Fatalf("child not capped: %v", cexp)
	}
}

func TestOpenInviteRevoke(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	other := e.mkUser(tok, "bob", false)
	r, itok := openInvite(e, tok, 5, 3)
	id := r.J()["id"].(float64)
	acc := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok})
	e.want(acc, 200, "accept")
	g := acc.S("access_token")
	path := "/api/reverse-shares/invites/" + strings.TrimSuffix(strings.TrimSpace(jsonNum(id)), ".0") + "/revoke"
	e.want(e.do("POST", path, other, nil), 404, "non-owner")
	e.want(e.do("POST", path, "", nil), 401, "anon")
	e.want(e.do("POST", path, g, nil), 403, "guest")
	e.want(e.do("POST", path, tok, nil), 200, "owner revoke")
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 404, "revoked accept")
	// outstanding child's guest is dead
	e.want(e.do("POST", "/api/uploads", g, map[string]any{"files": []map[string]any{{"name": "a", "full_path": "a", "size": 1}}}), 403, "child expired")
	l := listOwnInvites(e, tok)
	if len(l) != 1 || l[0]["active"] != false {
		t.Fatalf("list %v", l)
	}
	e.want(e.do("POST", "/api/reverse-shares/invites/9999/revoke", tok, nil), 404, "missing")
}

func jsonNum(f float64) string { b, _ := json.Marshal(int64(f)); return string(b) }

func TestOpenInviteConcurrentAcceptNeverExceedsMax(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	const max, tries = 5, 30
	_, itok := openInvite(e, tok, max, 3)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < tries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok})
			mu.Lock()
			codes[r.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	// The shared auth-slot limiter may answer 429 under heavy parallelism.
	if codes[200] > max || codes[200]+codes[410]+codes[429] != tries {
		t.Fatalf("codes %v", codes)
	}
	for codes[200] < max {
		r := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok})
		if r.Code == 200 {
			codes[200]++
		} else if r.Code != 429 {
			t.Fatalf("unexpected %d", r.Code)
		}
	}
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 410, "full")
	var kids, guests int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM reverse_invites WHERE parent_id IS NOT NULL`).Scan(&kids)
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE is_guest=1`).Scan(&guests)
	if kids != max || guests != max {
		t.Fatalf("kids=%d guests=%d", kids, guests)
	}
}

func TestOpenInviteQuotaOwnerAndOwnerDelete(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	owner := e.mkUser(admin, "carol", false)
	_, itok := openInvite(e, owner, 2, 2)
	acc := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok})
	e.want(acc, 200, "accept")
	e.want(e.share(acc.S("access_token"), map[string]string{"x.txt": "data"}, nil), 201, "upload")
	var uid, shareOwner int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='carol'`).Scan(&uid)
	e.s.St.DB.QueryRow(`SELECT user_id FROM shares`).Scan(&shareOwner)
	if shareOwner != uid {
		t.Fatalf("share owner %d want %d", shareOwner, uid)
	}
	e.want(e.do("DELETE", "/api/users/"+jsonNum(float64(uid)), admin, nil), 200, "delete owner")
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM reverse_invites`).Scan(&n)
	if n != 0 {
		t.Fatalf("invites remain %d", n)
	}
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE is_guest=1`).Scan(&n)
	if n != 0 {
		t.Fatalf("guests remain %d", n)
	}
	e.want(e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": itok}), 404, "owner gone")
}
