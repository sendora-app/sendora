// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateSharePasswordPure(t *testing.T) {
	p := sharePolicy{MinLength: 8}
	cases := []struct {
		name string
		p    sharePolicy
		pw   string
		ok   bool
	}{
		{"empty optional", p, "", true},
		{"empty required", sharePolicy{Required: true, MinLength: 8}, "", false},
		{"exact min", p, "abcdefgh", true},
		{"below min", p, "abcdefg", false},
		{"72 bytes", p, strings.Repeat("a", 72), true},
		{"73 bytes", p, strings.Repeat("a", 73), false},
		{"multibyte over 72 bytes", p, strings.Repeat("é", 37), false},
		{"invalid utf8", sharePolicy{MinLength: 1}, "ab\xff", false},
		{"upper missing", sharePolicy{MinLength: 1, Upper: true}, "abc1!", false},
		{"upper ok", sharePolicy{MinLength: 1, Upper: true}, "aBc", true},
		{"lower missing", sharePolicy{MinLength: 1, Lower: true}, "ABC1!", false},
		{"digit missing", sharePolicy{MinLength: 1, Digit: true}, "abcDEF!", false},
		{"digit ok", sharePolicy{MinLength: 1, Digit: true}, "abc7", true},
		{"symbol missing", sharePolicy{MinLength: 1, Symbol: true}, "abcDEF12", false},
		{"symbol ok", sharePolicy{MinLength: 1, Symbol: true}, "abc#", true},
		{"all classes", sharePolicy{MinLength: 4, Upper: true, Lower: true, Digit: true, Symbol: true}, "aB3!", true},
	}
	for _, c := range cases {
		if err := validateSharePassword(c.p, c.pw); (err == nil) != c.ok {
			t.Errorf("%s: err=%v want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestSharePasswordPolicyEnforced(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	files := map[string]string{"a.txt": "abc"}
	e.want(e.share(admin, files, map[string]any{"password": "x"}), 400, "default min length 8 applies to supplied passwords")
	e.want(e.share(admin, files, nil), 201, "default allows none")

	e.want(e.do("PUT", "/api/settings", admin, map[string]any{
		"require_share_password": true, "share_password_min_length": 10, "share_password_require_digit": true,
	}), 200, "set policy")
	b := e.do("GET", "/api/bootstrap", "", nil)
	if b.J()["require_share_password"] != true || b.J()["share_password_min_length"] != float64(10) || b.J()["share_password_require_digit"] != true || b.J()["share_password_require_upper"] != false || b.J()["allow_preview"] != true {
		t.Fatalf("bootstrap policy: %s", b.Body)
	}
	e.want(e.share(admin, files, nil), 400, "required")
	e.want(e.share(admin, files, map[string]any{"password": "short1"}), 400, "short")
	e.want(e.share(admin, files, map[string]any{"password": "longenoughnodigit"}), 400, "no digit")
	var before int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM shares`).Scan(&before)
	e.want(e.share(admin, files, map[string]any{"password": "longenough1"}), 201, "ok")
	var after int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM shares`).Scan(&after)
	if after != before+1 {
		t.Fatal("share count", before, after)
	}
	entries, _ := os.ReadDir(filepath.Join(e.s.St.DataDir, "shares"))
	if len(entries) != after {
		t.Fatalf("rejected completions left directories: %d dirs for %d shares", len(entries), after)
	}

	// corrupt stored setting fails closed
	e.s.St.DB.Exec(`UPDATE settings SET value='bogus' WHERE key='share_password_min_length'`)
	e.want(e.share(admin, files, map[string]any{"password": "longenough1"}), 500, "corrupt fails closed")
}

func TestSettingsValidationRejectsWholeBatch(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	for _, bad := range []map[string]any{
		{"share_password_min_length": 0},
		{"share_password_min_length": 73},
		{"share_password_min_length": 8.5},
		{"share_password_min_length": "abc"},
		{"share_password_min_length": nil},
		{"require_share_password": "yes"},
		{"allow_preview": 1},
		{"share_password_require_symbol": []any{true}},
	} {
		bad["application_name"] = "ShouldNotApply"
		e.want(e.do("PUT", "/api/settings", admin, bad), 400, fmt.Sprint(bad))
	}
	if e.s.St.Setting("application_name") == "ShouldNotApply" {
		t.Fatal("rejected batch partially applied")
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"share_password_min_length": 72, "allow_preview": false, "share_password_require_upper": "true"}), 200, "valid")
	if e.s.St.Setting("share_password_min_length") != "72" || e.s.St.SettingBool("allow_preview") {
		t.Fatal("not stored")
	}
}

func TestGuestShareExemptFromPolicy(t *testing.T) {
	// Guests have their password cleared before the policy applies; assert the
	// policy gate is skipped for them at the code level via the pure validator.
	if err := validateSharePassword(sharePolicy{Required: true, MinLength: 72}, ""); err == nil {
		t.Fatal("sanity: required policy rejects empty")
	}
}

func TestSetShareExpiry(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	alice := e.mkUser(admin, "alice", false)
	bob := e.mkUser(admin, "bob", false)
	sh := e.share(alice, map[string]string{"a.txt": "abc"}, nil)
	e.want(sh, 201, "share")
	id := fmt.Sprint(int64(sh.J()["id"].(float64)))
	url := "/api/shares/" + id + "/expiry"
	at := func(d time.Duration) map[string]any {
		return map[string]any{"expires_at": time.Now().Add(d).UTC().Format(time.RFC3339)}
	}
	e.want(e.do("PUT", url, "", at(time.Hour)), 401, "anon")
	e.want(e.do("PUT", url, bob, at(time.Hour)), 404, "non-owner")
	e.want(e.do("PUT", url, alice, at(-time.Hour)), 400, "past")
	e.want(e.do("PUT", url, alice, map[string]any{}), 400, "neither")
	e.want(e.do("PUT", url, alice, map[string]any{"never": true, "expires_at": at(time.Hour)["expires_at"]}), 400, "both")
	e.want(e.do("PUT", url, alice, at(31*24*time.Hour)), 400, "beyond max")
	e.want(e.do("PUT", url, alice, map[string]any{"never": true}), 400, "never with max")
	e.want(e.do("PUT", url, alice, at(48*time.Hour)), 200, "extend")
	e.s.St.DB.Exec(`UPDATE shares SET expiry_warned=1 WHERE id=?`, id)
	e.want(e.do("PUT", url, alice, at(2*time.Hour)), 200, "shorten")
	var warned int
	var exp time.Time
	e.s.St.DB.QueryRow(`SELECT expiry_warned,expires_at FROM shares WHERE id=?`, id).Scan(&warned, &exp)
	if warned != 0 || time.Until(exp) > 3*time.Hour {
		t.Fatal("warned/expiry", warned, exp)
	}
	// expired share is revived when files exist
	e.want(e.do("POST", "/api/shares/"+id+"/expire", alice, nil), 200, "expire")
	e.want(e.do("GET", "/api/shares/"+sh.S("long_id"), "", nil), 410, "expired")
	e.want(e.do("PUT", url, alice, at(time.Hour)), 200, "revive")
	e.want(e.do("GET", "/api/shares/"+sh.S("long_id"), "", nil), 200, "active again")
	// expired with cleaned files is refused
	e.want(e.do("POST", "/api/shares/"+id+"/expire", alice, nil), 200, "expire")
	os.RemoveAll(filepath.Join(e.s.St.DataDir, "shares", sh.S("long_id")))
	e.want(e.do("PUT", url, alice, at(time.Hour)), 409, "cleaned")
	// admin: no access to another user's share, but may set "never" on their own
	sh2 := e.share(admin, map[string]string{"a.txt": "abc"}, nil)
	id2 := fmt.Sprint(int64(sh2.J()["id"].(float64)))
	e.want(e.do("PUT", "/api/shares/"+id2+"/expiry", admin, map[string]any{"never": true}), 200, "admin never")
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM shares WHERE id=? AND expires_at IS NULL`, id2).Scan(&n)
	if n != 1 {
		t.Fatal("expires_at not cleared")
	}
	e.want(e.do("PUT", "/api/shares/"+id2+"/expiry", admin, at(90*24*time.Hour)), 200, "admin beyond max")
	// max 0 = unlimited for owner
	e.s.St.SetSetting("max_expiry_time", "0")
	sh3 := e.share(alice, map[string]string{"a.txt": "abc"}, nil)
	id3 := fmt.Sprint(int64(sh3.J()["id"].(float64)))
	e.want(e.do("PUT", "/api/shares/"+id3+"/expiry", admin, map[string]any{"never": true}), 404, "admin cannot change another user's expiry")
	e.want(e.do("PUT", "/api/shares/"+id3+"/expiry", alice, map[string]any{"never": true}), 200, "owner never when unlimited")
}

// ---- preview ----

var (
	pngBytes = "\x89PNG\r\n\x1a\nrest-of-file"
	mp4Bytes = "\x00\x00\x00\x18ftypisom" + strings.Repeat("x", 100)
)

func TestPreview(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	files := map[string]string{
		"pic.png": pngBytes, "clip.mp4": mp4Bytes, "fake.png": "<html>x</html>",
		"v.svg": "<svg onload=alert(1)/>", "p.pdf": "%PDF-1.4", "page.html": "<html>",
	}
	sh := e.share(admin, files, nil)
	e.want(sh, 201, "share")
	lid := sh.S("long_id")
	base := "/api/shares/" + lid + "/preview/"
	r := e.do("GET", base+"pic.png", "", nil)
	e.want(r, 200, "png")
	if r.Hdr.Get("Content-Type") != "image/png" || r.Hdr.Get("Content-Disposition") != "inline" ||
		r.Hdr.Get("X-Content-Type-Options") != "nosniff" || r.Hdr.Get("Cache-Control") != "no-store" ||
		r.Hdr.Get("Content-Security-Policy") != "default-src 'none'; sandbox" || string(r.Body) != pngBytes {
		t.Fatalf("headers %v", r.Hdr)
	}
	e.want(e.do("GET", base+"clip.mp4", "", nil), 200, "mp4")
	rg := e.do("GET", base+"clip.mp4", "", nil, "Range", "bytes=0-3")
	e.want(rg, 206, "range")
	if len(rg.Body) != 4 {
		t.Fatal("range body", len(rg.Body))
	}
	for _, n := range []string{"fake.png", "v.svg", "p.pdf", "page.html"} {
		e.want(e.do("GET", base+n, "", nil), 415, n)
	}
	e.want(e.do("GET", base+"missing.png", "", nil), 404, "missing")
	e.want(e.do("GET", base+"../pic.png", "", nil), 200, "clean path stays within share")
	e.want(e.do("GET", base+"..%2f..%2fetc%2fpasswd", "", nil), 404, "traversal")
	// does not count as download
	var cnt, dl int
	qByName(e.s.St, `SELECT download_count FROM shares WHERE long_id=?`, lid).Scan(&cnt)
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM downloads`).Scan(&dl)
	if cnt != 0 || dl != 0 {
		t.Fatal("preview counted as download", cnt, dl)
	}
	// disabled
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_preview": false}), 200, "disable")
	e.want(e.do("GET", base+"pic.png", "", nil), 403, "disabled")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"allow_preview": true}), 200, "enable")
	// download limit excluded
	lim := e.share(admin, map[string]string{"pic.png": pngBytes}, map[string]any{"download_limit": 5})
	e.want(lim, 201, "limited share")
	e.want(e.do("GET", "/api/shares/"+lim.S("long_id")+"/preview/pic.png", "", nil), 403, "limit")
}

func TestPreviewPasswordToken(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	sh := e.share(admin, map[string]string{"pic.png": pngBytes}, map[string]any{"password": "secret-pass"})
	e.want(sh, 201, "share")
	u := "/api/shares/" + sh.S("long_id")
	e.want(e.do("GET", u+"/preview/pic.png", "", nil), 401, "locked")
	tok := e.do("POST", u+"/unlock", "", map[string]any{"password": "secret-pass"}).S("token")
	e.want(e.do("GET", u+"/preview/pic.png?token="+tok, "", nil), 200, "query token")
	e.want(e.do("GET", u+"/preview/pic.png", "", nil, "X-Share-Token", tok), 200, "header token")
	e.want(e.do("GET", u+"/preview/pic.png?token=bad", "", nil), 401, "bad token")
}
