// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

func quotaUserID(t *testing.T, e *env, name string) int64 {
	t.Helper()
	var id int64
	if err := qByName(e.s.St, `SELECT id FROM users WHERE username=?`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
func quotaSet(t *testing.T, e *env, id, quota int64) {
	t.Helper()
	if _, err := e.s.St.DB.Exec(`UPDATE users SET quota_inherits_default=0,quota_bytes=? WHERE id=?`, quota, id); err != nil {
		t.Fatal(err)
	}
}
func quotaUsage(t *testing.T, e *env, id int64, want store.StorageUsage) {
	t.Helper()
	got, err := e.s.St.UserStorageUsage(id)
	if err != nil || *got != want {
		t.Fatalf("usage got=%+v want=%+v err=%v", got, want, err)
	}
}
func quotaReserve(e *env, token string, size int64) resp {
	return e.do("POST", "/api/uploads", token, map[string]any{"files": []map[string]any{{"name": "a.txt", "full_path": "a.txt", "size": size}}})
}
func quotaGuest(e *env, owner string) string {
	inv := e.do("POST", "/api/reverse-shares/invite", owner, map[string]any{})
	e.want(inv, 201, "invite")
	acc := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": filepath.Base(inv.S("url"))})
	e.want(acc, 200, "accept invite")
	return acc.S("access_token")
}

func TestQuotaBoundaryCompletionAndRetainedExpiry(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	uid := quotaUserID(t, e, "admin")
	quotaSet(t, e, uid, 5)
	reservation := quotaReserve(e, token, 5)
	e.want(reservation, 201, "exact boundary")
	id := reservation.S("id")
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 5, ReservedBytes: 5})
	e.want(quotaReserve(e, token, 1), 413, "reserved space blocks new upload")
	// Reducing quota does not revoke an admitted reservation. Even zero-byte
	// requests must be rejected while the account is already over quota.
	quotaSet(t, e, uid, 0)
	e.want(quotaReserve(e, token, 0), 413, "over-quota empty upload")
	e.want(e.do("PATCH", "/api/uploads/"+id+"/files/0", token, []byte("hello"), "Upload-Offset", "0"), 200, "chunk")
	completed := e.do("POST", "/api/uploads/"+id+"/complete", token, map[string]any{})
	e.want(completed, 201, "finish admitted reservation after lowering quota")
	quotaUsage(t, e, uid, store.StorageUsage{StoredBytes: 5})
	if _, err := e.s.St.DB.Exec(`UPDATE shares SET status='expired',expires_at=? WHERE id=?`, time.Now().Add(-time.Hour), completed.J()["id"]); err != nil {
		t.Fatal(err)
	}
	quotaUsage(t, e, uid, store.StorageUsage{StoredBytes: 5})
	e.want(quotaReserve(e, token, 0), 413, "expired retained files still charged")
	e.want(e.do("DELETE", "/api/shares/"+completed.S("id"), token, nil), 200, "delete retained files")
	quotaUsage(t, e, uid, store.StorageUsage{})
	e.want(quotaReserve(e, token, 1), 413, "zero quota is not unlimited")
	empty := quotaReserve(e, token, 0)
	e.want(empty, 201, "empty upload at zero exact boundary")
	e.want(e.do("POST", "/api/uploads/"+empty.S("id")+"/complete", token, map[string]any{}), 201, "complete empty upload")
}

func TestQuotaAbortAndStaleCleanup(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	uid := quotaUserID(t, e, "admin")
	quotaSet(t, e, uid, 7)
	first := quotaReserve(e, token, 7)
	e.want(first, 201, "reserve")
	e.want(e.do("PATCH", "/api/uploads/"+first.S("id")+"/files/0", token, []byte("x"), "Upload-Offset", "0"), 200, "partial chunk")
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 7, ReservedBytes: 7})
	e.want(e.do("DELETE", "/api/uploads/"+first.S("id"), token, nil), 200, "abort")
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 7, AvailableBytes: 7})
	second := quotaReserve(e, token, 7)
	e.want(second, 201, "reserve after abort")
	if _, err := e.s.St.DB.Exec(`UPDATE upload_sessions SET created_at=? WHERE id=?`, time.Now().Add(-25*time.Hour), second.S("id")); err != nil {
		t.Fatal(err)
	}
	e.s.maintain()
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 7, AvailableBytes: 7})
	if _, err := os.Stat(e.s.uploadDir(second.S("id"))); !os.IsNotExist(err) {
		t.Fatalf("stale directory retained: %v", err)
	}
}

func TestQuotaConcurrentAdmission(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	uid := quotaUserID(t, e, "admin")
	quotaSet(t, e, uid, 9)
	start := make(chan struct{})
	codes := make(chan int, 12)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; codes <- quotaReserve(e, token, 3).Code }()
	}
	close(start)
	wg.Wait()
	close(codes)
	accepted := 0
	for code := range codes {
		if code == 201 {
			accepted++
		} else if code != 413 {
			t.Fatalf("unexpected admission status %d", code)
		}
	}
	if accepted != 3 {
		t.Fatalf("accepted %d reservations, want 3", accepted)
	}
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 9, ReservedBytes: 9})
}

func TestQuotaReverseOwnerAndGuestCompetition(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	owner := e.mkUser(admin, "owner", false)
	other := e.mkUser(admin, "other", false)
	uid := quotaUserID(t, e, "owner")
	otherID := quotaUserID(t, e, "other")
	quotaSet(t, e, uid, 4)
	quotaSet(t, e, otherID, 4)
	guest1, guest2 := quotaGuest(e, owner), quotaGuest(e, owner)
	if _, err := e.s.St.DB.Exec(`UPDATE users SET quota_inherits_default=0,quota_bytes=0 WHERE id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=?)`, uid); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan struct {
		token string
		r     resp
	}, 3)
	var wg sync.WaitGroup
	for _, tok := range []string{owner, guest1, guest2} {
		wg.Add(1)
		go func(tok string) {
			defer wg.Done()
			<-start
			results <- struct {
				token string
				r     resp
			}{tok, quotaReserve(e, tok, 4)}
		}(tok)
	}
	close(start)
	wg.Wait()
	close(results)
	var winner string
	var reservation resp
	accepted := 0
	for result := range results {
		if result.r.Code == 201 {
			accepted++
			winner, reservation = result.token, result.r
		} else {
			e.want(result.r, 413, "shared owner quota")
		}
	}
	if accepted != 1 {
		t.Fatalf("owner and guests admitted %d uploads", accepted)
	}
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 4, ReservedBytes: 4})
	// Another inviter's budget is independent.
	otherGuest := quotaGuest(e, other)
	e.want(quotaReserve(e, otherGuest, 4), 201, "independent inviter quota")
	quotaUsage(t, e, otherID, store.StorageUsage{QuotaBytes: 4, ReservedBytes: 4})
	e.want(e.do("DELETE", "/api/uploads/"+reservation.S("id"), winner, nil), 200, "abort winning reservation")
	// Ensure a reverse upload, regardless of who won the concurrency race,
	// transfers its reservation to retained files owned by the original inviter.
	reverse := quotaReserve(e, guest1, 4)
	e.want(reverse, 201, "guest reservation")
	e.want(e.do("PATCH", "/api/uploads/"+reverse.S("id")+"/files/0", guest1, []byte("data"), "Upload-Offset", "0"), 200, "guest chunk")
	complete := e.do("POST", "/api/uploads/"+reverse.S("id")+"/complete", guest1, map[string]any{})
	e.want(complete, 201, "guest completion")
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 4, StoredBytes: 4})
	var storedOwner int64
	// Guests do not receive the share id; find the share through its invitation.
	if err := e.s.St.DB.QueryRow(`SELECT user_id FROM shares WHERE invite_id IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&storedOwner); err != nil || storedOwner != uid {
		t.Fatalf("share owner %d err=%v", storedOwner, err)
	}
}

func TestQuotaConcurrentCompletionAndAbort(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	uid := quotaUserID(t, e, "admin")
	quotaSet(t, e, uid, 1)
	for attempt := 0; attempt < 8; attempt++ {
		reservation := quotaReserve(e, token, 1)
		e.want(reservation, 201, "reserve for completion race")
		id := reservation.S("id")
		e.want(e.do("PATCH", "/api/uploads/"+id+"/files/0", token, []byte("x"), "Upload-Offset", "0"), 200, "chunk")
		start := make(chan struct{})
		completed, aborted := make(chan resp, 1), make(chan resp, 1)
		go func() { <-start; completed <- e.do("POST", "/api/uploads/"+id+"/complete", token, map[string]any{}) }()
		go func() { <-start; aborted <- e.do("DELETE", "/api/uploads/"+id, token, nil) }()
		close(start)
		c, a := <-completed, <-aborted
		switch c.Code {
		case 201:
			e.want(a, 404, "completion wins abort race")
			quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 1, StoredBytes: 1})
			e.want(e.do("DELETE", "/api/shares/"+c.S("id"), token, nil), 200, "release completed share")
		case 404:
			e.want(a, 200, "abort wins completion race")
		default:
			t.Fatalf("completion race got %d: %s; abort %d", c.Code, c.Body, a.Code)
		}
		quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 1, AvailableBytes: 1})
		if _, err := os.Stat(e.s.uploadDir(id)); !os.IsNotExist(err) {
			t.Fatalf("upload directory survives completion/abort race: %v", err)
		}
	}
}

func TestQuotaConcurrentPendingCap(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	uid := quotaUserID(t, e, "admin")
	quotaSet(t, e, uid, 0)
	start := make(chan struct{})
	codes := make(chan int, 20)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; codes <- quotaReserve(e, token, 0).Code }()
	}
	close(start)
	wg.Wait()
	close(codes)
	accepted := 0
	for code := range codes {
		if code == 201 {
			accepted++
		} else if code != 429 {
			t.Fatalf("pending cap status %d", code)
		}
	}
	if accepted != 16 {
		t.Fatalf("pending cap accepted %d, want 16", accepted)
	}
	quotaUsage(t, e, uid, store.StorageUsage{})
}

func TestQuotaCleanupRechecksExtendedShare(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	uid := quotaUserID(t, e, "admin")
	quotaSet(t, e, uid, 5)
	completed := e.share(token, map[string]string{"a": "hello"}, nil)
	e.want(completed, 201, "share")
	var sid int64
	if err := qByName(e.s.St, `SELECT id FROM shares WHERE long_id=?`, completed.S("long_id")).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	// Simulate discovery of an expired share followed by extension before the
	// cleanup transaction acquires its lock.
	if _, err := e.s.St.DB.Exec(`UPDATE shares SET status='expired',expires_at=? WHERE id=?`, time.Now().Add(-30*24*time.Hour), sid); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("POST", "/api/shares/"+completed.S("id")+"/extend", token, map[string]any{"days": 1}), 200, "extend discovered share")
	removed, err := e.s.removeShareIf(sid, ports.ShareFilter{Kind: ports.ShareRetiredBefore, At: time.Now().Add(-7 * 24 * time.Hour)})
	if err != nil || removed {
		t.Fatalf("extended share removed=%v err=%v", removed, err)
	}
	quotaUsage(t, e, uid, store.StorageUsage{QuotaBytes: 5, StoredBytes: 5})
	if _, err := os.Stat(filepath.Join(e.s.St.DataDir, "shares", completed.S("long_id"))); err != nil {
		t.Fatal(err)
	}
}

func TestQuotaConcurrentShareRemovalCountsOnce(t *testing.T) {
	e := newEnv(t)
	token := e.setup()
	completed := e.share(token, map[string]string{"a": "hello"}, nil)
	e.want(completed, 201, "share")
	var sid int64
	if err := qByName(e.s.St, `SELECT id FROM shares WHERE long_id=?`, completed.S("long_id")).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); ok, err := e.s.removeShare(sid); results <- ok; errs <- err }()
	}
	wg.Wait()
	close(results)
	close(errs)
	removed := 0
	for ok := range results {
		if ok {
			removed++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if removed != 1 {
		t.Fatalf("removed count %d", removed)
	}
	if _, err := os.Stat(filepath.Join(e.s.St.DataDir, "shares", completed.S("long_id"))); !os.IsNotExist(err) {
		t.Fatal(fmt.Sprintf("share directory remains: %v", err))
	}
}

func TestQuotaDefaultAPIChoicesAndSessions(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	setDefault := func(v any) {
		t.Helper()
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{store.DefaultStorageQuotaKey: v}), 200, "change default")
	}
	setDefault("23")
	created := e.do("POST", "/api/users", admin, map[string]any{"username": "inherited", "password": "password123", "email": "inherited@x.io"})
	e.want(created, 201, "inherited user")
	id := created.S("id")
	check := func(r resp, quota int64, inherits bool) {
		t.Helper()
		var u User
		if err := json.Unmarshal(r.Body, &u); err != nil || u.QuotaBytes != quota || u.QuotaInheritsDefault != inherits {
			t.Fatalf("quota user=%+v expected=%d/%v error=%v body=%s", u, quota, inherits, err, r.Body)
		}
	}
	check(created, 23, true)
	login := e.do("POST", "/api/auth/login", "", map[string]any{"username": "inherited", "password": "password123"})
	e.want(login, 200, "login")
	token := login.S("access_token")
	update := func(fields map[string]any) resp {
		fields["email"] = "inherited@x.io"
		return e.do("PUT", "/api/users/"+id, admin, fields)
	}
	for _, fields := range []map[string]any{
		{"quota_inherits_default": true, "quota_bytes": 23},
		{"quota_inherits_default": false},
		{"quota_inherits_default": false, "quota_bytes": nil},
		{"quota_bytes": 1.5},
		{"quota_bytes": int64(1 << 53)},
	} {
		e.want(update(fields), 400, "reject contradictory/incomplete quota")
	}
	for _, step := range []struct {
		fields   map[string]any
		quota    int64
		inherits bool
	}{
		{map[string]any{}, 23, true},
		{map[string]any{"quota_bytes": nil, "quota_inherits_default": nil}, 23, true},
		{map[string]any{"quota_bytes": 0}, 0, false},
		{map[string]any{}, 0, false},
		{map[string]any{"quota_bytes": nil}, 0, false},
		{map[string]any{"quota_inherits_default": true}, 23, true},
		{map[string]any{"quota_inherits_default": false, "quota_bytes": 7}, 7, false},
	} {
		r := update(step.fields)
		e.want(r, 200, "quota choice update")
		check(r, step.quota, step.inherits)
	}
	setDefault(31)
	profile := e.do("GET", "/api/users/me", token, nil)
	e.want(profile, 200, "quota changes do not revoke access token")
	if profile.J()["quota_bytes"] != float64(7) || profile.J()["quota_inherits_default"] != false {
		t.Fatal(profile.J())
	}
	reset := update(map[string]any{"quota_inherits_default": true})
	e.want(reset, 200, "reset default")
	check(reset, 31, true)
	// Refresh continues through the same one-connection transaction and returns
	// effective policy, rather than the user's stale underlying legacy value.
	cookies := (&http.Response{Header: login.Hdr}).Cookies()
	if len(cookies) != 1 {
		t.Fatal(cookies)
	}
	refreshed := e.do("POST", "/api/auth/refresh", "", nil, "Cookie", cookies[0].Name+"="+cookies[0].Value)
	e.want(refreshed, 200, "refresh after quota reset")
	userJSON, _ := json.Marshal(refreshed.J()["user"])
	check(resp{Body: userJSON}, 31, true)
	setDefault(0)
	e.want(quotaReserve(e, token, 1), 413, "global zero quota is not unlimited")
	list := e.do("GET", "/api/users", admin, nil)
	e.want(list, 200, "list effective quotas")
	var users []User
	if err := json.Unmarshal(list.Body, &users); err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.QuotaBytes != 0 || !u.QuotaInheritsDefault {
			t.Fatal(u)
		}
	}
}

func TestQuotaDefaultSettingsValidationAndAtomicity(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	before := e.s.St.Setting("application_name")
	for _, value := range []any{"", " 1", "1x", "1.0", "1e3", "NaN", "-1", "-0", "+1", "9007199254740992", nil, true, []int{1}, 1.5, int64(1 << 53), json.Number("9007199254740991.1")} {
		r := e.do("PUT", "/api/settings", admin, map[string]any{store.DefaultStorageQuotaKey: value, "application_name": "must-not-change"})
		e.want(r, 400, "invalid quota rejects entire batch")
		if e.s.St.Setting("application_name") != before || e.s.St.Setting(store.DefaultStorageQuotaKey) != fmt.Sprint(store.DefaultQuotaBytes) {
			t.Fatal("invalid quota partially changed settings", value)
		}
	}
	for _, value := range []any{int64(store.MaxSafeQuotaBytes), "0", "10737418240"} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{store.DefaultStorageQuotaKey: value}), 200, "valid quota setting")
	}
	// Force a write failure to prove the whole batch rolls back regardless of map order.
	if _, err := e.s.St.DB.Exec(`CREATE TRIGGER quota_settings_test_failure BEFORE UPDATE ON settings WHEN NEW.key='default_storage_quota_bytes' BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{store.DefaultStorageQuotaKey: "31", "application_name": "must-not-change"}), 500, "failed batch")
	if e.s.St.Setting("application_name") != before || e.s.St.Setting(store.DefaultStorageQuotaKey) != "10737418240" {
		t.Fatal("failed batch partially committed")
	}
}

func TestQuotaDefaultsAllCreationPathsAndRestart(t *testing.T) {
	e := newEnv(t)
	if err := e.s.St.SetSetting(store.DefaultStorageQuotaKey, "37"); err != nil {
		t.Fatal(err)
	}
	setup := e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "admin", "password": "password123", "email": "admin@x.io"})
	e.want(setup, 200, "setup follows configured default")
	admin := setup.S("access_token")
	if setup.J()["user"].(map[string]any)["quota_bytes"] != float64(37) {
		t.Fatal(setup.J())
	}
	for _, fields := range []map[string]any{
		{"username": "implicit"},
		{"username": "explicit-inherit", "quota_inherits_default": true},
		{"username": "null-inherit", "quota_bytes": nil, "quota_inherits_default": nil},
	} {
		fields["password"] = "password123"
		e.want(e.do("POST", "/api/users", admin, fields), 201, "admin creation inherits")
	}
	for _, fields := range []map[string]any{
		{"username": "bad-choice", "quota_inherits_default": false},
		{"username": "contradiction", "quota_inherits_default": true, "quota_bytes": 37},
	} {
		fields["password"] = "password123"
		e.want(e.do("POST", "/api/users", admin, fields), 400, "invalid creation choice")
	}
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "override-zero", "password": "password123", "quota_bytes": 0}), 201, "zero override creation")
	e.useSMTP(newSMTP(t))
	if err := e.s.St.SetSetting("allow_self_registration", "true"); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "registered", "email": "registered@x.io", "password": "password123", "quota_bytes": 0, "quota_inherits_default": false}), 201, "public registration inherits, ignoring admin policy fields")
	if _, err := e.s.St.DB.Exec(`INSERT INTO auth_providers(id,uuid,name,type) VALUES(1,'quota-provider-id','quota-provider','oidc')`); err != nil {
		t.Fatal(err)
	}
	provider, msg := e.s.resolveExternalUser(&Provider{ID: 1, Type: "oidc", AllowRegistration: true}, extIdentity{Sub: "quota-sub", Username: "provider-user"})
	if provider == nil || msg != "" || provider.QuotaBytes != 37 || !provider.QuotaInheritsDefault {
		t.Fatal(provider, msg)
	}
	guestToken := quotaGuest(e, admin)
	guestProfile := e.do("GET", "/api/users/me", guestToken, nil)
	e.want(guestProfile, 200, "guest profile effective default")
	if guestProfile.J()["quota_bytes"] != float64(37) || guestProfile.J()["quota_inherits_default"] != true {
		t.Fatal(guestProfile.J())
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{store.DefaultStorageQuotaKey: "41"}), 200, "change all inherited accounts")
	// Reopen a separate connection to the isolated fixture, exercising the actual
	// startup migration rather than only invoking it in memory.
	reopened, err := store.Open(e.s.St.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	rows, err := reopened.DB.Query(`SELECT id,username,quota_inherits_default FROM users`)
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		id       int64
		name     string
		inherits bool
	}
	var accounts []entry
	for rows.Next() {
		var account entry
		if err := rows.Scan(&account.id, &account.name, &account.inherits); err != nil {
			t.Fatal(err)
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if len(accounts) != 8 {
		t.Fatal("creation count", len(accounts))
	}
	for _, account := range accounts {
		u, err := reopened.UserStorageUsage(account.id)
		want, inherits := int64(41), true
		if account.name == "override-zero" {
			want, inherits = 0, false
		}
		if err != nil || u.QuotaBytes != want || u.QuotaInheritsDefault != inherits || account.inherits != inherits {
			t.Fatal(account, u, err)
		}
	}
}

func TestQuotaCorruptPolicyDeniesAPIAndUserScan(t *testing.T) {
	for _, statement := range []string{
		`UPDATE settings SET value='3x' WHERE key='default_storage_quota_bytes'`,
		`DELETE FROM settings WHERE key='default_storage_quota_bytes'`,
		`UPDATE users SET quota_bytes='3x'`,
		`UPDATE users SET quota_inherits_default=2`,
	} {
		t.Run(statement, func(t *testing.T) {
			e := newEnv(t)
			token := e.setup()
			id := quotaUserID(t, e, "admin")
			if _, err := e.s.St.DB.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if _, err := e.s.userByID(id); err == nil {
				t.Fatal("corrupt policy user scan accepted")
			}
			e.want(e.do("GET", "/api/users/me", token, nil), 401, "corrupt policy fails closed")
			e.want(quotaReserve(e, token, 0), 401, "corrupt policy denies admission")
		})
	}
}
