// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sendora-app/sendora/internal/store"
)

func auditCount(e *env, where string, args ...any) int {
	e.t.Helper()
	return len(auditRowsWhere(e, where, args...))
}

// With mfa_policy=all an auditor must be able to enrol a second factor, and can
// then read the audit log.
func TestAuditorEnrolsMFAWhenRequiredForAll(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkAuditor(admin, "audrey")
	e.setting("mfa_policy", "all")
	login := e.login("audrey", "password123")
	e.want(login, 200, "auditor login")
	restricted := login.S("access_token")
	if claimsOf(t, restricted)["mfa_enroll"] != true {
		t.Fatalf("expected an enrolment-only token: %s", login.Body)
	}
	if r := e.do("GET", "/api/audit", restricted, nil); r.Code != 403 || r.S("error") != "mfa enrollment required" {
		t.Fatalf("audit log before enrolment: %d %s", r.Code, r.Body)
	}
	e.want(e.do("GET", "/api/users/me/mfa", restricted, nil), 200, "auditor reads its own MFA status")
	_, tok, codes := e.enrollTOTP(restricted, "password123")
	if tok == "" || len(codes) == 0 {
		t.Fatal("enrolment did not return a full session and recovery codes")
	}
	if claimsOf(t, tok)["mfa_enroll"] == true {
		t.Fatal("token after enrolment is still restricted")
	}
	r := e.do("GET", "/api/audit", tok, nil)
	e.want(r, 200, "auditor reads the audit log after enrolling")
	if !strings.Contains(string(r.Body), "mfa_enrolled") {
		t.Fatalf("enrolment not in the log: %s", r.Body)
	}
	// Still read-only everywhere else.
	e.want(e.do("GET", "/api/shares", tok, nil), 403, "auditor share list")
	e.want(e.do("GET", "/api/users", tok, nil), 403, "auditor user list")
	// It manages its own factors.
	e.want(e.do("POST", "/api/users/me/mfa/recovery/regenerate", tok, map[string]any{"password": "password123"}), 200, "manage own factors")
}

// Only a known user who is refused is recorded as access_denied; tokens that do
// not verify are not recorded at all.
func TestAuditAccessDeniedOnlyForKnownUsers(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	auditor := e.mkAuditor(admin, "audrey")

	var bobID int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='bob'`).Scan(&bobID)
	u, err := e.s.userByID(bobID)
	if err != nil {
		t.Fatal(err)
	}
	expired, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": strconv.FormatInt(bobID, 10), "purpose": "access", "jti": "x", "credential": e.s.credentialVersion(u),
		"auth_time": time.Now().Add(-time.Hour).Unix(), "exp": time.Now().Add(-time.Minute).Unix(),
	}).SignedString(e.s.key(keyAccess))
	forged, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "1", "purpose": "access", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("not-the-key"))

	before := auditCount(e, "1=1")
	for _, tok := range []string{expired, forged, "garbage", "a.b.c"} {
		e.want(e.do("GET", "/api/users", tok, nil), 401, "bad token on an admin route")
		e.want(e.do("GET", "/api/shares", tok, nil), 401, "bad token on a user route")
		e.want(e.do("POST", "/api/shares/prune-expired", tok, nil), 401, "bad token on a mutating route")
	}
	if n := auditCount(e, "1=1"); n != before {
		t.Fatalf("unverified tokens wrote %d records: %+v", n-before, auditRowsWhere(e, "seq>(SELECT MAX(seq)-? FROM audit_log)", n-before))
	}

	// Known users who are refused are recorded with their identity and role.
	e.want(e.do("GET", "/api/users", bob, nil), 403, "user on an admin route")
	e.want(e.do("GET", "/api/shares", auditor, nil), 403, "auditor on a route outside its allowlist")
	inv := e.do("POST", "/api/reverse-shares/invite", bob, map[string]any{"open": true, "max_uploads": 2, "days": 1, "name": "Drop"})
	e.want(inv, 201, "invite")
	link := inv.S("url")
	acc := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": link[strings.LastIndex(link, "/")+1:]})
	e.want(acc, 200, "accept")
	e.want(e.do("GET", "/api/users", acc.S("access_token"), nil), 403, "guest on an admin route")
	rows := auditRowsWhere(e, "action='access_denied' AND category='security'")
	roles := map[string]string{}
	for _, r := range rows {
		roles[r.Role] = r.ActorNm
	}
	if len(rows) != 3 || roles["user"] != "bob" || roles["auditor"] != "audrey" || roles["guest"] == "" {
		t.Fatalf("want three refusals by user, auditor and guest: %+v", rows)
	}
}

// A handler that panics still gets its outcome recorded (status 500, failed).
func TestAuditMiddlewareRecordsPanics(t *testing.T) {
	e := newEnv(t)
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, e.s.auditMiddleware)
	boom := func(http.ResponseWriter, *http.Request) { panic("boom") }
	r.With(e.s.critical("user_deleted", "user")).Delete("/boom/{id}", boom)
	r.Post("/plain", boom)
	for _, c := range []struct{ method, path string }{{"DELETE", "/boom/7"}, {"POST", "/plain"}} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != 500 {
			t.Fatalf("%s %s: Recoverer must still answer 500, got %d", c.method, c.path, rec.Code)
		}
	}
	crit := auditRowsWhere(e, "action='user_deleted' AND target='user#7'")
	if len(crit) != 2 || crit[0].Outcome != "attempted" || crit[1].Outcome != "failed" || crit[1].Detail != "status=500" {
		t.Fatalf("critical action: want attempted then failed status=500, got %+v", crit)
	}
	plain := auditRowsWhere(e, "action='POST /plain'")
	if len(plain) != 1 || plain[0].Outcome != "failed" || plain[0].Detail != "status=500" {
		t.Fatalf("mutation: %+v", plain)
	}
}

// GracefulStop stops the jobs, shuts the server down and then writes
// system_stop synchronously, exactly once.
func TestGracefulStopWritesSystemStopOnce(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.s.RunJobs(ctx)
	var order []string
	var mu sync.Mutex
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }
	shutdown := func(context.Context) error {
		note("shutdown")
		return nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.s.GracefulStop(time.Second, func() { note("jobs"); cancel() }, shutdown, nil)
			// Every caller returns only after the record exists.
			if auditCount(e, "action='system_stop'") != 1 {
				t.Error("GracefulStop returned before system_stop was written")
			}
		}()
	}
	wg.Wait()
	if strings.Join(order, ",") != "jobs,shutdown" {
		t.Fatalf("stop ran %v, want jobs then shutdown once", order)
	}
	select {
	case <-*e.s.jobsDone.Load():
	default:
		t.Fatal("the jobs loop was not waited for")
	}
	rows := auditRowsWhere(e, "action='system_stop'")
	if len(rows) != 1 || rows[0].Category != "system" || rows[0].Role != "system" {
		t.Fatalf("%+v", rows)
	}
	// The import swap records the stop only once as well.
	e.s.recordStop()
	if auditCount(e, "action='system_stop'") != 1 {
		t.Fatal("system_stop written twice")
	}
	// A failing shutdown falls back to closing connections.
	e2 := newEnv(t)
	closed := false
	e2.s.GracefulStop(time.Millisecond, nil, func(context.Context) error { return errors.New("timeout") }, func() error { closed = true; return nil })
	if !closed || auditCount(e2, "action='system_stop'") != 1 {
		t.Fatalf("closed=%v", closed)
	}
}

// A refused purge is recorded once, not every maintenance run, and shown in the status.
func TestAuditPurgeFailureRecordedOnceAndShown(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	auditor := e.mkAuditor(admin, "audrey")
	old := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(store.AuditTimeLayout)
	for i := 0; i < 3; i++ {
		e.s.St.AuditAppend(store.AuditRecord{TS: old, Category: "admin", Action: "ancient", Outcome: "ok"})
	}
	if st := e.do("GET", "/api/audit/status", auditor, nil); st.J()["purge_refused"] != false {
		t.Fatalf("%s", st.Body)
	}
	e.s.St.DB.Exec(`UPDATE audit_log SET detail='x' WHERE action='ancient'`)
	for i := 0; i < 3; i++ {
		e.s.purgeAudit()
	}
	rows := auditRowsWhere(e, "action='audit_purge_failed'")
	if len(rows) != 1 || !strings.Contains(rows[0].Detail, "refused") {
		t.Fatalf("want one audit_purge_failed record, got %+v", rows)
	}
	st := e.do("GET", "/api/audit/status", auditor, nil)
	j := st.J()
	if j["purge_refused"] != true || j["purge_refused_since"] == nil || j["verified"] != false {
		t.Fatalf("%s", st.Body)
	}
	if a := e.do("GET", "/api/logs/status", admin, nil); a.J()["purge_refused"] != true {
		t.Fatalf("admin status: %s", a.Body)
	}
	if auditCount(e, "action='ancient'") != 3 {
		t.Fatal("evidence removed")
	}
}

// The status endpoint follows appends incrementally and still reports tampering
// of records it verified before, like a full check.
func TestAuditStatusIncrementalMatchesFullCheck(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	auditor := e.mkAuditor(admin, "audrey")
	for i := 0; i < 20; i++ {
		e.s.logEvent(0, "tester", "bulk_event", fmt.Sprint(i), "")
	}
	for round := 0; round < 3; round++ {
		st := e.do("GET", "/api/audit/status", auditor, nil).J()
		full := chainStatus(e)
		if st["verified"] != true || int64(st["count"].(float64)) > full.Count || int64(st["last_seq"].(float64)) > full.LastSeq {
			t.Fatalf("round %d: %v vs %+v", round, st, full)
		}
		e.s.logEvent(0, "tester", "bulk_event", "more", "")
	}
	e.s.St.DB.Exec(`UPDATE audit_log SET detail='changed' WHERE seq=3`)
	st := e.do("GET", "/api/audit/status", auditor, nil).J()
	if st["verified"] != false || st["first_broken_seq"].(float64) != 3 {
		t.Fatalf("tampering of an already verified record not reported: %v", st)
	}
}

func TestSettingsChangeDetailCountsWhatDoesNotFit(t *testing.T) {
	updates, olds := map[string]string{}, map[string]string{}
	for i := 0; i < 60; i++ {
		k := fmt.Sprintf("setting_%02d", i)
		updates[k], olds[k] = strings.Repeat("n", 70), strings.Repeat("o", 70)
	}
	d := settingsChangeDetail(updates, olds)
	if len(d) > store.AuditFieldMax || !strings.HasSuffix(d, " more)") {
		t.Fatalf("len %d: ...%s", len(d), d[max(0, len(d)-40):])
	}
	shown := strings.Count(d, "setting_")
	var more int
	fmt.Sscanf(d[strings.LastIndex(d, "(+"):], "(+%d more)", &more)
	if shown+more != 60 || shown == 0 {
		t.Fatalf("shown %d + more %d != 60", shown, more)
	}
	if small := settingsChangeDetail(map[string]string{"a": "1"}, map[string]string{"a": "0"}); small != "a: '0' -> '1'" {
		t.Fatal(small)
	}
}

// Exports are counted before anything is loaded and streamed in pages.
func TestAuditExportCountsFirstAndStreamsPages(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	auditor := e.mkAuditor(admin, "audrey")
	for i := 0; i < 23; i++ {
		e.s.logEvent(0, "tester", "bulk_event", fmt.Sprint(i), "")
	}
	defer func(p, m int) { auditExportPage, auditExportMax = p, m }(auditExportPage, auditExportMax)
	auditExportPage = 4
	for _, c := range []struct{ who, path string }{{auditor, "/api/audit/export?action=bulk_event"}, {admin, "/api/logs/export?action=bulk_event"}} {
		r := e.do("GET", c.path, c.who, nil)
		e.want(r, 200, c.path)
		recs, err := csv.NewReader(strings.NewReader(string(r.Body))).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(recs[0], ",") != strings.Join(auditCSVHeader, ",") {
			t.Fatalf("%s header %v", c.path, recs[0])
		}
		if len(recs) != 24 {
			t.Fatalf("%s: %d data rows, want 23", c.path, len(recs)-1)
		}
		last := int64(0)
		for _, rec := range recs[1:] {
			seq, _ := strconv.ParseInt(rec[0], 10, 64)
			if seq <= last || rec[11] == "" || rec[12] == "" {
				t.Fatalf("rows out of order or without hashes: %v", rec)
			}
			last = seq
		}
	}
	jl := e.do("GET", "/api/audit/export?format=jsonl&action=bulk_event", auditor, nil)
	if n := strings.Count(strings.TrimSpace(string(jl.Body)), "\n") + 1; n != 23 {
		t.Fatalf("jsonl lines %d", n)
	}
	if ok := auditRowsWhere(e, "action='audit_exported' AND outcome='ok'"); len(ok) != 3 || !strings.Contains(ok[0].Detail, "23 records") {
		t.Fatalf("%+v", ok)
	}
	// Too many: refused with 413 before loading, and the attempt is on record.
	auditExportMax = 10
	r := e.do("GET", "/api/audit/export?action=bulk_event", auditor, nil)
	e.want(r, 413, "too many")
	if last := auditRowsWhere(e, "action='audit_exported'"); last[len(last)-1].Outcome != "failed" {
		t.Fatalf("%+v", last[len(last)-1])
	}
}

func TestAuditPagingKeysetAndCappedTotal(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	auditor := e.mkAuditor(admin, "audrey")
	for i := 0; i < 30; i++ {
		e.s.logEvent(0, "Tester", "bulk_event", fmt.Sprint(i), "Mixed CASE Detail")
	}
	q := "/api/audit?action=bulk_event&limit=10"
	first := e.do("GET", q, auditor, nil).J()
	if first["total"].(float64) != 30 || first["total_capped"] != false || first["next_before_seq"].(float64) == 0 {
		t.Fatalf("%v", first)
	}
	seen := map[float64]bool{}
	next := first["next_before_seq"].(float64)
	for _, rec := range first["records"].([]any) {
		seen[rec.(map[string]any)["seq"].(float64)] = true
	}
	for next != 0 {
		page := e.do("GET", fmt.Sprintf("%s&before_seq=%d", q, int64(next)), auditor, nil).J()
		for _, rec := range page["records"].([]any) {
			s := rec.(map[string]any)["seq"].(float64)
			if seen[s] || s >= next {
				t.Fatalf("keyset page repeats or overlaps: %v", s)
			}
			seen[s] = true
		}
		next = page["next_before_seq"].(float64)
	}
	if len(seen) != 30 {
		t.Fatalf("keyset pages covered %d records", len(seen))
	}
	// Offset keeps working and agrees with the keyset pages.
	off := e.do("GET", q+"&offset=10", auditor, nil).J()["records"].([]any)
	if off[0].(map[string]any)["seq"].(float64) >= first["records"].([]any)[9].(map[string]any)["seq"].(float64) {
		t.Fatal("offset paging broken")
	}
	e.want(e.do("GET", "/api/audit?before_seq=0", auditor, nil), 400, "before_seq 0")
	e.want(e.do("GET", "/api/audit?before_seq=x", auditor, nil), 400, "before_seq junk")
	// Search stays case-insensitive without lower().
	for _, s := range []string{"q=mixed+case", "q=MIXED", "actor=tESTER"} {
		if n := e.do("GET", "/api/audit?action=bulk_event&"+s, auditor, nil).J()["total"].(float64); n != 30 {
			t.Fatalf("%s: %v", s, n)
		}
	}
	// The total is capped; the legacy endpoint reports the same.
	defer func(c int64) { auditTotalCap = c }(auditTotalCap)
	auditTotalCap = 12
	for _, p := range []string{"/api/audit?action=bulk_event", "/api/logs?action=bulk_event"} {
		j := e.do("GET", p, admin, nil).J()
		if j["total"].(float64) != 12 || j["total_capped"] != true {
			t.Fatalf("%s: %v %v", p, j["total"], j["total_capped"])
		}
	}
	// /api/logs returns the same records as /api/audit, under its legacy names.
	a := e.do("GET", "/api/audit?action=bulk_event&limit=5", admin, nil).J()["records"].([]any)
	l := e.do("GET", "/api/logs?action=bulk_event&limit=5", admin, nil).J()["logs"].([]any)
	for i := range a {
		if a[i].(map[string]any)["seq"] != l[i].(map[string]any)["id"] || a[i].(map[string]any)["actor"] != l[i].(map[string]any)["actor"] {
			t.Fatalf("record %d differs: %v vs %v", i, a[i], l[i])
		}
	}
}

// The admin's MFA reset request is one critical action: one attempted record
// and one outcome record, under mfa_reset_requested in the account category.
func TestAuditMFAResetRequestRecordedOnce(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "bob", false)
	var id int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='bob'`).Scan(&id)
	e.do("POST", fmt.Sprintf("/api/users/%d/mfa/reset", id), admin, nil) // no verified email / SMTP: refused
	rows := auditRowsWhere(e, "action LIKE 'mfa_reset%'")
	if len(rows) != 2 || rows[0].Action != "mfa_reset_requested" || rows[0].Outcome != "attempted" || rows[1].Action != "mfa_reset_requested" ||
		rows[1].Outcome != "failed" || rows[0].Category != "account" {
		t.Fatalf("%+v", rows)
	}
	for _, a := range []string{"mfa_reset_requested", "mfa_reset_confirmed"} {
		if c, _ := classifyAction(a); c != catAccount {
			t.Errorf("%s is %s, want account", a, c)
		}
	}
}

// The cached audit_log_ip follows settings written through SetSetting too.
func TestAuditIPSettingCacheFollowsSettingsChanges(t *testing.T) {
	e := newEnv(t)
	if e.s.auditLogIP() {
		t.Fatal("default off")
	}
	e.setting("audit_log_ip", "true")
	if !e.s.auditLogIP() {
		t.Fatal("cache not refreshed after SetSetting")
	}
	e.s.St.DB.Exec(`UPDATE settings SET value='false' WHERE key='audit_log_ip'`)
	e.s.St.SettingsChanged()
	if e.s.auditLogIP() {
		t.Fatal("cache not refreshed after SettingsChanged")
	}
}

// Password changes and resets are evidence for an auditor (who changed which
// account's credentials, and how), so they are explicit audit records with the
// account as actor, not only generic api_mutation entries.
func TestPasswordChangesAndResetsAreAudited(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	e.want(e.do("PUT", "/api/users/me", bob, map[string]any{"name": "Bob", "email": "bob@x.io", "password": "newpassword1", "current_password": "password123"}), 200, "own change")
	var uid int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='bob'`).Scan(&uid)
	tok := "audit-reset-token"
	if _, err := e.s.St.DB.Exec(`INSERT INTO password_resets(hash,user_id,expires_at,kind) VALUES(?,?,?,'reset')`, hashToken(tok), uid, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": tok, "password": "anotherpass9"}), 200, "reset")

	changed := auditRowsWhere(e, "action='password_changed'")
	if len(changed) != 1 || changed[0].ActorNm != "bob" || changed[0].Category != "auth" || !strings.Contains(changed[0].Target, "bob") {
		t.Fatalf("password_changed: %+v", changed)
	}
	reset := auditRowsWhere(e, "action='password_reset'")
	if len(reset) != 1 || reset[0].ActorNm != "bob" || !strings.Contains(reset[0].Detail, "reset link") {
		t.Fatalf("password_reset: %+v", reset)
	}
	for _, r := range append(changed, reset...) {
		if strings.Contains(r.Detail, "newpassword1") || strings.Contains(r.Detail, "anotherpass9") || strings.Contains(r.Detail, tok) {
			t.Fatalf("secret in audit detail: %+v", r)
		}
	}
	// Expired or used MFA reset requests are purged by maintenance.
	e.s.St.DB.Exec(`INSERT INTO mfa_reset_requests(hash,user_id,expires_at) VALUES('old',?,?)`, uid, time.Now().Add(-time.Hour))
	e.s.maintain()
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM mfa_reset_requests WHERE hash='old'`).Scan(&n)
	if n != 0 {
		t.Fatal("expired MFA reset request not purged")
	}
}

// mfa_policy "privileged" requires a second factor for administrators and
// auditors, not for ordinary users; enabling it needs the admin's own factor.
func TestMFAPolicyPrivilegedCoversAdminsAndAuditors(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	r := e.do("PUT", "/api/settings", admin, map[string]any{"mfa_policy": "privileged"})
	if r.Code != 400 {
		t.Fatalf("enforcing without an own factor must be refused: %d %s", r.Code, r.Body)
	}
	e.setting("mfa_policy", "privileged")
	bob := e.mkUser(admin, "bob", false)
	auditor := e.mkAuditor(admin, "audrey")
	required := func(tok string) bool {
		me := e.do("GET", "/api/users/me", tok, nil)
		u, _ := me.J()["user"].(map[string]any)
		return u["mfa_required"] == true
	}
	if !required(admin) {
		t.Fatal("administrator must be required to use MFA")
	}
	if !required(auditor) {
		t.Fatal("auditor must be required to use MFA")
	}
	if required(bob) {
		t.Fatal("an ordinary user must not be required to use MFA")
	}
	if e.s.mfaGlobal() != "privileged" {
		t.Fatalf("policy not kept: %q", e.s.mfaGlobal())
	}
}
