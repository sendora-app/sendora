// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sendora-app/sendora/internal/store"
)

func (e *env) mkAuditor(admin, name string) string {
	e.t.Helper()
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": name, "password": "password123", "email": name + "@x.io", "auditor": true}), 201, "create auditor")
	r := e.do("POST", "/api/auth/login", "", map[string]any{"username": name, "password": "password123"})
	e.want(r, 200, "login "+name)
	return r.S("access_token")
}

type auditRow struct {
	Seq                                                          int64
	Category, Role, Action, Target, Outcome, Detail, IP, ActorNm string
}

func auditRowsWhere(e *env, where string, args ...any) []auditRow {
	e.t.Helper()
	rows, err := e.s.St.DB.Query(`SELECT seq,category,actor_role,action,target,outcome,detail,ip,actor_name FROM audit_log WHERE `+where+` ORDER BY seq`, args...)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.Seq, &r.Category, &r.Role, &r.Action, &r.Target, &r.Outcome, &r.Detail, &r.IP, &r.ActorNm); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func auditActions(e *env, where string, args ...any) []string {
	var out []string
	for _, r := range auditRowsWhere(e, where, args...) {
		out = append(out, r.Action)
	}
	return out
}

func hasAction(list []string, a string) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

func chainStatus(e *env) store.AuditStatus {
	e.t.Helper()
	st, err := e.s.St.AuditVerify()
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

func TestAuditRecordsEventsWithoutSecrets(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	secretTyped := "TypedPassw0rdInUsername"
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": secretTyped, "password": "x1x1x1x1"}), 401, "unknown login")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "WrongPassword9"}), 401, "bad pw")
	sh := e.share(bob, map[string]string{"a.txt": "abc"}, map[string]any{"password": "SharePw12345"})
	e.want(sh, 201, "share")
	id := fmt.Sprint(int64(sh.J()["id"].(float64)))
	path := "/api/shares/" + id
	e.want(e.do("POST", path+"/extend", bob, map[string]any{"days": 2}), 200, "extend")
	e.want(e.do("POST", path+"/download-limit", bob, map[string]any{"limit": 5}), 200, "limit")
	e.want(e.do("PUT", path, bob, map[string]any{"name": "SecretNewName", "password": "AnotherPw98765"}), 200, "edit")
	e.want(e.do("POST", path+"/expire", bob, nil), 200, "expire")
	e.want(e.do("POST", path+"/extend", bob, map[string]any{"days": 1}), 200, "extend again")
	sh2 := e.share(bob, map[string]string{"b.txt": "xyz"}, nil)
	e.want(sh2, 201, "share2")
	e.want(e.do("GET", "/api/shares/"+sh2.S("long_id")+"/download", "", nil), 200, "download")
	e.want(e.do("DELETE", "/api/shares/"+fmt.Sprint(int64(sh2.J()["id"].(float64))), bob, nil), 200, "delete share")
	e.want(e.do("POST", "/api/users/2/force-reset-password", admin, nil), 200, "force reset")
	e.want(e.do("POST", "/api/users/2/unlock-login", admin, nil), 200, "unlock")
	e.want(e.do("PUT", "/api/users/2", admin, map[string]any{"name": "Bob", "email": "bob@x.io"}), 200, "update user")
	inv := e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{"name": "g", "open": true, "max_uploads": 2})
	e.want(inv, 201, "invite")
	e.want(e.do("POST", "/api/reverse-shares/invites/"+fmt.Sprint(int64(inv.J()["id"].(float64)))+"/revoke", admin, nil), 200, "revoke")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"application_name": "SecretAppName", "smtp_pass": "smtp-secret-pw", "smtp_host": "mail.example.org"}), 200, "settings")
	b := e.do("POST", "/api/backups", admin, nil)
	e.want(b, 201, "backup")
	e.want(e.do("DELETE", "/api/backups/"+b.S("name"), admin, nil), 200, "delete backup")
	e.want(e.do("DELETE", "/api/users/2", admin, nil), 200, "delete user")

	acts := auditActions(e, "1=1")
	for _, want := range []string{"login_ok", "login_failed", "share_created", "share_extended", "share_limit_changed", "share_edited",
		"share_expired_manual", "download_started", "share_deleted", "user_created", "user_updated", "user_deleted", "user_force_reset",
		"user_unlocked", "invite_created", "invite_revoked", "settings_changed", "backup_created", "backup_deleted"} {
		if !hasAction(acts, want) {
			t.Errorf("missing action %s in %v", want, acts)
		}
	}
	unknown := false
	for _, r := range auditRowsWhere(e, "1=1") {
		line := strings.Join([]string{r.ActorNm, r.Action, r.Target, r.Detail}, "|")
		for _, bad := range []string{secretTyped, "WrongPassword9", "SharePw12345", "AnotherPw98765", "smtp-secret-pw", "ChangedPass123", "127.0.0.1", "::1", sh.S("long_id"), sh2.S("long_id")} {
			if strings.Contains(line, bad) {
				t.Errorf("row leaks %q: %s", bad, line)
			}
		}
		if r.Action == "login_failed" && r.ActorNm == "unknown" {
			unknown = true
		}
		if r.Action == "settings_changed" && r.Outcome == "ok" {
			if !strings.Contains(r.Detail, "application_name") || !strings.Contains(r.Detail, "SecretAppName") || !strings.Contains(r.Detail, "smtp_pass") || !strings.Contains(r.Detail, "smtp_host") {
				t.Errorf("settings detail should name the fields and old/new of plain ones: %s", r.Detail)
			}
		}
	}
	if !unknown {
		t.Error("failed login for unknown account should be actor unknown")
	}
	// Share events carry the share category; settings do not.
	for _, r := range auditRowsWhere(e, "action IN ('share_created','download_started','invite_created')") {
		if r.Category != "share" {
			t.Errorf("%s should be a share event, got %s", r.Action, r.Category)
		}
	}
	if st := chainStatus(e); !st.OK {
		t.Fatalf("chain broken after normal use: %+v", st)
	}
}

func TestAuditCriticalRecordsAttemptBeforeAction(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "carol", false)
	rows := auditRowsWhere(e, "action='user_created'")
	if len(rows) < 2 || rows[0].Outcome != "attempted" || rows[0].Role != "admin" {
		t.Fatalf("want an attempted record first: %+v", rows)
	}
	// A failing critical action gets a final failed record from the middleware.
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "carol", "password": "password123", "email": "c2@x.io"}), 400, "duplicate")
	last := auditRowsWhere(e, "action='user_created'")
	if len(last) < 3 || last[len(last)-1].Outcome != "failed" {
		t.Fatalf("%+v", last)
	}
}

func TestAuditCriticalActionRefusedWhenAuditWriteFails(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	fail := func() error { return errors.New("forced audit failure") }
	e.s.audit.hook.Store(&fail)
	var before int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&before)
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "dave", "password": "password123", "email": "d@x.io"}), 503, "create user without audit")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"application_name": "NoAudit"}), 503, "settings without audit")
	e.want(e.do("POST", "/api/backups", admin, nil), 503, "backup without audit")
	e.want(e.do("DELETE", "/api/users/1", admin, nil), 503, "delete without audit")
	var after int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&after)
	if after != before || e.s.St.Setting("application_name") == "NoAudit" {
		t.Fatal("a critical action ran without being audited")
	}
	if e.s.audit.fails.Load() < 4 {
		t.Fatalf("failure counter %d", e.s.audit.fails.Load())
	}
	// Non-critical requests are not blocked by an audit failure (best effort, counted).
	e.want(e.do("GET", "/api/users/me", admin, nil), 200, "read")
	e.s.audit.hook.Store(nil)
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "dave", "password": "password123", "email": "d@x.io"}), 201, "create user")
}

func TestAuditAdminAndAuditorSeeTheSameEvents(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	auditor := e.mkAuditor(admin, "audrey")
	sh := e.share(bob, map[string]string{"a.txt": "abc"}, map[string]any{"name": "BobSecretShareName"})
	e.want(sh, 201, "share")
	e.want(e.do("GET", "/api/shares/"+sh.S("long_id")+"/download", "", nil), 200, "download")

	// Administrators see share events, but never share names, link IDs or file names.
	body := string(e.do("GET", "/api/logs?limit=100", admin, nil).Body)
	for _, want := range []string{"share_created", "download_started", "user_created"} {
		if !strings.Contains(body, want) {
			t.Fatalf("administrator misses %s: %s", want, body)
		}
	}
	for _, leak := range []string{"BobSecretShareName", sh.S("long_id"), "a.txt"} {
		if strings.Contains(body, leak) {
			t.Fatalf("audit log leaks %q: %s", leak, body)
		}
	}
	exp := e.do("GET", "/api/logs/export", admin, nil)
	e.want(exp, 200, "admin export")
	if !strings.Contains(string(exp.Body), "share_created") {
		t.Fatal("admin export misses share events")
	}
	if r := e.do("GET", "/api/logs?category=share", admin, nil); r.J()["total"].(float64) == 0 {
		t.Fatal("share category must be visible to administrators")
	}
	if r := e.do("GET", "/api/logs?q=share_created", admin, nil); r.J()["total"].(float64) == 0 {
		t.Fatal("search must find share events")
	}

	// The auditor endpoints return the same records for an administrator.
	// (Reading the log is itself recorded once per reader, so let both read once
	// before comparing.)
	e.want(e.do("GET", "/api/audit?limit=100", auditor, nil), 200, "auditor list")
	e.want(e.do("GET", "/api/audit?limit=100", admin, nil), 200, "administrator reads /api/audit")
	ra := e.do("GET", "/api/audit?limit=100", auditor, nil)
	rb := e.do("GET", "/api/audit?limit=100", admin, nil)
	if ra.J()["total"] != rb.J()["total"] {
		t.Fatalf("administrator and auditor see different logs: %v vs %v", ra.J()["total"], rb.J()["total"])
	}
	e.want(e.do("GET", "/api/audit/status", admin, nil), 200, "administrator reads the chain status")
	e.want(e.do("GET", "/api/audit/export?format=jsonl", admin, nil), 200, "administrator exports JSONL")
	// Ordinary users never read it.
	e.want(e.do("GET", "/api/audit", bob, nil), 403, "user cannot read the audit log")
}

func TestAuditorEndpointsFiltersExportAndViewThrottle(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	auditor := e.mkAuditor(admin, "audrey")
	e.s.logEvent(0, "=cmd|' /C calc'!A0", "=evil", "+target", "@detail")
	for i := 0; i < 130; i++ {
		e.s.logEvent(0, "tester", "bulk_event", fmt.Sprintf("t%d", i), "")
	}
	r := e.do("GET", "/api/audit", auditor, nil)
	e.want(r, 200, "list")
	if len(r.J()["records"].([]any)) != 50 || r.J()["total"].(float64) < 131 {
		t.Fatal(string(r.Body))
	}
	if n := len(e.do("GET", "/api/audit?limit=1000", auditor, nil).J()["records"].([]any)); n != 100 {
		t.Fatalf("limit cap %d", n)
	}
	e.want(e.do("GET", "/api/audit?limit=0", auditor, nil), 400, "limit 0")
	e.want(e.do("GET", "/api/audit?category=bogus", auditor, nil), 400, "bad category")
	e.want(e.do("GET", "/api/audit?outcome=bogus", auditor, nil), 400, "bad outcome")
	e.want(e.do("GET", "/api/audit?from=yesterday", auditor, nil), 400, "bad from")
	if r := e.do("GET", "/api/audit?action=bulk_event&actor=TESTER&q=t129", auditor, nil); r.J()["total"].(float64) != 1 {
		t.Fatalf("filters: %s", r.Body)
	}
	// Words are separated by spaces, underscores, dashes and * wildcards, and each may
	// occur anywhere: "bulk*event", "event bulk" and "bulk_event" find the same records.
	base := e.do("GET", "/api/audit?q=bulk_event", auditor, nil).J()["total"].(float64)
	if base == 0 {
		t.Fatal("word search finds nothing")
	}
	for _, q := range []string{"bulk*event", "event+bulk", "BULK-EVENT", "bulk"} {
		if got := e.do("GET", "/api/audit?q="+q, auditor, nil).J()["total"].(float64); got != base {
			t.Fatalf("search %q: %v results, want %v", q, got, base)
		}
	}
	if got := e.do("GET", "/api/audit?q=create", auditor, nil).J()["total"].(float64); got == 0 {
		t.Fatal("partial word must match")
	}
	future := time.Now().UTC().AddDate(0, 0, 2).Format("2006-01-02")
	if r := e.do("GET", "/api/audit?from="+future, auditor, nil); r.J()["total"].(float64) != 0 {
		t.Fatal("from filter")
	}
	today := time.Now().UTC().Format("2006-01-02")
	if r := e.do("GET", "/api/audit?action=bulk_event&to="+today, auditor, nil); r.J()["total"].(float64) != 130 {
		t.Fatalf("to filter includes the whole day: %s", r.Body)
	}

	// Viewing is audited at most once per 5 minutes; exporting every time.
	if n := len(auditRowsWhere(e, "action='audit_viewed'")); n != 1 {
		t.Fatalf("audit_viewed %d", n)
	}
	csvResp := e.do("GET", "/api/audit/export", auditor, nil)
	e.want(csvResp, 200, "csv")
	if !strings.HasPrefix(csvResp.Hdr.Get("Content-Type"), "text/csv") {
		t.Fatal(csvResp.Hdr)
	}
	records, err := csv.NewReader(strings.NewReader(string(csvResp.Body))).ReadAll()
	if err != nil || strings.Join(records[0], ",") != "seq,time_utc,category,actor_id,user,role,action,target,outcome,details,ip,prev_hash,hash" {
		t.Fatal(records[0], err)
	}
	seenEvil := false
	for _, rec := range records[1:] {
		if rec[4] == "'=cmd|' /C calc'!A0" && rec[6] == "'=evil" && rec[7] == "'+target" && rec[9] == "'@detail" {
			seenEvil = true
		}
		for _, i := range []int{4, 6, 7, 9} {
			if rec[i] != "" && strings.ContainsRune("=+-@", rune(rec[i][0])) {
				t.Fatal("formula cell not neutralised", rec[i])
			}
		}
	}
	if !seenEvil {
		t.Fatal("csv injection row missing")
	}
	jl := e.do("GET", "/api/audit/export?format=jsonl", auditor, nil)
	e.want(jl, 200, "jsonl")
	lines := strings.Split(strings.TrimSpace(string(jl.Body)), "\n")
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"seq", "ts", "category", "actor_name", "action", "outcome", "prev_hash", "hash"} {
		if _, ok := first[k]; !ok {
			t.Fatalf("jsonl lacks %s: %v", k, first)
		}
	}
	e.want(e.do("GET", "/api/audit/export?format=xml", auditor, nil), 400, "bad format")
	// Every export request is recorded before it is served (attempted); the two that
	// were served also have an ok record, and the refused one a failed record.
	count := func(outcome string) int {
		return len(auditRowsWhere(e, "action='audit_exported' AND outcome=?", outcome))
	}
	if count("attempted") != 3 || count("ok") != 2 || count("failed") != 1 {
		t.Fatalf("audit_exported records: attempted=%d ok=%d failed=%d", count("attempted"), count("ok"), count("failed"))
	}
	if n := len(auditRowsWhere(e, "action='audit_viewed'")); n != 1 {
		t.Fatalf("audit_viewed after exports %d", n)
	}
	// After the window the next view is recorded again.
	e.s.audit.viewMu.Lock()
	for id := range e.s.audit.viewed {
		e.s.audit.viewed[id] = time.Now().Add(-6 * time.Minute)
	}
	e.s.audit.viewMu.Unlock()
	e.want(e.do("GET", "/api/audit", auditor, nil), 200, "list again")
	if n := len(auditRowsWhere(e, "action='audit_viewed'")); n != 2 {
		t.Fatalf("audit_viewed after window %d", n)
	}
	// Status.
	st := e.do("GET", "/api/audit/status", auditor, nil)
	e.want(st, 200, "status")
	j := st.J()
	if j["verified"] != true || j["count"].(float64) < 130 || j["retention_days"].(float64) != 90 || j["write_failures"].(float64) != 0 {
		t.Fatal(string(st.Body))
	}
}

func TestAuditTamperDetectedByAPIStatus(t *testing.T) {
	cases := map[string]string{
		"edited row":   `UPDATE audit_log SET detail='changed' WHERE seq=6`,
		"deleted row":  `DELETE FROM audit_log WHERE seq=6`,
		"inserted row": `INSERT INTO audit_log(seq,ts,category,actor_name,action,prev_hash,hash) SELECT 1000,ts,category,'evil','forged',hash,'00' FROM audit_log WHERE seq=6`,
		"swapped rows": `UPDATE audit_log SET action=CASE seq WHEN 6 THEN (SELECT action FROM audit_log WHERE seq=7) ELSE (SELECT action FROM audit_log WHERE seq=6) END, target=CASE seq WHEN 6 THEN 'x' ELSE 'y' END WHERE seq IN (6,7)`,
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			admin := e.setup()
			auditor := e.mkAuditor(admin, "audrey")
			for i := 0; i < 10; i++ {
				e.s.logEvent(0, "tester", "bulk_event", fmt.Sprint(i), "")
			}
			if r := e.do("GET", "/api/audit/status", auditor, nil); r.J()["verified"] != true {
				t.Fatal(string(r.Body))
			}
			if _, err := e.s.St.DB.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			r := e.do("GET", "/api/audit/status", auditor, nil)
			j := r.J()
			if j["verified"] != false || j["first_broken_seq"] == nil || j["first_broken_seq"].(float64) < 1 {
				t.Fatalf("tamper not detected: %s", r.Body)
			}
			// The administrator sees the status too, without details.
			a := e.do("GET", "/api/logs/status", admin, nil)
			e.want(a, 200, "admin status")
			if a.J()["verified"] != false || a.J()["first_broken_seq"] != nil || a.J()["count"] != nil {
				t.Fatalf("admin status: %s", a.Body)
			}
		})
	}
}

func TestAuditRetentionPurgeKeepsChainAndUpdatesCheckpoint(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	old := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(store.AuditTimeLayout)
	for i := 0; i < 4; i++ {
		if _, err := e.s.St.AuditAppend(store.AuditRecord{TS: old, Category: "admin", Action: "ancient", Outcome: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	// The default (and minimum) retention of 90 days removes the 100-day-old records.
	before := len(auditRowsWhere(e, "1=1"))
	e.s.purgeAudit()
	if n := len(auditRowsWhere(e, "action='ancient'")); n != 0 {
		t.Fatal("old records survive the purge")
	}
	st := chainStatus(e)
	if !st.OK || st.CheckpointSeq < 4 || st.CheckpointHash == "" || int(st.Count) != before-int(st.CheckpointSeq)+1 {
		t.Fatalf("%+v before=%d", st, before)
	}
	if !hasAction(auditActions(e, "1=1"), "audit_purged") {
		t.Fatal("the purge itself must be recorded")
	}
	// Changing it (back to the minimum is allowed) is audited with old and new value.
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_retention_days": 120}), 200, "retention 120")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_retention_days": 90}), 200, "retention 90")
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_retention_days": 30}), 400, "below the minimum")
	rows := auditRowsWhere(e, "action='audit_retention_changed'")
	if len(rows) != 2 || !strings.Contains(rows[1].Detail, "'120' -> '90'") || !strings.Contains(rows[0].Detail, "'90' -> '120'") {
		t.Fatalf("%+v", rows)
	}
	e.s.purgeAudit()
	if st := chainStatus(e); !st.OK {
		t.Fatalf("%+v", st)
	}
}

func TestAuditConcurrentWritersKeepValidChain(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				e.s.logEvent(0, fmt.Sprint("w", g), "bulk_event", fmt.Sprint(i), "")
				if i%5 == 0 {
					e.do("POST", "/api/shares/prune-expired", bob, nil)
				}
			}
		}(g)
	}
	wg.Wait()
	if st := chainStatus(e); !st.OK || st.Count < 120 {
		t.Fatalf("%+v", st)
	}
	if e.s.audit.fails.Load() != 0 {
		t.Fatalf("write failures: %d", e.s.audit.fails.Load())
	}
}

func TestAuditSettingsDefaultsAndValidation(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	s := e.do("GET", "/api/settings", admin, nil)
	e.want(s, 200, "settings")
	if s.S("audit_retention_days") != "90" || s.S("audit_log_ip") != "false" {
		t.Fatal(string(s.Body))
	}
	if _, ok := s.J()["logging_enabled"]; ok {
		t.Fatal("retired logging switch still listed")
	}
	for _, bad := range []any{0, 1, 30, 89, "89", 366, -1, 1.5, 90.5, "x", "", nil, true, []int{1}} {
		r := e.do("PUT", "/api/settings", admin, map[string]any{"application_name": "ShouldRollBack", "audit_retention_days": bad})
		e.want(r, 400, fmt.Sprintf("retention %v", bad))
		if num, ok := bad.(int); ok && num != 366 && num >= 0 && !strings.Contains(r.S("error"), "from 90 to 365") {
			t.Fatalf("message must name the range 90 to 365: %s", r.Body)
		}
		if e.s.St.Setting("application_name") == "ShouldRollBack" {
			t.Fatalf("batch not atomic for %v", bad)
		}
	}
	for _, bad := range []any{"yes", 1, "", nil} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_log_ip": bad}), 400, fmt.Sprintf("ip flag %v", bad))
	}
	for _, good := range []any{90, 365, "120"} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_retention_days": good}), 200, fmt.Sprintf("retention %v", good))
	}
	// The retired switches are accepted silently and never touch the log.
	n := len(auditRowsWhere(e, "1=1"))
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"logging_enabled": false, "log_retention_hours": 1}), 200, "retired settings")
	if len(auditRowsWhere(e, "1=1")) < n {
		t.Fatal("log shrank")
	}
	e.s.St.SetSetting("audit_retention_days", "garbage")
	if e.s.auditRetentionDays() != 90 {
		t.Fatal("an invalid stored value must fall back to the default, not shorten the log")
	}
	// Only administrators change it.
	user := e.mkUser(admin, "plain", false)
	e.want(e.do("PUT", "/api/settings", user, map[string]any{"audit_retention_days": 1}), 403, "user")
}

func TestAuditIPStoredOnlyWhenEnabled(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "ivy", false)
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "ivy", "password": "WrongPassword9"}), 401, "bad")
	for _, r := range auditRowsWhere(e, "1=1") {
		if r.IP != "" {
			t.Fatalf("ip stored while disabled: %+v", r)
		}
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"audit_log_ip": true}), 200, "enable")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "ivy", "password": "WrongPassword9"}), 401, "bad again")
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "jo", "password": "password123", "email": "jo@x.io"}), 201, "create")
	rows := auditRowsWhere(e, "seq>(SELECT MAX(seq) FROM audit_log WHERE action='audit_ip_logging_changed') AND ip<>''")
	if len(rows) == 0 {
		t.Fatal("no ip stored while enabled")
	}
	for _, r := range rows {
		if r.IP != "127.0.0.1" && r.IP != "::1" {
			t.Fatalf("unexpected ip %q", r.IP)
		}
	}
	// Events from background work have no request and so no address.
	e.s.logEvent(0, "system", "shares_expired", "", "1 shares")
	if r := auditRowsWhere(e, "action='shares_expired'"); len(r) != 1 || r[0].IP != "" || r[0].Role != "system" {
		t.Fatalf("%+v", r)
	}
}

func TestAuditorIsReadOnlyAndNeverAdmin(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	auditor := e.mkAuditor(admin, "audrey")
	user := e.mkUser(admin, "bob", false)
	me := e.do("GET", "/api/users/me", auditor, nil)
	e.want(me, 200, "me")
	if me.J()["user"].(map[string]any)["auditor"] != true {
		t.Fatalf("%s", me.Body)
	}
	// Own profile and password are allowed.
	e.want(e.do("PUT", "/api/users/me", auditor, map[string]any{"name": "Audrey", "email": "audrey@x.io", "current_password": "password123", "password": "NewPassword123"}), 200, "own profile")
	login := e.do("POST", "/api/auth/login", "", map[string]any{"username": "audrey", "password": "NewPassword123"})
	e.want(login, 200, "login with the new password")
	auditor = login.S("access_token")

	// Table-driven over every authenticated route: nothing outside the allowlist works.
	allowed := map[string]bool{"GET /api/users/me": true, "PUT /api/users/me": true, "GET /api/audit": true, "GET /api/audit/export": true, "GET /api/audit/status": true,
		"GET /api/access-review": true, "GET /api/access-review/export": true,
		"GET /api/users/me/sessions": true, "POST /api/users/me/sessions/revoke-others": true, "DELETE /api/users/me/sessions/{id}": true,
		// Personal data and terms are the auditor's own (gdpr.go, terms.go).
		"GET /api/users/me/export": true, "POST /api/users/me/erase": true, "POST /api/users/me/terms": true}
	public := func(p string) bool {
		return !strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/api/auth/") || strings.HasPrefix(p, "/api/shares/{id}") && !strings.HasPrefix(p, "/api/shares/{id}/") ||
			strings.HasPrefix(p, "/api/shares/{id}/unlock") || strings.HasPrefix(p, "/api/shares/{id}/download") || strings.HasPrefix(p, "/api/shares/{id}/preview") ||
			p == "/api/health" || p == "/api/health/ready" || p == "/api/metrics" || p == "/api/bootstrap" || p == "/api/capabilities" || p == "/api/setup" || strings.HasPrefix(p, "/api/i18n") || p == "/api/themes/active" ||
			strings.HasPrefix(p, "/api/backgrounds") && !strings.HasPrefix(p, "/api/backgrounds") || strings.HasPrefix(p, "/api/branding") || p == "/api/reverse-shares/accept"
	}
	checked := 0
	h := e.s.Router().(chi.Routes)
	err := chi.Walk(h, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		// The caller's own second factors are self-service for auditors too.
		if allowed[key] || public(route) || route == "/*" || mfaSelfServicePath(route) {
			return nil
		}
		// GET/POST on /api/backgrounds is public for GET only.
		if method == "GET" && (route == "/api/backgrounds" || route == "/api/backgrounds/{file}") {
			return nil
		}
		path := strings.NewReplacer("{id}", "1", "{fileId}", "1", "{idx}", "0", "{name}", "x.db", "{file}", "x.png", "{kind}", "logo", "{code}", "en", "{uuid}", "x").Replace(route)
		r := e.do(method, path, auditor, nil)
		if r.Code != 403 {
			t.Errorf("auditor reached %s: %d %s", key, r.Code, r.Body)
		}
		checked++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 60 {
		t.Fatalf("only %d routes checked", checked)
	}
	e.want(e.do("POST", "/api/uploads", auditor, map[string]any{"files": []map[string]any{{"name": "a", "full_path": "a", "size": 1}}}), 403, "upload")

	// Never both: create and update.
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "both", "password": "password123", "email": "b@x.io", "admin": true, "auditor": true}), 400, "create both")
	var uid int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='bob'`).Scan(&uid)
	put := func(body map[string]any) resp {
		body["name"], body["email"] = "Bob", "bob@x.io"
		return e.do("PUT", fmt.Sprintf("/api/users/%d", uid), admin, body)
	}
	e.want(put(map[string]any{"admin": true, "auditor": true}), 400, "update both")
	e.want(put(map[string]any{"admin": false, "auditor": true}), 200, "grant auditor")
	e.want(put(map[string]any{"admin": true}), 400, "make an auditor admin without removing the role")
	e.want(put(map[string]any{"admin": true, "auditor": false}), 200, "swap auditor for admin")
	e.want(e.do("GET", "/api/audit", user, nil), 200, "the former auditor is now an administrator, who reads the same log")
	// Auditors are not administrators: admin routes stay closed.
	e.want(e.do("GET", "/api/users", auditor, nil), 403, "auditor user list")
	if r := auditRowsWhere(e, "action='user_role_changed'"); len(r) != 2 {
		t.Fatalf("role changes audited: %+v", r)
	}
}

func TestAuditAccessDeniedAndGenericMutation(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	bob := e.mkUser(admin, "bob", false)
	eve := e.mkUser(admin, "eve", false)
	sh := e.share(bob, map[string]string{"a.txt": "abc"}, nil)
	e.want(sh, 201, "share")
	id := fmt.Sprint(int64(sh.J()["id"].(float64)))
	e.want(e.do("POST", "/api/shares/"+id+"/extend", eve, map[string]any{"days": 1}), 404, "other's share")
	e.want(e.do("POST", "/api/shares/99999/extend", eve, map[string]any{"days": 1}), 404, "missing share")
	rows := auditRowsWhere(e, "action='access_denied' AND category='share'")
	if len(rows) != 1 || rows[0].ActorNm != "eve" || rows[0].Outcome != "denied" || rows[0].Target != "share#"+id {
		t.Fatalf("%+v", rows)
	}
	// 403 on an authenticated route.
	e.want(e.do("GET", "/api/users", eve, nil), 403, "non-admin")
	if rows := auditRowsWhere(e, "action='access_denied' AND category='security'"); len(rows) != 1 || rows[0].ActorNm != "eve" {
		t.Fatalf("%+v", rows)
	}
	// A token that does not verify names nobody: not recorded (no flood from the internet).
	e.want(e.do("GET", "/api/users", "garbage", nil), 401, "bad token")
	if rows := auditRowsWhere(e, "action='access_denied' AND category='security'"); len(rows) != 1 {
		t.Fatalf("%+v", rows)
	}
	// Anonymous 401 without credentials is not noise.
	e.want(e.do("GET", "/api/users", "", nil), 401, "anonymous")
	if rows := auditRowsWhere(e, "action='access_denied' AND category='security'"); len(rows) != 1 {
		t.Fatalf("anonymous probe logged: %+v", rows)
	}
	// Generic entry for a mutating request the handler did not record itself.
	e.want(e.do("POST", "/api/shares/prune-expired", bob, nil), 200, "prune")
	rows = auditRowsWhere(e, "action='POST /api/shares/prune-expired'")
	if len(rows) != 1 || rows[0].Outcome != "ok" || rows[0].Category != "share" || rows[0].Role != "user" || rows[0].ActorNm != "bob" {
		t.Fatalf("%+v", rows)
	}
	e.want(e.do("PUT", "/api/shares/"+id+"/expiry", bob, map[string]any{"expires_at": "garbage"}), 400, "bad expiry")
	rows = auditRowsWhere(e, "action='PUT /api/shares/{id}/expiry'")
	if len(rows) != 1 || rows[0].Outcome != "failed" || strings.Contains(rows[0].Detail+rows[0].Target+rows[0].Action, sh.S("long_id")) {
		t.Fatalf("%+v", rows)
	}
	// Public mutation by an anonymous caller.
	e.want(e.do("POST", "/api/auth/forgot-password", "", map[string]any{"email": "nobody@x.io"}), 200, "forgot")
	if rows := auditRowsWhere(e, "action='POST /api/auth/forgot-password'"); len(rows) != 1 || rows[0].Role != "anonymous" {
		t.Fatalf("%+v", rows)
	}
	// Handled requests are not double-recorded; exempt routes are skipped.
	n := len(auditRowsWhere(e, "action LIKE 'POST /api/auth/login%'"))
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "bob", "password": "password123"}), 200, "login")
	if len(auditRowsWhere(e, "action LIKE 'POST /api/auth/login%'")) != n {
		t.Fatal("login recorded twice")
	}
	e.do("POST", "/api/auth/refresh", "", nil)
	if len(auditRowsWhere(e, "action='POST /api/auth/refresh'")) != 0 {
		t.Fatal("exempt route recorded")
	}
}

func TestAuditLockoutAndPasswordNeverLogged(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.mkUser(admin, "carol", false)
	for i := 0; i < 5; i++ {
		e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "carol", "password": "badbadbad1"}), 401, "bad")
	}
	if n := len(auditRowsWhere(e, "action='login_lockout'")); n != 1 {
		t.Fatalf("want one lockout, got %d", n)
	}
	r := auditRowsWhere(e, "action='login_lockout'")[0]
	if r.Outcome != "denied" || r.Category != "auth" {
		t.Fatalf("%+v", r)
	}
	if rows := auditRowsWhere(e, "detail LIKE '%badbadbad1%' OR target LIKE '%badbadbad1%'"); len(rows) != 0 {
		t.Fatal("password logged")
	}
}

func TestAuditStartupFingerprintAndOldEnvIgnored(t *testing.T) {
	t.Setenv("SENDORA_LOGGING_ENABLED", "false")
	t.Setenv("SENDORA_LOG_RETENTION_HOURS", "1")
	e := newEnv(t)
	e.setup()
	e.s.auditStartup()
	rows := auditRowsWhere(e, "action='system_start'")
	if len(rows) != 1 || rows[0].Category != "system" || !strings.Contains(rows[0].Detail, "version=test") || !strings.Contains(rows[0].Detail, "key=none") {
		t.Fatalf("%+v", rows)
	}
	if len(auditRowsWhere(e, "action='key_fingerprint_changed'")) != 0 {
		t.Fatal("first start must not report a change")
	}
	e.s.St.DB.Exec(`UPDATE settings SET value='0123456789abcdef' WHERE key='audit_key_fingerprint'`)
	e.s.auditStartup()
	if rows := auditRowsWhere(e, "action='key_fingerprint_changed'"); len(rows) != 1 || rows[0].Category != "security" {
		t.Fatalf("%+v", rows)
	}
	// The fingerprint is stored hidden from the settings screen.
	if _, ok := e.do("GET", "/api/settings", e.setupTokenAgain(), nil).J()["audit_key_fingerprint"]; ok {
		t.Fatal("fingerprint exposed in settings")
	}
	e.s.auditShutdown()
	if len(auditRowsWhere(e, "action='system_stop'")) != 1 {
		t.Fatal("system_stop missing")
	}
}

func (e *env) setupTokenAgain() string {
	r := e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"})
	return r.S("access_token")
}

// TestAuditCoversEveryMutatingRoute walks the router: every mutating route must
// be wrapped by the audit middleware, or be listed in auditExempt with a reason,
// and the exemption list must not contain stale entries.
func TestAuditCoversEveryMutatingRoute(t *testing.T) {
	e := newEnv(t)
	seenExempt := map[string]bool{}
	mutating := 0
	var uncovered []string
	err := chi.Walk(e.s.Router().(chi.Routes), func(method, route string, _ http.Handler, mws ...func(http.Handler) http.Handler) error {
		if !isMutating(method) {
			return nil
		}
		mutating++
		key := method + " " + route
		if reason, ok := auditExempt[key]; ok {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("exemption for %s has no reason", key)
			}
			seenExempt[key] = true
			return nil
		}
		for _, mw := range mws {
			if runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name() == runtime.FuncForPC(reflect.ValueOf(e.s.auditMiddleware).Pointer()).Name() {
				return nil
			}
		}
		uncovered = append(uncovered, key)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if mutating < 50 {
		t.Fatalf("walk found only %d mutating routes", mutating)
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		t.Fatalf("mutating routes not covered by the audit middleware and not exempt: %v", uncovered)
	}
	for key := range auditExempt {
		if !seenExempt[key] {
			t.Errorf("stale exemption %q: no such route", key)
		}
	}
}

// TestAuditCriticalRoutesAreGuarded checks that each critical admin route is
// wrapped by the attempt-before-action middleware.
func TestAuditCriticalRoutesAreGuarded(t *testing.T) {
	e := newEnv(t)
	want := map[string]bool{
		"POST /api/users": false, "PUT /api/users/{id}": false, "DELETE /api/users/{id}": false, "POST /api/users/{id}/erase": false,
		"POST /api/users/{id}/force-reset-password": false, "POST /api/users/{id}/mfa/reset": false, "PUT /api/settings": false,
		"POST /api/auth-providers": false, "PUT /api/auth-providers/{id}": false, "DELETE /api/auth-providers/{id}": false,
		"POST /api/backups": false, "GET /api/backups/{name}": false, "DELETE /api/backups/{name}": false, "POST /api/backups/import": false, "POST /api/backups/import/apply": false,
		"POST /api/users/{id}/disable": false, "POST /api/users/{id}/enable": false, "POST /api/users/{id}/sessions/revoke": false,
		"GET /api/access-review/export": false,
	}
	critName := runtime.FuncForPC(reflect.ValueOf(e.s.critical("x", "y")).Pointer()).Name()
	_ = critName
	chi.Walk(e.s.Router().(chi.Routes), func(method, route string, _ http.Handler, mws ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		if _, ok := want[key]; !ok {
			return nil
		}
		// The critical middleware is the closure created inside critical().
		for _, mw := range mws {
			if strings.Contains(runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name(), ".critical.") {
				want[key] = true
			}
		}
		return nil
	})
	for k, ok := range want {
		if !ok {
			t.Errorf("critical route %s is not guarded", k)
		}
	}
}

// Whoever downloads the audit log is recorded: who, when, format, how many records
// and which filters. The record is written before the export is served, and an
// export is refused when it cannot be recorded.
func TestAuditExportsAreRecordedBeforeServing(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	auditor := e.mkAuditor(admin, "audrey")

	e.want(e.do("GET", "/api/logs/export?q=login&category=auth", admin, nil), 200, "admin CSV export")
	e.want(e.do("GET", "/api/audit/export?format=jsonl&from=2020-01-01", auditor, nil), 200, "auditor JSONL export")
	e.want(e.do("GET", "/api/audit/export?format=csv", admin, nil), 200, "admin CSV export through the audit endpoint")

	rows := auditRowsWhere(e, "action='audit_exported'")
	byRole := map[string]int{}
	var okDetails []string
	for _, r := range rows {
		byRole[r.Role+"/"+r.Outcome]++
		if r.Target != "audit_log" {
			t.Fatalf("unexpected target %q", r.Target)
		}
		if r.Outcome == "ok" {
			okDetails = append(okDetails, r.Detail)
		}
	}
	if byRole["admin/attempted"] != 2 || byRole["admin/ok"] != 2 || byRole["auditor/attempted"] != 1 || byRole["auditor/ok"] != 1 {
		t.Fatalf("every export needs an attempted and an ok record, got %v", byRole)
	}
	joined := strings.Join(okDetails, " | ")
	for _, want := range []string{"csv", "jsonl", "records", "q=login", "category=auth", "from=2020-01-01"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("export details miss %q: %s", want, joined)
		}
	}

	// Without a record there is no export.
	fail := func() error { return errors.New("forced audit failure") }
	e.s.audit.hook.Store(&fail)
	for _, c := range []struct{ who, path string }{
		{admin, "/api/logs/export"}, {admin, "/api/audit/export?format=jsonl"}, {auditor, "/api/audit/export"},
	} {
		r := e.do("GET", c.path, c.who, nil)
		if r.Code != 503 || strings.Contains(string(r.Body), "sendora-audit") || strings.Contains(string(r.Body), "prev_hash") {
			t.Fatalf("%s served without being recorded: %d %.80s", c.path, r.Code, r.Body)
		}
	}
	e.s.audit.hook.Store(nil)
}
