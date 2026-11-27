// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type keyListing struct {
	Tenants []keyRow `json:"tenants"`
	Running int      `json:"running"`
}

func listKeyRows(t *testing.T, c *env, cookie string) keyListing {
	t.Helper()
	r := c.do("GET", "/api/platform/keys", "", nil, "Cookie", cookie)
	c.want(r, 200, "key listing")
	var l keyListing
	if err := json.Unmarshal(r.Body, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestMTOperatorForcedKeyRotation(t *testing.T) {
	t.Setenv("SENDORA_KEY_OPS_PER_HOUR", "3")
	m := newMTEnv(t)
	c, cookie, secret := m.consoleLogin()
	for _, slug := range []string{"alfa", "beta", "gamma"} {
		m.newTenant(slug)
	}
	// gamma holds its own key and is not unlocked on any controller (no
	// cluster here): bulk skips it, a single request answers "locked".
	gamma, _ := m.p.TenantBySlug("gamma")
	if err := m.p.SetKEK(gamma.ID, "tenant", "abcdef0123456789"); err != nil {
		t.Fatal(err)
	}
	alfa, _ := m.p.TenantBySlug("alfa")
	beta, _ := m.p.TenantBySlug("beta")

	// Not signed in: refused; the key listing has no key material.
	c.want(c.do("GET", "/api/platform/keys", "", nil), 401, "listing without a session")
	c.want(c.do("POST", "/api/platform/keys/rotate-all", "", map[string]any{"purposes": []string{"data"}}), 401, "bulk without a session")
	l := listKeyRows(t, c, cookie)
	if len(l.Tenants) != 3 {
		t.Fatalf("listing: %+v", l)
	}
	for _, row := range l.Tenants {
		if row.Slug == "alfa" && (row.State != keyStateOK || row.Active["data"] != 1 || row.KEKMode != "platform") {
			t.Fatalf("alfa row: %+v", row)
		}
	}
	// Validation and step-up come before anything is queued.
	c.want(c.do("POST", "/api/platform/keys/rotate-all", "", map[string]any{"purposes": []string{"audit-mac"}, "reason": "incident", "code": m.nextCode(secret)}, "Cookie", cookie), 400, "unknown purpose")
	c.want(c.do("POST", "/api/platform/keys/rotate-all", "", map[string]any{"purposes": []string{"data"}, "reason": "", "code": m.nextCode(secret)}, "Cookie", cookie), 400, "no reason")
	c.want(c.do("POST", "/api/platform/keys/rotate-all", "", map[string]any{"purposes": []string{"data"}, "reason": "incident", "code": "000000"}, "Cookie", cookie), 403, "no step-up")
	if strings.Contains(platformAuditText(t, c, cookie), "key") {
		t.Fatal("a refused request left platform audit records")
	}

	// One tenant, two purposes.
	r := c.do("POST", "/api/platform/tenants/"+alfa.ID+"/keys/rotate", "", map[string]any{"purposes": []string{"data", "files"}, "reason": "incident 42", "code": m.nextCode(secret)}, "Cookie", cookie)
	c.want(r, 202, "single rotation")
	if r.S("result") != "queued" {
		t.Fatalf("single: %s", r.Body)
	}
	waitKeyJobs(t, m, "alfa")
	srv := m.server("alfa")
	ov, err := srv.KeyOverview(t.Context())
	if err != nil || ov.Active["data"] != 2 || ov.Active["files"] != 2 || ov.Active["index"] != 1 || ov.Behind != 2 || ov.LastRotation.IsZero() || ov.LastFinished.IsZero() {
		t.Fatalf("overview after rotation: %+v %v", ov, err)
	}

	// Bulk: platform-managed tenants are queued, the tenant-managed one is skipped and reported.
	r = c.do("POST", "/api/platform/keys/rotate-all", "", map[string]any{"purposes": []string{"secrets"}, "reason": "routine", "code": m.nextCode(secret)}, "Cookie", cookie)
	c.want(r, 202, "bulk rotation")
	var bulk struct {
		Results []map[string]any `json:"results"`
		Counts  map[string]int   `json:"counts"`
	}
	json.Unmarshal(r.Body, &bulk)
	if bulk.Counts["queued"] != 2 || bulk.Counts["tenant_managed"] != 1 {
		t.Fatalf("bulk counts: %s", r.Body)
	}
	waitKeyJobs(t, m, "alfa")
	waitKeyJobs(t, m, "beta")
	if ov, _ := m.server("beta").KeyOverview(t.Context()); ov.Active["secrets"] != 2 || ov.Active["data"] != 1 {
		t.Fatalf("beta overview: %+v", ov)
	}
	// Asked for singly, a tenant-managed tenant is only refused ("locked") when
	// a cluster reports its key as not unlocked on every controller; this
	// single-process environment has no controllers, so the request is
	// accepted. The locked path runs in the kind end-to-end test.
	c.want(c.do("POST", "/api/platform/tenants/"+gamma.ID+"/keys/rotate", "", map[string]any{"purposes": []string{"data"}, "reason": "incident 42", "code": m.nextCode(secret)}, "Cookie", cookie), 202, "tenant-managed tenant, no cluster")
	// The budget (3 per hour) counted every accepted request: single, bulk, tenant-managed; now exhausted.
	c.want(c.do("POST", "/api/platform/tenants/"+beta.ID+"/keys/rotate", "", map[string]any{"purposes": []string{"data"}, "reason": "again", "code": m.nextCode(secret)}, "Cookie", cookie), 429, "budget")

	// Both sides recorded it; the listing shows the last operation.
	body := platformAuditText(t, c, cookie)
	for _, a := range []string{"tenant_keys_rotation_requested", "keys_rotation_requested_all"} {
		if !strings.Contains(body, a) {
			t.Fatalf("platform audit lacks %s", a)
		}
	}
	for _, row := range listKeyRows(t, c, cookie).Tenants {
		switch row.Slug {
		case "alfa":
			if row.LastFinished == "" || row.Behind == 0 || row.LastRotation == "" {
				t.Fatalf("alfa row: %+v", row)
			}
		}
	}
}

func platformAuditText(t *testing.T, c *env, cookie string) string {
	t.Helper()
	r := c.do("GET", "/api/platform/audit", "", nil, "Cookie", cookie)
	c.want(r, 200, "platform audit")
	return string(r.Body)
}

// waitKeyJobs runs the tenant's key jobs on this (single) process until none is open.
func waitKeyJobs(t *testing.T, m *mtEnv, slug string) {
	t.Helper()
	srv := m.server(slug)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		srv.RunKeyJobs(t.Context())
		ov, err := srv.KeyOverview(t.Context())
		if err == nil && len(ov.Running) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: key jobs did not finish", slug)
}

func TestMTMasterKeyConsole(t *testing.T) {
	t.Setenv("SENDORA_KEY_OPS_PER_HOUR", "20")
	m := newMTEnv(t)
	c, cookie, secret := m.consoleLogin()
	m.newTenant("alfa")
	c.want(c.do("GET", "/api/platform/master", "", nil), 401, "status without a session")
	r := c.do("GET", "/api/platform/master", "", nil, "Cookie", cookie)
	c.want(r, 200, "status")
	if r.J()["active"] != float64(1) || r.J()["in_progress"] != false || r.J()["tenants"].(map[string]any)["1"] != float64(1) {
		t.Fatalf("status: %s", r.Body)
	}
	body := func(v int, reason string) map[string]any {
		return map[string]any{"version": v, "reason": reason, "code": m.nextCode(secret)}
	}
	c.want(c.do("POST", "/api/platform/master/rotate", "", map[string]any{"version": 2, "reason": "routine", "code": "000000"}, "Cookie", cookie), 403, "no step-up")
	c.want(c.do("POST", "/api/platform/master/rotate", "", body(2, ""), "Cookie", cookie), 400, "no reason")
	c.want(c.do("POST", "/api/platform/master/rotate", "", body(3, "routine"), "Cookie", cookie), 409, "skipping a version")
	c.want(c.do("POST", "/api/platform/master/rotate", "", body(2, "routine"), "Cookie", cookie), 202, "start")
	c.want(c.do("POST", "/api/platform/master/rotate", "", body(2, "routine"), "Cookie", cookie), 409, "second start")
	if st := m.p.MasterState(); st.Target != 2 {
		t.Fatalf("state: %+v", st)
	}
	c.want(c.do("POST", "/api/platform/master/retire", "", body(1, "cleanup"), "Cookie", cookie), 409, "retire during a rotation / the infrastructure version")
	text := platformAuditText(t, c, cookie)
	for _, a := range []string{"master_rotation_requested", "master_version_retired"} {
		if !strings.Contains(text, a) {
			t.Fatalf("platform audit lacks %s", a)
		}
	}
	// Non-admin sessions never reach it.
	_, tok := m.newTenant("beta")
	c.want(c.do("POST", "/api/platform/master/rotate", tok, body(2, "x")), 401, "tenant token")
}
