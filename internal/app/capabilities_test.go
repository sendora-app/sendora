// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"testing"

	"github.com/sendora-app/sendora/internal/capabilities"
)

type capsResponse struct {
	Flavour  string                         `json:"flavour"`
	Version  string                         `json:"version"`
	Features map[string]capabilities.Status `json:"features"`
}

func getCapabilities(t *testing.T, e *env) capsResponse {
	t.Helper()
	r := e.do("GET", "/api/capabilities", "", nil)
	e.want(r, 200, "capabilities without a session")
	var c capsResponse
	if err := json.Unmarshal(r.Body, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Features) != len(capabilities.Features) {
		t.Fatalf("got %d features, want %d", len(c.Features), len(capabilities.Features))
	}
	return c
}

func TestCapabilitiesSingleTenant(t *testing.T) {
	c := getCapabilities(t, newEnv(t))
	if c.Flavour != "single" || c.Version != "test" {
		t.Fatalf("flavour %q version %q", c.Flavour, c.Version)
	}
	if !c.Features["multi_tenant_conversion"].Available || !c.Features["database_import"].Available {
		t.Fatalf("single-tenant features missing: %+v", c.Features)
	}
	if st := c.Features["platform_console"]; st.Available || st.Reason == "" {
		t.Fatalf("platform_console in single-tenant: %+v", st)
	}
}

func TestCapabilitiesTenantOfMultiTenantHost(t *testing.T) {
	m := newMTEnv(t)
	e, _ := m.newTenant("acme")
	c := getCapabilities(t, e)
	if c.Flavour != "multi" {
		t.Fatalf("flavour %q", c.Flavour)
	}
	if !c.Features["platform_console"].Available {
		t.Fatalf("platform_console: %+v", c.Features["platform_console"])
	}
	// The conversion and the in-app import are refused for tenants
	// (mtConvStatus, prepareImport); the capabilities must say so.
	for _, id := range []string{"multi_tenant_conversion", "database_import"} {
		if st := c.Features[id]; st.Available || st.Reason == "" {
			t.Fatalf("%s for a tenant: %+v", id, st)
		}
	}
}
