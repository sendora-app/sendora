// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func capsOf(t *testing.T, s *Server) (string, map[string]struct{ Available bool }) {
	t.Helper()
	w := httptest.NewRecorder()
	s.capabilitiesHandler(w, httptest.NewRequest("GET", "/api/capabilities", nil))
	var out struct {
		Flavour  string                              `json:"flavour"`
		Features map[string]struct{ Available bool } `json:"features"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Flavour, out.Features
}

// A tenant served by the Cluster flavour reports flavour cluster, not multi.
func TestCapabilitiesClusterTenant(t *testing.T) {
	s := &Server{tenant: &tenantState{}, cl: &clusterTenant{rt: &ClusterRuntime{}, tenantID: "t"}}
	f, feats := capsOf(t, s)
	if f != "cluster" {
		t.Fatalf("flavour = %q", f)
	}
	for _, id := range []string{"tenant_managed_kek", "horizontal_scaling", "column_encryption"} {
		if !feats[id].Available {
			t.Errorf("%s unavailable in the Cluster flavour", id)
		}
	}
}

func TestCapabilitiesPlainMultiTenant(t *testing.T) {
	f, feats := capsOf(t, &Server{tenant: &tenantState{}})
	if f != "multi" {
		t.Fatalf("flavour = %q", f)
	}
	if feats["tenant_managed_kek"].Available {
		t.Error("tenant_managed_kek available without the Cluster")
	}
}
