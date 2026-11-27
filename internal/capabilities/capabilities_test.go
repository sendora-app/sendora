// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/sendora-app/sendora/internal/flavour"
)

// TestMatrixUpToDate fails when docs/CAPABILITIES.md is stale (design 2A.4 #4).
func TestMatrixUpToDate(t *testing.T) {
	got, err := os.ReadFile(filepath.Join("..", "..", "docs", "CAPABILITIES.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != Matrix() {
		t.Fatal("docs/CAPABILITIES.md is stale: run go generate ./internal/capabilities")
	}
}

func TestRegistryValid(t *testing.T) {
	ids := make([]string, len(Features))
	seen := map[string]bool{}
	for i, f := range Features {
		ids[i] = f.ID
		if f.ID == "" || f.Description == "" || seen[f.ID] {
			t.Fatalf("feature %d: empty or duplicate ID/description: %+v", i, f)
		}
		seen[f.ID] = true
		if f.Maturity != Stable && f.Maturity != Preview {
			t.Fatalf("%s: maturity %q", f.ID, f.Maturity)
		}
		for _, p := range f.Requires {
			if missingReason[p] == "" {
				t.Fatalf("%s: provide %s has no reason text", f.ID, p)
			}
		}
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("Features not sorted by ID: %v", ids)
	}
	for _, fi := range Flavours {
		for _, p := range fi.Provides {
			if missingReason[p] == "" {
				t.Fatalf("%s: provide %s has no reason text", fi.Flavour, p)
			}
		}
	}
}

func TestEvaluate(t *testing.T) {
	single, multi, cluster := Evaluate(flavour.Single), Evaluate(flavour.Multi), Evaluate(flavour.Cluster)
	for _, m := range []map[string]Status{single, multi, cluster} {
		if len(m) != len(Features) {
			t.Fatalf("got %d features, want %d", len(m), len(Features))
		}
	}
	check := func(name string, st Status, available bool) {
		t.Helper()
		if st.Available != available || (!available && st.Reason == "") || (available && st.Reason != "") {
			t.Fatalf("%s: %+v, want available=%v with a reason exactly when unavailable", name, st, available)
		}
	}
	check("single shares", single["shares"], true)
	check("single conversion", single["multi_tenant_conversion"], true)
	check("single import", single["database_import"], true)
	check("single console", single["platform_console"], false)
	check("single scaling", single["horizontal_scaling"], false)
	check("multi console", multi["platform_console"], true)
	check("multi conversion", multi["multi_tenant_conversion"], false)
	check("multi import", multi["database_import"], false)
	check("multi restart", multi["in_app_restart"], true)
	for id, st := range cluster {
		if st.Maturity != Preview {
			t.Fatalf("cluster %s: %+v", id, st)
		}
	}
	check("cluster shares", cluster["shares"], true)
	check("cluster scaling", cluster["horizontal_scaling"], true)
	check("cluster tenant KEK", cluster["tenant_managed_kek"], true)
	check("single tenant KEK", single["tenant_managed_kek"], false)
	check("cluster console", cluster["platform_console"], true)
	check("cluster master key rotation", cluster["master_key_rotation"], true)
	check("multi master key rotation", multi["master_key_rotation"], false)
	check("multi operator key rotation", multi["operator_key_rotation"], true)
	check("single operator key rotation", single["operator_key_rotation"], false)
	check("cluster conversion", cluster["multi_tenant_conversion"], false)
	for _, id := range []string{"journal_anchors", "external_kms"} {
		check("not built "+id, cluster[id], false)
		check("not built "+id, single[id], false)
	}
	for name, m := range map[string]map[string]Status{"single": single, "multi": multi, "cluster": cluster} {
		check(name+" key management UI", m["key_management_ui"], true)
	}
	if st := Evaluate("other")["shares"]; st.Available {
		t.Fatalf("unknown flavour: %+v", st)
	}
}
