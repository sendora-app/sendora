// SPDX-License-Identifier: AGPL-3.0-or-later

package flavour

import (
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestFromEnvValid(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		flavour Flavour
		mtEnv   string
	}{
		// Unset: 0.2 detection, SENDORA_MULTI_TENANT passed through untouched.
		{"nothing set", nil, "", ""},
		{"legacy alias true", map[string]string{EnvMultiTenant: "true"}, Multi, "true"},
		{"legacy alias TRUE", map[string]string{EnvMultiTenant: " TRUE "}, Multi, " TRUE "},
		{"legacy false", map[string]string{EnvMultiTenant: "false"}, Single, "false"},
		{"legacy other value ignored as in 0.2", map[string]string{EnvMultiTenant: "yes"}, "", "yes"},
		{"single", map[string]string{EnvFlavour: "single"}, Single, "false"},
		{"single + alias false", map[string]string{EnvFlavour: "single", EnvMultiTenant: "false"}, Single, "false"},
		{"multi", map[string]string{EnvFlavour: "multi"}, Multi, "true"},
		{"multi upper case", map[string]string{EnvFlavour: " Multi "}, Multi, "true"},
		{"multi + alias true", map[string]string{EnvFlavour: "multi", EnvMultiTenant: "true"}, Multi, "true"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sel, err := FromEnv(envOf(c.env))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sel.Flavour != c.flavour || sel.MultiTenantEnv != c.mtEnv {
				t.Fatalf("got %+v, want flavour %q mtEnv %q", sel, c.flavour, c.mtEnv)
			}
		})
	}
}

func TestFromEnvInvalid(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"unknown flavour", map[string]string{EnvFlavour: "pro"}, `SENDORA_FLAVOUR="pro" is not valid`},
		{"single contradicts alias", map[string]string{EnvFlavour: "single", EnvMultiTenant: "true"}, "contradicts SENDORA_MULTI_TENANT=true"},
		{"multi contradicts false", map[string]string{EnvFlavour: "multi", EnvMultiTenant: "false"}, "contradicts SENDORA_MULTI_TENANT=false"},
		{"role without cluster", map[string]string{EnvRole: "web"}, "SENDORA_ROLE is only used by SENDORA_FLAVOUR=cluster"},
		{"role with single", map[string]string{EnvFlavour: "single", EnvRole: "controller"}, "SENDORA_ROLE is only used"},
		{"role with multi alias", map[string]string{EnvMultiTenant: "true", EnvRole: "web"}, "SENDORA_ROLE is only used"},
		{"cluster without role", map[string]string{EnvFlavour: "cluster"}, "needs SENDORA_ROLE=web or SENDORA_ROLE=controller"},
		{"cluster bad role", map[string]string{EnvFlavour: "cluster", EnvRole: "worker"}, `SENDORA_ROLE="worker" is not valid`},
		{"cluster with alias", map[string]string{EnvFlavour: "cluster", EnvRole: "web", EnvMultiTenant: "true"}, "not used by SENDORA_FLAVOUR=cluster"},
		{"long value clipped", map[string]string{EnvFlavour: strings.Repeat("x", 100)}, `..." is not valid`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := FromEnv(envOf(c.env))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want it to contain %q", err, c.want)
			}
		})
	}
}

// The Cluster flavour is selected with its role; the rest of its
// configuration is validated by ClusterFromEnv (cluster_test.go).
func TestFromEnvCluster(t *testing.T) {
	for _, role := range []string{"web", "controller", "WEB"} {
		sel, err := FromEnv(envOf(map[string]string{EnvFlavour: "cluster", EnvRole: role}))
		if err != nil || sel.Flavour != Cluster || sel.Role != strings.ToLower(role) {
			t.Fatalf("role %s: %+v, %v", role, sel, err)
		}
	}
}
