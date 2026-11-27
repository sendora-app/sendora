// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sendora-app/sendora/internal/flavour"
)

// A web replica of the Cluster flavour is configured without the master key
// file (D42): the key endpoint settings replace it, and the file is refused.
func TestClusterWebHasNoMasterKey(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	os.WriteFile(ca, []byte("x"), 0o600)
	vars := map[string]string{
		flavour.EnvPGPooler: "pooler:5432", flavour.EnvPGSSLMode: "require", "SENDORA_BASE_DOMAIN": "files.example", "DATA_DIR": filepath.Join(dir, "d"),
		flavour.EnvPodName: "w", flavour.EnvKeyURL: "https://keys:8443", flavour.EnvKeyCA: ca, flavour.EnvKeyTokenFile: "/tok",
	}
	get := func(k string) string { return vars[k] }
	cfg, err := flavour.ClusterFromEnv(flavour.RoleWeb, get)
	if err != nil || cfg.KeyFile != "" {
		t.Fatalf("web without a key file: %+v %v", cfg, err)
	}
	vars["SENDORA_DB_KEY_FILE"] = "/etc/sendora-key/db.key"
	if _, err := flavour.ClusterFromEnv(flavour.RoleWeb, get); err == nil {
		t.Fatal("a web replica must refuse the master key file")
	}
}
