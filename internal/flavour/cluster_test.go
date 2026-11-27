// SPDX-License-Identifier: AGPL-3.0-or-later

package flavour

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clusterEnv(t *testing.T, role string, extra map[string]string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	os.WriteFile(ca, []byte("x"), 0o600)
	prov := filepath.Join(dir, "prov")
	os.Mkdir(prov, 0o700)
	os.WriteFile(filepath.Join(prov, "username"), []byte("sendora_provisioner"), 0o600)
	os.WriteFile(filepath.Join(prov, "password"), []byte("x"), 0o600)
	m := map[string]string{
		EnvPGPooler: "pooler.example:5432", EnvPGCAFile: ca, "SENDORA_BASE_DOMAIN": "files.example",
		"DATA_DIR": filepath.Join(dir, "data"), EnvPodName: "pod-1",
	}
	if role == RoleWeb {
		m[EnvKeyURL], m[EnvKeyCA], m[EnvKeyTokenFile] = "https://keys.example:8443", ca, "/tok/token"
	}
	if role == RoleController {
		m["SENDORA_DB_KEY_FILE"] = "/keys/master"
		m[EnvKeyTLSCert], m[EnvKeyTLSKey] = "/tls/tls.crt", "/tls/tls.key"
		m[EnvPGDirect] = "rw.example:5432"
		m[EnvPGProvisionerDir] = prov
	}
	for k, v := range extra {
		if v == "-" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

func TestClusterFromEnvValid(t *testing.T) {
	c, err := ClusterFromEnv(RoleWeb, envOf(clusterEnv(t, RoleWeb, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if c.SSLMode != "verify-full" || c.PlatformDatabase != "sendora_platform" || c.Poolers != 2 || c.PollInterval != 10*time.Second || c.DirectAddr != "" {
		t.Fatalf("defaults: %+v", c)
	}
	if dsn := c.DSN(c.PoolerAddr); !strings.Contains(dsn, "host=pooler.example port=5432 sslmode=verify-full sslrootcert=") {
		t.Fatalf("dsn %q", dsn)
	}
	c, err = ClusterFromEnv(RoleController, envOf(clusterEnv(t, RoleController, map[string]string{EnvCoordPoll: "1", EnvPGSSLMode: "require", EnvPGCAFile: "-"})))
	if err != nil {
		t.Fatal(err)
	}
	if c.DirectAddr != "rw.example:5432" || c.PollInterval != time.Second || c.ProvisionerDir == "" {
		t.Fatalf("controller: %+v", c)
	}
}

func TestClusterFromEnvErrors(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "sendora.db"), nil, 0o600)
	for _, tc := range []struct {
		name, role string
		extra      map[string]string
		want       string
	}{
		{"web with provisioner", RoleWeb, map[string]string{EnvPGProvisionerDir: "/x"}, "must not be set for SENDORA_ROLE=web"},
		{"controller without direct", RoleController, map[string]string{EnvPGDirect: "-"}, "SENDORA_PG_DIRECT is required"},
		{"controller without provisioner", RoleController, map[string]string{EnvPGProvisionerDir: "-"}, "SENDORA_PG_PROVISIONER_DIR is required"},
		{"no pooler", RoleWeb, map[string]string{EnvPGPooler: "-"}, "SENDORA_PG_POOLER is required"},
		{"pooler not host:port", RoleWeb, map[string]string{EnvPGPooler: "pooler"}, "is not host:port"},
		{"verify-full without CA", RoleWeb, map[string]string{EnvPGCAFile: "-"}, "needs SENDORA_PG_CA_FILE"},
		{"bad sslmode", RoleWeb, map[string]string{EnvPGSSLMode: "disable"}, "SENDORA_PG_SSLMODE=\"disable\" is not valid"},
		{"bad poll", RoleWeb, map[string]string{EnvCoordPoll: "0"}, "SENDORA_COORD_POLL_SECONDS"},
		{"no base domain", RoleWeb, map[string]string{"SENDORA_BASE_DOMAIN": "-"}, "SENDORA_BASE_DOMAIN is required"},
		{"controller without key", RoleController, map[string]string{"SENDORA_DB_KEY_FILE": "-"}, "SENDORA_DB_KEY_FILE is required"},
		{"controller without key TLS", RoleController, map[string]string{EnvKeyTLSCert: "-"}, "SENDORA_KEY_TLS_CERT and SENDORA_KEY_TLS_KEY are required"},
		{"web with master key", RoleWeb, map[string]string{"SENDORA_DB_KEY_FILE": "/keys/master"}, "must not be set for SENDORA_ROLE=web"},
		{"web without key URL", RoleWeb, map[string]string{EnvKeyURL: "-"}, "SENDORA_KEY_URL is required"},
		{"web with http key URL", RoleWeb, map[string]string{EnvKeyURL: "http://keys:8443"}, "SENDORA_KEY_URL is required"},
		{"web without key CA", RoleWeb, map[string]string{EnvKeyCA: "-"}, "SENDORA_KEY_CA is required"},
		{"web without key token", RoleWeb, map[string]string{EnvKeyTokenFile: "-"}, "SENDORA_KEY_TOKEN_FILE is required"},
		{"sqlite data dir", RoleWeb, map[string]string{"DATA_DIR": dir}, "holds a Community database"},
		{"initialize", RoleWeb, map[string]string{"SENDORA_DB_INITIALIZE": "true"}, "SENDORA_DB_INITIALIZE is not used"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ClusterFromEnv(tc.role, envOf(clusterEnv(t, tc.role, tc.extra)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}
