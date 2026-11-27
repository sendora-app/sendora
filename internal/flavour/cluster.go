// SPDX-License-Identifier: AGPL-3.0-or-later

package flavour

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Environment of the Cluster flavour (docs/cluster/DESIGN.md 2.2, 3.3).
const (
	EnvPGPooler           = "SENDORA_PG_POOLER"            // host:port of the rw PgBouncer (web and controller)
	EnvPGDirect           = "SENDORA_PG_DIRECT"            // host:port of the rw service (controller; LISTEN, DDL)
	EnvPGSSLMode          = "SENDORA_PG_SSLMODE"           // verify-full (default), verify-ca or require
	EnvPGCAFile           = "SENDORA_PG_CA_FILE"           // CA of the cluster's server certificates
	EnvPGPlatformDatabase = "SENDORA_PG_PLATFORM_DATABASE" // default sendora_platform
	EnvPGProvisionerDir   = "SENDORA_PG_PROVISIONER_DIR"   // username/password files (controller only)
	EnvPGPoolers          = "SENDORA_PG_POOLERS"           // PgBouncer instances (connection limits, 9.3)
	EnvLeaseName          = "SENDORA_LEASE_NAME"           // controller Lease (default sendora-controller)
	EnvPodName            = "SENDORA_POD_NAME"             // replica identity (downward API; default host name)
	EnvCoordPoll          = "SENDORA_COORD_POLL_SECONDS"   // version polling period (default 10)
	EnvLeaseDuration      = "SENDORA_LEASE_SECONDS"        // lease duration (default 15)

	// Controller key endpoint (docs/cluster/DESIGN.md D42).
	EnvKeyAddr      = "SENDORA_KEY_ADDR"        // controller: listen address (default :8443)
	EnvKeyTLSCert   = "SENDORA_KEY_TLS_CERT"    // controller: server certificate file
	EnvKeyTLSKey    = "SENDORA_KEY_TLS_KEY"     // controller: server key file
	EnvKeyUser      = "SENDORA_KEY_USER"        // controller: allowed caller (default system:serviceaccount:<ns>:sendora-web)
	EnvKeyURL       = "SENDORA_KEY_URL"         // web: https URL of the key endpoint
	EnvKeyCA        = "SENDORA_KEY_CA"          // web: CA bundle of the endpoint's certificate
	EnvKeyTokenFile = "SENDORA_KEY_TOKEN_FILE"  // web: projected ServiceAccount token (audience sendora-keys)
	EnvKeyTTL       = "SENDORA_KEY_TTL_SECONDS" // web: cache lifetime (default 600)
)

// ClusterConfig is the validated configuration of a Cluster replica.
type ClusterConfig struct {
	Role             string
	PoolerAddr       string // host:port
	DirectAddr       string // host:port ("" on web replicas: polling only)
	SSLMode          string
	CAFile           string
	PlatformDatabase string
	ProvisionerDir   string // controller only
	Poolers          int
	LeaseName        string
	PodName          string
	PollInterval     time.Duration
	LeaseDuration    time.Duration
	BaseDomain       string
	DataDir          string
	KeyFile          string // controller only: the master key

	KeyAddr, KeyTLSCert, KeyTLSKey, KeyUser string        // controller
	KeyURL, KeyCA, KeyTokenFile             string        // web
	KeyTTL                                  time.Duration // web
}

// DSN returns the libpq-style connection string (without user, password and
// database) for addr with the configured TLS settings.
func (c ClusterConfig) DSN(addr string) string {
	host, port, _ := net.SplitHostPort(addr)
	dsn := "host=" + host + " port=" + port + " sslmode=" + c.SSLMode
	if c.CAFile != "" {
		dsn += " sslrootcert=" + c.CAFile
	}
	return dsn
}

// ClusterFromEnv reads and validates the configuration of a Cluster replica
// with role (web or controller). Every problem is reported at once, each with
// the variable to fix.
func ClusterFromEnv(role string, getenv func(string) string) (ClusterConfig, error) {
	c := ClusterConfig{Role: role}
	var errs []string
	bad := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	val := func(k string) string { return strings.TrimSpace(getenv(k)) }

	addr := func(k string, required bool) string {
		v := val(k)
		if v == "" {
			if required {
				bad("%s is required (host:port)", k)
			}
			return ""
		}
		if h, p, err := net.SplitHostPort(v); err != nil || h == "" || p == "" {
			bad("%s=%q is not host:port", k, clip(v))
			return ""
		}
		return v
	}
	c.PoolerAddr = addr(EnvPGPooler, true)
	c.DirectAddr = addr(EnvPGDirect, role == RoleController)

	c.SSLMode = val(EnvPGSSLMode)
	if c.SSLMode == "" {
		c.SSLMode = "verify-full"
	}
	c.CAFile = val(EnvPGCAFile)
	switch c.SSLMode {
	case "verify-full", "verify-ca":
		if c.CAFile == "" {
			bad("%s=%s needs %s (the CloudNativePG cluster's CA certificate)", EnvPGSSLMode, c.SSLMode, EnvPGCAFile)
		}
	case "require":
	default:
		bad("%s=%q is not valid; use verify-full (default), verify-ca or require", EnvPGSSLMode, clip(c.SSLMode))
	}
	if c.CAFile != "" {
		if _, err := os.Stat(c.CAFile); err != nil {
			bad("%s: %v", EnvPGCAFile, err)
		}
	}

	c.PlatformDatabase = val(EnvPGPlatformDatabase)
	if c.PlatformDatabase == "" {
		c.PlatformDatabase = "sendora_platform"
	}

	c.ProvisionerDir = val(EnvPGProvisionerDir)
	switch {
	case role == RoleWeb && c.ProvisionerDir != "":
		bad("%s must not be set for %s=%s: the provisioner credentials are mounted only into the controller (design 2.2)", EnvPGProvisionerDir, EnvRole, RoleWeb)
	case role == RoleController && c.ProvisionerDir == "":
		bad("%s is required for %s=%s (directory with the files username and password of sendora_provisioner)", EnvPGProvisionerDir, EnvRole, RoleController)
	case c.ProvisionerDir != "":
		for _, f := range []string{"username", "password"} {
			if _, err := os.Stat(filepath.Join(c.ProvisionerDir, f)); err != nil {
				bad("%s: %v", EnvPGProvisionerDir, err)
			}
		}
	}

	intVal := func(k string, def, lo, hi int) int {
		v := val(k)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			bad("%s=%q must be a number from %d to %d", k, clip(v), lo, hi)
			return def
		}
		return n
	}
	c.Poolers = intVal(EnvPGPoolers, 2, 1, 16)
	c.PollInterval = time.Duration(intVal(EnvCoordPoll, 10, 1, 300)) * time.Second
	c.LeaseDuration = time.Duration(intVal(EnvLeaseDuration, 15, 5, 300)) * time.Second

	c.LeaseName = val(EnvLeaseName)
	if c.LeaseName == "" {
		c.LeaseName = "sendora-controller"
	}
	c.PodName = val(EnvPodName)
	if c.PodName == "" {
		c.PodName, _ = os.Hostname()
	}
	if c.PodName == "" {
		bad("%s is required (no host name available)", EnvPodName)
	}

	c.BaseDomain = val("SENDORA_BASE_DOMAIN")
	if c.BaseDomain == "" {
		bad("SENDORA_BASE_DOMAIN is required: the Cluster flavour is always multi-tenant")
	}
	c.KeyFile = val("SENDORA_DB_KEY_FILE")
	if role == RoleController {
		// The master key exists only in controller pods (D42).
		if c.KeyFile == "" {
			bad("SENDORA_DB_KEY_FILE is required for %s=%s: the master key the tenants' keys and database passwords are derived from", EnvRole, RoleController)
		}
		c.KeyAddr = val(EnvKeyAddr)
		if c.KeyAddr == "" {
			c.KeyAddr = ":8443"
		}
		c.KeyTLSCert, c.KeyTLSKey, c.KeyUser = val(EnvKeyTLSCert), val(EnvKeyTLSKey), val(EnvKeyUser)
		if c.KeyTLSCert == "" || c.KeyTLSKey == "" {
			bad("%s and %s are required for %s=%s (server certificate of the key endpoint)", EnvKeyTLSCert, EnvKeyTLSKey, EnvRole, RoleController)
		}
	} else {
		if c.KeyFile != "" {
			bad("SENDORA_DB_KEY_FILE must not be set for %s=%s: the master key is mounted only into the controller; web replicas fetch derived keys from the key endpoint", EnvRole, RoleWeb)
		}
		c.KeyURL, c.KeyCA, c.KeyTokenFile = val(EnvKeyURL), val(EnvKeyCA), val(EnvKeyTokenFile)
		if !strings.HasPrefix(c.KeyURL, "https://") {
			bad("%s is required and must be an https:// URL (the controller's key endpoint)", EnvKeyURL)
		}
		if c.KeyCA == "" {
			bad("%s is required (CA bundle of the key endpoint's certificate)", EnvKeyCA)
		}
		if c.KeyTokenFile == "" {
			bad("%s is required (projected ServiceAccount token, audience sendora-keys)", EnvKeyTokenFile)
		}
		c.KeyTTL = time.Duration(intVal(EnvKeyTTL, 600, 1, 86400)) * time.Second
	}
	c.DataDir = val("DATA_DIR")
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	// SQLite paths are refused (design 2A.5): a Community data directory is
	// migrated with bundles, never opened by the Cluster flavour.
	for _, f := range []string{"sendora.db", "platform.db"} {
		if _, err := os.Stat(filepath.Join(c.DataDir, f)); err == nil {
			bad("DATA_DIR %s holds a Community database (%s); the Cluster flavour stores data in PostgreSQL and uses DATA_DIR only for files (a shared RWX volume). Use an empty directory", c.DataDir, f)
		}
	}
	for _, k := range []string{"SENDORA_DB_INITIALIZE"} {
		// "false" is what the container image sets for every flavour and means nothing here.
		if v := val(k); v != "" && !strings.EqualFold(v, "false") {
			bad("%s is not used by %s=cluster (the controller creates and migrates the databases); remove it", k, EnvFlavour)
		}
	}
	if len(errs) > 0 {
		return ClusterConfig{}, errors.New("cluster configuration:\n  - " + strings.Join(errs, "\n  - "))
	}
	return c, nil
}
