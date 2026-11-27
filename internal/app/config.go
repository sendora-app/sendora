// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/sendora-app/sendora/internal/flavour"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/storage"
)

// Server configuration from the environment, typically a Kubernetes ConfigMap
// (settings) and Secret (passwords and client secrets).
//
// Every setting of Admin -> Settings has a variable SENDORA_<KEY IN CAPITALS>,
// for example SENDORA_SMTP_HOST or SENDORA_ALLOW_SELF_REGISTRATION. A variable
// with the suffix _FILE names a file holding the value instead (for a mounted
// Secret). Login providers use SENDORA_PROVIDER_<ID>_<FIELD>.
//
// Configured values are validated with the same rules as the admin screen,
// written to the database at every start and shown read-only in the screen:
// the configuration always wins. An invalid value stops the server with a
// message naming the variable. Removing a variable makes the setting editable
// again, keeping its last value.

const configMaxFileBytes = 64 << 10

// configExcluded are not plain settings: the signing secret is generated, logo
// and favicon are uploaded files.
var configExcluded = map[string]bool{"jwt_secret": true, "ui_logo": true, "ui_favicon": true}

// configAliases are friendlier extra names for some variables.
var configAliases = map[string][]string{"smtp_pass": {"SENDORA_SMTP_PASSWORD"}}

func settingEnvName(key string) string { return "SENDORA_" + strings.ToUpper(key) }

// JWTSecretFromEnv returns the session-signing secret from JWT_SECRET or the file
// named by JWT_SECRET_FILE ("" = generate and store one in the database).
func JWTSecretFromEnv() (string, error) {
	v, _, err := readConfigValue("JWT_SECRET")
	return strings.TrimSpace(v), err
}

// serverEnvNames are the SENDORA_* variables read outside the settings loader.
// k8sServiceLinkRe matches the variables Kubernetes injects for a Service named
// "sendora" (enableServiceLinks), or "sendora-web"/"sendora-controller" (the
// Cluster flavour's two Deployments), which are not settings.
var k8sServiceLinkRe = regexp.MustCompile(`^SENDORA(_WEB|_CONTROLLER)?_(SERVICE_(HOST|PORT)(_[A-Z0-9_]+)?|PORT(_\d+_(TCP|UDP|SCTP)(_(PROTO|PORT|ADDR))?)?)$`)

var serverEnvNames = map[string]bool{
	"SENDORA_DB_KEY_FILE": true, "SENDORA_KEY_OPS_PER_HOUR": true, "SENDORA_KEY_JOB_CONCURRENCY": true, "SENDORA_SOURCE_URL": true, "SENDORA_DB_INITIALIZE": true, "SENDORA_TRUSTED_PROXIES": true,
	"SENDORA_SETUP_CODE": true, "SENDORA_FORCE_LOCAL_LOGIN": true, "SENDORA_DISABLE_IP_BANS": true,
	"SENDORA_VERIFIED_DOWNLOAD_MAX_BYTES": true, "SENDORA_DISABLE_ADMIN_IP_ALLOWLIST": true,
	forwardTokenEnv: true, metricsTokenEnv: true,
	// Flavour selection (internal/flavour).
	"SENDORA_FLAVOUR": true, "SENDORA_ROLE": true,
	// Cluster flavour (internal/flavour/cluster.go, main_cluster.go).
	flavour.EnvPGPooler: true, flavour.EnvPGDirect: true, flavour.EnvPGSSLMode: true, flavour.EnvPGCAFile: true,
	flavour.EnvPGPlatformDatabase: true, flavour.EnvPGProvisionerDir: true, flavour.EnvPGPoolers: true,
	flavour.EnvLeaseName: true, flavour.EnvPodName: true, flavour.EnvCoordPoll: true, flavour.EnvLeaseDuration: true,
	"SENDORA_K8S_API":  true,
	flavour.EnvKeyAddr: true, flavour.EnvKeyTLSCert: true, flavour.EnvKeyTLSKey: true, flavour.EnvKeyUser: true,
	flavour.EnvKeyURL: true, flavour.EnvKeyCA: true, flavour.EnvKeyTokenFile: true, flavour.EnvKeyTTL: true,
	// Multi-tenant mode (mt_host.go); the platform settings add their own names.
	"SENDORA_MULTI_TENANT": true, "SENDORA_BASE_DOMAIN": true, "SENDORA_PLATFORM_SETUP_CODE": true,
	"SENDORA_RESTART_MODE": true, "SENDORA_ALLOW_SELF_RESTART": true,
	// Retired switches of the former optional event log: accepted and ignored.
	"SENDORA_LOGGING_ENABLED": true, "SENDORA_LOG_RETENTION_HOURS": true,
}

// warnConfig logs configuration that is probably a mistake: SENDORA_* variables
// that nothing reads (a typo silently changes nothing), and local login switched
// off while no enabled sign-in provider exists (everyone would be locked out).
func (s *Server) warnConfig(settingKeys []string) {
	known := map[string]bool{}
	for k := range serverEnvNames {
		known[k] = true
	}
	for _, k := range platform.SettingEnvNames() {
		known[k] = true
	}
	for _, k := range settingKeys {
		for _, n := range append([]string{settingEnvName(k)}, configAliases[k]...) {
			known[n], known[n+"_FILE"] = true, true
		}
	}
	for _, kv := range os.Environ() {
		name := strings.SplitN(kv, "=", 2)[0]
		if strings.HasPrefix(name, "SENDORA_") && !strings.HasPrefix(name, "SENDORA_PROVIDER_") && !known[name] && !k8sServiceLinkRe.MatchString(name) {
			log.Printf("WARNING: environment variable %s is not a Sendora setting and is ignored (typo?)", name)
		}
	}
	if s.isManagedSetting(settingLocalLogin) && !s.St.SettingBool(settingLocalLogin) {
		n, _ := s.St.Repos().AuthProviders().CountEnabled(context.Background())
		if n == 0 && os.Getenv("SENDORA_FORCE_LOCAL_LOGIN") != "true" {
			log.Printf("WARNING: local login is switched off by the configuration but no sign-in provider is enabled: nobody can sign in (recovery: SENDORA_FORCE_LOCAL_LOGIN=true)")
		}
	}
	s.warnSecurityConfig()
}

// readConfigValue returns the value of NAME or of the file named by NAME_FILE.
func readConfigValue(name string) (string, bool, error) {
	if p := os.Getenv(name + "_FILE"); p != "" {
		f, err := os.Open(p)
		if err != nil {
			return "", true, fmt.Errorf("%s_FILE: %v", name, err)
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, configMaxFileBytes+1))
		if err != nil || len(b) > configMaxFileBytes {
			return "", true, fmt.Errorf("%s_FILE: unreadable or larger than 64 KiB", name)
		}
		return strings.TrimRight(string(b), "\r\n"), true, nil
	}
	v, ok := os.LookupEnv(name)
	return v, ok, nil
}

// isManagedSetting: set by the deployment's configuration, so the screen cannot
// change it. The APP_URL environment variable also locks application_url, which
// it overrides everywhere (emailBaseURL, baseURL), so an administrator cannot
// redirect emailed links by editing the setting.
func (s *Server) isManagedSetting(key string) bool {
	return s.managedSettings[key] || (key == "application_url" && s.BaseURL != "")
}

// managedSettingList is the sorted list for the admin screen.
func (s *Server) managedSettingList() []string {
	out := make([]string, 0, len(s.managedSettings)+1)
	for k := range s.managedSettings {
		out = append(out, k)
	}
	if !s.managedSettings["application_url"] && s.isManagedSetting("application_url") {
		out = append(out, "application_url")
	}
	sort.Strings(out)
	return out
}

// applyConfig loads configured settings and providers into the database.
func (s *Server) applyConfig() error {
	s.managedSettings = map[string]bool{}
	var keys []string
	stored, err := s.St.Repos().Settings().EditableKeysOrdered(context.Background())
	if err != nil {
		return err
	}
	for _, k := range stored {
		if !configExcluded[k] {
			keys = append(keys, k)
		}
	}
	for _, key := range keys {
		// Multi-tenant mode: the platform decides where tenants' files go
		// (SENDORA_PLATFORM_STORAGE_*); SENDORA_STORAGE_* does not apply to tenants.
		if s.tenant != nil && storage.IsSetting(key) && key != "backup_remote_enabled" {
			continue
		}
		names := append([]string{settingEnvName(key)}, configAliases[key]...)
		for _, name := range names {
			v, ok, err := readConfigValue(name)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if !secretKeys[key] {
				v = strings.TrimSpace(v)
				if lv := strings.ToLower(v); lv == "true" || lv == "false" {
					v = lv
				}
			}
			norm, err := s.normalizeSetting(key, v)
			if err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
			if err := s.St.Repos().Settings().Update(context.Background(), key, norm); err != nil {
				return err
			}
			s.managedSettings[key] = true
			break
		}
	}
	if s.BaseURL != "" && !s.managedSettings["application_url"] {
		// APP_URL wins over the stored setting; show it as the setting's value.
		if norm, err := s.normalizeSetting("application_url", s.BaseURL); err == nil {
			if err := s.St.Repos().Settings().SetApplicationURL(context.Background(), norm); err != nil {
				return err
			}
		}
	}
	if err := s.applyProviderConfig(); err != nil {
		return err
	}
	// Every tenant would repeat the same warnings at each lazy open.
	if s.tenant == nil || tenantConfigWarned.CompareAndSwap(false, true) {
		s.warnConfig(keys)
	}
	return nil
}

var providerFields = []string{"CLIENT_SECRET", "ALLOW_REGISTRATION", "TRUST_EMAIL", "ISSUER_URL", "TENANT_ID", "CLIENT_ID", "ENABLED", "NAME", "TYPE", "ICON"}
var providerIDPattern = regexp.MustCompile(`^[A-Z0-9]{1,32}$`)

func parseConfigBool(name, v string, def bool) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return def, nil
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	}
	return false, fmt.Errorf("%s must be true or false", name)
}

// applyProviderConfig creates or updates login providers described by
// SENDORA_PROVIDER_<ID>_<FIELD> variables. <ID> (letters and digits) keeps the
// provider's callback URL stable: /api/auth/oidc/config-<id>/callback.
func (s *Server) applyProviderConfig() error {
	ids := map[string]bool{}
	for _, kv := range os.Environ() {
		name := strings.SplitN(kv, "=", 2)[0]
		rest, ok := strings.CutPrefix(name, "SENDORA_PROVIDER_")
		if !ok {
			continue
		}
		rest = strings.TrimSuffix(rest, "_FILE")
		matched := false
		for _, f := range providerFields {
			if id, ok := strings.CutSuffix(rest, "_"+f); ok && providerIDPattern.MatchString(id) {
				ids[id] = true
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: unknown provider variable (expected SENDORA_PROVIDER_<ID>_<%s>)", name, strings.Join(providerFields, "|"))
		}
	}
	configured := []string{}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		get := func(field string) (string, error) {
			v, _, err := readConfigValue("SENDORA_PROVIDER_" + id + "_" + field)
			if field != "CLIENT_SECRET" {
				v = strings.TrimSpace(v)
			}
			return v, err
		}
		prefix := "SENDORA_PROVIDER_" + id + "_"
		p := Provider{UUID: "config-" + strings.ToLower(id)}
		var err error
		if p.Name, err = get("NAME"); err != nil {
			return err
		}
		if p.Name == "" {
			p.Name = strings.ToLower(id)
		}
		vals := map[string]*string{"TYPE": &p.Type, "TENANT_ID": &p.TenantID, "CLIENT_ID": &p.ClientID, "CLIENT_SECRET": &p.ClientSecret, "ISSUER_URL": &p.IssuerURL, "ICON": &p.Icon}
		for f, dst := range vals {
			if *dst, err = get(f); err != nil {
				return err
			}
		}
		p.Type = strings.ToLower(p.Type)
		for f, b := range map[string]struct {
			dst *bool
			def bool
		}{"ENABLED": {&p.Enabled, true}, "ALLOW_REGISTRATION": {&p.AllowRegistration, false}, "TRUST_EMAIL": {&p.TrustEmail, false}} {
			v, err := get(f)
			if err != nil {
				return err
			}
			if *b.dst, err = parseConfigBool(prefix+f, v, b.def); err != nil {
				return err
			}
		}
		if msg := validProvider(&p); msg != "" {
			return fmt.Errorf("%s*: %s", prefix, msg)
		}
		ap := s.St.Repos().AuthProviders()
		existingID, oldType, oldClient, oldIssuer, oldSecret, err := ap.ManagedConfig(context.Background(), p.UUID)
		if err == nil {
			linked, _ := ap.CountProviderLinks(context.Background(), existingID)
			if linked > 0 && (oldType != p.Type || oldClient != p.ClientID || oldIssuer != p.IssuerURL) {
				return fmt.Errorf("%s*: the type, client ID or issuer of a provider with linked accounts cannot change; use a new <ID>", prefix)
			}
			if p.ClientSecret == "" {
				p.ClientSecret = oldSecret
			}
			if err := ap.UpdateManaged(context.Background(), existingID, providerSettings(&p)); err != nil {
				return err
			}
		} else {
			if err := ap.CreateManaged(context.Background(), p.UUID, providerSettings(&p)); err != nil {
				return err
			}
		}
		configured = append(configured, p.UUID)
	}
	// Providers no longer in the configuration become editable again.
	return s.St.Repos().AuthProviders().ReleaseUnconfigured(context.Background(), configured)
}
