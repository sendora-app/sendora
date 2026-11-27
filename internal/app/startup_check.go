// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
)

// Startup checks for secrets supplied through the environment.

// secretFileVars lists the *_FILE variables that carry a secret (files) and the
// matching plain variables (plain): the signing secret, secret settings (SMTP
// password) and the client secret of every configured login provider.
// SENDORA_DB_KEY_FILE has its own, identical check in store.ReadDatabaseKey.
func secretFileVars() (files, plain []string) {
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			files = append(files, name+"_FILE")
			plain = append(plain, name)
		}
	}
	add("JWT_SECRET")
	for key := range secretKeys {
		add(settingEnvName(key))
		for _, alias := range configAliases[key] {
			add(alias)
		}
	}
	for _, kv := range os.Environ() {
		name := strings.SplitN(kv, "=", 2)[0]
		if strings.HasPrefix(name, "SENDORA_PROVIDER_") {
			base := strings.TrimSuffix(name, "_FILE")
			if strings.HasSuffix(base, "_CLIENT_SECRET") {
				add(base)
			}
		}
	}
	// Token files without a plain-variable form (audit forwarding, metrics).
	files = append(files, forwardTokenEnv, metricsTokenEnv)
	sort.Strings(files)
	sort.Strings(plain)
	return files, plain
}

// checkSecretFile applies the database key rule: a regular file, no group-write
// and no world access (mode & 0027 == 0; group-read stays possible for a
// Kubernetes fsGroup mount), owned by root or by the current user. The message
// names the variable and never the contents.
func checkSecretFile(varName, p string) error {
	f, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("%s: file cannot be opened", varName)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s: must name a regular file", varName)
	}
	if st.Mode().Perm()&0027 != 0 {
		return fmt.Errorf("%s: file permissions are too open (%#o); use 0400 or 0440 (no group-write, no world access)", varName, st.Mode().Perm())
	}
	if owner, ok := st.Sys().(*syscall.Stat_t); !ok || (owner.Uid != 0 && int(owner.Uid) != os.Getuid()) {
		return fmt.Errorf("%s: file is owned by another user (must be root or the Sendora user)", varName)
	}
	return nil
}

// CheckSecretFiles refuses to start when any secret *_FILE is too accessible.
func CheckSecretFiles() error {
	files, _ := secretFileVars()
	for _, name := range files {
		if p := os.Getenv(name); p != "" {
			if err := checkSecretFile(name, p); err != nil {
				return err
			}
		}
	}
	return nil
}

// WarnPlainSecrets logs (never the value) each secret that comes from a plain
// environment variable instead of a mounted file.
func WarnPlainSecrets() {
	_, plain := secretFileVars()
	for _, name := range plain {
		if os.Getenv(name) != "" && os.Getenv(name+"_FILE") == "" {
			log.Printf("WARNING: %s is set as a plain environment variable; environment variables are visible to every process of the container and to inspection tools. Prefer %s_FILE with a mounted secret", name, name)
		}
	}
}

// hostIsLoopback: an empty HOST means the default 127.0.0.1.
func hostIsLoopback(h string) bool {
	return h == "" || isLoopbackHost(strings.Trim(h, "[]"))
}

// warnSecurityConfig logs risky but permitted configuration, once at start.
func (s *Server) warnSecurityConfig() {
	appURL := s.BaseURL
	if appURL == "" {
		appURL = strings.TrimSpace(s.St.Setting("application_url"))
	}
	if host := os.Getenv("HOST"); !hostIsLoopback(host) && (appURL == "" || !strings.HasPrefix(strings.ToLower(appURL), "https://")) {
		why := "not https"
		if appURL == "" {
			why = "empty"
		}
		log.Printf("WARNING: HOST=%s is not a loopback address but the application URL is %s; serve users over https (set APP_URL or application_url to an https:// address and terminate TLS in front of Sendora)", host, why)
	}
	if s.St.SettingBool("allow_self_registration") {
		if strings.TrimSpace(s.St.Setting("registration_email_domains")) == "" {
			log.Printf("WARNING: self-registration is on without a domain allowlist (registration_email_domains): anyone can create an account")
		}
		if !s.St.SettingBool("require_email_verification") {
			log.Printf("WARNING: self-registration is on without email verification (require_email_verification)")
		}
		if strings.TrimSpace(s.St.Setting("smtp_host")) == "" {
			log.Printf("WARNING: self-registration is on but no SMTP host is configured: addresses cannot be verified")
		}
	}
}

var warnForwardedOnce sync.Once

// noteForwardedHeader warns once when a request carries X-Forwarded-For although
// no trusted proxy is configured: the header is ignored, so every client behind
// the proxy appears to have the proxy's address (shared rate limits and bans).
func (s *Server) noteForwardedHeader(r *http.Request) {
	if len(s.trustedProxies) == 0 && r.Header.Get("X-Forwarded-For") != "" {
		warnForwardedOnce.Do(s.logForwardedWarning)
	}
}

func (s *Server) logForwardedWarning() {
	log.Printf("WARNING: X-Forwarded-For received while SENDORA_TRUSTED_PROXIES is empty; the header is ignored and all clients behind the proxy share one address. Set SENDORA_TRUSTED_PROXIES to your reverse proxy's address")
}
