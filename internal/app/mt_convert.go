// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Converting a single-tenant installation to multi-tenant mode from the web
// UI (Admin -> Multi-tenant). The administrator schedules the conversion; it
// runs at the next start of the server, before anything is opened, with the
// tested offline conversion (platform.ImportSingleTenant: verified,
// resumable, abortable), then the server starts in multi-tenant mode. The
// mode is persisted in DATA_DIR, so later starts need no environment change.
//
// Precedence of the mode: SENDORA_MULTI_TENANT (true/false) > the persisted
// mode (DATA_DIR/sendora-mode.json) > single-tenant.

const (
	// ConversionPendingFile holds a scheduled conversion (0600; the platform
	// administrator's password only as a bcrypt hash).
	ConversionPendingFile = "multitenant-pending.json"
	// ConversionErrorFile records why the last conversion failed (shown in the UI).
	ConversionErrorFile = "multitenant-conversion-error.json"
	// ModeFile persists the mode chosen by a conversion.
	ModeFile = "sendora-mode.json"
	// ExitRestart is the exit code of "Restart now": the supervisor restarts us.
	ExitRestart = 75
)

// ConversionRequest is a scheduled conversion.
type ConversionRequest struct {
	BaseDomain        string `json:"base_domain"`
	Slug              string `json:"slug"`
	Name              string `json:"name"`
	AdminUsername     string `json:"admin_username"`
	AdminEmail        string `json:"admin_email"`
	AdminPasswordHash string `json:"admin_password_hash"`
	MFARequired       bool   `json:"mfa_required"`
	CustomDomain      string `json:"custom_domain,omitempty"`
	RequestedBy       string `json:"requested_by"`
	RequestedAt       string `json:"requested_at"`
}

// PersistedMode is DATA_DIR/sendora-mode.json.
type PersistedMode struct {
	Mode        string `json:"mode"` // "multi-tenant"
	BaseDomain  string `json:"base_domain"`
	ConvertedAt string `json:"converted_at"`
}

// ResolveMode decides the mode: SENDORA_MULTI_TENANT wins ("true"/"false"),
// then the persisted mode, then single-tenant. baseDomain comes from
// SENDORA_BASE_DOMAIN or the persisted mode.
func ResolveMode(envMulti, envBase, dataDir string) (multi bool, baseDomain string) {
	baseDomain = envBase
	pm, _ := ReadPersistedMode(dataDir)
	if baseDomain == "" && pm != nil {
		baseDomain = pm.BaseDomain
	}
	switch strings.ToLower(strings.TrimSpace(envMulti)) {
	case "true":
		return true, baseDomain
	case "false":
		return false, baseDomain
	}
	return pm != nil && pm.Mode == "multi-tenant", baseDomain
}

// ReadPersistedMode reads DATA_DIR/sendora-mode.json (nil when absent).
func ReadPersistedMode(dataDir string) (*PersistedMode, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, ModeFile))
	if err != nil {
		return nil, err
	}
	var pm PersistedMode
	if err := json.Unmarshal(b, &pm); err != nil {
		return nil, err
	}
	return &pm, nil
}

// ConversionPending reports whether a conversion is scheduled.
func ConversionPending(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, ConversionPendingFile))
	return err == nil
}

func readConversion(dataDir string) (*ConversionRequest, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, ConversionPendingFile))
	if err != nil {
		return nil, err
	}
	var c ConversionRequest
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("unreadable %s: %v", ConversionPendingFile, err)
	}
	return &c, nil
}

func writeFile0600(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SplitBaseDomain checks a base domain "host" or "host:port" (no scheme or
// path) and returns its parts; the port is "" when absent.
func SplitBaseDomain(base string) (host, port string, err error) {
	host = strings.ToLower(strings.TrimSpace(base))
	if strings.ContainsAny(host, "/@ ?#") {
		return "", "", errors.New("invalid base domain: enter the host name only (no scheme or path) and the port separately")
	}
	if h, p, e := net.SplitHostPort(host); e == nil {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return "", "", errors.New("invalid port of the base domain (1-65535)")
		}
		host, port = h, p
		if port == "80" || port == "443" {
			port = ""
		}
	}
	if _, ok := platform.NormalizeDomain("x." + host); !ok || strings.Contains(host, ":") {
		return "", "", errors.New("invalid base domain (a host name such as sendora.example.com)")
	}
	return host, port, nil
}

// JoinBaseDomain is the stored form of a base domain.
func JoinBaseDomain(host, port string) string {
	if port == "" || port == "80" || port == "443" {
		return host
	}
	return host + ":" + port
}

// basePortWarning explains when the base domain's port differs from the one
// this server is reached on (generated links would lack or carry a wrong
// port), unless a reverse proxy is evidently in front.
func (s *Server) basePortWarning(r *http.Request, port string) string {
	if len(s.trustedProxies) > 0 || r.Header.Get("X-Forwarded-Host") != "" || r.Header.Get("X-Forwarded-Proto") != "" {
		return ""
	}
	_, reqPort, _ := net.SplitHostPort(r.Host)
	if reqPort == "80" || reqPort == "443" {
		reqPort = ""
	}
	if reqPort == port {
		return ""
	}
	if port == "" {
		return "the base domain has no port, but this server is reached on port " + reqPort + ": the platform's links would lack the port; enter " + reqPort + " as the port unless a reverse proxy serves the platform on 80/443"
	}
	if reqPort == "" {
		return "the base domain uses port " + port + ", but this server is reached without a port"
	}
	return "the base domain uses port " + port + ", but this server is reached on port " + reqPort
}

// validateConversion checks a request (also again at start-up).
func validateConversion(c *ConversionRequest) error {
	host, port, err := SplitBaseDomain(c.BaseDomain)
	if err != nil {
		return err
	}
	c.BaseDomain = JoinBaseDomain(host, port)
	if !platform.ValidSlug(c.Slug) {
		return errors.New("invalid or reserved subdomain for the first tenant")
	}
	if !validAdminName(c.AdminUsername) {
		return errors.New("invalid platform administrator username")
	}
	if c.CustomDomain != "" {
		// A custom domain is a host name (served on 80/443 by the proxy);
		// a pasted port or scheme is dropped.
		if h, _, err := SplitBaseDomain(strings.SplitN(strings.TrimPrefix(strings.TrimPrefix(c.CustomDomain, "https://"), "http://"), "/", 2)[0]); err == nil {
			c.CustomDomain = h
		}
		d, ok := platform.NormalizeDomain(c.CustomDomain)
		base := strings.ToLower(host)
		if !ok || d == base || strings.HasSuffix(d, "."+base) {
			return errors.New("invalid custom domain (a host name outside the base domain)")
		}
	}
	return nil
}

// ---------- admin endpoints (single-tenant only) ----------

// supervisorLikely: something starts the process again after it exits
// (container PID 1, Kubernetes, or explicitly allowed).
func supervisorLikely() bool {
	return os.Getpid() == 1 || os.Getenv("KUBERNETES_SERVICE_HOST") != "" || os.Getenv("SENDORA_ALLOW_SELF_RESTART") == "true"
}

// RestartMode is how "Restart now" restarts: "exec" (the process replaces
// itself with the same executable, arguments and environment after an orderly
// stop) or "exit" (exit with ExitRestart for a supervisor:
// SENDORA_RESTART_MODE=exit, or where exec is not available).
func RestartMode() string {
	if os.Getenv("SENDORA_RESTART_MODE") == "exit" || runtime.GOOS == "windows" {
		return "exit"
	}
	return "exec"
}

// suggestedCustomDomain is the host of the current public URL, when it can
// be a custom domain (existing share links keep working through it).
func (s *Server) suggestedCustomDomain() string {
	raw := s.BaseURL
	if raw == "" {
		raw = s.St.Setting("application_url")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	if d, ok := platform.NormalizeDomain(u.Hostname()); ok {
		return d
	}
	return ""
}

// publicPort is the port of the configured public URL ("" for 80/443 or none).
func (s *Server) publicPort() string {
	raw := s.BaseURL
	if raw == "" {
		raw = s.St.Setting("application_url")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Port() == "80" || u.Port() == "443" {
		return ""
	}
	return u.Port()
}

// mtConvStatus: GET /api/admin/multitenant.
func (s *Server) mtConvStatus(w http.ResponseWriter, r *http.Request) {
	if s.tenant != nil {
		jerr(w, 404, "not found")
		return
	}
	out := map[string]any{"suggested_custom_domain": s.suggestedCustomDomain(), "supervisor": supervisorLikely(), "restart_mode": RestartMode(),
		"restart_available": s.restartFn != nil, "password_min_length": consoleMinPassword, "public_port": s.publicPort(),
		"jwt_secret_set": os.Getenv("JWT_SECRET") != "" || os.Getenv("JWT_SECRET_FILE") != ""}
	if c, err := readConversion(s.St.DataDir); err == nil {
		c.AdminPasswordHash = ""
		out["pending"] = c
	}
	if b, err := os.ReadFile(filepath.Join(s.St.DataDir, ConversionErrorFile)); err == nil {
		var e map[string]any
		if json.Unmarshal(b, &e) == nil {
			out["last_error"] = e
		}
	}
	jout(w, 200, out)
}

// mtConvSchedule: POST /api/admin/multitenant (administrators, step-up).
func (s *Server) mtConvSchedule(w http.ResponseWriter, r *http.Request) {
	if s.tenant != nil {
		jerr(w, 404, "not found")
		return
	}
	var b struct {
		BaseDomain    string `json:"base_domain"`
		Slug          string `json:"slug"`
		Name          string `json:"name"`
		AdminUsername string `json:"admin_username"`
		AdminEmail    string `json:"admin_email"`
		AdminPassword string `json:"admin_password"`
		MFARequired   *bool  `json:"mfa_required"`
		CustomDomain  string `json:"custom_domain"`
	}
	if decode(r, &b) != nil {
		jerr(w, 400, "bad request")
		return
	}
	c := &ConversionRequest{BaseDomain: strings.ToLower(strings.TrimSpace(b.BaseDomain)), Slug: strings.ToLower(strings.TrimSpace(b.Slug)),
		Name: strings.TrimSpace(b.Name), AdminUsername: strings.TrimSpace(b.AdminUsername), MFARequired: b.MFARequired == nil || *b.MFARequired,
		CustomDomain: strings.ToLower(strings.TrimSpace(b.CustomDomain))}
	if err := validateConversion(c); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	if c.Name == "" {
		c.Name = c.Slug
	}
	if len(c.Name) > 200 || strings.ContainsAny(c.Name, "\r\n\x00") {
		jerr(w, 400, "invalid tenant name")
		return
	}
	email, err := canonicalEmail(b.AdminEmail)
	if err != nil || email == "" {
		jerr(w, 400, "valid email required for the platform administrator")
		return
	}
	c.AdminEmail = email
	if msg := platformPasswordProblem(b.AdminPassword, c.AdminUsername); msg != "" {
		jerr(w, 400, msg)
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(b.AdminPassword), hashCost)
	if err != nil {
		jerr(w, 400, "invalid password")
		return
	}
	c.AdminPasswordHash = string(h)
	me := s.ctxUser(r)
	c.RequestedBy, c.RequestedAt = me.Username, time.Now().UTC().Format(time.RFC3339)
	if err := writeFile0600(filepath.Join(s.St.DataDir, ConversionPendingFile), c); err != nil {
		jerr(w, 500, "could not store the conversion request")
		return
	}
	os.Remove(filepath.Join(s.St.DataDir, ConversionErrorFile))
	s.logEvent(me.ID, me.Username, "multitenant_conversion_scheduled", "platform",
		fmt.Sprintf("base_domain=%s tenant=%s platform_admin=%s mfa_required=%t custom_domain=%s; runs at the next start", c.BaseDomain, c.Slug, c.AdminUsername, c.MFARequired, c.CustomDomain))
	_, port, _ := SplitBaseDomain(c.BaseDomain)
	jout(w, 200, map[string]any{"ok": true, "supervisor": supervisorLikely(), "warning": s.basePortWarning(r, port)})
}

// mtConvCancel: DELETE /api/admin/multitenant (administrators, step-up).
func (s *Server) mtConvCancel(w http.ResponseWriter, r *http.Request) {
	if s.tenant != nil {
		jerr(w, 404, "not found")
		return
	}
	err := os.Remove(filepath.Join(s.St.DataDir, ConversionPendingFile))
	os.Remove(filepath.Join(s.St.DataDir, ConversionErrorFile))
	if err != nil && !os.IsNotExist(err) {
		jerr(w, 500, "could not remove the conversion request")
		return
	}
	me := s.ctxUser(r)
	s.logEvent(me.ID, me.Username, "multitenant_conversion_cancelled", "platform", "")
	jout(w, 200, map[string]any{"ok": true})
}

// mtConvRestart: POST /api/multitenant/restart (administrators, step-up): an
// orderly stop, then the process restarts itself (RestartMode) and runs the
// scheduled conversion.
func (s *Server) mtConvRestart(w http.ResponseWriter, r *http.Request) {
	if s.tenant != nil || !ConversionPending(s.St.DataDir) {
		jerr(w, 409, "no conversion is scheduled")
		return
	}
	if s.restartFn == nil {
		jerr(w, 409, "restart the server to run the conversion")
		return
	}
	me := s.ctxUser(r)
	mode := RestartMode()
	if mode == "exit" && !supervisorLikely() {
		log.Printf("WARNING: restart requested with SENDORA_RESTART_MODE=exit but no supervisor detected; the server may stay stopped")
	}
	s.logEvent(me.ID, me.Username, "restart_requested", "platform", "multi-tenant conversion; mode="+mode)
	jout(w, 202, map[string]any{"ok": true, "mode": mode})
	go func() {
		time.Sleep(500 * time.Millisecond)
		s.restartFn()
	}()
}

// SetRestarter registers how main stops the server for "Restart now".
func (s *Server) SetRestarter(fn func()) { s.restartFn = fn }

// ---------- conversion at start-up ----------

// ConvertPending runs a scheduled conversion before the server starts (the
// single-tenant store must not be open). On success it returns the base
// domain to start multi-tenant mode with. On failure everything is put back
// (the import is aborted, the new platform database moved aside), the error
// is recorded for the UI and the request is renamed so it does not run again
// at every start; the caller then starts single-tenant as before.
func ConvertPending(dataDir string, key []byte, logf func(string, ...any)) (string, error) {
	c, err := readConversion(dataDir)
	if err != nil {
		return "", err
	}
	fail := func(stage string, err error) (string, error) {
		logf("MULTI-TENANT CONVERSION FAILED (%s): %v; starting single-tenant, the data directory is unchanged", stage, err)
		writeFile0600(filepath.Join(dataDir, ConversionErrorFile), map[string]any{"stage": stage, "error": err.Error(), "at": time.Now().UTC().Format(time.RFC3339)})
		os.Rename(filepath.Join(dataDir, ConversionPendingFile), filepath.Join(dataDir, ConversionPendingFile+".failed"))
		return "", err
	}
	if err := validateConversion(c); err != nil {
		return fail("validation", err)
	}
	if c.AdminPasswordHash == "" {
		return fail("validation", errors.New("no platform administrator password"))
	}
	if _, err := os.Stat(filepath.Join(dataDir, store.PlatformDBFile)); err == nil {
		return fail("validation", errors.New("a platform database already exists in the data directory"))
	}
	src, err := store.DBPath(dataDir)
	if err != nil {
		return fail("backup", err)
	}
	// A full, verified, encrypted copy of the database before anything else.
	backup := filepath.Join(dataDir, "pre-multitenant-backup-"+time.Now().UTC().Format("20060102-150405")+".db")
	if err := store.ExportDatabase(src, backup, key, key); err != nil {
		return fail("backup", err)
	}
	logf("multi-tenant conversion: database backup written to %s", backup)
	p, err := platform.Open(dataDir, key, true)
	if err != nil {
		os.Remove(filepath.Join(dataDir, store.PlatformDBFile))
		return fail("platform database", err)
	}
	res, err := p.ImportSingleTenant(platform.ImportOptions{Slug: c.Slug, Name: c.Name, Logf: logf})
	if err != nil {
		if _, aerr := p.ImportSingleTenant(platform.ImportOptions{Abort: true, Logf: logf}); aerr != nil {
			logf("multi-tenant conversion: abort: %v (see docs/MULTI-TENANT.md §7, sendora-db tenant-import -abort)", aerr)
		}
		p.Close()
		aside := filepath.Join(dataDir, "failed-conversion-"+time.Now().UTC().Format("20060102-150405"))
		os.MkdirAll(aside, 0o700)
		for _, f := range []string{store.PlatformDBFile, store.PlatformDBFile + "-wal", store.PlatformDBFile + "-shm"} {
			os.Rename(filepath.Join(dataDir, f), filepath.Join(aside, f))
		}
		os.Remove(filepath.Join(dataDir, "tenants")) // only when empty
		return fail("tenant import", err)
	}
	defer p.Close()
	// The rest cannot lose data any more: failures are logged, the platform
	// starts anyway (a missing administrator falls back to the setup code).
	if _, err := p.CreateFirstAdmin(c.AdminUsername, c.AdminEmail, c.AdminPasswordHash); err != nil {
		logf("multi-tenant conversion: platform administrator: %v (use the setup code from the log)", err)
	}
	if !c.MFARequired {
		if _, err := p.PutSettings(map[string]string{"platform_mfa_required": "false"}, nil); err != nil {
			logf("multi-tenant conversion: platform_mfa_required: %v", err)
		}
	}
	// The converted installation keeps the storage it had: its directory.
	if err := p.SetStorage(res.TenantID, platform.OfferLocal, true); err != nil {
		logf("multi-tenant conversion: storage: %v", err)
	}
	if c.CustomDomain != "" {
		if _, err := p.AddCustomDomain(res.TenantID, c.CustomDomain, c.BaseDomain); err != nil {
			logf("multi-tenant conversion: custom domain %s: %v", c.CustomDomain, err)
		} else if err := p.MarkDomainVerified(res.TenantID, c.CustomDomain); err != nil {
			logf("multi-tenant conversion: verifying %s: %v", c.CustomDomain, err)
		}
	}
	p.Audit(0, "system", "multitenant_conversion_completed", "tenant "+res.Slug+" ("+res.TenantID+")", "ok",
		fmt.Sprintf("requested by %s at %s; base_domain=%s platform_admin=%s mfa_required=%t custom_domain=%s; %d files verified; backup %s",
			c.RequestedBy, c.RequestedAt, c.BaseDomain, c.AdminUsername, c.MFARequired, c.CustomDomain, res.Files, filepath.Base(backup)), "")
	if err := writeFile0600(filepath.Join(dataDir, ModeFile), PersistedMode{Mode: "multi-tenant", BaseDomain: c.BaseDomain, ConvertedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		logf("multi-tenant conversion: persisting the mode: %v (set SENDORA_MULTI_TENANT=true)", err)
	}
	os.Remove(filepath.Join(dataDir, ConversionPendingFile))
	os.Remove(filepath.Join(dataDir, ConversionErrorFile))
	logf("multi-tenant conversion completed: tenant %s (%s), platform console at admin.%s", res.Slug, res.TenantID, c.BaseDomain)
	return c.BaseDomain, nil
}
