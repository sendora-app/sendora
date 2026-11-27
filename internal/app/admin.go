// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/storage"
	"github.com/sendora-app/sendora/internal/store"
)

// ---------- settings ----------

var secretKeys = map[string]bool{"smtp_pass": true,
	"storage_s3_secret_key": true, "storage_azure_account_key": true, "storage_azure_sas_token": true, "storage_gcs_credentials_json": true}

const msgSMTPPasswordAgain = "enter the SMTP password again when changing the server, port, user or security"

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.St.Repos().Settings().ListEditable(context.Background())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	out := map[string]any{}
	for _, st := range settings {
		k, v := st.Key, st.Value
		if secretKeys[k] {
			out[k] = ""
			out[k+"_set"] = v != ""
			continue
		}
		out[k] = v
	}
	out["managed_settings"] = s.managedSettingList()
	jout(w, 200, out)
}

// normalizeSetting validates one setting value and returns its stored form. It
// is shared by the admin screen and the configuration loader (ConfigMap /
// environment), so both follow exactly the same rules.
func (s *Server) normalizeSetting(k, str string) (string, error) {
	if k == store.DefaultStorageQuotaKey {
		if _, err := store.ParseQuotaBytes(str); err != nil {
			return "", fmt.Errorf("invalid default storage quota")
		}
	}
	if norm, owned, err := storage.NormalizeSetting(k, str); owned {
		if err != nil {
			return "", err
		}
		return norm, nil
	}
	if owned, err := validateShareSetting(k, str); owned && err != nil {
		return "", err
	}
	if owned, err := validateAccountSetting(k, str); owned && err != nil {
		return "", err
	}
	if owned, err := validateBackgroundSetting(k, str); owned && err != nil {
		return "", err
	}
	if owned, err := s.validateGeneralSetting(k, &str); owned && err != nil {
		return "", err
	}
	if owned, err := validateReplyToSetting(k, &str); owned && err != nil {
		return "", err
	}
	if owned, err := validateIPBanSetting(k, &str); owned && err != nil {
		return "", err
	}
	if owned, err := validateIdleSetting(k, str); owned && err != nil {
		return "", err
	}
	if owned, err := validateMFASetting(k, str); owned && err != nil {
		return "", err
	}
	if owned, err := validateAccountSecuritySetting(k, &str); owned && err != nil {
		return "", err
	}
	if k == settingLocalLogin {
		norm, ok := normalizeLocalLoginSetting(str)
		if !ok {
			return "", fmt.Errorf("invalid value for %s: must be true or false", k)
		}
		str = norm
	}
	if k == settingRegistrationDomains {
		norm, err := normalizeRegistrationDomains(str)
		if err != nil {
			return "", err
		}
		str = norm
	}
	return str, nil
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	decoder := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	decoder.UseNumber() // Do not round quota input through float64 before validation.
	if decoder.Decode(&in) != nil {
		jerr(w, 400, "bad request")
		return
	}
	// Only existing, editable settings can be written; anything else the
	// browser sends (such as derived flags like smtp_pass_set) is ignored and
	// never appears in the activity log.
	editable := map[string]bool{}
	if keys, err := s.St.Repos().Settings().EditableKeys(context.Background()); err == nil {
		for _, k := range keys {
			editable[k] = true
		}
	}
	updates := make(map[string]string, len(in))
	for k, v := range in {
		if !editable[k] {
			continue
		}
		var str string
		switch t := v.(type) {
		case bool:
			str = strconv.FormatBool(t)
		case json.Number:
			str = t.String()
			if k != store.DefaultStorageQuotaKey {
				n, err := t.Float64()
				if err != nil {
					continue
				}
				str = strconv.FormatFloat(n, 'f', -1, 64)
			}
		case string:
			str = t
		default:
			if k == settingLocalLogin {
				jerr(w, 400, "invalid value for "+k)
				return
			}
			if owned, _ := validateShareSetting(k, ""); owned {
				jerr(w, 400, "invalid value for "+k)
				return
			}
			if owned, _ := validateAccountSetting(k, ""); owned {
				jerr(w, 400, "invalid value for "+k)
				return
			}
			if k == "audit_retention_days" || k == "audit_log_ip" || auditForwardKeys[k] {
				jerr(w, 400, "invalid value for "+k)
				return
			}
			if owned, _ := validateBackgroundSetting(k, ""); owned {
				jerr(w, 400, "invalid value for "+k)
				return
			}
			if owned, _ := validateMFASetting(k, ""); owned {
				jerr(w, 400, "invalid value for "+k)
				return
			}
			if owned, _ := validateIdleSetting(k, ""); owned {
				jerr(w, 400, "invalid value for "+k)
				return
			}
			if k == store.DefaultStorageQuotaKey {
				jerr(w, 400, "invalid default storage quota")
				return
			}
			continue
		}
		norm, err := s.normalizeSetting(k, str)
		if err != nil {
			jerr(w, 400, err.Error())
			return
		}
		str = norm
		if s.isManagedSetting(k) {
			// Set by the deployment's configuration: the screen cannot change it.
			if str != s.St.Setting(k) && !(secretKeys[k] && str == "") {
				jerr(w, 400, fmt.Sprintf("%s is managed by the server configuration and cannot be changed here", k))
				return
			}
			continue
		}
		// Only turning local login off needs the lockout check; the whole batch is rejected.
		if k == settingLocalLogin && str == "false" && s.St.SettingBool(settingLocalLogin) {
			if safe, msg := s.localLoginSafe(s.ctxUser(r).ID); !safe {
				jerr(w, 400, msg)
				return
			}
		}
		if secretKeys[k] && str == "" {
			continue // blank = keep
		}
		if k == "jwt_secret" || k == "ui_logo" || k == "ui_favicon" {
			continue // managed via upload endpoints
		}
		updates[k] = str
	}
	// The stored SMTP password is only ever sent to the server it was entered
	// for: changing where or how it is sent requires typing it again, so an
	// administrator session cannot redirect it to a server of its own.
	if _, typed := updates["smtp_pass"]; !typed && s.St.Setting("smtp_pass") != "" {
		for _, k := range []string{"smtp_host", "smtp_port", "smtp_user", "smtp_tls"} {
			if v, ok := updates[k]; ok && v != s.St.Setting(k) {
				jerr(w, 400, msgSMTPPasswordAgain)
				return
			}
		}
	}
	// Enforcing MFA must not lock out the administrator who switches it on: they
	// need a factor of their own (or an explicit exemption) first.
	if np, ok := updates["mfa_policy"]; ok && (np == "admins" || np == "privileged" || np == "all") {
		if me := s.ctxUser(r); me != nil && me.MFAPolicy != "exempt" && !s.userHasFactor(me) {
			jerr(w, 400, msgMFAEnforceSelf)
			return
		}
	}
	if !s.guardSettingsUpdate(w, r, updates) { // step-up, admin network list, terms (stepup.go)
		return
	}
	if !s.validateStorageUpdate(w, r, updates) { // complete and reachable (storage.go)
		return
	}
	if !s.validateTargetUpdates(w, r, updates) { // multi-tenant SSRF guard (mt_tenant.go)
		return
	}
	olds := make(map[string]string, len(updates))
	for k := range updates {
		olds[k] = s.St.Setting(k)
	}
	tx, err := s.St.Repos().Begin(context.Background())
	if err != nil {
		jerr(w, 500, "settings update failed")
		return
	}
	defer tx.Rollback()
	for k, str := range updates {
		if err := tx.Settings().UpdateEditable(context.Background(), k, str); err != nil {
			jerr(w, 500, "settings update failed")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "settings update failed")
		return
	}
	// The transaction has committed and released the connection.
	s.St.SettingsChanged() // caches keyed on SettingsGen (audit_log_ip) refresh
	me := s.ctxUser(r)
	s.logEvent(me.ID, me.Username, "settings_changed", "settings", settingsChangeDetail(updates, olds))
	for _, k := range []string{"audit_retention_days", "audit_log_ip", "application_url"} {
		if v, ok := updates[k]; ok && v != olds[k] {
			s.logEvent(me.ID, me.Username, map[string]string{"audit_retention_days": "audit_retention_changed", "audit_log_ip": "audit_ip_logging_changed", "application_url": "application_url_changed"}[k], "settings", auditValue(olds[k])+" -> "+auditValue(v))
		}
	}
	if np, ok := updates["mfa_policy"]; ok {
		s.logEvent(me.ID, me.Username, "mfa_policy_changed", "settings", "policy="+np)
	}
	if v, ok := updates["storage_backend"]; ok && v != olds["storage_backend"] {
		s.logEvent(me.ID, me.Username, "storage_backend_changed", "settings", auditValue(olds["storage_backend"])+" -> "+auditValue(v)+" ("+s.storageFromSettings().Describe()+")")
	}
	jout(w, 200, map[string]any{"ok": true})
}

// auditValue is a setting value made safe for one audit line.
func auditValue(v string) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, v)
	return "'" + clip(v, 80) + "'"
}

// secretSettingName reports settings whose value must never reach the audit log.
func secretSettingName(k string) bool {
	if secretKeys[k] {
		return true
	}
	if strings.Contains(k, "secret") {
		return true
	}
	for _, suffix := range []string{"_pass", "_password", "_token", "_key"} {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}

// settingsChangeDetail lists the changed settings: names always, old and new
// values only for settings that are not secret.
func settingsChangeDetail(updates, olds map[string]string) string {
	keys := make([]string, 0, len(updates))
	for k, v := range updates {
		if v != olds[k] {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return "no changes"
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if secretSettingName(k) || strings.HasPrefix(k, "tpl_") {
			parts = append(parts, k)
			continue
		}
		parts = append(parts, k+": "+auditValue(olds[k])+" -> "+auditValue(updates[k]))
	}
	return joinWithinAuditField(parts)
}

// joinWithinAuditField joins parts with "; " so the result fits one audit
// field. Parts that do not fit are not cut off silently: they are counted as
// " (+N more)".
func joinWithinAuditField(parts []string) string {
	var b strings.Builder
	for i, p := range parts {
		sep := ""
		if i > 0 {
			sep = "; "
		}
		rest := len(parts) - i
		limit := store.AuditFieldMax
		if rest > 1 {
			limit -= len(fmt.Sprintf(" (+%d more)", rest)) // keep room to count what follows
		}
		if b.Len()+len(sep)+len(p) > limit {
			if i == 0 {
				b.WriteString(clipBytes(p, store.AuditFieldMax-len(fmt.Sprintf(" (+%d more)", rest))))
				rest--
			}
			if rest > 0 {
				fmt.Fprintf(&b, " (+%d more)", rest)
			}
			return b.String()
		}
		b.WriteString(sep + p)
	}
	return b.String()
}

// clipBytes cuts v to at most n bytes at a character boundary.
func clipBytes(v string, n int) string {
	if len(v) <= n {
		return v
	}
	for n > 0 && !utf8.RuneStart(v[n]) {
		n--
	}
	return v[:n]
}

// ---------- branding & backgrounds ----------

var imgExt = map[string]string{"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "image/gif": ".gif", "image/svg+xml": ".svg", "image/x-icon": ".ico", "image/vnd.microsoft.icon": ".ico"}

var imgMime = map[string]string{".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif", ".svg": "image/svg+xml", ".ico": "image/x-icon"}

func readImage(w http.ResponseWriter, r *http.Request, allowSVG bool) ([]byte, string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		jerr(w, 400, "upload too large or invalid")
		return nil, "", false
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		jerr(w, 400, "file required")
		return nil, "", false
	}
	defer f.Close()
	data, _ := io.ReadAll(f)
	ct := http.DetectContentType(data)
	if strings.Contains(string(data[:min(len(data), 512)]), "<svg") && allowSVG {
		ct = "image/svg+xml"
	}
	if ct == "text/xml; charset=utf-8" && allowSVG && strings.Contains(string(data), "<svg") {
		ct = "image/svg+xml"
	}
	if len(data) >= 4 && string(data[:4]) == "\x00\x00\x01\x00" {
		ct = "image/x-icon"
	}
	ext, ok := imgExt[ct]
	if !ok || (ext == ".svg" && !allowSVG) {
		jerr(w, 400, "unsupported image type")
		return nil, "", false
	}
	return data, ext, true
}

func (s *Server) uploadBranding(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	if kind != "logo" && kind != "favicon" {
		jerr(w, 404, "not found")
		return
	}
	data, ext, ok := readImage(w, r, true)
	if !ok {
		return
	}
	name := kind + ext
	p, err := localJoin(filepath.Join(s.St.DataDir, "branding"), name)
	if err != nil {
		jerr(w, 400, "invalid branding name")
		return
	}
	s.clearBranding(kind)
	os.WriteFile(p, data, 0o600)
	s.St.Repos().Settings().Update(context.Background(), "ui_"+kind, name)
	jout(w, 200, map[string]any{"ok": true})
}

func (s *Server) clearBranding(kind string) {
	if old := s.St.Setting("ui_" + kind); old != "" {
		os.Remove(filepath.Join(s.St.DataDir, "branding", filepath.Base(old)))
	}
}

func (s *Server) deleteBranding(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	if kind != "logo" && kind != "favicon" {
		jerr(w, 404, "not found")
		return
	}
	s.clearBranding(kind)
	s.St.Repos().Settings().Clear(context.Background(), "ui_"+kind)
	jout(w, 200, map[string]any{"ok": true})
}

// serveImage serves the image name (a single file name) from the trusted
// directory dir.
func serveImage(w http.ResponseWriter, r *http.Request, dir, name string) {
	p, err := localJoin(dir, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ext := strings.ToLower(filepath.Ext(p))
	ct, ok := imgMime[ext]
	f, err := os.Open(p)
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, filepath.Base(p), st.ModTime(), f)
}

func (s *Server) serveBranding(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	if kind != "logo" && kind != "favicon" {
		http.NotFound(w, r)
		return
	}
	name := s.St.Setting("ui_" + kind)
	if name == "" {
		http.NotFound(w, r)
		return
	}
	serveImage(w, r, filepath.Join(s.St.DataDir, "branding"), filepath.Base(name))
}

func (s *Server) listBackgrounds(w http.ResponseWriter, r *http.Request) {
	ents, _ := os.ReadDir(filepath.Join(s.St.DataDir, "backgrounds"))
	out := []string{}
	for _, e := range ents {
		if _, ok := imgMime[strings.ToLower(filepath.Ext(e.Name()))]; ok && !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	jout(w, 200, out)
}

func (s *Server) uploadBackground(w http.ResponseWriter, r *http.Request) {
	data, ext, ok := readImage(w, r, false)
	if !ok {
		return
	}
	name := randHex(6) + ext
	os.WriteFile(filepath.Join(s.St.DataDir, "backgrounds", name), data, 0o600)
	jout(w, 201, map[string]any{"name": name})
}

func (s *Server) serveBackground(w http.ResponseWriter, r *http.Request) {
	serveImage(w, r, filepath.Join(s.St.DataDir, "backgrounds"), filepath.Base(chi.URLParam(r, "file")))
}

func (s *Server) deleteBackground(w http.ResponseWriter, r *http.Request) {
	// Unsafe names cannot exist in the folder; answer as before without touching disk.
	if p, err := localJoin(filepath.Join(s.St.DataDir, "backgrounds"), filepath.Base(chi.URLParam(r, "file"))); err == nil {
		os.Remove(p)
	}
	jout(w, 200, map[string]any{"ok": true})
}

// ---------- themes ----------

type Theme struct {
	ID       int64             `json:"id"`
	Name     string            `json:"name"`
	Category string            `json:"category"`
	Bundled  bool              `json:"bundled"`
	Active   bool              `json:"active"`
	Data     map[string]string `json:"data"`
}

var colorRe = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)
var themeKeys = []string{"primary", "bg", "surface", "text", "muted", "border", "danger"}

func sanitizeTheme(in map[string]string) (map[string]string, error) {
	if len(in) != len(themeKeys) {
		return nil, fmt.Errorf("all seven theme colors required; no extra fields allowed")
	}
	out := map[string]string{}
	for _, k := range themeKeys {
		v := in[k]
		if !colorRe.MatchString(v) {
			return nil, fmt.Errorf("%s must be a hex colour", k)
		}
		out[k] = v
	}
	return out, nil
}

// allThemes returns every theme, bundled first, then by name.
func (s *Server) allThemes() []Theme {
	return themesFrom(s.St.Repos().Themes().List(context.Background()))
}

// themesFrom turns stored themes into API themes.
func themesFrom(recs []ports.ThemeRecord, _ error) []Theme {
	out := []Theme{}
	for _, rec := range recs {
		t := Theme{ID: rec.ID, Name: rec.Name, Category: rec.Category, Bundled: rec.Bundled, Active: rec.Active}
		json.Unmarshal([]byte(rec.Data), &t.Data)
		out = append(out, t)
	}
	return out
}

func (s *Server) activeTheme(w http.ResponseWriter, r *http.Request) {
	t := themesFrom(s.St.Repos().Themes().ListActive(context.Background()))
	if len(t) == 0 {
		jout(w, 200, nil)
		return
	}
	jout(w, 200, t[0])
}

func (s *Server) listThemes(w http.ResponseWriter, r *http.Request) {
	jout(w, 200, s.allThemes())
}

func (s *Server) saveTheme(w http.ResponseWriter, r *http.Request) {
	var t Theme
	if decodeMailRequest(w, r, &t) != nil || strings.TrimSpace(t.Name) == "" || len(t.Name) > 80 || !utf8.ValidString(t.Name) || strings.IndexFunc(t.Name, unicode.IsControl) >= 0 || t.ID < 0 {
		jerr(w, 400, "valid theme name and ID required")
		return
	}
	data, err := sanitizeTheme(t.Data)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	b, _ := json.Marshal(data)
	if t.ID > 0 {
		n, err := s.St.Repos().Themes().UpdateCustom(context.Background(), t.ID, strings.TrimSpace(t.Name), string(b))
		if err != nil {
			jerr(w, 400, "theme update failed; name may already be used")
			return
		}
		if n == 0 {
			jerr(w, 400, "theme not editable")
			return
		}
	} else if err := s.St.Repos().Themes().Create(context.Background(), strings.TrimSpace(t.Name), string(b)); err != nil {
		jerr(w, 400, "name already used")
		return
	}
	jout(w, 200, map[string]any{"ok": true})
}

func (s *Server) deleteTheme(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if n, _ := s.St.Repos().Themes().DeleteCustomInactive(context.Background(), id); n == 0 {
		jerr(w, 400, "cannot delete bundled or active theme")
		return
	}
	jout(w, 200, map[string]any{"ok": true})
}

func (s *Server) activateTheme(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	tx, err := s.St.Repos().Begin(context.Background())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	if err := tx.Themes().DeactivateAll(context.Background()); err != nil {
		jerr(w, 500, "database error")
		return
	}
	n, err := tx.Themes().Activate(context.Background(), id)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if n == 0 {
		jerr(w, 404, "not found")
		return
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "database error")
		return
	}
	jout(w, 200, map[string]any{"ok": true})
}

// ---------- stats ----------

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	st := s.St.Repos().Stats()
	ctx := context.Background()
	q := func(n int64, _ error) int64 { return n }
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	type day struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	perDay := []day{}
	days, _ := st.DownloadsPerDay(ctx, time.Now().AddDate(0, 0, -14))
	for _, d := range days {
		perDay = append(perDay, day{Day: d.Day, Count: d.Count})
	}
	jout(w, 200, map[string]any{
		"users":             q(st.CountLocalUsers(ctx)),
		"shares":            q(st.CountShares(ctx)),
		"active_shares":     q(st.CountActiveShares(ctx, time.Now())),
		"files":             q(st.CountFiles(ctx)),
		"storage_bytes":     q(st.SumFileBytes(ctx)),
		"downloads":         q(st.CountDownloads(ctx)),
		"downloads_per_day": perDay,
		"system": map[string]any{
			"version": s.Version, "go": runtime.Version(), "os": runtime.GOOS + "/" + runtime.GOARCH,
			"uptime_seconds": int(time.Since(s.Started).Seconds()), "mem_bytes": m.Sys, "goroutines": runtime.NumGoroutine(),
		},
	})
}

// ---------- backups ----------

var backupRe = regexp.MustCompile(`^(?:sendora-plain-\d{8}-\d{6}|sendora-(?:encrypted|preimport)-\d{8}-\d{6}-[a-f0-9]{12})\.db$`)

func (s *Server) makeBackup() (string, error) { return s.makeBackupAs("sendora-encrypted-") }

// makeBackupAs writes a backup named prefix+timestamp+random. Only the
// "sendora-encrypted-" prefix is subject to automatic pruning.
func (s *Server) makeBackupAs(prefix string) (string, error) {
	if s.St.IsEncrypted() {
		name := prefix + time.Now().Format("20060102-150405") + "-" + randHex(6) + ".db"
		// Do not expose a partly generated backup through list/download endpoints.
		temp := filepath.Join(s.St.DataDir, "backups", ".pending-"+name)
		if err := s.St.ExportEncryptedBackup(temp); err != nil {
			return "", err
		}
		if err := os.Rename(temp, filepath.Join(s.St.DataDir, "backups", name)); err != nil {
			os.Remove(temp)
			return "", err
		}
		return name, nil
	}
	// Explicit plaintext fixtures only; production entrypoint requires SQLCipher.
	name := "sendora-plain-" + time.Now().Format("20060102-150405") + ".db"
	p := filepath.Join(s.St.DataDir, "backups", name)
	if err := s.St.Repos().System().CopyTo(context.Background(), p); err != nil {
		return "", err
	}
	if err := os.Chmod(p, 0o600); err != nil {
		os.Remove(p)
		return "", err
	}
	return name, nil
}

func (s *Server) listBackups(w http.ResponseWriter, r *http.Request) {
	ents, _ := os.ReadDir(filepath.Join(s.St.DataDir, "backups"))
	out := []map[string]any{}
	for _, e := range ents {
		if backupRe.MatchString(e.Name()) && !e.IsDir() {
			i, err := e.Info()
			if err != nil {
				continue
			}
			out = append(out, map[string]any{"name": e.Name(), "size": i.Size(), "created_at": i.ModTime(), "encrypted": strings.HasPrefix(e.Name(), "sendora-encrypted-") || strings.HasPrefix(e.Name(), "sendora-preimport-"), "pre_import": strings.HasPrefix(e.Name(), "sendora-preimport-")})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a]["name"].(string) > out[b]["name"].(string) })
	jout(w, 200, out)
}

func (s *Server) createBackup(w http.ResponseWriter, r *http.Request) {
	n, err := s.makeBackup()
	if err != nil {
		log.Printf("create backup failed: %v", err)
		jerr(w, 500, "backup failed (details are in the server log)")
		return
	}
	me := s.ctxUser(r)
	s.logEvent(me.ID, me.Username, "backup_created", n, "")
	jout(w, 201, map[string]any{"name": n})
}

// backupDownloadInfo names the backup and its size for the backup_downloaded
// record, which is written before the file is served (critical middleware).
func (s *Server) backupDownloadInfo(r *http.Request) (string, string, bool) {
	n := chi.URLParam(r, "name")
	if !backupRe.MatchString(n) {
		return "", "", false
	}
	st, err := os.Stat(filepath.Join(s.St.DataDir, "backups", n))
	if err != nil || !st.Mode().IsRegular() {
		return "", "", false
	}
	return n, "size=" + strconv.FormatInt(st.Size(), 10) + " bytes", true
}

func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	n := chi.URLParam(r, "name")
	if !backupRe.MatchString(n) {
		jerr(w, 404, "not found")
		return
	}
	serveDisk(w, r, filepath.Join(s.St.DataDir, "backups", n), n)
}

func (s *Server) deleteBackup(w http.ResponseWriter, r *http.Request) {
	n := chi.URLParam(r, "name")
	if !backupRe.MatchString(n) {
		jerr(w, 404, "not found")
		return
	}
	os.Remove(filepath.Join(s.St.DataDir, "backups", n))
	me := s.ctxUser(r)
	s.logEvent(me.ID, me.Username, "backup_deleted", n, "")
	jout(w, 200, map[string]any{"ok": true})
}
