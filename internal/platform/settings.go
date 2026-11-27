// SPDX-License-Identifier: AGPL-3.0-or-later

package platform

import (
	"context"
	"fmt"
	"io"
	"net/mail"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/sendora-app/sendora/internal/storage"
)

// Platform settings: stored in platform.db, editable in the console, and set
// (read-only in the console) by SENDORA_<KEY IN CAPITALS> or its _FILE form,
// like the tenant settings. The base domain is environment-only
// (SENDORA_BASE_DOMAIN): the console itself is reached through it.

type settingDef struct{ Key, Grp, Val string }

var settingDefaults = []settingDef{
	{"tenant_idle_minutes", "system", "15"},
	{"max_open_tenants", "system", "50"},
	{"tenant_maintenance_hours", "system", "6"},
	{"default_max_users", "system", "0"},
	{"default_max_storage_bytes", "system", "0"},
	{"platform_audit_retention_days", "system", "365"},
	{"platform_smtp_host", "email", ""},
	{"platform_smtp_port", "email", "587"},
	{"platform_smtp_user", "email", ""},
	{"platform_smtp_pass", "email", ""},
	{"platform_smtp_from", "email", ""},
	{"platform_smtp_tls", "email", "starttls"},
	// Platform administrators must use an authenticator app (owner decision;
	// false lets them sign in with a password only, enrolment stays possible).
	{"platform_mfa_required", "security", "true"},
	// What the platform provides to new tenants: none (they set up their own
	// storage), platform (the default bucket with their prefix) or local disk.
	{"new_tenant_storage_offer", "storage", "none"},
	// Master key versions (D46); internal, changed only through the master
	// rotation (Platform.SetMasterSetting), never through the settings form.
	{"master_active_version", "system", "1"},
	{"master_rotation_target", "system", "0"},
	{"master_retired", "system", ""},
	{"master_rotation_note", "system", ""},
}

// MasterSettings are the internal master-rotation settings.
var MasterSettings = map[string]bool{"master_active_version": true, "master_rotation_target": true, "master_retired": true, "master_rotation_note": true}

func init() {
	// The platform default object storage: the storage_* settings of a
	// single-tenant installation with a platform_ prefix (internal/storage).
	for _, st := range storage.Settings {
		if st.Key == "backup_remote_enabled" {
			continue
		}
		settingDefaults = append(settingDefaults, settingDef{"platform_" + st.Key, "storage", st.Default})
		if st.Secret {
			SecretSettings["platform_"+st.Key] = true
		}
	}
}

// SecretSettings are never returned to the console.
var SecretSettings = map[string]bool{"platform_smtp_pass": true}

// IsStorageSetting reports whether key is a platform default storage setting
// (platform_storage_*); they are changed through the console's storage form.
func IsStorageSetting(key string) bool {
	k, ok := strings.CutPrefix(key, "platform_")
	return ok && storage.IsSetting(k) && k != "backup_remote_enabled"
}

var settingAliases = map[string][]string{"platform_smtp_pass": {"SENDORA_PLATFORM_SMTP_PASSWORD"}}

// SettingEnvNames lists every environment variable the platform settings read
// (for the unknown-variable warning).
func SettingEnvNames() []string {
	var out []string
	for _, d := range settingDefaults {
		for _, n := range append([]string{envName(d.Key)}, settingAliases[d.Key]...) {
			out = append(out, n, n+"_FILE")
		}
	}
	return out
}

func envName(key string) string { return "SENDORA_" + strings.ToUpper(key) }

// NormalizeSetting validates one platform setting value.
func NormalizeSetting(key, v string) (string, error) {
	if !SecretSettings[key] {
		v = strings.TrimSpace(v)
	}
	intRange := func(lo, hi int64) (string, error) {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < lo || n > hi {
			return "", fmt.Errorf("must be a whole number from %d to %d", lo, hi)
		}
		return strconv.FormatInt(n, 10), nil
	}
	if IsStorageSetting(key) {
		norm, _, err := storage.NormalizeSetting(strings.TrimPrefix(key, "platform_"), v)
		return norm, err
	}
	switch key {
	case "new_tenant_storage_offer":
		v = strings.ToLower(v)
		if !ValidOffer(v) {
			return "", fmt.Errorf("must be none, platform or local")
		}
		return v, nil
	case "platform_mfa_required":
		switch strings.ToLower(v) {
		case "true", "1", "yes":
			return "true", nil
		case "false", "0", "no":
			return "false", nil
		}
		return "", fmt.Errorf("must be true or false")
	case "tenant_idle_minutes":
		return intRange(1, 1440)
	case "max_open_tenants":
		return intRange(1, 10000)
	case "tenant_maintenance_hours":
		return intRange(1, 168)
	case "default_max_users":
		return intRange(0, 1000000)
	case "default_max_storage_bytes":
		return intRange(0, 1<<60)
	case "platform_audit_retention_days":
		return intRange(90, 36500)
	case "platform_smtp_port":
		return intRange(1, 65535)
	case "platform_smtp_tls":
		if v != "none" && v != "tls" && v != "starttls" {
			return "", fmt.Errorf("must be none, tls or starttls")
		}
		return v, nil
	case "platform_smtp_from":
		if v == "" {
			return v, nil
		}
		if _, err := mail.ParseAddress(v); err != nil || strings.ContainsAny(v, "\r\n") {
			return "", fmt.Errorf("invalid sender address")
		}
		return v, nil
	case "platform_smtp_host", "platform_smtp_user":
		if strings.ContainsAny(v, "\r\n\x00 ") || len(v) > 255 {
			return "", fmt.Errorf("invalid value")
		}
		return v, nil
	case "platform_smtp_pass":
		if strings.ContainsAny(v, "\r\n\x00") || len(v) > 1024 {
			return "", fmt.Errorf("invalid value")
		}
		return v, nil
	}
	return "", fmt.Errorf("unknown setting")
}

// Setting returns a platform setting.
func (p *Platform) Setting(key string) string {
	v, _ := p.repo.PlatformSettings().Get(context.Background(), key)
	return v
}

// SettingInt returns a platform setting as a number (def when unset/invalid).
func (p *Platform) SettingInt(key string, def int64) int64 {
	n, err := strconv.ParseInt(p.Setting(key), 10, 64)
	if err != nil {
		return def
	}
	return n
}

// SettingIntRange is SettingInt clamped to [lo, hi] (values go into int and
// time.Duration conversions).
func (p *Platform) SettingIntRange(key string, def, lo, hi int64) int64 {
	n := p.SettingInt(key, def)
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// MFARequired reports whether platform administrators must use an
// authenticator app (platform_mfa_required, default true).
func (p *Platform) MFARequired() bool { return p.Setting("platform_mfa_required") != "false" }

// Settings returns all editable settings; secrets only say whether they are set.
func (p *Platform) Settings() map[string]any {
	out := map[string]any{}
	for _, d := range settingDefaults {
		if IsStorageSetting(d.Key) || MasterSettings[d.Key] {
			continue // GET /api/platform/storage; the master rotation has its own endpoints
		}
		v := p.Setting(d.Key)
		if SecretSettings[d.Key] {
			out[d.Key+"_set"] = v != ""
			continue
		}
		out[d.Key] = v
	}
	return out
}

// PutSettings validates and stores settings; managed (environment) ones are refused.
func (p *Platform) PutSettings(in map[string]string, managed map[string]bool) ([]string, error) {
	defer p.changed()
	known := map[string]bool{}
	for _, d := range settingDefaults {
		known[d.Key] = true
	}
	norm := map[string]string{}
	for k, v := range in {
		if !known[k] || IsStorageSetting(k) || MasterSettings[k] {
			return nil, fmt.Errorf("%s: unknown setting", k)
		}
		if managed[k] {
			return nil, fmt.Errorf("%s is set by the server configuration", k)
		}
		if SecretSettings[k] && v == "" {
			continue // empty = keep
		}
		n, err := NormalizeSetting(k, v)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", k, err)
		}
		norm[k] = n
	}
	ctx := context.Background()
	tx, err := p.repo.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var changed []string
	for k, v := range norm {
		if err := tx.PlatformSettings().Update(ctx, k, v); err != nil {
			return nil, err
		}
		changed = append(changed, k)
	}
	sort.Strings(changed)
	return changed, tx.Commit()
}

// StorageSettings returns the platform default storage settings under their
// storage_* names (the form of internal/storage), secrets included.
func (p *Platform) StorageSettings() map[string]string {
	out := map[string]string{}
	for _, k := range storageKeys() {
		out[k] = p.Setting("platform_" + k)
	}
	return out
}

// PutStorageSettings stores the complete platform default storage settings
// (storage_* names, validated by MergeStorageSettings); managed ones are kept.
func (p *Platform) PutStorageSettings(next map[string]string, managed map[string]bool) ([]string, error) {
	defer p.changed()
	cur := p.StorageSettings() // before the transaction: the database has one connection
	ctx := context.Background()
	tx, err := p.repo.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var changed []string
	for _, k := range storageKeys() {
		v, ok := next[k]
		if !ok || managed["platform_"+k] || v == cur[k] {
			continue
		}
		if err := tx.PlatformSettings().Update(ctx, "platform_"+k, v); err != nil {
			return nil, err
		}
		changed = append(changed, "platform_"+k)
	}
	return changed, tx.Commit()
}

// ApplyEnv writes settings given by the environment and returns the set of
// managed keys. An invalid value is an error naming the variable.
func (p *Platform) ApplyEnv() (map[string]bool, error) {
	managed := map[string]bool{}
	for _, d := range settingDefaults {
		for _, name := range append([]string{envName(d.Key)}, settingAliases[d.Key]...) {
			v, ok, err := readEnv(name)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			n, err := NormalizeSetting(d.Key, v)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", name, err)
			}
			if err := p.repo.PlatformSettings().Update(context.Background(), d.Key, n); err != nil {
				return nil, err
			}
			managed[d.Key] = true
			break
		}
	}
	return managed, nil
}

func readEnv(name string) (string, bool, error) {
	if f := os.Getenv(name + "_FILE"); f != "" {
		fh, err := os.Open(f)
		if err != nil {
			return "", true, fmt.Errorf("%s_FILE: %v", name, err)
		}
		defer fh.Close()
		b, err := io.ReadAll(io.LimitReader(fh, 64<<10+1))
		if err != nil || len(b) > 64<<10 {
			return "", true, fmt.Errorf("%s_FILE: unreadable or larger than 64 KiB", name)
		}
		return strings.TrimRight(string(b), "\r\n"), true, nil
	}
	v, ok := os.LookupEnv(name)
	return v, ok, nil
}

// MailDefault maps a tenant SMTP setting (smtp_host, ...) to the platform's
// default SMTP value, used by tenants that have no SMTP server of their own.
func (p *Platform) MailDefault(key string) string {
	return p.Setting("platform_" + key)
}
