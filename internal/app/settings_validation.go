// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sendora-app/sendora/internal/store"
)

var boolSettings = map[string]bool{
	"show_language_selector": true, "allow_reverse_shares": true, "allow_self_registration": true,
	"require_email_verification": true, "auto_clean_files": true, "backups_enabled": true,
	"ui_use_unsplash": true, "ui_default_background": true, "audit_log_ip": true,
	"audit_forward_stdout": true, "audit_forward_syslog_tls": true,
}

// intSettings lists the allowed range of each numeric setting.
var intSettings = map[string][2]int{
	"max_expiry_time":      {0, 3650}, // 0 = no maximum
	"default_expiry_time":  {1, 3650},
	"max_share_size":       {0, 100 << 20}, // MB; 0 = no limit
	"clean_files_days":     {0, 3650},
	"expiry_warning_days":  {0, 365},
	"backup_keep":          {1, 365},
	"ui_slideshow_seconds": {5, 3600},
	"smtp_port":            {1, 65535},
	"audit_retention_days": {store.AuditRetentionMinDays, 365}, // never shorter: lowering it must not remove evidence
}

func plainText(v string, max int) bool {
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > max || hasFormatRune(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// validateGeneralSetting covers the settings without a dedicated validator, so
// no value can switch a protection off by accident (a negative cleanup age, a
// broken public URL used by the cross-origin check) or bloat every page.
func (s *Server) validateGeneralSetting(key string, val *string) (owned bool, err error) {
	v := *val
	if boolSettings[key] {
		if v != "true" && v != "false" {
			return true, fmt.Errorf("%s must be true or false", key)
		}
		return true, nil
	}
	if r, ok := intSettings[key]; ok {
		if _, ok := parseStrictInt(v, r[0], r[1]); !ok {
			// The generic text is translated in the UI; for audit_retention_days it
			// reads "from 90 to 365".
			return true, fmt.Errorf("%s must be a whole number from %d to %d", key, r[0], r[1])
		}
		return true, nil
	}
	switch key {
	case "application_name":
		if strings.TrimSpace(v) == "" || !plainText(v, 80) {
			return true, fmt.Errorf("application name must be 1 to 80 characters without control characters")
		}
	case "application_url":
		v = strings.TrimRight(strings.TrimSpace(v), "/")
		if v != "" {
			u, e := url.Parse(v)
			if e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
				return true, fmt.Errorf("application URL must look like https://files.example.com (no path, query or credentials)")
			}
		}
		*val = v
	case "default_language":
		if !s.St.ValidUILanguage(v) {
			return true, fmt.Errorf("unsupported UI language")
		}
	case "smtp_tls":
		if v != "none" && v != "tls" && v != "starttls" {
			return true, fmt.Errorf("SMTP security must be none, tls or starttls")
		}
	case "smtp_host":
		if len(v) > 253 || strings.ContainsAny(v, " /\\@") || !plainText(v, 253) {
			return true, fmt.Errorf("invalid SMTP server name")
		}
	case "smtp_user":
		if !plainText(v, 320) {
			return true, fmt.Errorf("invalid SMTP username")
		}
	case "smtp_from":
		if v = strings.TrimSpace(v); v != "" {
			if _, e := mail.ParseAddress(v); e != nil || strings.ContainsAny(v, "\r\n") {
				return true, fmt.Errorf("invalid SMTP sender address")
			}
		}
		*val = v
	case "audit_forward_syslog":
		norm, err := validateForwardSyslog(v)
		if err != nil {
			return true, err
		}
		*val = norm
	case "audit_forward_webhook_url":
		norm, err := validateForwardWebhook(v)
		if err != nil {
			return true, err
		}
		*val = norm
	case "ui_background":
		if !plainText(v, 200) || strings.ContainsAny(v, "/\\") {
			return true, fmt.Errorf("invalid background")
		}
	default:
		return false, nil
	}
	return true, nil
}
