// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"database/sql"
	"encoding/json"
	"math"
	"path/filepath"
	"strconv"
	"testing"
)

func TestAdditiveMigrationPreservesExistingData(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "sendora.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"application_name": "My Company", "allow_self_registration": "false", "tpl_verify_email": "Custom code: {{.Code}}", "default_language": "fr", "require_email_verification": "true"} {
		if _, err := db.Exec(`INSERT INTO settings(key,value,grp) VALUES(?,?,?)`, key, value, map[bool]string{true: "email_templates", false: "system"}[key == "tpl_verify_email"]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO users(username,email,password_hash) VALUES('existing','existing@example.com','preserved-hash')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var language, uiLanguage, hash string
	if err := st.DB.QueryRow(`SELECT language,ui_language,password_hash FROM users WHERE username='existing'`).Scan(&language, &uiLanguage, &hash); err != nil || language != "en" || uiLanguage != "en" || hash != "preserved-hash" {
		t.Fatalf("account changed %s %s %v", language, hash, err)
	}
	if st.Setting("tpl_verify_email_en") != "Custom code: {{.Code}}" || st.Setting("tpl_verify_email") != "Custom code: {{.Code}}" {
		t.Fatal("custom template lost")
	}
	// Existing settings are never rewritten by migrations.
	if st.Setting("application_name") != "My Company" || st.Setting("allow_self_registration") != "false" || st.Setting("default_language") != "fr" {
		t.Fatal("existing settings changed by migration")
	}
	for _, event := range MailEvents {
		for _, language := range MailLanguages {
			if st.Setting("tpl_"+event+"_"+language) == "" || st.Setting("subj_"+event+"_"+language) == "" {
				t.Fatal("missing variant", event, language)
			}
		}
	}
	st.SetSetting("tpl_verify_email_en", "Changed after migration")
	st.DB.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	if st.Setting("tpl_verify_email_en") != "Changed after migration" {
		t.Fatal("migration repeated")
	}
}

func TestDownloadDefaultsUpgradePreservesCustomAndUILanguage(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, language := range MailLanguages {
		subject, body := legacyMailDefaults("share_downloaded", language)
		st.SetSetting("subj_share_downloaded_"+language, subject)
		st.SetSetting("tpl_share_downloaded_"+language, body)
	}
	_, oldBody := legacyMailDefaults("share_downloaded", "en")
	st.SetSetting("tpl_share_downloaded", oldBody)
	st.SetSetting("tpl_share_downloaded_fr", "Custom {{.ShareName}} {{.DownloadCount}}")
	st.SetSetting("subj_share_downloaded_es", "Custom subject")
	if _, err := st.DB.Exec(`INSERT INTO users(username,language,ui_language) VALUES('existing','de','nl')`); err != nil {
		t.Fatal(err)
	}
	st.DB.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	for _, language := range MailLanguages {
		subject, body := MailDefaults("share_downloaded", language)
		if language != "fr" && st.Setting("tpl_share_downloaded_"+language) != body {
			t.Fatal("default body not upgraded", language)
		}
		if language != "es" && st.Setting("subj_share_downloaded_"+language) != subject {
			t.Fatal("default subject not upgraded", language)
		}
	}
	_, body := MailDefaults("share_downloaded", "en")
	if st.Setting("tpl_share_downloaded") != body || st.Setting("tpl_share_downloaded_fr") != "Custom {{.ShareName}} {{.DownloadCount}}" || st.Setting("subj_share_downloaded_es") != "Custom subject" {
		t.Fatal("custom or alias migration incorrect")
	}
	var ui, language string
	if err := st.DB.QueryRow(`SELECT ui_language,language FROM users WHERE username='existing'`).Scan(&ui, &language); err != nil || ui != "nl" || language != "de" {
		t.Fatal("persisted preferences changed", ui, language, err)
	}
}

func TestBundledThemesSeedPreservesExisting(t *testing.T) {
	for _, activeName := range []string{"Dark", "My custom theme", "Ocean"} {
		t.Run(activeName, func(t *testing.T) {
			st, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer st.DB.Close()
			if _, err := st.DB.Exec(`DELETE FROM themes`); err != nil {
				t.Fatal(err)
			}
			const customData = `{"primary":"#123456","text":"#abcdef"}`
			if _, err := st.DB.Exec(`INSERT INTO themes(name,category,bundled,data,active) VALUES(?,'custom',0,?,1)`, activeName, customData); err != nil {
				t.Fatal(err)
			}
			st.seed()
			st.seed()
			var active, data, category string
			var count, bundled int
			if err := st.DB.QueryRow(`SELECT name,data,category,bundled FROM themes WHERE active=1`).Scan(&active, &data, &category, &bundled); err != nil {
				t.Fatal(err)
			}
			if active != activeName || data != customData || category != "custom" || bundled != 0 {
				t.Fatal("existing selection or custom theme overwritten")
			}
			st.DB.QueryRow(`SELECT COUNT(*) FROM themes WHERE active=1`).Scan(&count)
			if count != 1 {
				t.Fatal("seed changed active theme count", count)
			}
			for _, theme := range builtinThemes {
				st.DB.QueryRow(`SELECT COUNT(*) FROM themes WHERE name=?`, theme.Name).Scan(&count)
				if count != 1 {
					t.Fatal("missing or duplicate bundled theme", theme.Name, count)
				}
			}
		})
	}
}

func TestBundledThemesFreshDefaultAndContrast(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	var name string
	var count int
	st.DB.QueryRow(`SELECT name FROM themes WHERE active=1`).Scan(&name)
	st.DB.QueryRow(`SELECT COUNT(*) FROM themes WHERE active=1`).Scan(&count)
	if name != "Light" || count != 1 || len(builtinThemes) < 9 {
		t.Fatal("incorrect fresh default or missing theme options", name, count)
	}
	luminance := func(hex string) float64 {
		n, err := strconv.ParseUint(hex[1:], 16, 24)
		if err != nil || len(hex) != 7 {
			t.Fatal("invalid color", hex)
		}
		var l float64
		for i, weight := range []float64{0.2126, 0.7152, 0.0722} {
			c := float64((n>>uint(16-8*i))&255) / 255
			if c <= 0.04045 {
				c /= 12.92
			} else {
				c = math.Pow((c+0.055)/1.055, 2.4)
			}
			l += c * weight
		}
		return l
	}
	contrast := func(a, b string) float64 {
		la, lb := luminance(a), luminance(b)
		return (math.Max(la, lb) + 0.05) / (math.Min(la, lb) + 0.05)
	}
	for _, theme := range builtinThemes {
		var colors map[string]string
		if err := json.Unmarshal([]byte(theme.Data), &colors); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"primary", "bg", "surface", "text", "muted", "border", "danger"} {
			if colors[key] == "" {
				t.Fatal("missing color", theme.Name, key)
			}
		}
		for _, key := range []string{"primary", "danger"} {
			if math.Max(contrast(colors[key], "#000000"), contrast(colors[key], "#ffffff")) < 4.5 {
				t.Fatal("button contrast below WCAG AA", theme.Name, key)
			}
		}
		// Existing palettes remain untouched; all new bundles have readable text,
		// secondary labels, links and errors on their background and surface.
		if theme.Name == "Light" || theme.Name == "Dark" || theme.Name == "Forest" {
			continue
		}
		for _, foreground := range []string{"text", "muted", "primary", "danger"} {
			for _, background := range []string{"bg", "surface"} {
				if contrast(colors[foreground], colors[background]) < 4.5 {
					t.Fatal("text contrast below WCAG AA", theme.Name, foreground, background)
				}
			}
		}
	}
}

func TestFreshSendoraDefaults(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	for key, value := range map[string]string{"application_name": "Sendora", "default_language": "en", "allow_self_registration": "false", "require_email_verification": "true"} {
		if st.Setting(key) != value {
			t.Fatalf("%s=%q", key, st.Setting(key))
		}
	}
}
