// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Variables the application supplies to templates (internal/app/mail.go mailVars).
var knownMailVars = map[string]bool{
	"ApplicationName": true, "RecipientName": true, "SenderName": true, "URL": true, "Message": true,
	"Expires": true, "ShareName": true, "Code": true, "DownloadCount": true, "FileName": true,
	"FileNames": true, "StartedAt": true, "Username": true, "LoginURL": true, "SetPasswordURL": true,
	"ExpiresDays": true, "Time": true, "Browser": true,
}

var mailVarRE = regexp.MustCompile(`\{\{\.([A-Za-z]+)\}\}`)

// mailVarSet returns the variables used by a template and fails when the template
// contains anything other than plain {{.Variable}} actions.
func mailVarSet(t *testing.T, label, text string) []string {
	t.Helper()
	matches := mailVarRE.FindAllStringSubmatch(text, -1)
	if strings.Count(text, "{{") != len(matches) || strings.Count(text, "}}") != len(matches) {
		t.Fatalf("%s: only plain {{.Variable}} actions are allowed: %q", label, text)
	}
	seen := map[string]bool{}
	for _, m := range matches {
		if !knownMailVars[m[1]] {
			t.Fatalf("%s: unknown variable %s", label, m[1])
		}
		seen[m[1]] = true
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func TestMailTemplatesCoverEveryEventAndLanguage(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	for _, event := range MailEvents {
		enSubject, enBody := MailDefaults(event, "en")
		if enSubject == "" || enBody == "" {
			t.Fatalf("%s: English default missing", event)
		}
		enSubjectVars := strings.Join(mailVarSet(t, event+"/en subject", enSubject), ",")
		enBodyVars := strings.Join(mailVarSet(t, event+"/en body", enBody), ",")
		for _, language := range MailLanguages {
			label := event + "/" + language
			subject, body := MailDefaults(event, language)
			if strings.TrimSpace(subject) == "" || strings.TrimSpace(body) == "" {
				t.Fatalf("%s: empty default", label)
			}
			// Seeded settings must exist and, for fresh databases, equal the defaults.
			if got := st.Setting("subj_" + event + "_" + language); got != subject {
				t.Fatalf("%s: seeded subject %q != default %q", label, got, subject)
			}
			if got := st.Setting("tpl_" + event + "_" + language); got != body {
				t.Fatalf("%s: seeded body differs from default", label)
			}
			if got := strings.Join(mailVarSet(t, label+" subject", subject), ","); got != enSubjectVars {
				t.Fatalf("%s: subject variables %q differ from English %q", label, got, enSubjectVars)
			}
			if got := strings.Join(mailVarSet(t, label+" body", body), ","); got != enBodyVars {
				t.Fatalf("%s: body variables %q differ from English %q", label, got, enBodyVars)
			}
			if language == "en" {
				continue
			}
			if subject == enSubject || body == enBody {
				t.Fatalf("%s: still the English text", label)
			}
		}
		if st.Setting("tpl_"+event) != enBody {
			t.Fatalf("%s: legacy English key out of sync", event)
		}
	}
}

func TestMailSeedAddsMissingRowsAndKeepsCustomisedTemplates(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	const custom = "Custom text for {{.Username}}"
	if err := st.SetSetting("tpl_welcome_de", custom); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("subj_share_created_fr", "Custom subject"); err != nil {
		t.Fatal(err)
	}
	// Simulate a database from before a language/event existed.
	for _, key := range []string{"tpl_welcome_es", "subj_welcome_es", "tpl_password_reset_nl", "subj_verify_email_fr"} {
		if _, err := st.DB.Exec(`DELETE FROM settings WHERE key=?`, key); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ { // idempotent across restarts
		if err := st.migrateMailLocalization(); err != nil {
			t.Fatal(err)
		}
	}
	if got := st.Setting("tpl_welcome_de"); got != custom {
		t.Fatalf("customised template overwritten: %q", got)
	}
	if got := st.Setting("subj_share_created_fr"); got != "Custom subject" {
		t.Fatalf("customised subject overwritten: %q", got)
	}
	for _, key := range []string{"tpl_welcome_es", "subj_welcome_es", "tpl_password_reset_nl", "subj_verify_email_fr"} {
		if st.Setting(key) == "" {
			t.Fatalf("missing row %s was not re-added", key)
		}
	}
}

func TestRefinedMailDefaultsOnlyReplaceUntouchedRows(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	for _, r := range refinedMailDefaults {
		if r.previous == r.current {
			t.Fatal("refinement must change the text:", r.key)
		}
		if got := st.Setting(r.key); got != r.current {
			t.Fatalf("%s: fresh install must use the refined text", r.key)
		}
		// Untouched previous default is upgraded.
		if err := st.SetSetting(r.key, r.previous); err != nil {
			t.Fatal(err)
		}
		if err := st.migrateMailLocalization(); err != nil {
			t.Fatal(err)
		}
		if got := st.Setting(r.key); got != r.current {
			t.Fatalf("%s: previous default was not upgraded", r.key)
		}
		// An administrator's text is left alone.
		if err := st.SetSetting(r.key, "my own wording {{.URL}}"); err != nil {
			t.Fatal(err)
		}
		if err := st.migrateMailLocalization(); err != nil {
			t.Fatal(err)
		}
		if got := st.Setting(r.key); got != "my own wording {{.URL}}" {
			t.Fatalf("%s: customised text was overwritten", r.key)
		}
	}
}

func TestTestMailTextIsTranslated(t *testing.T) {
	enSubject, enBody := TestMailText("en")
	if enSubject != "Test email" || enBody != "SMTP works." {
		t.Fatalf("English test mail changed: %q / %q", enSubject, enBody)
	}
	for _, language := range MailLanguages {
		subject, body := TestMailText(language)
		if subject == "" || body == "" {
			t.Fatalf("%s: empty test mail text", language)
		}
		if language != "en" && (subject == enSubject || body == enBody) {
			t.Fatalf("%s: test mail text is still English", language)
		}
	}
	if s, b := TestMailText("xx"); s != enSubject || b != enBody {
		t.Fatal("unknown language must fall back to English")
	}
}
