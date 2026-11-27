// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sendora-app/sendora/internal/store"
)

type mailBundleText struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}
type mailBundle struct {
	Format    string                    `json:"format"`
	Version   int                       `json:"version"`
	Language  string                    `json:"language"`
	Name      string                    `json:"name"`
	Templates map[string]mailBundleText `json:"templates"`
}

func validateMailBundle(b *mailBundle) string {
	if b.Format != "sendora-email-templates" || b.Version != 1 {
		return "unsupported translation format or version"
	}
	if !store.ValidMailCode(b.Language) || b.Name == "" || strings.TrimSpace(b.Name) != b.Name || len(b.Name) > 80 || !utf8.ValidString(b.Name) || strings.IndexFunc(b.Name, unicode.IsControl) >= 0 {
		return "valid language code and name required"
	}
	// Events added after the first export format (the welcome email) stay optional,
	// so translation files exported by an older version keep importing.
	known := 0
	for _, event := range store.MailEvents {
		if _, ok := b.Templates[event]; ok {
			known++
		}
	}
	if known != len(b.Templates) {
		return "all required mail events must be present (and no unknown ones)"
	}
	for _, event := range store.MailEvents {
		text, ok := b.Templates[event]
		if !ok {
			if store.IsOptionalMailEvent(event) {
				continue
			}
			return "missing mail event: " + event
		}
		if err := validateMailTemplate(text.Subject, true); err != nil {
			return event + " subject: " + err.Error()
		}
		if err := validateMailTemplate(text.Body, false); err != nil {
			return event + " body: " + err.Error()
		}
	}
	b.Format = "sendora-email-templates"
	return ""
}

func (s *Server) exportMailBundle(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("language")
	name, err := s.St.Repos().Mail().LanguageName(context.Background(), code)
	if err != nil {
		jerr(w, 404, "language not found")
		return
	}
	b := mailBundle{Format: "sendora-email-templates", Version: 1, Language: code, Name: name, Templates: map[string]mailBundleText{}}
	for _, event := range store.MailEvents {
		b.Templates[event] = mailBundleText{Subject: s.St.Setting("subj_" + event + "_" + code), Body: s.St.Setting("tpl_" + event + "_" + code)}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="sendora-email-`+code+`.json"`)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(b)
}

func (s *Server) importMailBundle(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Bundle    mailBundle `json:"bundle"`
		Apply     bool       `json:"apply"`
		Overwrite bool       `json:"overwrite"`
	}
	if decodeMailRequest(w, r, &in) != nil {
		jerr(w, 400, "invalid translation JSON")
		return
	}
	if msg := validateMailBundle(&in.Bundle); msg != "" {
		jerr(w, 400, msg)
		return
	}
	unlock := s.stripe(&s.identityLocks, "mail-languages")
	defer unlock()
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	var exists, count int
	if exists, err = tx.Mail().CountLanguage(ctx, in.Bundle.Language); err != nil {
		jerr(w, 500, "database error")
		return
	}
	if !in.Apply {
		jout(w, 200, map[string]any{"bundle": in.Bundle, "exists": exists != 0, "applied": false})
		return
	}
	if exists != 0 && !in.Overwrite {
		jerr(w, 409, "explicit overwrite confirmation required")
		return
	}
	if exists == 0 {
		if count, err = tx.Mail().CountLanguages(ctx); err != nil {
			jerr(w, 500, "database error")
			return
		}
		if count >= 32 {
			jerr(w, 400, "maximum 32 email languages")
			return
		}
		if err = tx.Mail().AddLanguage(ctx, in.Bundle.Language, in.Bundle.Name); err != nil {
			jerr(w, 500, "import failed")
			return
		}
	}
	for _, event := range store.MailEvents {
		text, present := in.Bundle.Templates[event]
		if !present {
			continue // optional event not in this file: keep the current text
		}
		for _, part := range []struct{ prefix, value string }{{"subj_", text.Subject}, {"tpl_", text.Body}} {
			key := part.prefix + event + "_" + in.Bundle.Language
			if err = tx.Mail().PutTemplate(ctx, key, part.value); err != nil {
				jerr(w, 500, "import failed")
				return
			}
			if in.Bundle.Language == "en" && part.prefix == "tpl_" {
				if err = tx.Mail().SetTemplate(ctx, "tpl_"+event, part.value); err != nil {
					jerr(w, 500, "import failed")
					return
				}
			}
		}
	}
	if err = tx.Commit(); err != nil {
		jerr(w, 500, "import failed")
		return
	}
	jout(w, 200, map[string]any{"applied": true, "language": in.Bundle.Language})
}
