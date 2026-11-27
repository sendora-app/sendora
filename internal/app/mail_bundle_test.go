// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"github.com/sendora-app/sendora/internal/store"
	"strings"
	"testing"
)

func TestMailBundleRoundTripAndAtomicImport(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	user := e.mkUser(admin, "translator", false)
	e.want(e.do("GET", "/api/email-templates/export?language=en", user, nil), 403, "export admin only")
	exported := e.do("GET", "/api/email-templates/export?language=en", admin, nil)
	e.want(exported, 200, "export")
	if !strings.Contains(exported.Hdr.Get("Content-Disposition"), "sendora-email-en.json") {
		t.Fatal("not downloadable")
	}
	var b mailBundle
	if err := json.Unmarshal(exported.Body, &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Templates) != len(store.MailEvents) || b.Format != "sendora-email-templates" {
		t.Fatal("invalid export")
	}
	b.Language = "it"
	b.Name = "Italiano"
	b.Templates["verify_email"] = mailBundleText{Subject: "Verifica", Body: "Codice: {{.Code}}"}
	payload := func(apply, overwrite bool) map[string]any {
		return map[string]any{"bundle": b, "apply": apply, "overwrite": overwrite}
	}
	e.want(e.do("POST", "/api/email-templates/import", user, payload(false, false)), 403, "import admin only")
	checked := e.do("POST", "/api/email-templates/import", admin, payload(false, false))
	e.want(checked, 200, "dry run")
	if e.s.St.ValidMailLanguage("it") {
		t.Fatal("dry run persisted")
	}
	e.want(e.do("POST", "/api/email-templates/import", admin, payload(true, false)), 200, "new language import")
	if !e.s.St.ValidMailLanguage("it") || e.s.St.Setting("tpl_verify_email_it") != "Codice: {{.Code}}" {
		t.Fatal("import missing")
	}
	b.Templates["verify_email"] = mailBundleText{Subject: "Updated", Body: "Updated {{.Code}}"}
	e.want(e.do("POST", "/api/email-templates/import", admin, payload(true, false)), 409, "overwrite must be explicit")
	if e.s.St.Setting("tpl_verify_email_it") != "Codice: {{.Code}}" {
		t.Fatal("unconfirmed overwrite")
	}
	e.want(e.do("POST", "/api/email-templates/import", admin, payload(true, true)), 200, "confirmed overwrite")
	b.Templates["verify_email"] = mailBundleText{Subject: "bad\r\nBcc: x", Body: "Bad"}
	e.want(e.do("POST", "/api/email-templates/import", admin, payload(true, true)), 400, "header injection")
	if e.s.St.Setting("tpl_verify_email_it") != "Updated {{.Code}}" {
		t.Fatal("non-atomic invalid import")
	}
	b.Templates["verify_email"] = mailBundleText{Subject: "OK", Body: "{{range .Code}}bad{{end}}"}
	e.want(e.do("POST", "/api/email-templates/import", admin, payload(true, true)), 400, "unsafe template")
	delete(b.Templates, "verify_email")
	e.want(e.do("POST", "/api/email-templates/import", admin, payload(true, true)), 400, "missing event")
	b.Templates["not_an_event"] = mailBundleText{}
	e.want(e.do("POST", "/api/email-templates/import", admin, payload(true, true)), 400, "unknown event")
	b.Language = "../en"
	e.want(e.do("POST", "/api/email-templates/import", admin, payload(true, true)), 400, "invalid code")
	e.want(e.do("POST", "/api/email-templates/import", admin, []byte(`{"bundle":{"format":"sendora-email-templates","version":1,"language":"it","name":"Italiano","templates":{},"secret":"no"}}`), "Content-Type", "application/json"), 400, "unknown JSON fields")
	e.want(e.do("POST", "/api/email-templates/import", admin, []byte(strings.Repeat(" ", 1<<20)+`{}`), "Content-Type", "application/json"), 400, "oversized request")
}

func TestMailBundleImportRoundTrip(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	exported := e.do("GET", "/api/email-templates/export?language=en", admin, nil)
	e.want(exported, 200, "export")
	var b mailBundle
	if err := json.Unmarshal(exported.Body, &b); err != nil {
		t.Fatal(err)
	}
	b.Language = "it"
	b.Name = "Italiano"
	b.Templates["verify_email"] = mailBundleText{Subject: "Verifica", Body: "Codice: {{.Code}}"}
	checked := e.do("POST", "/api/email-templates/import", admin, map[string]any{"bundle": b, "apply": false})
	e.want(checked, 200, "dry run")
	var preview struct {
		Bundle mailBundle `json:"bundle"`
	}
	if err := json.Unmarshal(checked.Body, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Bundle.Format != "sendora-email-templates" {
		t.Fatal("format missing in preview")
	}
	if e.s.St.ValidMailLanguage("it") {
		t.Fatal("dry run persisted")
	}
	e.want(e.do("POST", "/api/email-templates/import", admin, map[string]any{"bundle": b, "apply": true}), 200, "import")
	if e.s.St.Setting("tpl_verify_email_it") != "Codice: {{.Code}}" {
		t.Fatal("import missing")
	}
	exported = e.do("GET", "/api/email-templates/export?language=it", admin, nil)
	e.want(exported, 200, "export imported language")
	if err := json.Unmarshal(exported.Body, &b); err != nil {
		t.Fatal(err)
	}
	if b.Format != "sendora-email-templates" {
		t.Fatal("format missing in export")
	}
	if !strings.Contains(exported.Hdr.Get("Content-Disposition"), "sendora-email-it.json") {
		t.Fatal("export filename wrong")
	}
}
