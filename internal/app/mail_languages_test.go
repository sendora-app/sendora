// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"github.com/sendora-app/sendora/internal/store"
	"strings"
	"testing"
)

func TestCustomMailLanguages(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	user := e.mkUser(admin, "reader", false)
	e.want(e.do("GET", "/api/auth/email-languages", "", nil), 200, "public language names")
	e.want(e.do("POST", "/api/email-languages", user, map[string]any{"code": "it", "name": "Italiano"}), 403, "language creation admin only")
	for _, code := range []string{"../en", "en_x", "a", "pt--br", "pt-br<script>", strings.Repeat("a", 25)} {
		e.want(e.do("POST", "/api/email-languages", admin, map[string]any{"code": code, "name": "Test"}), 400, "reject invalid code")
	}
	for _, name := range []string{"", "Bad\nname", strings.Repeat("x", 81)} {
		e.want(e.do("POST", "/api/email-languages", admin, map[string]any{"code": "it", "name": name}), 400, "reject invalid name")
	}
	added := e.do("POST", "/api/email-languages", admin, map[string]any{"code": " PT-BR ", "name": "Português (Brasil)"})
	e.want(added, 201, "add language")
	if added.S("code") != "pt-br" {
		t.Fatal("not canonicalized")
	}
	e.want(e.do("POST", "/api/email-languages", admin, map[string]any{"code": "pt-br", "name": "Again"}), 409, "duplicate")
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM settings WHERE grp='email_templates' AND key LIKE '%_pt-br'`).Scan(&n)
	if n != 2*len(store.MailEvents) { // subject + body per event
		t.Fatalf("missing template slots %d", n)
	}
	fallback := e.do("POST", "/api/email-templates/preview", admin, map[string]any{"key": "verify_email", "language": "pt-br", "data": map[string]string{"Code": "123456"}})
	e.want(fallback, 200, "English fallback")
	if !strings.Contains(fallback.S("body"), "123456") || !strings.Contains(fallback.S("body"), "verification") {
		t.Fatal("fallback broken", fallback.J())
	}
	e.want(e.do("PUT", "/api/email-templates", admin, map[string]any{"subj_verify_email_pt-br": "Verifique seu email", "tpl_verify_email_pt-br": "Código: {{.Code}}"}), 200, "manual translation")
	translated := e.do("POST", "/api/email-templates/preview", admin, map[string]any{"key": "verify_email", "language": "pt-br", "data": map[string]string{"Code": "123456"}})
	e.want(translated, 200, "translated preview")
	if translated.S("body") != "Código: 123456" {
		t.Fatal(translated.J())
	}
	e.want(e.do("PUT", "/api/email-templates", admin, map[string]any{"tpl_verify_email_pt-br": "valid", "subj_verify_email_pt-br": "bad\r\nBcc: victim"}), 400, "header injection atomic rejection")
	e.want(e.do("PUT", "/api/email-templates", admin, map[string]any{"tpl_verify_email_it": "unknown"}), 400, "unknown language")
	saved := e.do("PUT", "/api/users/me", user, map[string]any{"name": "Reader", "email": "reader@x.io", "language": "pt-br", "ui_language": "nl"})
	e.want(saved, 200, "custom email and fixed UI preferences")
	if saved.J()["user"].(map[string]any)["language"] != "pt-br" {
		t.Fatal("custom language lost")
	}
	if e.s.recipientLanguage("reader@x.io", "en") != "pt-br" {
		t.Fatal("recipient preference not used")
	}
	e.want(e.do("PUT", "/api/users/me", saved.S("access_token"), map[string]any{"name": "Reader", "email": "reader@x.io", "language": "pt-br", "ui_language": "pt-br"}), 400, "custom language not UI language")
	if e.s.recipientLanguage("outside@example.com", "pt-br") != "pt-br" {
		t.Fatal("external selection lost")
	}
	for i := 0; i < 26; i++ {
		// 5 built-ins + pt-br + 26 custom = 32.
		code := fmt.Sprintf("x%c", 'a'+i)
		e.want(e.do("POST", "/api/email-languages", admin, map[string]any{"code": code, "name": code}), 201, "bounded language addition")
	}
	e.want(e.do("POST", "/api/email-languages", admin, map[string]any{"code": "zz", "name": "Overflow"}), 400, "language cap")
}
