// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
)

const uiKeysFixture = `["Save","Cancel","Max {n} MB per share","Hello {name}, {name}"]`
const uiServerFixture = `{"static":["bad request"],"dynamic":["%d file(s) in %d share(s)"],"alreadyTranslated":[]}`

func uiEnv(t *testing.T) (*env, string) {
	e := newEnv(t)
	e.s.Static = fstest.MapFS{
		"index.html":                     {Data: []byte("<html>spa</html>")},
		"i18n-keys/keys.json":            {Data: []byte(uiKeysFixture)},
		"i18n-keys/server-messages.json": {Data: []byte(uiServerFixture)},
	}
	return e, e.setup()
}

func TestUILanguageImportExportDelete(t *testing.T) {
	e, admin := uiEnv(t)
	user := e.mkUser(admin, "reader", false)
	body := map[string]any{"code": "pt-br", "name": "Português (Brasil)", "translations": map[string]string{"Save": "Salvar", "Max {n} MB per share": "Máx {n} MB", "bad request": "pedido inválido", "%d file(s) in %d share(s)": "%d arquivo(s) em %d"}}

	// admin only
	e.want(e.do("POST", "/api/ui-languages", "", body), 401, "anonymous import")
	e.want(e.do("POST", "/api/ui-languages", user, body), 403, "user import")
	e.want(e.do("GET", "/api/ui-languages", user, nil), 403, "user list")
	e.want(e.do("DELETE", "/api/ui-languages/pt-br", user, nil), 403, "user delete")

	e.want(e.do("POST", "/api/ui-languages", admin, body), 200, "import")
	list := e.do("GET", "/api/ui-languages", admin, nil)
	e.want(list, 200, "list")
	if !strings.Contains(string(list.Body), `"pt-br"`) || !strings.Contains(string(list.Body), `"nl"`) {
		t.Fatal(string(list.Body))
	}
	ex := e.do("GET", "/api/ui-languages/pt-br/export", admin, nil)
	e.want(ex, 200, "export")
	if !strings.Contains(string(ex.Body), "Salvar") {
		t.Fatal(string(ex.Body))
	}
	e.want(e.do("GET", "/api/ui-languages/xx/export", admin, nil), 404, "export unknown")

	// replace is atomic and complete: old keys disappear
	e.want(e.do("POST", "/api/ui-languages", admin, map[string]any{"code": "pt-br", "name": "PT", "translations": map[string]string{"Cancel": "Cancelar"}}), 200, "replace")
	ex = e.do("GET", "/api/ui-languages/pt-br/export", admin, nil)
	if strings.Contains(string(ex.Body), "Salvar") || !strings.Contains(string(ex.Body), "Cancelar") {
		t.Fatal("not replaced", string(ex.Body))
	}
	// failed import leaves the stored dictionary untouched
	e.want(e.do("POST", "/api/ui-languages", admin, map[string]any{"code": "pt-br", "name": "PT", "translations": map[string]string{"Save": "S", "Nope": "x"}}), 400, "unknown key")
	ex = e.do("GET", "/api/ui-languages/pt-br/export", admin, nil)
	if !strings.Contains(string(ex.Body), "Cancelar") {
		t.Fatal("failed import changed data")
	}

	// users pick the custom language; deleting resets them to English
	saved := e.do("PUT", "/api/users/me", user, map[string]any{"name": "Reader", "email": "reader@x.io", "ui_language": "pt-br"})
	e.want(saved, 200, "custom ui_language accepted")
	e.want(e.do("PUT", "/api/users/me", saved.S("access_token"), map[string]any{"name": "Reader", "email": "reader@x.io", "ui_language": "zz"}), 400, "unknown ui_language")
	e.want(e.do("DELETE", "/api/ui-languages/pt-br", admin, nil), 200, "delete")
	e.want(e.do("DELETE", "/api/ui-languages/pt-br", admin, nil), 404, "delete twice")
	var ui string
	qByName(e.s.St, `SELECT ui_language FROM users WHERE username='reader'`).Scan(&ui)
	if ui != "en" {
		t.Fatal("user not reset", ui)
	}
	e.want(e.do("GET", "/api/i18n/pt-br", "", nil), 404, "gone")
}

func TestUILanguageValidation(t *testing.T) {
	e, admin := uiEnv(t)
	ok := map[string]string{"Save": "Opslaan"}
	post := func(v any) resp { return e.do("POST", "/api/ui-languages", admin, v) }
	for _, code := range []string{"", "../x", "NL_x", "a", "pt--br", strings.Repeat("a", 25), "pt br"} {
		e.want(post(map[string]any{"code": code, "name": "X", "translations": ok}), 400, "code "+code)
	}
	for _, name := range []string{"", "a\nb", "a\u0007", "a‮b", strings.Repeat("x", 81), " x"} {
		e.want(post(map[string]any{"code": "it", "name": name, "translations": ok}), 400, "name")
	}
	bad := []map[string]string{
		{"Unknown": "x"},
		{"Save": strings.Repeat("x", 2001)},
		{"Save": "a\x00b"},
		{"Save": "a‮b"},
		{"Max {n} MB per share": "Max"},
		{"Max {n} MB per share": "Max {m}"},
		{"Max {n} MB per share": "{n} {n}"},
		{"Hello {name}, {name}": "Hallo {name}"},
		{"%d file(s) in %d share(s)": "%d file"},
		{"%d file(s) in %d share(s)": "%s file(s) in %d"},
	}
	for i, tr := range bad {
		e.want(post(map[string]any{"code": "it", "name": "Italiano", "translations": tr}), 400, fmt.Sprintf("bad %d", i))
	}
	// multiset: order may change
	e.want(post(map[string]any{"code": "it", "name": "Italiano", "translations": map[string]string{"%d file(s) in %d share(s)": "in %d: %d"}}), 200, "same multiset")
	e.want(post(map[string]any{"code": "it", "name": "Italiano", "translations": map[string]string{"Hello {name}, {name}": "{name}, {name}!", "Save": "a\tb\nc"}}), 200, "multiset and whitespace")
	// unknown JSON fields, trailing data, oversize
	e.want(e.do("POST", "/api/ui-languages", admin, []byte(`{"code":"it","name":"I","translations":{},"extra":1}`), "Content-Type", "application/json"), 400, "unknown field")
	e.want(e.do("POST", "/api/ui-languages", admin, []byte(`{"code":"it","name":"I","translations":{}} {}`), "Content-Type", "application/json"), 400, "trailing data")
	huge := fmt.Sprintf(`{"code":"it","name":"I","translations":{"Save":"%s"}}`, strings.Repeat("x", 1<<20))
	e.want(e.do("POST", "/api/ui-languages", admin, []byte(huge), "Content-Type", "application/json"), 413, "oversize")
	// built-in codes keep their name and store overrides
	e.want(post(map[string]any{"code": "nl", "name": "Hacked", "translations": map[string]string{"Save": "Bewaar"}}), 200, "built-in override")
	list := e.do("GET", "/api/ui-languages", admin, nil)
	if strings.Contains(string(list.Body), "Hacked") {
		t.Fatal("built-in name overwritten")
	}
	e.want(e.do("DELETE", "/api/ui-languages/nl", admin, nil), 200, "reset built-in")
	list = e.do("GET", "/api/ui-languages", admin, nil)
	if !strings.Contains(string(list.Body), `"nl"`) {
		t.Fatal("built-in language removed")
	}
}

func TestUILanguageLimits(t *testing.T) {
	e, admin := uiEnv(t)
	for i := 0; i < 32; i++ {
		code := fmt.Sprintf("x%c", 'a'+i%26)
		if i >= 26 {
			code = fmt.Sprintf("y%c", 'a'+i-26)
		}
		e.want(e.do("POST", "/api/ui-languages", admin, map[string]any{"code": code, "name": code, "translations": map[string]string{}}), 200, "add "+code)
	}
	e.want(e.do("POST", "/api/ui-languages", admin, map[string]any{"code": "zz", "name": "Overflow", "translations": map[string]string{}}), 409, "language cap")
	// replacing an existing one at the cap still works; built-in overrides do not count
	e.want(e.do("POST", "/api/ui-languages", admin, map[string]any{"code": "xa", "name": "again", "translations": map[string]string{}}), 200, "replace at cap")
	e.want(e.do("POST", "/api/ui-languages", admin, map[string]any{"code": "de", "name": "x", "translations": map[string]string{"Save": "Speichern"}}), 200, "built-in at cap")
}

func TestUILanguageKeyCountLimit(t *testing.T) {
	known := map[string]bool{}
	tr := map[string]string{}
	for i := 0; i < uiMaxKeys+1; i++ {
		k := fmt.Sprintf("k%d", i)
		known[k] = true
		tr[k] = k
	}
	if err := validateUITranslations(tr, known); err == nil {
		t.Fatal("too many keys accepted")
	}
	delete(tr, "k0")
	if err := validateUITranslations(tr, known); err != nil {
		t.Fatal(err)
	}
}

func TestPublicUIEndpoints(t *testing.T) {
	e, admin := uiEnv(t)
	e.want(e.do("POST", "/api/ui-languages", admin, map[string]any{"code": "pt-br", "name": "Português", "translations": map[string]string{"Save": "Salvar"}}), 200, "import")
	langs := e.do("GET", "/api/i18n/languages", "", nil)
	e.want(langs, 200, "public list without auth")
	if !strings.Contains(string(langs.Body), "Português") || strings.Contains(string(langs.Body), "Salvar") {
		t.Fatal(string(langs.Body))
	}
	if langs.Hdr.Get("Cache-Control") == "" || strings.Contains(langs.Hdr.Get("Cache-Control"), "no-store") {
		t.Fatal("cache header", langs.Hdr.Get("Cache-Control"))
	}
	d := e.do("GET", "/api/i18n/pt-br", "", nil)
	e.want(d, 200, "public dictionary")
	etag := d.Hdr.Get("ETag")
	if etag == "" || !strings.Contains(d.Hdr.Get("Cache-Control"), "max-age") || !strings.Contains(string(d.Body), "Salvar") {
		t.Fatal("headers", d.Hdr, string(d.Body))
	}
	e.want(e.do("GET", "/api/i18n/pt-br", "", nil, "If-None-Match", etag), 304, "not modified")
	e.want(e.do("POST", "/api/ui-languages", admin, map[string]any{"code": "pt-br", "name": "Português", "translations": map[string]string{"Save": "Guardar"}}), 200, "update")
	changed := e.do("GET", "/api/i18n/pt-br", "", nil, "If-None-Match", etag)
	e.want(changed, 200, "changed content")
	if changed.Hdr.Get("ETag") == etag {
		t.Fatal("etag unchanged")
	}
	e.want(e.do("GET", "/api/i18n/unknown", "", nil), 404, "unknown")
	e.want(e.do("GET", "/api/i18n/..%2Fx", "", nil), 404, "bad code")
}

func TestUILanguageEventLogHasCountsOnly(t *testing.T) {
	e, admin := uiEnv(t)
	e.want(e.do("POST", "/api/ui-languages", admin, map[string]any{"code": "pt-br", "name": "Português", "translations": map[string]string{"Save": "Salvar-geheim"}}), 200, "import")
	e.want(e.do("DELETE", "/api/ui-languages/pt-br", admin, nil), 200, "delete")
	var detail, target string
	e.s.St.DB.QueryRow(`SELECT target,detail FROM audit_log WHERE action='ui_language_imported'`).Scan(&target, &detail)
	var deleted int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='ui_language_deleted'`).Scan(&deleted)
	if deleted != 1 {
		t.Fatal("delete not logged")
	}
	if detail != "1 keys" || target != "lang:pt-br" {
		t.Fatalf("log entry %q %q", target, detail)
	}
}
