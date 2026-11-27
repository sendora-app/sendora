// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A language created before a mail event existed has no row for it; saving the
// template must still store it.
func TestTemplateSaveCreatesMissingRows(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.want(e.do("POST", "/api/email-languages", admin, map[string]any{"code": "it", "name": "Italiano"}), 201, "add language")
	e.s.St.DB.Exec(`DELETE FROM settings WHERE key IN ('tpl_welcome_it','subj_welcome_it')`)
	e.want(e.do("PUT", "/api/email-templates", admin, map[string]any{"subj_welcome_it": "Benvenuto", "tpl_welcome_it": "Ciao {{.RecipientName}}"}), 200, "save")
	if got := e.s.St.Setting("tpl_welcome_it"); got != "Ciao {{.RecipientName}}" {
		t.Fatalf("template not saved: %q", got)
	}
}

func TestNewShareMustFitTheDownloadLimit(t *testing.T) {
	t.Setenv("SENDORA_VERIFIED_DOWNLOAD_MAX_BYTES", "1000")
	e := newEnv(t)
	tok := e.setup()
	r := e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "big.bin", "full_path": "big.bin", "size": 2000}}})
	e.want(r, 413, "share larger than the download limit")
	if !strings.Contains(string(r.Body), "download limit") {
		t.Fatal(string(r.Body))
	}
	e.want(e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "ok.bin", "full_path": "ok.bin", "size": 900}}}), 201, "fits")
}

func TestProviderUsernamesStayWithinTheLimit(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.s.St.DB.Exec(`INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,trust_email,allow_registration) VALUES('pl','OIDC','oidc',1,'c','s','https://issuer.example',0,1)`)
	p, _ := e.s.providerByUUID("pl")
	long := strings.Repeat("a", 200)
	for i := 0; i < 3; i++ {
		u, msg := e.s.resolveExternalUser(p, extIdentity{Sub: fmt.Sprint("s", i), Username: long})
		if u == nil {
			t.Fatal(msg)
		}
		if len(u.Username) > 64 {
			t.Fatalf("username %d characters long", len(u.Username))
		}
	}
}

// Stale upload sessions are cleaned up whether created_at holds SQLite's UTC text
// (the column default) or a Go time with an offset.
func TestStaleUploadCleanupHandlesBothTimeFormats(t *testing.T) {
	e := newEnv(t)
	tok := e.setup()
	mk := func() string {
		r := e.do("POST", "/api/uploads", tok, map[string]any{"files": []map[string]any{{"name": "a.txt", "full_path": "a.txt", "size": 1}}})
		e.want(r, 201, "create")
		return r.S("id")
	}
	utcText, goTime, fresh := mk(), mk(), mk()
	e.s.St.DB.Exec(`UPDATE upload_sessions SET created_at=? WHERE id=?`, time.Now().UTC().Add(-25*time.Hour).Format("2006-01-02 15:04:05"), utcText)
	e.s.St.DB.Exec(`UPDATE upload_sessions SET created_at=? WHERE id=?`, time.Now().In(time.FixedZone("UTC+5", 5*3600)).Add(-25*time.Hour), goTime)
	e.s.maintain()
	count := func(id string) (n int) {
		e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM upload_sessions WHERE id=?`, id).Scan(&n)
		return
	}
	if count(utcText) != 0 || count(goTime) != 0 || count(fresh) != 1 {
		t.Fatalf("utc=%d go=%d fresh=%d", count(utcText), count(goTime), count(fresh))
	}
}
