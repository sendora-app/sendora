// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/http/httptest"
	"net/mail"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/store"
)

func TestLocalizedMailTemplates(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	data := map[string]any{"SenderName": "Zoë", "RecipientName": "René", "URL": "https://example.com/share/1", "ShareName": "Données", "Code": "123456", "Expires": "2026-12-01", "Message": "Olá"}
	for _, event := range store.MailEvents {
		for _, language := range store.MailLanguages {
			t.Run(event+"_"+language, func(t *testing.T) {
				subject, body, got, err := e.s.renderMail(event, language, data)
				if err != nil || got != language || subject == "" || body == "" || strings.Contains(body, "{{") {
					t.Fatalf("render %q %q %v", subject, body, err)
				}
				e.want(e.do("POST", "/api/email-templates/preview", admin, map[string]any{"key": event, "language": language}), 200, "preview")
			})
		}
	}
	e.s.St.SetSetting("tpl_verify_email_nl", "")
	_, body, _, err := e.s.renderMail("verify_email", "nl", data)
	if err != nil || body != "Your verification code is 123456" {
		t.Fatalf("English fallback: %q %v", body, err)
	}
	e.s.St.SetSetting("tpl_verify_email_nl", "{{.Invalid}}")
	_, body, _, _ = e.s.renderMail("verify_email", "nl", data)
	if body != "Your verification code is 123456" {
		t.Fatal("broken template did not fall back")
	}
	subject, _, language, _ := e.s.renderMail("verify_email", "unsupported", data)
	if language != "en" || subject != "Verify your email" {
		t.Fatal("unsupported language fallback")
	}
}

func TestMailTemplateEditingAtomicAndSafePreview(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	original := e.s.St.Setting("tpl_verify_email_en")
	for _, bad := range []map[string]any{
		{"tpl_verify_email_en": "edited", "unknown": "x"},
		{"tpl_verify_email_en": "edited", "tpl_share_created_fr": "{{.URL"},
		{"tpl_verify_email_en": "edited", "subj_share_created_fr": strings.Repeat("x", 501)},
		{"tpl_verify_email_en": "edited", "tpl_share_created_fr": strings.Repeat("x", 65537)},
		{"tpl_verify_email_en": "edited", "tpl_share_created_fr": "{{if .Code}}{{.Unknown}}{{end}}"},
		{"tpl_verify_email": "alias", "tpl_verify_email_en": "conflict"},
	} {
		e.want(e.do("PUT", "/api/email-templates", admin, bad), 400, "invalid atomic save")
		if e.s.St.Setting("tpl_verify_email_en") != original {
			t.Fatal("partial save")
		}
	}
	e.s.St.DB.Exec(`CREATE TRIGGER fail_mail_update BEFORE UPDATE ON settings WHEN NEW.key='tpl_verify_email_en' BEGIN SELECT RAISE(ABORT,'test failure'); END`)
	e.want(e.do("PUT", "/api/email-templates", admin, map[string]any{"tpl_verify_email_en": "changed", "subj_verify_email_nl": "changed"}), 500, "database save failure")
	if e.s.St.Setting("subj_verify_email_nl") == "changed" {
		t.Fatal("database transaction partially committed")
	}
	e.s.St.DB.Exec(`DROP TRIGGER fail_mail_update`)
	e.want(e.do("PUT", "/api/email-templates", admin, map[string]any{"tpl_verify_email": "{{.ApplicationName}}: {{.Code}}", "subj_verify_email_nl": "Verificatie voor {{.ApplicationName}}"}), 200, "alias save")
	if e.s.St.Setting("tpl_verify_email_en") != e.s.St.Setting("tpl_verify_email") {
		t.Fatal("legacy alias not synchronized")
	}
	r := e.do("POST", "/api/email-templates/preview", admin, map[string]any{"key": "verify_email", "data": map[string]string{"Code": "123456"}})
	e.want(r, 200, "render only without SMTP")
	if r.S("body") != "Sendora: 123456" || r.J()["sent"] != false {
		t.Fatal(string(r.Body))
	}
	e.want(e.do("POST", "/api/email-templates/preview", admin, map[string]any{"key": "verify_email", "send": true, "to": "victim@example.com"}), 400, "preview cannot override recipient")
	user := e.mkUser(admin, "normal", false)
	e.want(e.do("POST", "/api/email-templates/preview", user, map[string]any{"key": "verify_email"}), 403, "preview admin only")
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.want(e.do("POST", "/api/email-templates/preview", admin, map[string]any{"key": "verify_email", "send": true}), 200, "send preview")
	m := sink.wait(t, "Sendora:")
	if !strings.Contains(m, "To: <admin@x.io>") {
		t.Fatal("preview not sent to admin", m)
	}
}

func TestMailMIME(t *testing.T) {
	body := "Première ligne\r\nZweite Zeile\n" + strings.Repeat("á", 200)
	raw := mailMessage(&mail.Address{Address: "from@example.com"}, &mail.Address{Address: "to@example.com"}, "Fichiers téléchargés\r\nBcc: no@example.com", body)
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil || subject != "Fichiers téléchargés  Bcc: no@example.com" {
		t.Fatal(subject, err)
	}
	if m.Header.Get("Bcc") != "" || !strings.Contains(m.Header.Get("Subject"), "=?UTF-8?") {
		t.Fatal("header injection or missing RFC2047")
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(m.Body))
	if err != nil {
		t.Fatal(err)
	}
	normalized := strings.ReplaceAll(string(decoded), "\r\n", "\n")
	if normalized != strings.ReplaceAll(body, "\r\n", "\n") {
		t.Fatal("body corrupt")
	}
	for _, line := range strings.Split(raw, "\r\n")[9:] {
		if len(line) > 76 {
			t.Fatal("oversized MIME line")
		}
	}
}

func TestMailBackpressureAndRecovery(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.BaseURL = "https://example.com"
	// Saturate all slots before enqueueing 20 messages. No message may disappear.
	for i := 0; i < cap(e.s.mailSlots); i++ {
		e.s.mailSlots <- struct{}{}
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := e.s.deliverTemplate(fmt.Sprintf("recipient%d@example.com", i), "tpl_verify_email", map[string]any{"Code": fmt.Sprintf("marker%02d", i)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	for i := 0; i < cap(e.s.mailSlots); i++ {
		<-e.s.mailSlots
	}
	wg.Wait()
	for i := 0; i < 20; i++ {
		sink.wait(t, fmt.Sprintf("marker%02d", i))
	}
	// A valid existing reset does not block issuance after the one-minute cooldown.
	e.s.St.DB.Exec(`INSERT INTO password_resets(hash,user_id,expires_at) VALUES('old',1,?)`, time.Now().Add(time.Hour))
	e.want(e.do("POST", "/api/auth/forgot-password", "", map[string]any{"email": "admin@x.io"}), 200, "reset replacement")
	sink.wait(t, "reset-password")
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM password_resets WHERE user_id=1`).Scan(&n)
	if n != 2 {
		t.Fatal("live token prevented replacement")
	}
	// Legacy recursive templates remain saved but are never executed.
	e.s.St.SetSetting("tpl_verify_email_en", `{{template "mail" .}}`)
	_, body, _, err := e.s.renderMail("verify_email", "en", map[string]any{"Code": "123456"})
	if err != nil || body != "Your verification code is 123456" || e.s.St.Setting("tpl_verify_email_en") != `{{template "mail" .}}` {
		t.Fatal("unsafe legacy fallback", err, body)
	}
	// Successive changed addresses each get a fresh code, not a shared user throttle.
	first := e.do("PUT", "/api/users/me", admin, map[string]any{"name": "Admin", "email": "first@example.com", "current_password": "password123"})
	e.want(first, 200, "first email change")
	second := e.do("PUT", "/api/users/me", first.S("access_token"), map[string]any{"name": "Admin", "email": "second@example.com", "current_password": "password123"})
	e.want(second, 200, "second email change")
	sink.wait(t, "second@example.com")
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM email_verifications WHERE user_id=1`).Scan(&n)
	if n != 1 {
		t.Fatal("replacement verification missing")
	}
}

func TestSetupAndAdminLanguage(t *testing.T) {
	e := newEnv(t)
	setup := e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "admin", "email": "admin@example.com", "password": "password123", "language": "fr"})
	e.want(setup, 200, "setup language")
	if setup.J()["user"].(map[string]any)["language"] != "fr" {
		t.Fatal("setup preference ignored")
	}
	created := e.do("POST", "/api/users", setup.S("access_token"), map[string]any{"username": "german", "password": "password123", "language": "de"})
	e.want(created, 201, "admin creation language")
	if created.S("language") != "de" {
		t.Fatal("admin preference ignored")
	}
}

func TestUILanguageIndependentPersistence(t *testing.T) {
	e := newEnv(t)
	setup := e.do("POST", "/api/setup", "", map[string]any{"setup_code": e.s.setupCode, "username": "admin", "password": "password123", "email": "admin@x.io", "language": "fr", "ui_language": "nl"})
	e.want(setup, 200, "independent setup preferences")
	admin := setup.S("access_token")
	check := func(r resp, ui, email string) {
		t.Helper()
		e.want(r, 200, "profile preferences")
		u := r.J()["user"].(map[string]any)
		if u["ui_language"] != ui || u["language"] != email {
			t.Fatalf("preferences: %v", u)
		}
	}
	check(setup, "nl", "fr")
	check(e.do("GET", "/api/users/me", admin, nil), "nl", "fr")
	for _, language := range store.MailLanguages {
		r := e.do("PUT", "/api/users/me", admin, map[string]any{"name": "Admin", "email": "admin@x.io", "ui_language": language})
		check(r, language, "fr")
		admin = r.S("access_token")
	}
	check(e.do("PUT", "/api/users/me", admin, map[string]any{"name": "Admin", "email": "admin@x.io", "language": "de"}), "es", "de")
	check(e.do("POST", "/api/auth/login", "", map[string]any{"username": "admin", "password": "password123"}), "es", "de")
	for _, bad := range []string{"pt", "", "NL"} {
		e.want(e.do("PUT", "/api/users/me", admin, map[string]any{"name": "Admin", "email": "admin@x.io", "ui_language": bad}), 400, "invalid UI preference")
	}
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "bad", "password": "password123", "ui_language": "pt"}), 400, "invalid admin UI language")
	created := e.do("POST", "/api/users", admin, map[string]any{"username": "normal", "password": "password123", "ui_language": "nl", "language": "es"})
	e.want(created, 201, "admin UI language")
	if created.S("ui_language") != "nl" || created.S("language") != "es" {
		t.Fatal(string(created.Body))
	}
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.s.St.SetSetting("allow_self_registration", "true")
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "badreg", "password": "password123", "email": "badreg@x.io", "ui_language": "pt"}), 400, "invalid signup UI language")
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "signed", "password": "password123", "email": "signed@x.io", "ui_language": "nl", "language": "fr"}), 201, "signup UI preference")
	sink.wait(t, "Votre code de vérification")
	var ui, email string
	if err := qByName(e.s.St, `SELECT ui_language,language FROM users WHERE username='signed'`).Scan(&ui, &email); err != nil || ui != "nl" || email != "fr" {
		t.Fatal(ui, email, err)
	}
}

func TestRepeatedDownloadStartsAndHistory(t *testing.T) {
	liftDownloadMailThrottle(t)
	e := newEnv(t)
	admin := e.setup()
	owner := e.mkUser(admin, "owner", false)
	other := e.mkUser(admin, "other", false)
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.want(e.do("PUT", "/api/users/me", owner, map[string]any{"name": "Owner", "email": "owner@x.io", "language": "nl", "ui_language": "de"}), 200, "owner preferences")
	e.want(e.do("PUT", "/api/email-templates", admin, map[string]any{"tpl_share_downloaded_nl": "Started marker{{.DownloadCount}} {{.FileNames}} at {{.StartedAt}}"}), 200, "editable download details")
	share := e.share(owner, map[string]string{"a.txt": "abcdef", "b.txt": "xyz"}, map[string]any{"name": "Bundle"})
	e.want(share, 201, "share")
	public := "/api/shares/" + share.S("long_id") + "/download"
	for i, suffix := range []string{"/a.txt", "", "/a.txt"} {
		headers := []string{}
		status := 200
		if i == 2 {
			headers = []string{"Range", "bytes=0-1"}
			status = 206
		}
		e.want(e.do("GET", public+suffix, "", nil, headers...), status, "download start")
		m := sink.wait(t, fmt.Sprintf("Started marker%d", i+1))
		if !strings.Contains(m, "a.txt") || !strings.Contains(m, "To: <owner@x.io>") || !strings.Contains(m, "Z") {
			t.Fatal(m)
		}
	}
	// A range that can never be satisfied is refused with 416 before any slot or download count is taken (changed in 0.1.5).
	e.want(e.do("GET", public+"/a.txt", "", nil, "Range", "bytes=999-"), 416, "invalid range")
	history := "/api/shares/" + share.S("id") + "/downloads"
	e.want(e.do("GET", history, "", nil), 401, "history authentication")
	e.want(e.do("GET", history, other, nil), 404, "history ownership")
	e.want(e.do("GET", "/api/shares/"+share.S("long_id")+"/downloads", owner, nil), 404, "numeric history ID")
	r := e.do("GET", history+"?limit=2&offset=1", owner, nil)
	e.want(r, 200, "paginated history")
	if r.J()["total"] != float64(3) || r.J()["limit"] != float64(2) || r.J()["offset"] != float64(1) || strings.Contains(string(r.Body), "\"ip\"") {
		t.Fatal(string(r.Body))
	}
	items := r.J()["downloads"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["file_name"] != "Bundle.zip" || items[1].(map[string]any)["file_name"] != "a.txt" {
		t.Fatal(items)
	}
	if items[0].(map[string]any)["id"].(float64) <= items[1].(map[string]any)["id"].(float64) || items[0].(map[string]any)["created_at"] == "" {
		t.Fatal("history order/time", items)
	}
	e.want(e.do("GET", history, admin, nil), 404, "admin cannot read another user's download history")
	for _, query := range []string{"?limit=0", "?offset=-1", "?limit=no"} {
		e.want(e.do("GET", history+query, owner, nil), 400, "invalid pagination")
	}
	files := e.s.shareFiles(int64(share.J()["id"].(float64)))
	if err := os.Remove(files[0].diskPath); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("GET", public, "", nil), 404, "ZIP missing source")
	e.want(e.do("GET", public+"/"+files[0].FullPath, "", nil), 404, "missing single file")
	var count int
	qByName(e.s.St, `SELECT download_count FROM shares WHERE long_id=?`, share.S("long_id")).Scan(&count)
	if count != 3 {
		t.Fatal("missing file reserved download", count)
	}
	// A successful subsequent start has count 4; no marker for the failed downloads is sent.
	e.want(e.do("GET", public+"/"+files[1].FullPath, "", nil), 200, "remaining source")
	sink.wait(t, "Started marker4")
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.msgs) != 4 {
		t.Fatal("unexpected notifications", len(sink.msgs))
	}
	for i := 0; i < 105; i++ {
		if _, err := e.s.St.DB.Exec(`INSERT INTO downloads(share_id,ip) VALUES(?,?)`, share.J()["id"], "private"); err != nil {
			t.Fatal(err)
		}
	}
	r = e.do("GET", history+"?limit=1000", owner, nil)
	if len(r.J()["downloads"].([]any)) != 100 || r.J()["limit"] != float64(100) || strings.Contains(string(r.Body), "private") {
		t.Fatal(string(r.Body))
	}
}

func TestConcurrentDownloadNotificationCounts(t *testing.T) {
	liftDownloadMailThrottle(t)
	e := newEnv(t)
	admin := e.setup()
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.want(e.do("PUT", "/api/email-templates", admin, map[string]any{"tpl_share_downloaded_en": "Concurrent marker{{.DownloadCount}} file {{.FileName}} {{.StartedAt}}"}), 200, "concurrent mail template")
	share := e.share(admin, map[string]string{"a.txt": "abc"}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.want(e.do("GET", "/api/shares/"+share.S("long_id")+"/download", "", nil), 200, "concurrent download")
		}()
	}
	wg.Wait()
	for i := 1; i <= 8; i++ {
		sink.wait(t, fmt.Sprintf("Concurrent marker%d file a.txt", i))
	}
	r := e.do("GET", "/api/shares/"+share.S("id")+"/downloads", admin, nil)
	if r.J()["total"] != float64(8) {
		t.Fatal(string(r.Body))
	}
}

func TestFailedResetDeliveryRemovesToken(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.s.BaseURL = "https://example.com"
	// Missing SMTP fails immediately; wait for the bounded async delivery to clean up.
	e.want(e.do("POST", "/api/auth/forgot-password", "", map[string]any{"email": "admin@x.io"}), 200, "reset hides delivery failure")
	for i := 0; i < 50; i++ {
		var n int
		e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM password_resets`).Scan(&n)
		if n == 0 {
			return
		}
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatal("failed reset token retained")
}

func TestMailRequestRejectsTrailingJSON(t *testing.T) {
	e := newEnv(t)
	e.setup()
	w := httptest.NewRecorder()
	e.s.putTemplates(w, httptest.NewRequest("PUT", "/", strings.NewReader(`{"tpl_verify_email":"changed"} {}`)))
	if w.Code != 400 || e.s.St.Setting("tpl_verify_email") == "changed" {
		t.Fatal("trailing data accepted")
	}
}

func TestLanguagePreferenceAndSignup(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	e.s.St.SetSetting("allow_self_registration", "true")
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "blocked", "email": "blocked@example.com", "password": "password123", "language": "nl"}), 503, "SMTP fails closed")
	var count int
	qByName(e.s.St, `SELECT COUNT(*) FROM users WHERE username='blocked'`).Scan(&count)
	if count != 0 {
		t.Fatal("unusable account created")
	}
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.want(e.do("POST", "/api/auth/register", "", map[string]any{"username": "badlang", "email": "badlang@example.com", "password": "password123", "language": "pt"}), 400, "unsupported signup language")
	e.s.St.SetSetting("require_email_verification", "false")
	reg := e.do("POST", "/api/auth/register", "", map[string]any{"username": "dutch", "email": "dutch@example.com", "password": "password123", "language": "nl"})
	e.want(reg, 201, "localized signup")
	if reg.J()["needs_verification"] != true {
		t.Fatal("verification bypass")
	}
	sink.wait(t, "Je verificatiecode is")
	if e.s.recipientLanguage("Dutch <DUTCH@example.com>", "fr") != "nl" || e.s.recipientLanguage("external@example.com", "fr") != "fr" || e.s.recipientLanguage("external@example.com", "") != "en" {
		t.Fatal("recipient preference precedence")
	}
	updated := e.do("PUT", "/api/users/me", admin, map[string]any{"name": "Admin", "email": "admin@x.io", "language": "de"})
	e.want(updated, 200, "profile language")
	if updated.J()["user"].(map[string]any)["language"] != "de" {
		t.Fatal("profile missing language")
	}
	e.want(e.do("PUT", "/api/users/me", admin, map[string]any{"name": "Admin", "email": "admin@x.io", "language": "pt"}), 400, "invalid profile language")
	updated = e.do("PUT", "/api/users/me", admin, map[string]any{"name": "Admin", "email": "admin@x.io"})
	if updated.J()["user"].(map[string]any)["language"] != "de" {
		t.Fatal("omission resets preference")
	}
	e.s.BaseURL = "https://example.com"
	share := e.share(admin, map[string]string{"a": "x"}, map[string]any{"recipients": []string{"dutch@example.com", "external@example.com"}, "email_language": "fr"})
	e.want(share, 201, "mixed language mail")
	sink.wait(t, "heeft bestanden met je gedeeld")
	sink.wait(t, "a partagé des fichiers avec vous")
	e.want(e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{"email": "invited@example.com", "email_language": "es"}), 201, "localized invite")
	sink.wait(t, "te invita a subir archivos")
	e.want(e.do("GET", "/api/shares/"+share.S("long_id")+"/download", "", nil), 200, "download notification")
	sink.wait(t, "wurde gestartet")
	// Owner notifications use the owner's preference, never the guest/selected language.
	eByName(e.s.St, `UPDATE shares SET expires_at=? WHERE long_id=?`, time.Now().Add(24*time.Hour), share.S("long_id"))
	e.s.maintain()
	sink.wait(t, "läuft am")
	invite := e.do("POST", "/api/reverse-shares/invite", admin, map[string]any{"name": "Guest"})
	url := invite.S("url")
	token := url[strings.LastIndex(url, "/")+1:]
	guest := e.do("POST", "/api/reverse-shares/accept", "", map[string]any{"token": token})
	e.want(guest, 200, "guest accepts")
	e.s.St.SetSetting("tpl_reverse_completed_de", "Completion-only {{.ShareName}} by {{.SenderName}}")
	e.want(e.share(guest.S("access_token"), map[string]string{"guest.txt": "guest content"}, map[string]any{"name": "Received"}), 201, "guest completes invite")
	sink.wait(t, "Completion-only Received by Guest")
	e.want(e.do("POST", "/api/auth/forgot-password", "", map[string]any{"email": "admin@x.io"}), 200, "localized reset")
	sink.wait(t, "Setze dein Passwort zurück")
}
