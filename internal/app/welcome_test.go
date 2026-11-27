// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/store"
)

var welcomeLinkRe = regexp.MustCompile(`http://[^\s]+/reset-password/([0-9a-f]{48})`)

func welcomeToken(t *testing.T, mail string) string {
	m := welcomeLinkRe.FindStringSubmatch(mail)
	if m == nil {
		t.Fatal("no set-password link in the mail:\n", mail)
	}
	return m[1]
}

func TestWelcomeTemplateSeededListedAndEditable(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	for _, lang := range store.MailLanguages {
		if e.s.St.Setting("tpl_welcome_"+lang) == "" || e.s.St.Setting("subj_welcome_"+lang) == "" {
			t.Fatal("welcome template missing for", lang)
		}
		for _, v := range []string{"{{.Username}}", "{{.LoginURL}}", "{{.SetPasswordURL}}", "{{.ExpiresDays}}"} {
			if !strings.Contains(e.s.St.Setting("tpl_welcome_"+lang), v) {
				t.Fatalf("%s default lacks %s", lang, v)
			}
		}
		if strings.Contains(strings.ToLower(e.s.St.Setting("tpl_welcome_"+lang)), "password:") {
			t.Fatal("the default must not carry a password")
		}
	}
	list := e.do("GET", "/api/email-templates", admin, nil)
	e.want(list, 200, "list templates")
	if _, ok := list.J()["tpl_welcome_nl"]; !ok {
		t.Fatal("welcome template not listed")
	}
	e.want(e.do("PUT", "/api/email-templates", admin, map[string]any{"tpl_welcome_en": "Hi {{.Username}} {{.SetPasswordURL}}", "subj_welcome_en": "Welcome {{.ApplicationName}}"}), 200, "edit welcome template")
	e.want(e.do("PUT", "/api/email-templates", admin, map[string]any{"tpl_welcome_en": "{{.Password}}"}), 400, "unknown variable rejected")
	p := e.do("POST", "/api/email-templates/preview", admin, map[string]any{"key": "welcome", "language": "en", "data": map[string]string{"Username": "alex", "SetPasswordURL": "http://x/y"}})
	e.want(p, 200, "preview welcome")
	if !strings.Contains(p.S("body"), "alex") {
		t.Fatal(p.S("body"))
	}
}

func TestCreateUserWelcomeMailFlow(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	e := newEnv(t)
	admin := e.setup()
	sink := newSMTP(t)
	e.useSMTP(sink)
	const initial = "Initial-Secret-1234"
	created := e.do("POST", "/api/users", admin, map[string]any{"username": "newbie", "name": "Nina", "email": "newbie@x.io", "password": initial, "must_change_password": true, "send_welcome": true, "language": "nl"})
	e.want(created, 201, "create with welcome")
	if _, hasNote := created.J()["welcome_note"]; created.S("welcome_email") != "sent" || hasNote {
		t.Fatal(string(created.Body))
	}
	mail := sink.wait(t, "newbie")
	for _, want := range []string{"Username: ", "newbie", "/login", "/reset-password/", "Nina"} {
		if !strings.Contains(strings.ToLower(mail), strings.ToLower(want)) && !strings.Contains(mail, "Gebruikersnaam") {
			t.Fatalf("mail lacks %q:\n%s", want, mail)
		}
	}
	if !strings.Contains(mail, "Gebruikersnaam") {
		t.Fatal("recipient language (nl) not used:\n", mail)
	}
	if strings.Contains(mail, initial) {
		t.Fatal("the initial password must never be mailed")
	}
	tok := welcomeToken(t, mail)
	if strings.Contains(string(created.Body), tok) {
		t.Fatal("the token must not appear in the API response")
	}
	// the typed initial password keeps working
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "newbie", "password": initial}), 200, "initial password still works")
	// make the mailbox proof visible: unverified until the link is used
	eByName(e.s.St, `UPDATE users SET email_verified=0, must_change_password=1 WHERE username='newbie'`)
	// weak password is refused and does not burn the link
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": tok, "password": "short"}), 400, "policy enforced")
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": tok, "password": "My-Own-Password-9"}), 200, "set own password")
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": tok, "password": "Another-Password-9"}), 400, "single use")
	var verified, must int
	qByName(e.s.St, `SELECT email_verified, must_change_password FROM users WHERE username='newbie'`).Scan(&verified, &must)
	if verified != 1 || must != 0 {
		t.Fatalf("redeeming the welcome link should verify the email and clear must-change: %d %d", verified, must)
	}
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "newbie", "password": "My-Own-Password-9"}), 200, "login with chosen password")
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{"username": "newbie", "password": initial}), 401, "initial password replaced")
	// nothing sensitive in logs or the audit log
	body := string(e.do("GET", "/api/logs?limit=100", admin, nil).Body)
	if !strings.Contains(body, "welcome=sent") {
		t.Fatal("audit entry should record welcome=sent:", body)
	}
	for _, secret := range []string{tok, initial, "My-Own-Password-9"} {
		if strings.Contains(body, secret) || strings.Contains(logs.String(), secret) {
			t.Fatal("secret leaked into logs/events:", secret)
		}
	}
}

func TestCreateUserWelcomeSkippedCasesStillCreateUser(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	create := func(name string, extra map[string]any) resp {
		body := map[string]any{"username": name, "password": "password123", "send_welcome": true}
		for k, v := range extra {
			body[k] = v
		}
		return e.do("POST", "/api/users", admin, body)
	}
	// no SMTP configured
	r := create("nosmtp", map[string]any{"email": "nosmtp@x.io"})
	e.want(r, 201, "created without SMTP")
	if r.S("welcome_email") != "skipped" || !strings.Contains(r.S("welcome_note"), "SMTP") {
		t.Fatal(string(r.Body))
	}
	sink := newSMTP(t)
	e.useSMTP(sink)
	// no email address
	r = create("noemail", nil)
	e.want(r, 201, "created without email")
	if r.S("welcome_email") != "skipped" || !strings.Contains(r.S("welcome_note"), "email address") {
		t.Fatal(string(r.Body))
	}
	// not requested: field omitted, nothing sent
	r = e.do("POST", "/api/users", admin, map[string]any{"username": "plain", "password": "password123", "email": "plain@x.io"})
	e.want(r, 201, "created without welcome")
	if _, present := r.J()["welcome_email"]; present {
		t.Fatal("welcome_email must be omitted when not requested")
	}
	// hourly limit
	var adminID int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='admin'`).Scan(&adminID)
	e.s.takeMail(adminID, mailRecipientsPerHour)
	r = create("limited", map[string]any{"email": "limited@x.io"})
	e.want(r, 201, "created despite the limit")
	if r.S("welcome_email") != "skipped" || !strings.Contains(r.S("welcome_note"), "limit") {
		t.Fatal(string(r.Body))
	}
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username IN ('nosmtp','noemail','plain','limited')`).Scan(&n)
	if n != 4 {
		t.Fatal("users must exist in every case:", n)
	}
	// skipped means no usable link was left behind
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM password_resets WHERE kind='welcome'`).Scan(&n)
	if n != 0 {
		t.Fatal("skipped welcome mails must not create tokens:", n)
	}
}

func TestCreateUserWelcomeDeliveryFailureRevokesLinkButKeepsUser(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	// Configured but unreachable SMTP server.
	e.s.St.SetSetting("smtp_host", "127.0.0.1")
	e.s.St.SetSetting("smtp_port", "1")
	e.s.St.SetSetting("smtp_tls", "none")
	e.s.St.SetSetting("smtp_from", "files@x.io")
	r := e.do("POST", "/api/users", admin, map[string]any{"username": "unlucky", "password": "password123", "email": "u@x.io", "send_welcome": true})
	e.want(r, 201, "user is created when delivery fails")
	if r.S("welcome_email") != "failed" || r.S("welcome_note") == "" {
		t.Fatal(string(r.Body))
	}
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM password_resets WHERE kind='welcome'`).Scan(&n)
	if n != 0 {
		t.Fatal("an undelivered link must not stay redeemable")
	}
}

func TestWelcomeTokenExpires(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.want(e.do("POST", "/api/users", admin, map[string]any{"username": "late", "password": "password123", "email": "late@x.io", "send_welcome": true}), 201, "create")
	tok := welcomeToken(t, sink.wait(t, "late"))
	e.s.St.DB.Exec(`UPDATE password_resets SET expires_at=? WHERE kind='welcome'`, time.Now().Add(-time.Minute))
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": tok, "password": "My-Own-Password-9"}), 400, "expired link")
	var exp time.Time
	e.s.St.DB.Exec(`UPDATE password_resets SET expires_at=?`, time.Now().Add(welcomeTokenTTL))
	e.s.St.DB.QueryRow(`SELECT expires_at FROM password_resets WHERE kind='welcome'`).Scan(&exp)
	if d := time.Until(exp); d < 6*24*time.Hour || d > 8*24*time.Hour {
		t.Fatal("welcome links live for about 7 days")
	}
}

func TestResendWelcome(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	user := e.mkUser(admin, "regular", false)
	var id int64
	qByName(e.s.St, `SELECT id FROM users WHERE username='regular'`).Scan(&id)
	path := fmt.Sprintf("/api/users/%d/welcome", id)
	// without SMTP: a clear rejection
	r := e.do("POST", path, admin, nil)
	e.want(r, 409, "no SMTP")
	if !strings.Contains(r.S("error"), "SMTP") {
		t.Fatal(string(r.Body))
	}
	sink := newSMTP(t)
	e.useSMTP(sink)
	e.want(e.do("POST", path, "", nil), 401, "anonymous")
	e.want(e.do("POST", path, user, nil), 403, "non-admin")
	e.want(e.do("POST", "/api/users/99999/welcome", admin, nil), 404, "unknown user")
	e.want(e.do("POST", path, admin, nil), 200, "first send")
	first := welcomeToken(t, sink.wait(t, "regular"))
	e.want(e.do("POST", path, admin, nil), 200, "second send")
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM password_resets WHERE kind='welcome' AND user_id=?`, id).Scan(&n)
	if n != 1 {
		t.Fatal("a resend must invalidate older unused welcome links:", n)
	}
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": first, "password": "My-Own-Password-9"}), 400, "old link no longer works")
	// a user without an email address is rejected with a clear message
	e.s.St.DB.Exec(`UPDATE users SET email='' WHERE id=?`, id)
	r = e.do("POST", path, admin, nil)
	e.want(r, 409, "no email address")
	if !strings.Contains(r.S("error"), "email address") {
		t.Fatal(string(r.Body))
	}
	// A normal reset token must not mark the email as verified (only welcome links do).
	e.s.St.DB.Exec(`UPDATE users SET email='regular@x.io', email_verified=0 WHERE id=?`, id)
	e.s.St.DB.Exec(`INSERT INTO password_resets(hash,user_id,expires_at) VALUES(?,?,?)`, hashToken("plainreset"), id, time.Now().Add(time.Hour))
	e.want(e.do("POST", "/api/auth/reset-password", "", map[string]any{"token": "plainreset", "password": "My-Own-Password-9"}), 200, "normal reset still works")
	var verified int
	e.s.St.DB.QueryRow(`SELECT email_verified FROM users WHERE id=?`, id).Scan(&verified)
	if verified != 0 {
		t.Fatal("a plain password-reset link must not verify the email address")
	}
}

func TestMailBundleWithoutWelcomeStillImports(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	exported := e.do("GET", "/api/email-templates/export?language=en", admin, nil)
	e.want(exported, 200, "export")
	var b mailBundle
	if err := json.Unmarshal(exported.Body, &b); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Templates["welcome"]; !ok {
		t.Fatal("exports must include the welcome event")
	}
	delete(b.Templates, "welcome") // what an older version exported
	b.Language, b.Name = "it", "Italiano"
	e.want(e.do("POST", "/api/email-templates/import", admin, map[string]any{"bundle": b, "apply": true, "overwrite": false}), 200, "older file imports")
	b.Templates["unknown_event"] = mailBundleText{Subject: "x", Body: "y"}
	e.want(e.do("POST", "/api/email-templates/import", admin, map[string]any{"bundle": b, "apply": false, "overwrite": false}), 400, "unknown keys still rejected")
}
