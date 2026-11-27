// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/sendora-app/sendora/internal/barrier"
	"github.com/sendora-app/sendora/internal/netguard"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
	"io"
	"log"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"
	"time"
	"unicode/utf8"
)

func cleanHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// parseMailAddress parses one RFC 5322 address and rejects any CR, LF or NUL
// in the input or the parsed result, so neither can reach a header or an SMTP
// command.
func parseMailAddress(s string) (*mail.Address, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return nil, fmt.Errorf("invalid address")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(a.Address, "\r\n\x00") || strings.ContainsAny(a.Name, "\r\n\x00") {
		return nil, fmt.Errorf("invalid address")
	}
	return a, nil
}

// headerAddress renders an address for a header line: names are RFC 2047
// encoded by mail.Address.String, and any CR/LF is removed as a last guard.
func headerAddress(a *mail.Address) string {
	return cleanHeader(a.String())
}

func (s *Server) sendMail(to, subject, body string) error {
	if err := s.smtpConfigured(); err != nil {
		return err
	}
	host := s.smtpSetting("smtp_host")
	if host == "" {
		return fmt.Errorf("smtp not configured")
	}
	addr, err := parseMailAddress(to)
	if err != nil {
		return fmt.Errorf("bad recipient")
	}
	port := s.smtpSetting("smtp_port")
	user, pass := s.smtpSetting("smtp_user"), s.smtpSetting("smtp_pass")
	from := s.smtpSetting("smtp_from")
	if from == "" {
		from = user
	}
	fa, err := parseMailAddress(from)
	if err != nil {
		return fmt.Errorf("bad from address")
	}
	msg := mailMessageReplyTo(fa, addr, s.replyToAddress(), subject, body)
	hp := net.JoinHostPort(host, port)
	mode := s.smtpSetting("smtp_tls")

	var c *smtp.Client
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	// A tenant's own SMTP server (not the platform default) must not be on the
	// platform's network (multi-tenant SSRF guard, checked after DNS).
	if s.guardTargets() && strings.TrimSpace(s.St.Setting("smtp_host")) != "" {
		dialer.Control = netguard.Control
	}
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if mode == "tls" {
		conn, err := tls.DialWithDialer(dialer, "tcp", hp, cfg)
		if err != nil {
			return err
		}
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		c, err = smtp.NewClient(conn, host)
		if err != nil {
			conn.Close()
			return err
		}
	} else {
		conn, err := dialer.Dial("tcp", hp)
		if err != nil {
			return err
		}
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		c, err = smtp.NewClient(conn, host)
		if err != nil {
			conn.Close()
			return err
		}
		if mode == "starttls" {
			if err := c.StartTLS(cfg); err != nil {
				c.Close()
				return err
			}
		}
	}
	defer c.Close()
	if user != "" {
		if err := c.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(fa.Address); err != nil {
		return err
	}
	if err := c.Rcpt(addr.Address); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	// Every header value in msg is CR/LF-free and every address was validated by
	// parseMailAddress (see mailMessageReplyTo). A remaining CodeQL
	// go/email-injection finding here is inherent: the recipient and the body
	// text (share message, names) are user-supplied by design; the body is
	// quoted-printable encoded after the header block and cannot add headers.
	if _, err := wc.Write([]byte(msg)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// smtpErrorCategory turns a delivery error into a short, fixed message for the
// browser. Raw network errors (addresses, ports, server banners) stay in the
// server log, so the test button cannot be used to map internal hosts.
func smtpErrorCategory(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "smtp not configured"), strings.Contains(msg, "bad from address"), strings.Contains(msg, "bad recipient"), strings.Contains(msg, "invalid smtp"):
		return err.Error()
	case strings.Contains(msg, "535"), strings.Contains(msg, "auth"):
		return "SMTP sign-in failed: check the username and password"
	case strings.Contains(msg, "tls"), strings.Contains(msg, "x509"), strings.Contains(msg, "certificate"):
		return "SMTP secure connection failed: check the security mode and port"
	case strings.Contains(msg, "dial"), strings.Contains(msg, "timeout"), strings.Contains(msg, "refused"), strings.Contains(msg, "no such host"):
		return "could not connect to the SMTP server: check the server and port"
	}
	return "sending the test email failed (details are in the server log)"
}

func mailMessage(from, to *mail.Address, subject, body string) string {
	return mailMessageReplyTo(from, to, nil, subject, body)
}

// replyToAddress is the optional Reply-To of all outgoing mail (nil when unset or invalid).
func (s *Server) replyToAddress() *mail.Address {
	v := strings.TrimSpace(s.smtpSetting("smtp_reply_to"))
	if v == "" {
		return nil
	}
	a, err := parseMailAddress(v)
	if err != nil {
		return nil
	}
	return a
}

// validateReplyToSetting accepts an empty value or one address, optionally with a name.
func validateReplyToSetting(key string, val *string) (owned bool, err error) {
	if key != "smtp_reply_to" {
		return false, nil
	}
	v := strings.TrimSpace(*val)
	if v == "" {
		*val = ""
		return true, nil
	}
	if len(v) > 320 || strings.ContainsAny(v, "\r\n\x00") {
		return true, fmt.Errorf("invalid reply-to address")
	}
	a, e := mail.ParseAddress(v)
	if e != nil {
		return true, fmt.Errorf("invalid reply-to address")
	}
	// Stored readably: a bare address without angle brackets, a name as a quoted
	// string in plain UTF-8 (mail.Address.String would RFC 2047-encode it). The
	// header itself is still encoded when the message is built.
	if a.Name == "" {
		*val = a.Address
	} else {
		quoted := `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(a.Name) + `"`
		*val = quoted + " <" + a.Address + ">"
		if b, e := mail.ParseAddress(*val); e != nil || b.Name != a.Name || b.Address != a.Address {
			*val = a.String()
		}
	}
	return true, nil
}

func mailMessageReplyTo(from, to, replyTo *mail.Address, subject, body string) string {
	var encoded bytes.Buffer
	qp := quotedprintable.NewWriter(&encoded)
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n")
	_, _ = qp.Write([]byte(body))
	_ = qp.Close()
	// Message-ID on the sender's own domain and Auto-Submitted mark this as a
	// well-formed automatic message, which junk filters otherwise penalise.
	domain := "localhost"
	if at := strings.LastIndexByte(from.Address, '@'); at >= 0 && at+1 < len(from.Address) {
		domain = from.Address[at+1:]
	}
	// Every header value is made CR/LF-free here, whatever the callers checked:
	// addresses via headerAddress, the subject is cleaned and RFC 2047 encoded.
	domain = strings.NewReplacer("\r", "", "\n", "", " ", "", "<", "", ">", "").Replace(domain)
	replyHeader := ""
	if replyTo != nil {
		replyHeader = "Reply-To: " + headerAddress(replyTo) + "\r\n"
	}
	return fmt.Sprintf("From: %s\r\n%sTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n%s", headerAddress(from), replyHeader, headerAddress(to), mime.QEncoding.Encode("UTF-8", cleanHeader(subject)), time.Now().Format(time.RFC1123Z), randHex(16), domain, encoded.String())
}

func (s *Server) smtpConfigured() error {
	if strings.TrimSpace(s.smtpSetting("smtp_host")) == "" {
		return fmt.Errorf("smtp not configured")
	}
	port, err := strconv.Atoi(s.smtpSetting("smtp_port"))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid SMTP port")
	}
	from := s.smtpSetting("smtp_from")
	if from == "" {
		from = s.smtpSetting("smtp_user")
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return fmt.Errorf("invalid SMTP sender")
	}
	mode := s.smtpSetting("smtp_tls")
	if mode != "none" && mode != "tls" && mode != "starttls" {
		return fmt.Errorf("invalid SMTP TLS mode")
	}
	return nil
}

func (s *Server) recipientLanguage(to, selected string) string {
	address, err := mail.ParseAddress(to)
	if err == nil {
		if language, err := s.St.Repos().Mail().LanguageOfUniqueEmail(context.Background(), strings.ToLower(address.Address)); err == nil {
			if s.St.ValidMailLanguage(language) {
				return language
			}
			return "en"
		}
	}
	if s.St.ValidMailLanguage(selected) {
		return selected
	}
	return "en"
}

var mailVars = []string{"ApplicationName", "RecipientName", "SenderName", "URL", "Message", "Expires", "ShareName", "Code", "DownloadCount", "FileName", "FileNames", "StartedAt", "Username", "LoginURL", "SetPasswordURL", "ExpiresDays", "Time", "Browser"}

type limitedMailWriter struct{ bytes.Buffer }

func (w *limitedMailWriter) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 128<<10 {
		return 0, fmt.Errorf("rendered template too large")
	}
	return w.Buffer.Write(p)
}

func executeMailTemplate(source string, data map[string]any) (string, error) {
	t, err := template.New("mail").Option("missingkey=error").Parse(source)
	if err != nil {
		return "", err
	}
	var b limitedMailWriter
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

func validateMailTemplate(source string, subject bool) error {
	limit := 64 << 10
	if subject {
		limit = 500
	}
	if len(source) > limit || !utf8.ValidString(source) || strings.ContainsRune(source, '\x00') {
		return fmt.Errorf("invalid or oversized template")
	}
	if subject && strings.ContainsAny(source, "\r\n") {
		return fmt.Errorf("subject must be one line")
	}
	t, err := template.New("mail").Parse(source)
	if err != nil {
		return err
	}
	// Restrict new edits to text and simple variables: no loops, definitions,
	// function calls or conditional branches hiding invalid variables.
	for _, node := range t.Tree.Root.Nodes {
		switch n := node.(type) {
		case *parse.TextNode:
		case *parse.ActionNode:
			if len(n.Pipe.Decl) != 0 || len(n.Pipe.Cmds) != 1 || len(n.Pipe.Cmds[0].Args) != 1 {
				return fmt.Errorf("use simple {{.Variable}} placeholders")
			}
			field, ok := n.Pipe.Cmds[0].Args[0].(*parse.FieldNode)
			if !ok || len(field.Ident) != 1 {
				return fmt.Errorf("use simple {{.Variable}} placeholders")
			}
			found := false
			for _, v := range mailVars {
				found = found || field.Ident[0] == v
			}
			if !found {
				return fmt.Errorf("unknown variable: %s", field.Ident[0])
			}
		default:
			return fmt.Errorf("use text and simple {{.Variable}} placeholders")
		}
	}
	if len(t.Templates()) != 1 {
		return fmt.Errorf("template definitions are not supported")
	}
	data := map[string]any{}
	for _, v := range mailVars {
		data[v] = "example"
	}
	_, err = executeMailTemplate(source, data)
	return err
}

func (s *Server) renderMail(event, language string, supplied map[string]any) (string, string, string, error) {
	if !s.St.ValidMailLanguage(language) {
		language = "en"
	}
	if _, _, ok := s.templateKey("tpl_" + event); !ok {
		return "", "", language, fmt.Errorf("unknown mail event")
	}
	data := map[string]any{}
	for _, v := range mailVars {
		data[v] = ""
	}
	for _, v := range mailVars {
		if value, ok := supplied[v]; ok {
			data[v] = value
		}
	}
	data["ApplicationName"] = s.St.Setting("application_name")
	render := func(prefix string, subject bool) (string, error) {
		for _, lang := range []string{language, "en"} {
			source := s.St.Setting(prefix + event + "_" + lang)
			if source == "" {
				continue
			}
			// Preserve migrated source in storage, but never execute unsafe legacy
			// control flow/recursion. Invalid legacy syntax falls back to English.
			if err := validateMailTemplate(source, subject); err != nil {
				continue
			}
			if value, err := executeMailTemplate(source, data); err == nil {
				return value, nil
			}
		}
		sub, body := store.MailDefaults(event, "en")
		if subject {
			return executeMailTemplate(sub, data)
		}
		return executeMailTemplate(body, data)
	}
	subject, err := render("subj_", true)
	if err != nil {
		return "", "", language, err
	}
	body, err := render("tpl_", false)
	return subject, body, language, err
}

func (s *Server) previewTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key      string            `json:"key"`
		Language string            `json:"language"`
		Data     map[string]string `json:"data"`
		Send     bool              `json:"send"`
	}
	if decodeMailRequest(w, r, &in) != nil {
		jerr(w, 400, "bad request")
		return
	}
	if in.Language == "" {
		in.Language = "en"
	}
	if !s.St.ValidMailLanguage(in.Language) {
		jerr(w, 400, "unsupported language")
		return
	}
	data := map[string]any{}
	for k, v := range in.Data {
		found := false
		for _, allowed := range mailVars {
			found = found || k == allowed
		}
		if !found || len(v) > 8192 {
			jerr(w, 400, "invalid preview data")
			return
		}
		data[k] = v
	}
	subject, body, language, err := s.renderMail(in.Key, in.Language, data)
	if err != nil {
		log.Printf("email template preview failed (key %q): %v", in.Key, err)
		jerr(w, 400, "this template could not be rendered")
		return
	}
	if in.Send {
		u := s.ctxUser(r)
		if u.Email == "" {
			jerr(w, 400, "set an email on your profile first")
			return
		}
		if err := s.sendMail(u.Email, subject, body); err != nil {
			log.Printf("email template preview send failed: %v", err)
			jerr(w, 400, smtpErrorCategory(err))
			return
		}
	}
	jout(w, 200, map[string]any{"subject": subject, "body": body, "language": language, "sent": in.Send})
}

func decodeMailRequest(w http.ResponseWriter, r *http.Request, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func (s *Server) sendTemplate(to, subject, key string, data map[string]any) {
	if err := s.deliverTemplate(to, key, data); err != nil {
		log.Printf("transactional mail delivery failed: %v", err)
	}
}

func (s *Server) deliverTemplate(to, key string, data map[string]any) error {
	// Backpressure rather than silently discarding messages above concurrency.
	s.mailSlots <- struct{}{}
	defer func() { <-s.mailSlots }()
	if to == "" {
		return fmt.Errorf("recipient required")
	}
	language, _ := data["EmailLanguage"].(string)
	subject, body, _, err := s.renderMail(strings.TrimPrefix(key, "tpl_"), s.recipientLanguage(to, language), data)
	if err != nil {
		return err
	}
	return s.sendMail(to, subject, body)
}

const downloadMailCapacity = 1000

// RunDownloadMail runs one bounded worker. Pending jobs survive process restarts;
// at-least-once SMTP delivery may duplicate mail after a crash following acceptance.
func (s *Server) RunDownloadMail(ctx context.Context) {
	s.downloadMailOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				if ctx.Err() != nil {
					return
				}
				if s.processDownloadMail(ctx) {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case <-s.downloadMailWake:
				case <-ticker.C:
				}
			}
		}()
	})
}

// downloadMailLease is how long a claimed download notification is reserved
// for the worker that sends it.
const downloadMailLease = 2 * time.Minute

func (s *Server) processDownloadMail(ctx context.Context) bool {
	// Acquiring before loading ensures no queued goroutine retains request/files.
	select {
	case s.mailSlots <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	defer func() { <-s.mailSlots }()
	now := time.Now()
	job, err := s.St.Repos().DownloadMails().NextDue(context.Background(), now)
	if err != nil {
		return false
	}
	id, recipient, language, source, attempts := job.ID, job.Recipient, job.Language, job.Data, job.Attempts
	// Claim-commit barrier (design 4.3): the mail is sent only after the claim
	// committed cleanly, which proves the job row is replicated; the lease
	// keeps other workers away. Not claimed (taken, or outcome unknown or
	// failed): nothing is sent; the job is retried later.
	claimed, err := barrier.Claim(context.Background(), s.St.Repos(), "download_mail_claim", func(tx ports.Tx) (bool, error) {
		// Cluster: a former leader's worker (stale epoch) claims nothing.
		if ok, err := s.jobFence(context.Background(), tx, WorkDownloadMail); err != nil || !ok {
			return false, err
		}
		n, err := tx.DownloadMails().Claim(context.Background(), id, now, now.Add(downloadMailLease))
		return n == 1, err
	})
	if err != nil {
		log.Printf("download notification %d not claimed: %v", id, err)
	}
	if !claimed {
		return false
	}
	data := map[string]any{}
	err = json.Unmarshal([]byte(source), &data)
	if err == nil {
		var subject, body string
		subject, body, _, err = s.renderMail("share_downloaded", language, data)
		if err == nil {
			err = s.sendMail(recipient, subject, body)
		}
	}
	if err == nil {
		if err := s.St.Repos().DownloadMails().Delete(context.Background(), id); err != nil {
			log.Printf("remove delivered download mail: %v", err)
		}
		return true
	}
	attempts++
	status := "pending"
	if attempts >= 3 {
		status = "failed"
	}
	if saveErr := s.St.Repos().DownloadMails().RecordFailure(context.Background(), id, attempts, status, err.Error(), time.Now().Add(time.Duration(attempts)*30*time.Second)); saveErr != nil {
		log.Printf("save download mail failure: %v", saveErr)
	}
	if status == "failed" {
		// Retain the newest bounded failure records for diagnosis, not an
		// ever-growing second queue when SMTP remains unavailable.
		if err := s.St.Repos().DownloadMails().PruneFailed(context.Background()); err != nil {
			log.Printf("prune download mail failures: %v", err)
		}
	}
	log.Printf("download notification %d delivery attempt %d failed: %v", id, attempts, err)
	return true
}

func (s *Server) notifyInviteCompleted(ownerID int64, guest *User, url, name string) {
	email, _ := s.St.Repos().Users().Email(context.Background(), ownerID)
	s.sendTemplate(email, "Files uploaded to you", "tpl_reverse_completed", map[string]any{
		"RecipientName": "", "SenderName": nameOf(guest), "URL": url, "Message": "", "Expires": "", "ShareName": name,
	})
}

// ---------- email templates API ----------

func (s *Server) getTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.St.Repos().Mail().Templates(context.Background())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	out := map[string]string{}
	for _, t := range templates {
		out[t.Key] = t.Value
	}
	jout(w, 200, out)
}

func (s *Server) putTemplates(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if decodeMailRequest(w, r, &in) != nil {
		jerr(w, 400, "bad request")
		return
	}
	updates := map[string]string{}
	for k, v := range in {
		canonical, subject, ok := s.templateKey(k)
		if !ok {
			jerr(w, 400, "unknown template key: "+k)
			return
		}
		if prior, exists := updates[canonical]; exists && prior != v {
			jerr(w, 400, "conflicting English alias: "+k)
			return
		}
		if err := validateMailTemplate(v, subject); err != nil {
			jerr(w, 400, k+": "+err.Error())
			return
		}
		updates[canonical] = v
	}
	tx, err := s.St.Repos().Begin(context.Background())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	for k, v := range updates {
		// Upsert: a language added before a mail event existed (e.g. welcome) has
		// no row for it yet, and an UPDATE alone would silently save nothing.
		if err := tx.Mail().PutTemplate(context.Background(), k, v); err != nil {
			jerr(w, 500, "template save failed")
			return
		}
		if strings.HasPrefix(k, "tpl_") && strings.HasSuffix(k, "_en") {
			if err := tx.Mail().SetTemplate(context.Background(), strings.TrimSuffix(k, "_en"), v); err != nil {
				jerr(w, 500, "template save failed")
				return
			}
		}
	}
	if err := tx.Commit(); err != nil {
		jerr(w, 500, "template save failed")
		return
	}
	jout(w, 200, map[string]any{"ok": true})
}

func (s *Server) testEmail(w http.ResponseWriter, r *http.Request) {
	u := s.ctxUser(r)
	if u.Email == "" {
		jerr(w, 400, "set an email on your profile first")
		return
	}
	subject, body := store.TestMailText(u.Language)
	if err := s.sendMail(u.Email, subject, body); err != nil {
		log.Printf("test email failed: %v", err)
		jerr(w, 400, smtpErrorCategory(err))
		return
	}
	jout(w, 200, map[string]any{"ok": true})
}
