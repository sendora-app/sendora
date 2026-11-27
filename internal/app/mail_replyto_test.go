// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/mail"
	"strings"
	"testing"
)

func TestMailReplyToHeader(t *testing.T) {
	from := &mail.Address{Name: "Sendora", Address: "noreply@example.test"}
	to := &mail.Address{Address: "to@example.test"}
	if strings.Contains(mailMessage(from, to, "Hi", "b"), "Reply-To") {
		t.Fatal("no Reply-To expected by default")
	}
	rt := &mail.Address{Name: "Support Team", Address: "support@example.test"}
	msg := mailMessageReplyTo(from, to, rt, "Hi", "b")
	parsed, err := mail.ReadMessage(strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	got, err := mail.ParseAddress(parsed.Header.Get("Reply-To"))
	if err != nil || got.Address != "support@example.test" || got.Name != "Support Team" {
		t.Fatalf("bad Reply-To: %v %v", got, err)
	}
	if parsed.Header.Get("From") == "" || strings.Count(msg, "Reply-To:") != 1 {
		t.Fatal("headers malformed")
	}
}

func TestReplyToSetting(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	for _, bad := range []string{"not an address", "a@b.c\r\nBcc: x@y.z", "a@b.c, d@e.f", strings.Repeat("a", 400) + "@x.io"} {
		e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_reply_to": bad}), 400, "reject "+bad[:min(len(bad), 12)])
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_reply_to": "  Support <support@example.test> "}), 200, "valid")
	if a := e.s.replyToAddress(); a == nil || a.Address != "support@example.test" || a.Name != "Support" {
		t.Fatalf("stored address not usable: %v", a)
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_reply_to": "info@example.test"}), 200, "bare address")
	if got := e.s.St.Setting("smtp_reply_to"); got != "info@example.test" {
		t.Fatalf("bare address must be stored without brackets: %q", got)
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_reply_to": "<info@example.test>"}), 200, "bracketed input")
	if got := e.s.St.Setting("smtp_reply_to"); got != "info@example.test" {
		t.Fatalf("brackets must be stripped: %q", got)
	}
	e.want(e.do("PUT", "/api/settings", admin, map[string]any{"smtp_reply_to": ""}), 200, "clear")
	if e.s.replyToAddress() != nil {
		t.Fatal("cleared setting must disable Reply-To")
	}
}
