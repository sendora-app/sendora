// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/mail"
	"regexp"
	"strings"
	"testing"
)

func TestMailMessageHasMessageIDAndAutoSubmitted(t *testing.T) {
	from := &mail.Address{Name: "Sendora", Address: "noreply@example.test"}
	to := &mail.Address{Address: "to@example.test"}
	msg := mailMessage(from, to, "Hello", "body")
	if !regexp.MustCompile(`(?m)^Message-ID: <[0-9a-f]{32}@example\.test>\r$`).MatchString(msg) {
		t.Fatal("missing or malformed Message-ID:\n", msg)
	}
	if !strings.Contains(msg, "\r\nAuto-Submitted: auto-generated\r\n") {
		t.Fatal("missing Auto-Submitted header")
	}
	if mailMessage(from, to, "Hello", "body") == msg {
		t.Fatal("Message-ID must be unique per message")
	}
	if _, err := mail.ReadMessage(strings.NewReader(msg)); err != nil {
		t.Fatal("message must stay parseable:", err)
	}
}
