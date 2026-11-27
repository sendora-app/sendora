// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnlite_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/webauthnlite"
)

func TestRPFromAppURL(t *testing.T) {
	ok := []struct{ in, id, origin string }{
		{"https://files.example.com", "files.example.com", "https://files.example.com"},
		{"https://files.example.com/", "files.example.com", "https://files.example.com"},
		{"  https://files.example.com  ", "files.example.com", "https://files.example.com"},
		{"https://Files.Example.COM", "files.example.com", "https://files.example.com"},
		{"https://files.example.com:8443", "files.example.com", "https://files.example.com:8443"},
		{"https://files.example.com:443", "files.example.com", "https://files.example.com"},
		{"https://localhost", "localhost", "https://localhost"},
		{"http://localhost", "localhost", "http://localhost"},
		{"http://localhost:9090", "localhost", "http://localhost:9090"},
		{"http://localhost:80", "localhost", "http://localhost"},
		{"http://LOCALHOST:8080/", "localhost", "http://localhost:8080"},
		{"http://127.0.0.1:8080", "127.0.0.1", "http://127.0.0.1:8080"},
		{"http://[::1]:9090", "::1", "http://[::1]:9090"},
		{"http://[::1]", "::1", "http://[::1]"},
		{"https://xn--bcher-kva.example", "xn--bcher-kva.example", "https://xn--bcher-kva.example"},
	}
	for _, c := range ok {
		rp, good := webauthnlite.RPFromAppURL(c.in)
		if !good || rp.ID != c.id || rp.Origin != c.origin {
			t.Errorf("%q: got %+v ok=%v want %s %s", c.in, rp, good, c.id, c.origin)
		}
	}
	bad := []string{
		"", " ", "example.com", "//example.com", "https://", "javascript:alert(1)", "ftp://example.com",
		"http://example.com", "http://example.com:8080", "http://192.168.1.5", "http://localhost.evil.com",
		"http://[::2]", "https://1.2.3.4", "https://[2001:db8::1]", "https://127.0.0.1",
		"https://user@example.com", "https://user:pw@example.com", "http://user@localhost",
		"https://example.com/path", "https://example.com/a/", "https://example.com/?x=1", "https://example.com?",
		"https://example.com/#frag", "https://example.com:0", "https://example.com:65536", "https://example.com:-1",
		"https://example.com:abc", "https://example.com:", "https://example.com.", "https://exämple.com",
		"https://exa mple.com", "https://example.com\x00", "https://exam\nple.com",
	}
	for _, in := range bad {
		if rp, good := webauthnlite.RPFromAppURL(in); good {
			t.Errorf("%q must be rejected, got %+v", in, rp)
		}
	}
}

func TestNewChallenge(t *testing.T) {
	a, err := webauthnlite.NewChallenge()
	if err != nil || len(a) != 32 {
		t.Fatal(len(a), err)
	}
	b, _ := webauthnlite.NewChallenge()
	if string(a) == string(b) {
		t.Fatal("challenges must differ")
	}
}

func TestOptionsAreJSONReady(t *testing.T) {
	rp := webauthnlite.RP{ID: "example.com", Origin: "https://example.com"}
	ch := make([]byte, 32)
	for i := range ch {
		ch[i] = 0xfb // forces '-' / '_' style characters and no padding with 32 bytes
	}
	user := webauthnlite.UserEntity{ID: []byte{1, 2, 3, 0xff}, Name: "alice", DisplayName: "Alice A."}
	co := webauthnlite.CreationOptions(rp, "Sendora", user, ch, nil)
	raw, err := json.Marshal(co)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["attestation"] != "none" || got["timeout"] != float64(300000) {
		t.Errorf("attestation/timeout: %v", got)
	}
	if strings.ContainsAny(got["challenge"].(string), "=+/") || len(got["challenge"].(string)) != 43 {
		t.Errorf("challenge not unpadded base64url: %q", got["challenge"])
	}
	if dec, err := webauthnlite.DecodeBase64URL(got["challenge"].(string)); err != nil || string(dec) != string(ch) {
		t.Errorf("challenge does not round-trip: %v", err)
	}
	if ex, ok := got["excludeCredentials"].([]any); !ok || len(ex) != 0 {
		t.Errorf("excludeCredentials must be an empty array, got %#v", got["excludeCredentials"])
	}
	algs := []float64{}
	for _, p := range got["pubKeyCredParams"].([]any) {
		m := p.(map[string]any)
		if m["type"] != "public-key" {
			t.Errorf("type %v", m["type"])
		}
		algs = append(algs, m["alg"].(float64))
	}
	if len(algs) != 3 || algs[0] != -7 || algs[1] != -8 || algs[2] != -257 {
		t.Errorf("algs %v", algs)
	}
	sel := got["authenticatorSelection"].(map[string]any)
	if sel["userVerification"] != "preferred" || sel["residentKey"] != "preferred" || sel["requireResidentKey"] != false {
		t.Errorf("selection %v", sel)
	}
	r := got["rp"].(map[string]any)
	if r["id"] != "example.com" || r["name"] != "Sendora" {
		t.Errorf("rp %v", r)
	}
	u := got["user"].(map[string]any)
	if id, _ := webauthnlite.DecodeBase64URL(u["id"].(string)); string(id) != string(user.ID) || u["name"] != "alice" || u["displayName"] != "Alice A." {
		t.Errorf("user %v", u)
	}

	co = webauthnlite.CreationOptions(rp, "Sendora", user, ch, [][]byte{{9, 9}, {8}})
	if len(co.ExcludeCredentials) != 2 || co.ExcludeCredentials[0].ID != webauthnlite.Base64URL([]byte{9, 9}) || co.ExcludeCredentials[0].Type != "public-key" {
		t.Errorf("exclude: %+v", co.ExcludeCredentials)
	}

	ro := webauthnlite.RequestOptions(rp, ch, [][]byte{{1}, {2, 3}})
	raw, _ = json.Marshal(ro)
	got = map[string]any{}
	_ = json.Unmarshal(raw, &got)
	if got["rpId"] != "example.com" || got["userVerification"] != "preferred" || got["timeout"] != float64(300000) {
		t.Errorf("request options %v", got)
	}
	if allow := got["allowCredentials"].([]any); len(allow) != 2 {
		t.Errorf("allow %v", allow)
	}
	empty := webauthnlite.RequestOptions(rp, ch, nil)
	raw, _ = json.Marshal(empty)
	if !strings.Contains(string(raw), `"allowCredentials":[]`) {
		t.Errorf("allowCredentials must be [] not null: %s", raw)
	}
}
