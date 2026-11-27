// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/webauthnlite"
	"github.com/sendora-app/sendora/internal/webauthnlite/virtual"
)

const (
	waTestOrigin = "https://sendora.example.test"
	waTestRPID   = "sendora.example.test"
)

// syncBuffer is a goroutine-safe log sink (background workers log concurrently).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func b64u(b []byte) string { return webauthnlite.Base64URL(b) }

// newWAEnv: an environment with passkeys switched on (secure origin configured).
func newWAEnv(t *testing.T) (*env, string) {
	t.Helper()
	e := newEnv(t)
	admin := e.setup()
	e.s.BaseURL = waTestOrigin
	e.setting("mfa_policy", "optional")
	return e, admin
}

func waDevice(t *testing.T, alg int) *virtual.Authenticator {
	t.Helper()
	d, err := virtual.New(alg)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func waCredJSON(id []byte, response map[string]any) map[string]any {
	return map[string]any{"id": b64u(id), "rawId": b64u(id), "type": "public-key", "response": response}
}

// optionChallenge extracts the challenge bytes from a begin response.
func optionChallenge(t *testing.T, r resp) []byte {
	t.Helper()
	opts, _ := r.J()["options"].(map[string]any)
	ch, _ := opts["challenge"].(string)
	raw, err := webauthnlite.DecodeBase64URL(ch)
	if err != nil || len(raw) == 0 {
		t.Fatalf("no challenge in %s", r.Body)
	}
	return raw
}

// waBegin starts a registration ceremony.
func (e *env) waBegin(tok, password string) resp {
	return e.do("POST", "/api/users/me/mfa/webauthn/begin", tok, map[string]any{"password": password})
}

// waFinish posts a registration response produced by the virtual authenticator.
func (e *env) waFinish(tok string, begin resp, dev *virtual.Authenticator, o virtual.Options, name string) resp {
	e.t.Helper()
	cd, att := dev.Register(waTestRPID, waTestOrigin, optionChallenge(e.t, begin), o)
	return e.do("POST", "/api/users/me/mfa/webauthn/finish", tok, map[string]any{
		"challenge_id": begin.S("challenge_id"), "name": name,
		"credential": waCredJSON(dev.CredID, map[string]any{"clientDataJSON": b64u(cd), "attestationObject": b64u(att)}),
	})
}

func (e *env) waRegister(tok string, dev *virtual.Authenticator, o virtual.Options, name string) resp {
	e.t.Helper()
	b := e.waBegin(tok, "password123")
	e.want(b, 200, "webauthn begin")
	return e.waFinish(tok, b, dev, o, name)
}

// waLoginStart does the password step and the begin call.
func (e *env) waLoginStart(name string) (mfaToken string, challenge []byte, begin resp) {
	e.t.Helper()
	l := e.login(name, "password123")
	e.want(l, 200, "password step")
	if l.J()["mfa_required"] != true {
		e.t.Fatalf("expected an MFA challenge: %s", l.Body)
	}
	mfaToken = l.S("mfa_token")
	begin = e.waLoginBegin(mfaToken)
	e.want(begin, 200, "webauthn login begin")
	return mfaToken, optionChallenge(e.t, begin), begin
}

// waLoginCeremonies maps an mfa_token to the challenge_id of its latest
// login begin (the sealed ceremony waLoginFinish sends back).
var waLoginCeremonies sync.Map

func (e *env) waLoginBegin(mfaToken string) resp {
	r := e.do("POST", "/api/auth/mfa/webauthn/begin", "", map[string]any{"mfa_token": mfaToken})
	if id := r.S("challenge_id"); id != "" {
		waLoginCeremonies.Store(mfaToken, id)
	}
	return r
}

func waLoginCeremony(mfaToken string) string {
	v, _ := waLoginCeremonies.Load(mfaToken)
	s, _ := v.(string)
	return s
}

func (e *env) waLoginFinish(mfaToken string, dev *virtual.Authenticator, challenge []byte, o virtual.Options) resp {
	e.t.Helper()
	cd, ad, sig := dev.Assert(waTestRPID, waTestOrigin, challenge, o)
	return e.do("POST", "/api/auth/mfa/webauthn/finish", "", map[string]any{
		"mfa_token": mfaToken, "challenge_id": waLoginCeremony(mfaToken),
		"credential": waCredJSON(dev.CredID, map[string]any{
			"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig), "userHandle": "",
		}),
	})
}

// waUser creates a user with one registered passkey.
func waUser(t *testing.T, name string, alg int) (*env, string, string, *virtual.Authenticator) {
	t.Helper()
	e, admin := newWAEnv(t)
	tok := e.mkUser(admin, name, false)
	dev := waDevice(t, alg)
	r := e.waRegister(tok, dev, virtual.Options{}, "")
	e.want(r, 200, "register passkey")
	return e, admin, r.S("access_token"), dev // factor changes revoke the old access token
}

func signCount(t *testing.T, e *env, cred []byte) int64 {
	t.Helper()
	var n int64
	if err := e.s.St.DB.QueryRow(`SELECT sign_count FROM user_webauthn WHERE cred_id=?`, cred).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func wantNoSession(t *testing.T, r resp, status int, msg string) {
	t.Helper()
	if r.Code != status || r.J()["access_token"] != nil || refreshCookie(r) != "" {
		t.Fatalf("%s: want %d without a session, got %d %s", msg, status, r.Code, r.Body)
	}
}

func TestWebAuthnEnrollAndLoginAllAlgorithms(t *testing.T) {
	for _, alg := range []int{webauthnlite.AlgES256, webauthnlite.AlgEdDSA, webauthnlite.AlgRS256} {
		t.Run(fmt.Sprint("alg", alg), func(t *testing.T) {
			e, _, tok, dev := waUser(t, "wanda", alg)
			status := e.do("GET", "/api/users/me/mfa", tok, nil)
			e.want(status, 200, "status")
			wa := status.J()["webauthn"].(map[string]any)
			creds := wa["credentials"].([]any)
			if wa["enabled"] != true || wa["available"] != true || len(creds) != 1 || creds[0].(map[string]any)["name"] != waDefaultKeyName {
				t.Fatal("credential listed with the default name", string(status.Body))
			}
			if status.J()["recovery_codes_remaining"] != float64(10) {
				t.Fatal("first factor creates the recovery codes", string(status.Body))
			}
			// First login: counter 0 -> 1.
			mfaToken, ch, begin := e.waLoginStart("wanda")
			opts := begin.J()["options"].(map[string]any)
			allow := opts["allowCredentials"].([]any)
			if opts["rpId"] != waTestRPID || len(allow) != 1 || allow[0].(map[string]any)["id"] != b64u(dev.CredID) {
				t.Fatal("request options name the rp and the user's credential", string(begin.Body))
			}
			ok := e.waLoginFinish(mfaToken, dev, ch, virtual.Options{})
			e.want(ok, 200, "passkey login")
			if ok.S("access_token") == "" || refreshCookie(ok) == "" || signCount(t, e, dev.CredID) != 1 {
				t.Fatal("session issued and counter stored", string(ok.Body))
			}
			// Second login keeps working with the next counter value.
			mfaToken, ch, _ = e.waLoginStart("wanda")
			e.want(e.waLoginFinish(mfaToken, dev, ch, virtual.Options{}), 200, "second passkey login")
			if signCount(t, e, dev.CredID) != 2 {
				t.Fatal("counter follows the authenticator")
			}
		})
	}
}

func TestWebAuthnLoginRejectsBadAssertions(t *testing.T) {
	one := uint32(1)
	cases := []struct {
		name string
		o    virtual.Options
		pre  bool // do one good login first (counter 1)
	}{
		{name: "wrong challenge", o: virtual.Options{Challenge: bytes.Repeat([]byte{7}, 32)}},
		{name: "wrong origin", o: virtual.Options{Origin: "https://evil.example.test"}},
		{name: "wrong rp id", o: virtual.Options{RPID: "evil.example.test"}},
		{name: "tampered signature", o: virtual.Options{TamperSignature: true}},
		{name: "tampered client data", o: virtual.Options{TamperClientData: true}},
		{name: "tampered authenticator data", o: virtual.Options{TamperAuthData: true}},
		{name: "no user presence", o: virtual.Options{NoUP: true}},
		{name: "wrong type", o: virtual.Options{Type: "webauthn.create"}},
		{name: "cross origin", o: virtual.Options{CrossOrigin: true}},
		{name: "counter regression", o: virtual.Options{Counter: &one}, pre: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, _, _, dev := waUser(t, "wanda", webauthnlite.AlgES256)
			if c.pre {
				mfaToken, ch, _ := e.waLoginStart("wanda")
				e.want(e.waLoginFinish(mfaToken, dev, ch, virtual.Options{}), 200, "first login")
			}
			_, failuresBefore := e.userRow("wanda")
			mfaToken, ch, _ := e.waLoginStart("wanda")
			bad := e.waLoginFinish(mfaToken, dev, ch, c.o)
			wantNoSession(t, bad, 401, c.name)
			if bad.S("error") != "invalid code" {
				t.Fatal("generic error only", string(bad.Body))
			}
			if _, failures := e.userRow("wanda"); failures != failuresBefore+1 {
				t.Fatalf("failure counted: %d -> %d", failuresBefore, failures)
			}
			// The ceremony is single use: even a perfect assertion for it is refused ...
			replay := e.waLoginFinish(mfaToken, dev, ch, virtual.Options{})
			wantNoSession(t, replay, 401, "used ceremony")
			// ... while a fresh begin with the same pending token still works.
			begin := e.waLoginBegin(mfaToken)
			e.want(begin, 200, "begin again")
			e.want(e.waLoginFinish(mfaToken, dev, optionChallenge(t, begin), virtual.Options{}), 200, "good assertion after a failure")
		})
	}
}

func TestWebAuthnLoginUnknownCredentialAndTokens(t *testing.T) {
	e, _, tok, dev := waUser(t, "wanda", webauthnlite.AlgES256)
	stranger := waDevice(t, webauthnlite.AlgES256)
	mfaToken, ch, _ := e.waLoginStart("wanda")
	wantNoSession(t, e.waLoginFinish(mfaToken, stranger, ch, virtual.Options{}), 401, "unregistered authenticator")

	// An access token (wrong purpose) or garbage is no pending token.
	for _, bad := range []string{tok, "garbage", ""} {
		r := e.do("POST", "/api/auth/mfa/webauthn/begin", "", map[string]any{"mfa_token": bad})
		if r.Code != 401 || r.S("error") != msgMFAExpired {
			t.Fatal("begin with a non-mfa token", r.Code, string(r.Body))
		}
	}
	// finish without begin
	mfaToken2 := e.login("wanda", "password123").S("mfa_token")
	cd, ad, sig := dev.Assert(waTestRPID, waTestOrigin, bytes.Repeat([]byte{1}, 32), virtual.Options{})
	r := e.do("POST", "/api/auth/mfa/webauthn/finish", "", map[string]any{"mfa_token": mfaToken2,
		"credential": waCredJSON(dev.CredID, map[string]any{"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig)})})
	wantNoSession(t, r, 401, "finish without begin")

	// A spent pending token cannot be reused for another login or ceremony.
	mfaToken3, ch3, _ := e.waLoginStart("wanda")
	e.want(e.waLoginFinish(mfaToken3, dev, ch3, virtual.Options{}), 200, "login")
	again := e.waLoginBegin(mfaToken3)
	if again.Code != 401 || again.S("error") != msgMFAExpired {
		t.Fatal("spent pending token", again.Code, string(again.Body))
	}
	// Malformed credential fields fail generically.
	mfaToken4, _, _ := e.waLoginStart("wanda")
	for _, cred := range []map[string]any{
		{"id": "!!", "rawId": "!!", "type": "public-key", "response": map[string]any{}},
		{"id": b64u(dev.CredID), "rawId": b64u([]byte("other")), "type": "public-key", "response": map[string]any{}},
		{"id": b64u(dev.CredID), "type": "password", "response": map[string]any{}},
	} {
		bad := e.do("POST", "/api/auth/mfa/webauthn/finish", "", map[string]any{"mfa_token": mfaToken4, "challenge_id": waLoginCeremony(mfaToken4), "credential": cred})
		if bad.Code != 401 || bad.J()["access_token"] != nil {
			t.Fatal("malformed credential", bad.Code, string(bad.Body))
		}
		// each failed finish consumed the ceremony: begin again for the next one
		e.want(e.waLoginBegin(mfaToken4), 200, "begin again")
	}
}

func TestWebAuthnFailuresShareTheLockout(t *testing.T) {
	e, _, _, dev := waUser(t, "wanda", webauthnlite.AlgES256)
	mfaToken := e.login("wanda", "password123").S("mfa_token")
	for i := 0; i < 2; i++ { // two wrong recovery codes ...
		r := e.do("POST", "/api/auth/mfa/recovery", "", map[string]any{"mfa_token": mfaToken, "code": "AAAA-AAAA-AAAA-AAAA"})
		wantNoSession(t, r, 401, "wrong recovery code")
	}
	for i := 0; i < 3; i++ { // ... plus three bad assertions reach five
		begin := e.waLoginBegin(mfaToken)
		e.want(begin, 200, "begin")
		wantNoSession(t, e.waLoginFinish(mfaToken, dev, optionChallenge(t, begin), virtual.Options{TamperSignature: true}), 401, "bad assertion")
	}
	var locked int64
	qByName(e.s.St, `SELECT login_locked_until FROM users WHERE username='wanda'`).Scan(&locked)
	if locked <= time.Now().Unix() {
		t.Fatal("five mixed failures lock the account")
	}
	begin := e.waLoginBegin(mfaToken)
	wantNoSession(t, begin, 401, "begin while locked")
	wantNoSession(t, e.login("wanda", "password123"), 401, "password login while locked")
}

func TestWebAuthnRegistrationRejectsBadResponses(t *testing.T) {
	cases := []struct {
		name string
		o    virtual.Options
	}{
		{"wrong challenge", virtual.Options{Challenge: bytes.Repeat([]byte{9}, 32)}},
		{"wrong origin", virtual.Options{Origin: "https://evil.example.test"}},
		{"wrong rp id", virtual.Options{RPID: "evil.example.test"}},
		{"wrong type", virtual.Options{Type: "webauthn.get"}},
		{"cross origin", virtual.Options{CrossOrigin: true}},
		{"no user presence", virtual.Options{NoUP: true}},
		{"bad packed signature", virtual.Options{Attestation: "packed-self", TamperSignature: true}},
		{"unsupported attestation format", virtual.Options{Attestation: "fido-u2f"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, admin := newWAEnv(t)
			tok := e.mkUser(admin, "wanda", false)
			r := e.waRegister(tok, waDevice(t, webauthnlite.AlgES256), c.o, "")
			if r.Code != 400 || r.S("error") != msgWAFailed || r.J()["access_token"] != nil {
				t.Fatal(c.name, r.Code, string(r.Body))
			}
			var n int
			e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM user_webauthn`).Scan(&n)
			if n != 0 {
				t.Fatal("nothing stored after a failed registration")
			}
		})
	}
}

func TestWebAuthnRegistrationCeremonyRules(t *testing.T) {
	e, admin := newWAEnv(t)
	tok := e.mkUser(admin, "wanda", false)
	other := e.mkUser(admin, "otto", false)
	dev := waDevice(t, webauthnlite.AlgES256)

	// wrong password: 401 and counted
	_, before := e.userRow("wanda")
	wantNoSession(t, e.waBegin(tok, "nope-nope-nope"), 401, "wrong password")
	if _, after := e.userRow("wanda"); after != before+1 {
		t.Fatal("wrong password counts towards the lock")
	}

	// another user's challenge id is useless, and burns nothing for the owner
	begin := e.waBegin(tok, "password123")
	e.want(begin, 200, "begin")
	if r := e.waFinish(other, begin, dev, virtual.Options{}, ""); r.Code != 400 || r.S("error") != msgWAExpired {
		t.Fatal("foreign challenge id", r.Code, string(r.Body))
	}

	// replayed challenge id
	begin = e.waBegin(tok, "password123")
	first := e.waFinish(tok, begin, dev, virtual.Options{}, "Laptop")
	e.want(first, 200, "register")
	tok = first.S("access_token")
	if r := e.waFinish(tok, begin, waDevice(t, webauthnlite.AlgES256), virtual.Options{}, "x"); r.Code != 400 || r.S("error") != msgWAExpired {
		t.Fatal("replayed challenge id", r.Code, string(r.Body))
	}
	// second factor does not create new recovery codes
	if r := e.waRegister(tok, waDevice(t, webauthnlite.AlgEdDSA), virtual.Options{}, "Phone"); r.Code != 200 || r.J()["recovery_codes"] != nil {
		t.Fatal("recovery codes only with the first factor", r.Code, string(r.Body))
	}

	// duplicate credential id (the same device again, also on another account)
	if r := e.waRegister(other, dev, virtual.Options{}, ""); r.Code != 409 || r.S("error") != msgWADuplicate {
		t.Fatal("same authenticator on another account", r.Code, string(r.Body))
	}

	// credential id in the request must match the attested one
	begin = e.waBegin(other, "password123")
	cd, att := waDevice(t, webauthnlite.AlgES256).Register(waTestRPID, waTestOrigin, optionChallenge(t, begin), virtual.Options{})
	r := e.do("POST", "/api/users/me/mfa/webauthn/finish", other, map[string]any{"challenge_id": begin.S("challenge_id"),
		"credential": waCredJSON([]byte("some-other-credential-id"), map[string]any{"clientDataJSON": b64u(cd), "attestationObject": b64u(att)})})
	if r.Code != 400 || r.S("error") != msgWAFailed {
		t.Fatal("credential id mismatch", r.Code, string(r.Body))
	}

	// invalid names
	for _, name := range []string{strings.Repeat("a", waMaxKeyNameRunes+1), "bad‮name", "tab\tname"} {
		b := e.waBegin(other, "password123")
		if r := e.waFinish(other, b, waDevice(t, webauthnlite.AlgES256), virtual.Options{}, name); r.Code != 400 || r.S("error") != "invalid name" {
			t.Fatal("name", name, r.Code, string(r.Body))
		}
	}
}

func TestWebAuthnCeremonyExpires(t *testing.T) {
	e, admin := newWAEnv(t)
	tok := e.mkUser(admin, "wanda", false)
	e.s.waCeremonies.ttl = 30 * time.Millisecond
	begin := e.waBegin(tok, "password123")
	e.want(begin, 200, "begin")
	time.Sleep(80 * time.Millisecond)
	if r := e.waFinish(tok, begin, waDevice(t, webauthnlite.AlgES256), virtual.Options{}, ""); r.Code != 400 || r.S("error") != msgWAExpired {
		t.Fatal("expired registration ceremony", r.Code, string(r.Body))
	}
	// login ceremony too
	e.s.waCeremonies.ttl = 0
	dev := waDevice(t, webauthnlite.AlgES256)
	e.want(e.waRegister(tok, dev, virtual.Options{}, ""), 200, "register")
	e.s.waCeremonies.ttl = 30 * time.Millisecond
	mfaToken, ch, _ := e.waLoginStart("wanda")
	time.Sleep(80 * time.Millisecond)
	wantNoSession(t, e.waLoginFinish(mfaToken, dev, ch, virtual.Options{}), 401, "expired login ceremony")
}

func TestWebAuthnCredentialLimit(t *testing.T) {
	e, admin := newWAEnv(t)
	tok := e.mkUser(admin, "wanda", false)
	for i := 0; i < waMaxCredentials; i++ {
		r := e.waRegister(tok, waDevice(t, webauthnlite.AlgES256), virtual.Options{}, fmt.Sprintf("key %d", i))
		e.want(r, 200, fmt.Sprintf("credential %d", i+1))
		tok = r.S("access_token")
	}
	if r := e.waBegin(tok, "password123"); r.Code != 409 || r.S("error") != msgWATooMany {
		t.Fatal("11th credential", r.Code, string(r.Body))
	}
}

func TestWebAuthnRenameAndRemove(t *testing.T) {
	e, admin := newWAEnv(t)
	tok := e.mkUser(admin, "wanda", false)
	otherTok := e.mkUser(admin, "otto", false)
	dev := waDevice(t, webauthnlite.AlgES256)
	reg := e.waRegister(tok, dev, virtual.Options{}, "Laptop")
	e.want(reg, 200, "register")
	tok = reg.S("access_token")
	var id int64
	e.s.St.DB.QueryRow(`SELECT id FROM user_webauthn WHERE name='Laptop'`).Scan(&id)
	path := fmt.Sprintf("/api/users/me/mfa/webauthn/%d", id)

	e.want(e.do("PUT", path, tok, map[string]any{"name": "  Work laptop "}), 200, "rename")
	var name string
	e.s.St.DB.QueryRow(`SELECT name FROM user_webauthn WHERE id=?`, id).Scan(&name)
	if name != "Work laptop" {
		t.Fatal("rename trims", name)
	}
	if r := e.do("PUT", path, tok, map[string]any{"name": strings.Repeat("x", 61)}); r.Code != 400 {
		t.Fatal("long name", r.Code)
	}
	e.want(e.do("PUT", path, otherTok, map[string]any{"name": "mine now"}), 404, "foreign rename")
	e.want(e.do("POST", path+"/remove", otherTok, map[string]any{"password": "password123"}), 404, "foreign remove")
	wantNoSession(t, e.do("POST", path+"/remove", tok, map[string]any{"password": "wrong-wrong-1"}), 401, "wrong password")

	// MFA required and no other factor: the last factor cannot go.
	eByName(e.s.St, `UPDATE users SET mfa_policy='required' WHERE username='wanda'`)
	if r := e.do("POST", path+"/remove", tok, map[string]any{"password": "password123"}); r.Code != 409 || r.S("error") != msgMFARequiredKeep {
		t.Fatal("last factor while required", r.Code, string(r.Body))
	}
	// With an authenticator app as well, the key may be removed.
	_, tok, _ = e.enrollTOTP(tok, "password123")
	rm := e.do("POST", path+"/remove", tok, map[string]any{"password": "password123"})
	e.want(rm, 200, "remove with another factor")
	if rm.S("access_token") == "" {
		t.Fatal("factor change returns a fresh session")
	}
	var n int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM user_webauthn`).Scan(&n)
	if n != 0 {
		t.Fatal("credential deleted")
	}
	// Not required any more: a user may drop the last passkey; recovery codes go with the last factor.
	eByName(e.s.St, `UPDATE users SET mfa_policy='inherit' WHERE username='wanda'`)
	var codes int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM user_recovery_codes`).Scan(&codes)
	if codes == 0 {
		t.Fatal("recovery codes stay while the authenticator app remains")
	}
}

func TestWebAuthnRemovingLastKeyDropsRecoveryCodes(t *testing.T) {
	e, _, tok, _ := waUser(t, "wanda", webauthnlite.AlgES256)
	var id int64
	e.s.St.DB.QueryRow(`SELECT id FROM user_webauthn`).Scan(&id)
	e.want(e.do("POST", fmt.Sprintf("/api/users/me/mfa/webauthn/%d/remove", id), tok, map[string]any{"password": "password123"}), 200, "remove")
	var codes int
	e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM user_recovery_codes`).Scan(&codes)
	if codes != 0 {
		t.Fatal("no factor left: recovery codes are removed")
	}
	if e.login("wanda", "password123").J()["mfa_required"] == true {
		t.Fatal("no factor left: plain login again")
	}
}

func TestWebAuthnDisabledOrUnavailable(t *testing.T) {
	e, _, tok, dev := waUser(t, "wanda", webauthnlite.AlgES256)
	mfaToken, ch, _ := e.waLoginStart("wanda")

	probe := func(what string, wantStatus int) {
		t.Helper()
		calls := []resp{
			e.do("POST", "/api/users/me/mfa/webauthn/begin", tok, map[string]any{"password": "password123"}),
			e.do("POST", "/api/users/me/mfa/webauthn/finish", tok, map[string]any{"challenge_id": "x", "credential": map[string]any{}}),
			e.do("PUT", "/api/users/me/mfa/webauthn/1", tok, map[string]any{"name": "x"}),
			e.do("POST", "/api/users/me/mfa/webauthn/1/remove", tok, map[string]any{"password": "password123"}),
			e.waLoginBegin(mfaToken),
			e.waLoginFinish(mfaToken, dev, ch, virtual.Options{}),
		}
		for i, r := range calls {
			if r.Code != wantStatus || (wantStatus == 409 && r.S("error") != msgMFANotEnabled) {
				t.Fatalf("%s: call %d answered %d %s", what, i, r.Code, r.Body)
			}
		}
	}
	e.setting("mfa_webauthn_enabled", "false")
	probe("method disabled", 409)
	e.setting("mfa_webauthn_enabled", "true")
	e.s.BaseURL = "http://insecure.example.test" // not a secure origin
	probe("insecure origin", 409)
	boot := e.do("GET", "/api/bootstrap", "", nil).J()
	if boot["webauthn_available"] != false || boot["mfa_webauthn_enabled"] != false {
		t.Fatal("bootstrap reflects an unavailable origin", boot)
	}
	e.s.BaseURL = waTestOrigin
	e.setting("mfa_policy", "off")
	probe("mfa off", 409)
}

func TestWebAuthnSpentSetIsBounded(t *testing.T) {
	var c waCeremonies
	c.cap = 3
	exp := time.Now().Add(40 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if !c.spend(fmt.Sprint("k", i), exp) {
			t.Fatal("room for", i)
		}
	}
	if c.spend("k1", exp) {
		t.Fatal("single use")
	}
	if c.spend("overflow", exp) {
		t.Fatal("a full set refuses (never forgets a live spend)")
	}
	time.Sleep(80 * time.Millisecond)
	if !c.spend("fresh", time.Now().Add(time.Minute)) || c.size() > 1 {
		t.Fatal("expired entries make room", c.size())
	}
}

// TestWebAuthnSealedCeremony: the challenge_id is opaque, authenticated,
// bound to kind, user and binding, expires, and completes once.
func TestWebAuthnSealedCeremony(t *testing.T) {
	s := &Server{Secret: bytes.Repeat([]byte{7}, 32)}
	ch := bytes.Repeat([]byte{9}, 32)
	id, err := s.waBeginCeremony(waKindLogin, 5, "jti-a", ch)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(id, b64u(ch)) {
		t.Fatal("challenge visible in the challenge_id")
	}
	for _, c := range []struct {
		kind string
		uid  int64
		bind string
	}{{waKindRegistration, 5, "jti-a"}, {waKindLogin, 6, "jti-a"}, {waKindLogin, 5, "jti-b"}} {
		if _, ok := s.waTakeCeremony(id, c.kind, c.uid, c.bind); ok {
			t.Fatalf("accepted with %+v", c)
		}
	}
	// a mismatch does not spend it
	if got, ok := s.waTakeCeremony(id, waKindLogin, 5, "jti-a"); !ok || !bytes.Equal(got, ch) {
		t.Fatal("valid ceremony refused")
	}
	if _, ok := s.waTakeCeremony(id, waKindLogin, 5, "jti-a"); ok {
		t.Fatal("ceremony completed twice")
	}
	// tampering, another tenant's secret, garbage
	id2, _ := s.waBeginCeremony(waKindStepUp, 5, "", ch)
	raw, _ := base64.RawURLEncoding.DecodeString(id2)
	raw[len(raw)-1] ^= 1
	if _, ok := s.waTakeCeremony(base64.RawURLEncoding.EncodeToString(raw), waKindStepUp, 5, ""); ok {
		t.Fatal("tampered challenge_id accepted")
	}
	other := &Server{Secret: bytes.Repeat([]byte{8}, 32)}
	if _, ok := other.waTakeCeremony(id2, waKindStepUp, 5, ""); ok {
		t.Fatal("ceremony of another tenant accepted")
	}
	for _, bad := range []string{"", "x", "!!!", strings.Repeat("A", 2000)} {
		if _, ok := s.waTakeCeremony(bad, waKindStepUp, 5, ""); ok {
			t.Fatal("garbage accepted:", bad)
		}
	}
	// expiry
	s.waCeremonies.ttl = 20 * time.Millisecond
	id3, _ := s.waBeginCeremony(waKindStepUp, 5, "", ch)
	time.Sleep(50 * time.Millisecond)
	if _, ok := s.waTakeCeremony(id3, waKindStepUp, 5, ""); ok {
		t.Fatal("expired ceremony accepted")
	}
}

func TestWebAuthnNothingSensitiveInLogsEventsOrErrors(t *testing.T) {
	logs := &syncBuffer{}
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) }) // never nil: background workers keep logging

	e, admin := newWAEnv(t)
	tok := e.mkUser(admin, "wanda", false)
	dev := waDevice(t, webauthnlite.AlgES256)

	var bodies bytes.Buffer
	secrets := [][]byte{dev.CredID, dev.COSEKey()}

	begin := e.waBegin(tok, "password123")
	secrets = append(secrets, optionChallenge(t, begin))
	bad := e.waFinish(tok, begin, dev, virtual.Options{Origin: "https://evil.example.test"}, "")
	bodies.Write(bad.Body)
	begin = e.waBegin(tok, "password123")
	secrets = append(secrets, optionChallenge(t, begin))
	reg := e.waFinish(tok, begin, dev, virtual.Options{}, "Laptop")
	e.want(reg, 200, "register")

	mfaToken, ch, _ := e.waLoginStart("wanda")
	secrets = append(secrets, ch)
	failed := e.waLoginFinish(mfaToken, dev, ch, virtual.Options{TamperSignature: true})
	bodies.Write(failed.Body)
	mfaToken, ch, _ = e.waLoginStart("wanda")
	secrets = append(secrets, ch)
	e.want(e.waLoginFinish(mfaToken, dev, ch, virtual.Options{}), 200, "login")

	rows, err := e.s.St.DB.Query(`SELECT actor_name||' '||action||' '||target||' '||detail FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	var events bytes.Buffer
	for rows.Next() {
		var line string
		rows.Scan(&line)
		events.WriteString(line + "\n")
	}
	rows.Close()
	if !strings.Contains(events.String(), "mfa_enrolled") || !strings.Contains(events.String(), "mfa_failed") || !strings.Contains(events.String(), "mfa_login_ok") {
		t.Fatal("events were written", events.String())
	}
	haystack := logs.String() + events.String() + bodies.String()
	for i, s := range secrets {
		for _, form := range []string{b64u(s), hex.EncodeToString(s), string(s)} {
			if len(form) > 8 && strings.Contains(haystack, form) {
				t.Fatalf("secret %d leaked into logs, events or error bodies", i)
			}
		}
	}
}
