// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnlite_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"sync"
	"testing"

	"github.com/sendora-app/sendora/internal/webauthnlite"
	"github.com/sendora-app/sendora/internal/webauthnlite/virtual"
)

var rp = webauthnlite.RP{ID: "example.com", Origin: "https://example.com"}

var (
	rsaOnce sync.Once
	rsaBase *virtual.Authenticator
)

// newAuth returns a fresh authenticator; the slow RSA key is generated once.
func newAuth(t testing.TB, alg int) *virtual.Authenticator {
	t.Helper()
	if alg == virtual.RS256 {
		rsaOnce.Do(func() {
			var err error
			if rsaBase, err = virtual.New(virtual.RS256); err != nil {
				panic(err)
			}
		})
		return rsaBase.Clone()
	}
	a, err := virtual.New(alg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var algs = []struct {
	name string
	alg  int
}{{"ES256", virtual.ES256}, {"EdDSA", virtual.EdDSA}, {"RS256", virtual.RS256}}

func chal(t testing.TB) []byte {
	t.Helper()
	c, err := webauthnlite.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func register(t testing.TB, a *virtual.Authenticator, o virtual.Options) (*webauthnlite.Credential, error) {
	t.Helper()
	c := chal(t)
	cd, obj := a.Register(rp.ID, rp.Origin, c, o)
	return webauthnlite.VerifyRegistration(rp, c, cd, obj)
}

func mustRegister(t testing.TB, a *virtual.Authenticator) webauthnlite.Credential {
	t.Helper()
	cred, err := register(t, a, virtual.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return *cred
}

func assertWith(t testing.TB, a *virtual.Authenticator, cred webauthnlite.Credential, o virtual.Options) (uint32, error) {
	t.Helper()
	c := chal(t)
	cd, ad, sig := a.Assert(rp.ID, rp.Origin, c, o)
	return webauthnlite.VerifyAssertion(rp, c, cred, cd, ad, sig)
}

// indepAuthData is an independent, offset-based authenticatorData parser used
// to cross-check what the library extracts.
func indepAuthData(t testing.TB, ad []byte) (rpHash []byte, flags byte, counter uint32, aaguid, credID, cose []byte) {
	t.Helper()
	rpHash, flags, counter = ad[:32], ad[32], binary.BigEndian.Uint32(ad[33:37])
	if flags&0x40 == 0 {
		return
	}
	aaguid = ad[37:53]
	n := int(binary.BigEndian.Uint16(ad[53:55]))
	credID = ad[55 : 55+n]
	cose = ad[55+n:]
	return
}

func TestRegistrationHappyPath(t *testing.T) {
	for _, al := range algs {
		for _, att := range []string{"none", "packed-self", "packed-x5c"} {
			t.Run(al.name+"/"+att, func(t *testing.T) {
				if att == "packed-self" && al.alg == 0 {
					t.Skip()
				}
				a := newAuth(t, al.alg)
				cred, err := register(t, a, virtual.Options{Attestation: att})
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(cred.ID, a.CredID) || !bytes.Equal(cred.AAGUID, a.AAGUID[:]) || cred.Alg != al.alg || cred.SignCount != 0 {
					t.Errorf("credential fields: %+v", cred)
				}
				if !bytes.Equal(cred.PublicKey, a.COSEKey()) {
					t.Error("stored public key must be the COSE key as received")
				}
				// Independent parse of the authenticatorData the virtual device wrote.
				h, flags, ctr, aaguid, id, cose := indepAuthData(t, a.LastAuthData)
				want := sha256.Sum256([]byte(rp.ID))
				if !bytes.Equal(h, want[:]) || flags&0x41 != 0x41 || ctr != 0 ||
					!bytes.Equal(aaguid, cred.AAGUID) || !bytes.Equal(id, cred.ID) || !bytes.Equal(cose, cred.PublicKey) {
					t.Errorf("independent parse disagrees with library result")
				}
			})
		}
	}
}

func TestRegistrationFlagsAndExtensions(t *testing.T) {
	a := newAuth(t, virtual.ES256)
	ext := virtual.Encode(map[any]any{"credProtect": 2, "hmac-secret": true})
	for name, o := range map[string]virtual.Options{
		"user verified":            {UV: true},
		"backup eligible+state":    {ExtraFlags: 0x18},
		"backup eligible only":     {ExtraFlags: 0x08},
		"with extension data":      {Extensions: ext},
		"credential id 1023 bytes": {CredIDLen: 1023},
		"credential id 1 byte":     {CredIDLen: 1},
		"nonzero initial counter":  {Counter: ptr(uint32(42))},
	} {
		if _, err := register(t, a, o); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if c, err := register(t, a, virtual.Options{Counter: ptr(uint32(42))}); err != nil || c.SignCount != 42 {
		t.Errorf("counter: %+v %v", c, err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestRegistrationRejections(t *testing.T) {
	a := newAuth(t, virtual.ES256)
	cases := []struct {
		name string
		o    virtual.Options
		want error
	}{
		{"wrong challenge", virtual.Options{Challenge: bytes.Repeat([]byte{7}, 32)}, webauthnlite.ErrBadChallenge},
		{"wrong origin", virtual.Options{Origin: "https://evil.example"}, webauthnlite.ErrBadOrigin},
		{"origin with port", virtual.Options{Origin: "https://example.com:8443"}, webauthnlite.ErrBadOrigin},
		{"http origin", virtual.Options{Origin: "http://example.com"}, webauthnlite.ErrBadOrigin},
		{"origin trailing slash", virtual.Options{Origin: "https://example.com/"}, webauthnlite.ErrBadOrigin},
		{"cross origin", virtual.Options{CrossOrigin: true}, webauthnlite.ErrBadOrigin},
		{"wrong type (get)", virtual.Options{Type: "webauthn.get"}, webauthnlite.ErrBadType},
		{"wrong rp id hash", virtual.Options{RPID: "evil.example"}, webauthnlite.ErrBadRPID},
		{"subdomain rp id", virtual.Options{RPID: "sub.example.com"}, webauthnlite.ErrBadRPID},
		{"no user presence", virtual.Options{NoUP: true}, webauthnlite.ErrUserPresence},
		{"unsupported format", virtual.Options{Attestation: "fido-u2f"}, webauthnlite.ErrUnsupported},
		{"packed-self bad signature", virtual.Options{Attestation: "packed-self", TamperSignature: true}, webauthnlite.ErrBadSignature},
		{"packed-self tampered client data", virtual.Options{Attestation: "packed-self", TamperClientData: true}, webauthnlite.ErrBadSignature},
		{"credential id too long", virtual.Options{CredIDLen: 1024}, webauthnlite.ErrMalformed},
		{"empty credential id", virtual.Options{CredIDLen: -1}, webauthnlite.ErrMalformed},
		{"backup state without eligibility", virtual.Options{ExtraFlags: 0x10}, webauthnlite.ErrMalformed},
		{"trailing authData bytes", virtual.Options{Trailing: []byte{0}}, webauthnlite.ErrMalformed},
		{"extension flag with non-map", virtual.Options{Extensions: virtual.Encode(5)}, webauthnlite.ErrMalformed},
		{"extension map plus garbage", virtual.Options{Extensions: virtual.Encode(map[any]any{"a": 1}), Trailing: []byte{0}}, webauthnlite.ErrMalformed},
		{"extension flag with truncated CBOR", virtual.Options{Extensions: []byte{0xa1, 0x61}}, webauthnlite.ErrMalformed},
	}
	for _, c := range cases {
		if _, err := register(t, a, c.o); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}

func TestRegistrationMalformedObjects(t *testing.T) {
	a := newAuth(t, virtual.ES256)
	c := chal(t)
	cd, good := a.Register(rp.ID, rp.Origin, c, virtual.Options{})
	ad := a.LastAuthData
	mk := func(m map[any]any) []byte { return virtual.Encode(m) }
	objs := map[string][]byte{
		"empty":               nil,
		"truncated":           good[:len(good)/2],
		"trailing byte":       append(append([]byte(nil), good...), 0),
		"not a map":           mk(nil),
		"array":               virtual.Encode([]any{1, 2, 3}),
		"missing fmt":         mk(map[any]any{"attStmt": map[any]any{}, "authData": ad, "x": 1}),
		"extra field":         mk(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": ad, "extra": 1}),
		"only two fields":     mk(map[any]any{"fmt": "none", "authData": ad}),
		"authData not bytes":  mk(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": "text"}),
		"attStmt not map":     mk(map[any]any{"fmt": "none", "attStmt": []any{}, "authData": ad}),
		"none with statement": mk(map[any]any{"fmt": "none", "attStmt": map[any]any{"x": 1}, "authData": ad}),
		"fmt not text":        mk(map[any]any{"fmt": 5, "attStmt": map[any]any{}, "authData": ad}),
		"short authData":      mk(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": ad[:36]}),
		"authData no AT":      mk(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": ad[:37]}),
		"truncated cose key":  mk(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": ad[:len(ad)-3]}),
		"packed without sig":  mk(map[any]any{"fmt": "packed", "attStmt": map[any]any{"alg": -7}, "authData": ad}),
		"packed unknown key":  mk(map[any]any{"fmt": "packed", "attStmt": map[any]any{"alg": -7, "sig": []byte{1}, "ecdaaKeyId": []byte{1}}, "authData": ad}),
		"packed bad x5c":      mk(map[any]any{"fmt": "packed", "attStmt": map[any]any{"alg": -7, "sig": []byte{1}, "x5c": "x"}, "authData": ad}),
		"packed empty x5c":    mk(map[any]any{"fmt": "packed", "attStmt": map[any]any{"alg": -7, "sig": []byte{1}, "x5c": []any{}}, "authData": ad}),
		"packed alg mismatch": mk(map[any]any{"fmt": "packed", "attStmt": map[any]any{"alg": -8, "sig": []byte{1}}, "authData": ad}),
	}
	for name, obj := range objs {
		cred, err := webauthnlite.VerifyRegistration(rp, c, cd, obj)
		if err == nil || cred != nil {
			t.Errorf("%s accepted", name)
		}
	}
	// The untouched object still verifies, so the rejections above are meaningful.
	if _, err := webauthnlite.VerifyRegistration(rp, c, cd, good); err != nil {
		t.Fatal(err)
	}
}

func TestClientDataChecks(t *testing.T) {
	a := newAuth(t, virtual.ES256)
	cred := mustRegister(t, a)
	c := chal(t)
	_, ad, sig := a.Assert(rp.ID, rp.Origin, c, virtual.Options{})
	b64 := webauthnlite.Base64URL
	cases := []struct {
		name string
		cd   string
		want error
	}{
		{"empty", "", webauthnlite.ErrMalformed},
		{"not json", "nope", webauthnlite.ErrMalformed},
		{"json array", "[]", webauthnlite.ErrMalformed},
		{"missing type", `{"challenge":"` + b64(c) + `","origin":"https://example.com"}`, webauthnlite.ErrBadType},
		{"challenge not base64url", `{"type":"webauthn.get","challenge":"!!","origin":"https://example.com"}`, webauthnlite.ErrBadChallenge},
		{"padded challenge", `{"type":"webauthn.get","challenge":"` + b64(c) + `=","origin":"https://example.com"}`, webauthnlite.ErrBadChallenge},
		{"challenge missing", `{"type":"webauthn.get","origin":"https://example.com"}`, webauthnlite.ErrBadChallenge},
		{"origin missing", `{"type":"webauthn.get","challenge":"` + b64(c) + `"}`, webauthnlite.ErrBadOrigin},
		{"oversized", `{"type":"webauthn.get","challenge":"` + b64(c) + `","origin":"https://example.com","pad":"` + string(bytes.Repeat([]byte{'a'}, 9000)) + `"}`, webauthnlite.ErrMalformed},
	}
	for _, tc := range cases {
		_, err := webauthnlite.VerifyAssertion(rp, c, cred, []byte(tc.cd), ad, sig)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, err, tc.want)
		}
	}
	// Extra client data members and an explicit crossOrigin=false are fine
	// (the signature still has to match, so this only proves they are not
	// rejected before the signature check).
	extra := `{"type":"webauthn.get","challenge":"` + b64(c) + `","origin":"https://example.com","crossOrigin":false,"other_keys_can_be_added_here":"x"}`
	if _, err := webauthnlite.VerifyAssertion(rp, c, cred, []byte(extra), ad, sig); !errors.Is(err, webauthnlite.ErrBadSignature) {
		t.Errorf("extra members: got %v, want a signature failure (not a client data failure)", err)
	}
	// Server-side expectation problems.
	cd, ad, sig := a.Assert(rp.ID, rp.Origin, c, virtual.Options{})
	for name, ch := range map[string][]byte{"nil challenge": nil, "short challenge": c[:8], "other challenge": chal(t)} {
		if _, err := webauthnlite.VerifyAssertion(rp, ch, cred, cd, ad, sig); !errors.Is(err, webauthnlite.ErrBadChallenge) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bad := range map[string]webauthnlite.RP{"empty rp": {}, "no origin": {ID: "example.com"}, "no id": {Origin: rp.Origin}} {
		if _, err := webauthnlite.VerifyAssertion(bad, c, cred, cd, ad, sig); !errors.Is(err, webauthnlite.ErrBadRPID) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAssertionHappyPathAndCounter(t *testing.T) {
	for _, al := range algs {
		t.Run(al.name, func(t *testing.T) {
			a := newAuth(t, al.alg)
			cred := mustRegister(t, a)
			for want := uint32(1); want <= 3; want++ {
				got, err := assertWith(t, a, cred, virtual.Options{})
				if err != nil || got != want {
					t.Fatalf("assertion %d: got %d, %v", want, got, err)
				}
				cred.SignCount = got
			}
			// Replaying the stored counter value, or going back, is a clone warning.
			for name, ctr := range map[string]uint32{"replay": 3, "lower": 1, "zero after nonzero": 0} {
				got, err := assertWith(t, a, cred, virtual.Options{Counter: ptr(ctr)})
				if !errors.Is(err, webauthnlite.ErrCounterRegression) || got != ctr {
					t.Errorf("%s: got %d, %v", name, got, err)
				}
			}
			// UV and backup flags do not matter for validity.
			if _, err := assertWith(t, a, cred, virtual.Options{Counter: ptr(uint32(50)), UV: true, ExtraFlags: 0x18}); err != nil {
				t.Errorf("flags: %v", err)
			}
		})
	}
}

func TestAssertionCounterZeroPolicy(t *testing.T) {
	a := newAuth(t, virtual.ES256)
	cred := mustRegister(t, a)
	// Authenticators without a counter always report 0: accepted while stored is 0.
	if got, err := assertWith(t, a, cred, virtual.Options{Counter: ptr(uint32(0))}); err != nil || got != 0 {
		t.Fatalf("both zero: %d %v", got, err)
	}
	if got, err := assertWith(t, a, cred, virtual.Options{Counter: ptr(uint32(7))}); err != nil || got != 7 {
		t.Fatalf("0 -> 7: %d %v", got, err)
	}
	cred.SignCount = 5
	if _, err := assertWith(t, a, cred, virtual.Options{Counter: ptr(uint32(5))}); !errors.Is(err, webauthnlite.ErrCounterRegression) {
		t.Fatalf("5 -> 5: %v", err)
	}
	cred.SignCount = ^uint32(0)
	if _, err := assertWith(t, a, cred, virtual.Options{Counter: ptr(uint32(0))}); !errors.Is(err, webauthnlite.ErrCounterRegression) {
		t.Fatalf("max -> 0: %v", err)
	}
}

func TestAssertionRejections(t *testing.T) {
	a := newAuth(t, virtual.ES256)
	cred := mustRegister(t, a)
	other := newAuth(t, virtual.ES256)
	cases := []struct {
		name string
		o    virtual.Options
		want error
	}{
		{"wrong challenge", virtual.Options{Challenge: bytes.Repeat([]byte{3}, 32)}, webauthnlite.ErrBadChallenge},
		{"wrong origin", virtual.Options{Origin: "https://evil.example"}, webauthnlite.ErrBadOrigin},
		{"cross origin", virtual.Options{CrossOrigin: true}, webauthnlite.ErrBadOrigin},
		{"wrong type (create)", virtual.Options{Type: "webauthn.create"}, webauthnlite.ErrBadType},
		{"wrong rp id", virtual.Options{RPID: "evil.example"}, webauthnlite.ErrBadRPID},
		{"no user presence", virtual.Options{NoUP: true}, webauthnlite.ErrUserPresence},
		{"tampered signature", virtual.Options{TamperSignature: true}, webauthnlite.ErrBadSignature},
		{"tampered client data", virtual.Options{TamperClientData: true}, webauthnlite.ErrBadSignature},
		{"tampered authenticator data", virtual.Options{TamperAuthData: true}, webauthnlite.ErrBadSignature},
		{"attested data flag in assertion", virtual.Options{ExtraFlags: 0x40}, webauthnlite.ErrMalformed},
		{"trailing authenticator data", virtual.Options{Trailing: []byte{1}}, webauthnlite.ErrMalformed},
		{"extension flag with non-map", virtual.Options{Extensions: virtual.Encode("x")}, webauthnlite.ErrMalformed},
	}
	for _, c := range cases {
		if _, err := assertWith(t, a, cred, c.o); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	// Extension data is accepted and covered by the signature.
	if _, err := assertWith(t, a, cred, virtual.Options{Extensions: virtual.Encode(map[any]any{"x": 1}), Counter: ptr(uint32(9))}); err != nil {
		t.Errorf("extension data: %v", err)
	}
	// Signature from another key.
	c := chal(t)
	cd, ad, sig := other.Assert(rp.ID, rp.Origin, c, virtual.Options{})
	if _, err := webauthnlite.VerifyAssertion(rp, c, cred, cd, ad, sig); !errors.Is(err, webauthnlite.ErrBadSignature) {
		t.Errorf("foreign key: %v", err)
	}
	// Truncated, empty and oversized parts.
	cd, ad, sig = a.Assert(rp.ID, rp.Origin, c, virtual.Options{})
	for name, bad := range map[string][3][]byte{
		"empty signature":   {cd, ad, nil},
		"short signature":   {cd, ad, sig[:len(sig)-1]},
		"extended sig":      {cd, ad, append(append([]byte(nil), sig...), 0)},
		"short authData":    {cd, ad[:36], sig},
		"empty authData":    {cd, nil, sig},
		"huge authData":     {cd, make([]byte, 70<<10), sig},
		"empty client data": {nil, ad, sig},
	} {
		if _, err := webauthnlite.VerifyAssertion(rp, c, cred, bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestAssertionStoredCredentialProblems(t *testing.T) {
	a := newAuth(t, virtual.ES256)
	cred := mustRegister(t, a)
	c := chal(t)
	cd, ad, sig := a.Assert(rp.ID, rp.Origin, c, virtual.Options{})
	mut := func(f func(*webauthnlite.Credential)) webauthnlite.Credential { x := cred; f(&x); return x }
	cases := []struct {
		name string
		cred webauthnlite.Credential
		want error
	}{
		{"garbage public key", mut(func(x *webauthnlite.Credential) { x.PublicKey = []byte{1, 2, 3} }), webauthnlite.ErrMalformed},
		{"empty public key", mut(func(x *webauthnlite.Credential) { x.PublicKey = nil }), webauthnlite.ErrMalformed},
		{"alg mismatch EdDSA", mut(func(x *webauthnlite.Credential) { x.Alg = webauthnlite.AlgEdDSA }), webauthnlite.ErrUnsupported},
		{"alg mismatch RS256", mut(func(x *webauthnlite.Credential) { x.Alg = webauthnlite.AlgRS256 }), webauthnlite.ErrUnsupported},
		{"alg zero", mut(func(x *webauthnlite.Credential) { x.Alg = 0 }), webauthnlite.ErrUnsupported},
		{"key from another credential", mut(func(x *webauthnlite.Credential) { x.PublicKey = newAuth(t, virtual.ES256).COSEKey() }), webauthnlite.ErrBadSignature},
	}
	for _, tc := range cases {
		if _, err := webauthnlite.VerifyAssertion(rp, c, tc.cred, cd, ad, sig); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, err, tc.want)
		}
	}
}

// Cross-check the signature path with the standard library directly: the
// virtual authenticator's output must verify without any library code, and a
// tampered signature must not, which proves the library tests are meaningful.
func TestIndependentSignatureCrossCheck(t *testing.T) {
	for _, al := range algs {
		t.Run(al.name, func(t *testing.T) {
			a := newAuth(t, al.alg)
			cred := mustRegister(t, a)
			c := chal(t)
			cd, ad, sig := a.Assert(rp.ID, rp.Origin, c, virtual.Options{})
			h := sha256.Sum256(cd)
			msg := append(append([]byte(nil), ad...), h[:]...)
			check := func(sig []byte) bool {
				switch pub := a.PublicKey().(type) {
				case *ecdsa.PublicKey:
					d := sha256.Sum256(msg)
					return ecdsa.VerifyASN1(pub, d[:], sig)
				case ed25519.PublicKey:
					return len(sig) == 64 && ed25519.Verify(pub, msg, sig)
				case *rsa.PublicKey:
					d := sha256.Sum256(msg)
					return rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig) == nil
				}
				return false
			}
			if !check(sig) {
				t.Fatal("independent verification failed for a correct response")
			}
			bad := append([]byte(nil), sig...)
			bad[len(bad)-1] ^= 1
			if check(bad) {
				t.Fatal("independent verification accepted a tampered signature")
			}
			if _, err := webauthnlite.VerifyAssertion(rp, c, cred, cd, ad, sig); err != nil {
				t.Fatalf("library rejected a response the standard library accepts: %v", err)
			}
			if _, err := webauthnlite.VerifyAssertion(rp, c, cred, cd, ad, bad); !errors.Is(err, webauthnlite.ErrBadSignature) {
				t.Fatalf("library accepted a tampered signature: %v", err)
			}
			// The signed message includes the counter: any change must invalidate it.
			ad2 := append([]byte(nil), ad...)
			ad2[36] ^= 0x01
			if _, err := webauthnlite.VerifyAssertion(rp, c, cred, cd, ad2, sig); !errors.Is(err, webauthnlite.ErrBadSignature) {
				t.Fatalf("modified authenticator data accepted: %v", err)
			}
		})
	}
}

func TestWeakRSAKeyRejectedAtRegistration(t *testing.T) {
	a, err := virtual.NewWithRSABits(1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := register(t, a, virtual.Options{}); !errors.Is(err, webauthnlite.ErrUnsupported) {
		t.Fatalf("1024-bit RSA: %v", err)
	}
}

// Whatever bytes arrive, verification must return an error or a result, never
// panic. Mutates valid responses of every algorithm.
func TestVerifyNeverPanicsOnMutatedResponses(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	mutate := func(b []byte) []byte {
		s := append([]byte(nil), b...)
		if len(s) == 0 {
			return s
		}
		for j, n := 0, 1+rng.Intn(3); j < n; j++ {
			switch rng.Intn(4) {
			case 0:
				s[rng.Intn(len(s))] = byte(rng.Intn(256))
			case 1:
				s[rng.Intn(len(s))] ^= 1 << uint(rng.Intn(8))
			case 2:
				s = s[:rng.Intn(len(s)+1)]
			case 3:
				s = append(s, byte(rng.Intn(256)))
			}
			if len(s) == 0 {
				break
			}
		}
		return s
	}
	guard := func(what string, f func()) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic in %s: %v", what, r)
			}
		}()
		f()
	}
	for _, al := range algs {
		a := newAuth(t, al.alg)
		cred := mustRegister(t, a)
		c := chal(t)
		rcd, robj := a.Register(rp.ID, rp.Origin, c, virtual.Options{Attestation: "packed-self"})
		acd, aad, asig := a.Assert(rp.ID, rp.Origin, c, virtual.Options{})
		n := 1500
		if al.alg == virtual.RS256 {
			n = 400
		}
		for i := 0; i < n; i++ {
			guard("registration", func() {
				_, _ = webauthnlite.VerifyRegistration(rp, c, mutate(rcd), mutate(robj))
				_, _ = webauthnlite.VerifyRegistration(rp, c, rcd, mutate(robj))
			})
			guard("assertion", func() {
				_, _ = webauthnlite.VerifyAssertion(rp, c, cred, mutate(acd), mutate(aad), mutate(asig))
				bad := cred
				bad.PublicKey = mutate(cred.PublicKey)
				_, _ = webauthnlite.VerifyAssertion(rp, c, bad, acd, aad, asig)
			})
		}
	}
}
