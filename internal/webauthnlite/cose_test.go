// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnlite

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/sendora-app/sendora/internal/webauthnlite/virtual"
)

func cose(m map[any]any) []byte { return virtual.Encode(m) }

func es256Key(x, y []byte) []byte {
	return cose(map[any]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
}

func TestParseCOSEKeyAcceptsVirtualKeys(t *testing.T) {
	for _, alg := range []int{virtual.ES256, virtual.EdDSA, virtual.RS256} {
		a, err := virtual.New(alg)
		if err != nil {
			t.Fatal(err)
		}
		k, err := parseCOSEKey(a.COSEKey())
		if err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		if k.Alg != alg {
			t.Errorf("alg %d parsed as %d", alg, k.Alg)
		}
		switch alg {
		case virtual.ES256:
			if !k.pub.(*ecdsa.PublicKey).Equal(a.PublicKey()) {
				t.Error("ES256 key differs")
			}
		case virtual.EdDSA:
			if !k.pub.(ed25519.PublicKey).Equal(a.PublicKey()) {
				t.Error("EdDSA key differs")
			}
		case virtual.RS256:
			if !k.pub.(*rsa.PublicKey).Equal(a.PublicKey()) {
				t.Error("RS256 key differs")
			}
		}
	}
}

// Published constants, checked as independent known answers for the COSE
// parser: the NIST P-256 base point (FIPS 186) and the P-256 public key used in
// the RFC 8152 appendix C examples must be accepted as on-curve, and the first
// RFC 8032 section 7.1 Ed25519 public key must round-trip.
func TestParseCOSEKeyPublishedPublicKeys(t *testing.T) {
	gx := hexb(t, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
	gy := hexb(t, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if _, err := parseCOSEKey(es256Key(gx, gy)); err != nil {
		t.Errorf("P-256 base point rejected: %v", err)
	}
	rx := hexb(t, "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")
	ry := hexb(t, "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")
	if _, err := parseCOSEKey(es256Key(rx, ry)); err != nil {
		t.Errorf("RFC 8152 example key rejected: %v", err)
	}
	edpub := hexb(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	k, err := parseCOSEKey(cose(map[any]any{1: 1, 3: -8, -1: 6, -2: edpub}))
	if err != nil {
		t.Fatal(err)
	}
	if string(k.pub.(ed25519.PublicKey)) != string(edpub) {
		t.Error("RFC 8032 key mangled")
	}
	// A coordinate off by one bit is no longer on the curve.
	bad := append([]byte(nil), gy...)
	bad[31] ^= 1
	if _, err := parseCOSEKey(es256Key(gx, bad)); !errors.Is(err, ErrMalformed) {
		t.Errorf("off-curve point: %v", err)
	}
}

func TestParseCOSEKeyRejections(t *testing.T) {
	a, err := virtual.New(virtual.ES256)
	if err != nil {
		t.Fatal(err)
	}
	pt, _ := a.PublicKey().(*ecdsa.PublicKey).Bytes()
	x, y := pt[1:33], pt[33:65]
	small, err := virtual.NewWithRSABits(1024)
	if err != nil {
		t.Fatal(err)
	}
	smallPub := small.PublicKey().(*rsa.PublicKey)
	r, err := virtual.New(virtual.RS256)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub := r.PublicKey().(*rsa.PublicKey)
	ed := make([]byte, 32)
	ed[0] = 1
	nbytes := rsaPub.N.Bytes()

	cases := []struct {
		name string
		key  []byte
		want error
	}{
		{"not a map", virtual.Encode([]any{1, 2}), ErrMalformed},
		{"missing alg", cose(map[any]any{1: 2, -1: 1, -2: x, -3: y}), ErrMalformed},
		{"missing kty", cose(map[any]any{3: -7, -1: 1, -2: x, -3: y}), ErrMalformed},
		{"unknown alg", cose(map[any]any{1: 2, 3: -35, -1: 2, -2: x, -3: y}), ErrUnsupported},
		{"ES256 wrong kty", cose(map[any]any{1: 1, 3: -7, -1: 1, -2: x, -3: y}), ErrMalformed},
		{"ES256 wrong curve P-384", cose(map[any]any{1: 2, 3: -7, -1: 2, -2: x, -3: y}), ErrUnsupported},
		{"ES256 missing curve", cose(map[any]any{1: 2, 3: -7, -2: x, -3: y}), ErrMalformed},
		{"ES256 short x", es256Key(x[:31], y), ErrMalformed},
		{"ES256 long y", es256Key(x, append(append([]byte(nil), y...), 0)), ErrMalformed},
		{"ES256 missing y", cose(map[any]any{1: 2, 3: -7, -1: 1, -2: x}), ErrMalformed},
		{"ES256 point at origin", es256Key(make([]byte, 32), make([]byte, 32)), ErrMalformed},
		{"EdDSA wrong curve X25519", cose(map[any]any{1: 1, 3: -8, -1: 4, -2: ed}), ErrUnsupported},
		{"EdDSA short key", cose(map[any]any{1: 1, 3: -8, -1: 6, -2: ed[:31]}), ErrMalformed},
		{"EdDSA wrong kty", cose(map[any]any{1: 2, 3: -8, -1: 6, -2: ed}), ErrMalformed},
		{"RSA short modulus (1024 bit)", cose(map[any]any{1: 3, 3: -257, -1: smallPub.N.Bytes(), -2: []byte{1, 0, 1}}), ErrUnsupported},
		{"RSA even modulus", cose(map[any]any{1: 3, 3: -257, -1: append(append([]byte(nil), nbytes[:len(nbytes)-1]...), nbytes[len(nbytes)-1]&^1), -2: []byte{1, 0, 1}}), ErrMalformed},
		{"RSA huge exponent (5 bytes)", cose(map[any]any{1: 3, 3: -257, -1: nbytes, -2: []byte{1, 0, 0, 0, 1}}), ErrMalformed},
		{"RSA exponent above 2^31-1", cose(map[any]any{1: 3, 3: -257, -1: nbytes, -2: []byte{0x80, 0, 0, 1}}), ErrUnsupported},
		{"RSA exponent 3", cose(map[any]any{1: 3, 3: -257, -1: nbytes, -2: []byte{3}}), ErrUnsupported},
		{"RSA even exponent", cose(map[any]any{1: 3, 3: -257, -1: nbytes, -2: []byte{1, 0, 0}}), ErrUnsupported},
		{"RSA missing exponent", cose(map[any]any{1: 3, 3: -257, -1: nbytes}), ErrMalformed},
		{"RSA wrong kty", cose(map[any]any{1: 2, 3: -257, -1: nbytes, -2: []byte{1, 0, 1}}), ErrMalformed},
		{"RSA modulus above 8192 bits", cose(map[any]any{1: 3, 3: -257, -1: append([]byte{0x80}, make([]byte, 1100)...), -2: []byte{1, 0, 1}}), ErrMalformed},
		{"trailing bytes after key", append(es256Key(x, y), 0), ErrMalformed},
	}
	for _, c := range cases {
		_, err := parseCOSEKey(c.key)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}
