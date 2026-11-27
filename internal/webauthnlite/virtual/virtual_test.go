// SPDX-License-Identifier: AGPL-3.0-or-later

package virtual

import (
	"encoding/hex"
	"testing"
)

// Published known answers: RFC 8949 Appendix A (diagnostic notation -> hex).
// They pin the independent test encoder, which in turn validates the library's
// decoder in the webauthnlite tests.
func TestEncodeRFC8949Vectors(t *testing.T) {
	big := uint64(18446744073709551615)
	cases := []struct {
		name string
		v    any
		hex  string
	}{
		{"0", 0, "00"},
		{"1", 1, "01"},
		{"10", 10, "0a"},
		{"23", 23, "17"},
		{"24", 24, "1818"},
		{"25", 25, "1819"},
		{"100", 100, "1864"},
		{"1000", 1000, "1903e8"},
		{"1000000", 1000000, "1a000f4240"},
		{"1000000000000", int64(1000000000000), "1b000000e8d4a51000"},
		{"18446744073709551615", big, "1bffffffffffffffff"},
		{"-1", -1, "20"},
		{"-10", -10, "29"},
		{"-100", -100, "3863"},
		{"-1000", -1000, "3903e7"},
		{"h''", []byte{}, "40"},
		{"h'01020304'", []byte{1, 2, 3, 4}, "4401020304"},
		{"\"\"", "", "60"},
		{"\"a\"", "a", "6161"},
		{"\"IETF\"", "IETF", "6449455446"},
		{"\"ü\"", "ü", "62c3bc"},
		{"false", false, "f4"},
		{"true", true, "f5"},
		{"null", nil, "f6"},
		{"[]", []any{}, "80"},
		{"[1,2,3]", []any{1, 2, 3}, "83010203"},
		{"[1,[2,3],[4,5]]", []any{1, []any{2, 3}, []any{4, 5}}, "8301820203820405"},
		{"{}", map[any]any{}, "a0"},
		{"{1:2,3:4}", map[any]any{1: 2, 3: 4}, "a201020304"},
		{"{\"a\":1,\"b\":[2,3]}", map[any]any{"a": 1, "b": []any{2, 3}}, "a26161016162820203"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(Encode(c.v)); got != c.hex {
			t.Errorf("%s: got %s want %s", c.name, got, c.hex)
		}
	}
	// Canonical (CTAP2) key order: shorter encoded keys first, then bytewise.
	got := hex.EncodeToString(Encode(map[any]any{"b": 1, 10: 2, "a": 3, -1: 4, 1: 5}))
	if want := "a5" + "0105" + "0a02" + "2004" + "616103" + "616201"; got != want {
		t.Errorf("canonical order: got %s want %s", got, want)
	}
}

func TestAuthenticatorBasics(t *testing.T) {
	for _, alg := range []int{ES256, EdDSA} {
		a, err := New(alg)
		if err != nil {
			t.Fatal(err)
		}
		cd, obj := a.Register("example.com", "https://example.com", make([]byte, 32), Options{})
		if len(cd) == 0 || len(obj) == 0 || len(a.LastAuthData) < 37 || len(a.COSEKey()) == 0 {
			t.Fatalf("alg %d: empty output", alg)
		}
		before := a.Counter
		_, ad, sig := a.Assert("example.com", "https://example.com", make([]byte, 32), Options{})
		if a.Counter != before+1 || len(ad) != 37 || len(sig) == 0 {
			t.Fatalf("alg %d: counter %d ad %d sig %d", alg, a.Counter, len(ad), len(sig))
		}
		c := a.Clone()
		if string(c.CredID) == string(a.CredID) || c.Counter != 0 {
			t.Fatal("clone must have a fresh id and counter")
		}
	}
	if _, err := New(12345); err == nil {
		t.Fatal("unknown alg must fail")
	}
}
