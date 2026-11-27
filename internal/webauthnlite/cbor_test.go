// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnlite

import (
	"bytes"
	"errors"
	"math"
	"math/rand"
	"reflect"
	"testing"

	"github.com/sendora-app/sendora/internal/webauthnlite/virtual"
)

func hexb(t testing.TB, s string) []byte {
	t.Helper()
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		var v byte
		for _, c := range []byte{s[i], s[i+1]} {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			default:
				t.Fatalf("bad hex %q", s)
			}
		}
		out = append(out, v)
	}
	return out
}

func TestDecodeCBORValid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want any
	}{
		{"0", "00", int64(0)},
		{"23", "17", int64(23)},
		{"24", "1818", int64(24)},
		{"1000", "1903e8", int64(1000)},
		{"1000000", "1a000f4240", int64(1000000)},
		{"int64 max", "1b7fffffffffffffff", int64(math.MaxInt64)},
		{"-1", "20", int64(-1)},
		{"-7 (ES256)", "26", int64(-7)},
		{"-257 (RS256)", "390100", int64(-257)},
		{"int64 min", "3b7fffffffffffffff", int64(math.MinInt64)},
		{"empty bytes", "40", []byte{}},
		{"bytes", "4401020304", []byte{1, 2, 3, 4}},
		{"empty text", "60", ""},
		{"text", "6449455446", "IETF"},
		{"unicode", "62c3bc", "ü"},
		{"false", "f4", false},
		{"true", "f5", true},
		{"null", "f6", nil},
		{"empty array", "80", []any{}},
		{"array", "83010203", []any{int64(1), int64(2), int64(3)}},
		{"empty map", "a0", map[any]any{}},
		{"mixed map", "a2613101" + "0242aabb", map[any]any{"1": int64(1), int64(2): []byte{0xaa, 0xbb}}},
		{"nested", "a1626161a1626262" + "63636363", map[any]any{"aa": map[any]any{"bb": "ccc"}}},
		{"non-minimal accepted (leniency)", "1800", int64(0)},
	}
	for _, c := range cases {
		got, err := decodeCBOR(hexb(t, c.in))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %#v want %#v", c.name, got, c.want)
		}
	}
}

func TestDecodeCBORErrors(t *testing.T) {
	deep := bytes.Repeat([]byte{0x81}, 9) // nine nested arrays...
	deep = append(deep, 0x00)             // ...around one int: depth 9 > 8
	deepOK := append(bytes.Repeat([]byte{0x81}, 8), 0x00)
	arr65 := append([]byte{0x98, 65}, bytes.Repeat([]byte{0x00}, 65)...)
	map65 := []byte{0xb8, 65}
	for i := 0; i < 65; i++ {
		map65 = append(map65, 0x18, byte(i), 0x00)
	}
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrMalformed},
		{"truncated head", hexb(t, "19"), ErrMalformed},
		{"truncated bytes", hexb(t, "4401"), ErrMalformed},
		{"truncated text", hexb(t, "6341"), ErrMalformed},
		{"truncated array", hexb(t, "8301"), ErrMalformed},
		{"truncated map", hexb(t, "a101"), ErrMalformed},
		{"trailing bytes", hexb(t, "0000"), ErrMalformed},
		{"indefinite bytes", hexb(t, "5fff"), ErrUnsupported},
		{"indefinite array", hexb(t, "9fff"), ErrUnsupported},
		{"indefinite map", hexb(t, "bfff"), ErrUnsupported},
		{"reserved info 28", hexb(t, "1c"), ErrMalformed},
		{"reserved info 30", hexb(t, "1e"), ErrMalformed},
		{"tag", hexb(t, "c074323031332d30332d32315432303a30343a30305a"), ErrUnsupported},
		{"half float", hexb(t, "f93c00"), ErrUnsupported},
		{"double float", hexb(t, "fb3ff199999999999a"), ErrUnsupported},
		{"undefined", hexb(t, "f7"), ErrUnsupported},
		{"simple value", hexb(t, "f820"), ErrUnsupported},
		{"uint64 over int64", hexb(t, "1b8000000000000000"), ErrMalformed},
		{"neg over int64", hexb(t, "3b8000000000000000"), ErrMalformed},
		{"invalid utf-8", hexb(t, "62c328"), ErrMalformed},
		{"huge claimed bytes", hexb(t, "5bffffffffffffffff"), ErrMalformed},
		{"huge claimed array", hexb(t, "9bffffffffffffffff"), ErrMalformed},
		{"depth 9", deep, ErrMalformed},
		{"array of 65", arr65, ErrMalformed},
		{"map of 65", map65, ErrMalformed},
		{"duplicate keys", hexb(t, "a201010102"), ErrMalformed},
		{"duplicate text keys", hexb(t, "a2616101616102"), ErrMalformed},
		{"bytes as map key", hexb(t, "a1410000"), ErrMalformed},
		{"array as map key", hexb(t, "a1800000"), ErrMalformed},
		{"oversized input", bytes.Repeat([]byte{0x00}, maxCBORSize+1), ErrMalformed},
	}
	for _, c := range cases {
		if c.want == nil {
			continue
		}
		_, err := decodeCBOR(c.in)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	if _, err := decodeCBOR(deepOK); err != nil {
		t.Errorf("depth 8 must be accepted: %v", err)
	}
}

func TestDecodeCBORPrefixReportsLength(t *testing.T) {
	in := append(virtual.Encode(map[any]any{1: 2, "k": []byte{9}}), 0xde, 0xad)
	v, n, err := decodeCBORPrefix(in)
	if err != nil || n != len(in)-2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, ok := v.(map[any]any); !ok {
		t.Fatalf("type %T", v)
	}
	if _, err := decodeCBOR(in); err == nil {
		t.Fatal("decodeCBOR must reject trailing bytes")
	}
}

// The decoder must never panic, whatever it is fed.
func mustNotPanic(t testing.TB, in []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on %x: %v", in, r)
		}
	}()
	_, _, _ = decodeCBORPrefix(in)
	_, _ = decodeCBOR(in)
	_, _ = parseAuthData(in, true)
	_, _ = parseAuthData(in, false)
	_, _ = parseCOSEKey(in)
}

func seedObjects(t testing.TB) [][]byte {
	var seeds [][]byte
	for _, alg := range []int{virtual.ES256, virtual.EdDSA} {
		a, err := virtual.New(alg)
		if err != nil {
			t.Fatal(err)
		}
		for _, att := range []string{"none", "packed-self", "packed-x5c"} {
			_, obj := a.Register("example.com", "https://example.com", bytes.Repeat([]byte{1}, 32), virtual.Options{Attestation: att})
			seeds = append(seeds, obj)
		}
		seeds = append(seeds, a.COSEKey())
	}
	return seeds
}

func TestDecodeNeverPanicsOnMutatedAndRandomInput(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	seeds := seedObjects(t)
	for i := 0; i < 20000; i++ {
		s := append([]byte(nil), seeds[rng.Intn(len(seeds))]...)
		for j, n := 0, 1+rng.Intn(4); j < n; j++ {
			switch rng.Intn(4) {
			case 0:
				s[rng.Intn(len(s))] = byte(rng.Intn(256))
			case 1:
				s[rng.Intn(len(s))] ^= 1 << uint(rng.Intn(8))
			case 2:
				s = s[:rng.Intn(len(s))+0]
				if len(s) == 0 {
					s = []byte{0}
				}
			case 3:
				s = append(s, byte(rng.Intn(256)))
			}
		}
		mustNotPanic(t, s)
	}
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(200))
		rng.Read(b)
		mustNotPanic(t, b)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(hexb(f, "a2613101024201"))
	f.Add(hexb(f, "5fff"))
	f.Add(hexb(f, "9bffffffffffffffff"))
	for _, s := range seedObjects(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in []byte) { mustNotPanic(t, in) })
}
