// SPDX-License-Identifier: AGPL-3.0-or-later

// Package virtual is a software WebAuthn authenticator for tests. It
// deliberately does NOT import webauthnlite: it has its own CBOR encoder and
// authenticatorData writer, so tests exercise the verifier against an
// independent implementation. Never use it outside tests.
package virtual

import (
	"bytes"
	"fmt"
	"sort"
)

// Raw is already encoded CBOR that Encode inserts verbatim.
type Raw []byte

// Encode encodes v as canonical CBOR (shortest heads, map keys ordered by
// length then bytes, as CTAP2 requires). Supported: int, int64, uint64, string,
// []byte, bool, nil, []any, map[any]any (int/string keys) and Raw. It panics on
// other types because it is test support.
func Encode(v any) []byte {
	var b bytes.Buffer
	enc(&b, v)
	return b.Bytes()
}

func head(b *bytes.Buffer, major byte, n uint64) {
	m := major << 5
	switch {
	case n < 24:
		b.WriteByte(m | byte(n))
	case n <= 0xff:
		b.WriteByte(m | 24)
		b.WriteByte(byte(n))
	case n <= 0xffff:
		b.WriteByte(m | 25)
		b.Write([]byte{byte(n >> 8), byte(n)})
	case n <= 0xffffffff:
		b.WriteByte(m | 26)
		b.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	default:
		b.WriteByte(m | 27)
		for s := 56; s >= 0; s -= 8 {
			b.WriteByte(byte(n >> uint(s)))
		}
	}
}

func enc(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteByte(0xf6)
	case bool:
		if x {
			b.WriteByte(0xf5)
		} else {
			b.WriteByte(0xf4)
		}
	case int:
		encInt(b, int64(x))
	case int64:
		encInt(b, x)
	case uint64:
		head(b, 0, x)
	case string:
		head(b, 3, uint64(len(x)))
		b.WriteString(x)
	case []byte:
		head(b, 2, uint64(len(x)))
		b.Write(x)
	case Raw:
		b.Write(x)
	case []any:
		head(b, 4, uint64(len(x)))
		for _, e := range x {
			enc(b, e)
		}
	case map[any]any:
		type kv struct{ k, v []byte }
		pairs := make([]kv, 0, len(x))
		for k, val := range x {
			pairs = append(pairs, kv{Encode(k), Encode(val)})
		}
		sort.Slice(pairs, func(i, j int) bool {
			if len(pairs[i].k) != len(pairs[j].k) {
				return len(pairs[i].k) < len(pairs[j].k)
			}
			return bytes.Compare(pairs[i].k, pairs[j].k) < 0
		})
		head(b, 5, uint64(len(pairs)))
		for _, p := range pairs {
			b.Write(p.k)
			b.Write(p.v)
		}
	default:
		panic(fmt.Sprintf("virtual.Encode: unsupported type %T", v))
	}
}

func encInt(b *bytes.Buffer, n int64) {
	if n >= 0 {
		head(b, 0, uint64(n))
		return
	}
	head(b, 1, uint64(-1-n))
}
