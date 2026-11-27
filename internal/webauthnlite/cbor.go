// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnlite

import (
	"math"
	"unicode/utf8"
)

// Minimal strict CBOR decoder: only what WebAuthn attestation objects and COSE
// keys need. Definite lengths only; unsigned/negative ints (within int64), byte
// strings, valid UTF-8 text strings, arrays, maps (keys: int64 or string only,
// duplicates rejected), and the simple values true/false/null. Tags, floats,
// undefined, other simple values and indefinite lengths are rejected. Decoded
// values are int64, []byte, string, []any, map[any]any, bool and nil.
//
// Non-minimal integer/length encodings are accepted on purpose (leniency with
// real authenticators costs nothing here: the signature always covers the raw
// authData bytes, not a re-encoding).

const (
	maxCBORSize  = 64 << 10 // total input bytes
	maxCBORDepth = 8        // nesting depth (top level is depth 0)
	maxCBORElems = 64       // elements per array / map
	maxCBORItems = 4096     // total items in one decode, belt and braces
)

type decoder struct {
	b     []byte
	pos   int
	items int
}

// decodeCBOR decodes exactly one item that must span the whole input.
func decodeCBOR(b []byte) (any, error) {
	v, n, err := decodeCBORPrefix(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, wrap(ErrMalformed, "trailing bytes after CBOR item")
	}
	return v, nil
}

// decodeCBORPrefix decodes one item from the start of b and reports how many
// bytes it consumed.
func decodeCBORPrefix(b []byte) (any, int, error) {
	if len(b) > maxCBORSize {
		return nil, 0, wrap(ErrMalformed, "CBOR input too large")
	}
	d := &decoder{b: b}
	v, err := d.item(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

func (d *decoder) argument(info byte) (uint64, error) {
	var n int
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24:
		n = 1
	case info == 25:
		n = 2
	case info == 26:
		n = 4
	case info == 27:
		n = 8
	case info == 31:
		return 0, wrap(ErrUnsupported, "indefinite-length CBOR")
	default:
		return 0, wrap(ErrMalformed, "reserved CBOR additional info %d", info)
	}
	if len(d.b)-d.pos < n {
		return 0, wrap(ErrMalformed, "truncated CBOR")
	}
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(d.b[d.pos+i])
	}
	d.pos += n
	return v, nil
}

func (d *decoder) item(depth int) (any, error) {
	if depth > maxCBORDepth {
		return nil, wrap(ErrMalformed, "CBOR nested too deeply")
	}
	d.items++
	if d.items > maxCBORItems {
		return nil, wrap(ErrMalformed, "too many CBOR items")
	}
	if d.pos >= len(d.b) {
		return nil, wrap(ErrMalformed, "truncated CBOR")
	}
	ib := d.b[d.pos]
	d.pos++
	major, info := ib>>5, ib&0x1f
	switch major {
	case 6:
		return nil, wrap(ErrUnsupported, "CBOR tags")
	case 7:
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, wrap(ErrUnsupported, "CBOR simple value or float")
	}
	arg, err := d.argument(info)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return nil, wrap(ErrMalformed, "integer out of range")
		}
		return int64(arg), nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, wrap(ErrMalformed, "integer out of range")
		}
		return -1 - int64(arg), nil
	case 2, 3:
		if arg > uint64(len(d.b)-d.pos) {
			return nil, wrap(ErrMalformed, "truncated CBOR string")
		}
		s := d.b[d.pos : d.pos+int(arg)]
		d.pos += int(arg)
		if major == 3 {
			if !utf8.Valid(s) {
				return nil, wrap(ErrMalformed, "invalid UTF-8 in CBOR text")
			}
			return string(s), nil
		}
		return append([]byte{}, s...), nil
	case 4:
		if arg > maxCBORElems || arg > uint64(len(d.b)-d.pos) {
			return nil, wrap(ErrMalformed, "CBOR array too large")
		}
		out := make([]any, 0, int(arg))
		for i := uint64(0); i < arg; i++ {
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if arg > maxCBORElems || arg*2 > uint64(len(d.b)-d.pos) {
			return nil, wrap(ErrMalformed, "CBOR map too large")
		}
		out := make(map[any]any, int(arg))
		for i := uint64(0); i < arg; i++ {
			k, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, wrap(ErrMalformed, "unsupported CBOR map key type")
			}
			if _, dup := out[k]; dup {
				return nil, wrap(ErrMalformed, "duplicate CBOR map key")
			}
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	}
	return nil, wrap(ErrMalformed, "unreachable CBOR major type") // major is 3 bits: 0..7 all handled
}

// Typed accessors for decoded maps.

func mapInt(m map[any]any, key any) (int64, bool) {
	v, ok := m[key].(int64)
	return v, ok
}

func mapBytes(m map[any]any, key any) ([]byte, bool) {
	v, ok := m[key].([]byte)
	return v, ok
}

func mapString(m map[any]any, key any) (string, bool) {
	v, ok := m[key].(string)
	return v, ok
}
