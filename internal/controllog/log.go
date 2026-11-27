// SPDX-License-Identifier: AGPL-3.0-or-later

package controllog

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// DESIGN §6.3:
// Canonical body = length-prefixed encoding of:
//   "sendora-control-v1\x00", tenant_id, seq, prev_hash, kind, [kind fields in order], actor, ts_text
// event_hash = SHA-256(body)
// Genesis prev_hash = SHA-256("sendora-control-genesis-v1" ‖ tenant_id ‖ chain_id)

var (
	ErrInvalidSequence = errors.New("invalid sequence number")
	ErrHashMismatch    = errors.New("prev_hash does not match previous event")
	ErrMACMismatch     = errors.New("control log event MAC verification failed")
)

type Event struct {
	TenantID  string
	Seq       int64
	PrevHash  []byte
	Kind      string
	Purpose   string
	Version   int
	Body      []byte
	EventHash []byte
	MACKEK    string
	MAC       []byte
}

// GenesisPrevHash calculates the seq 1 prev_hash
func GenesisPrevHash(tenantID, chainID string) []byte {
	h := sha256.New()
	h.Write([]byte("sendora-control-genesis-v1"))
	h.Write([]byte(tenantID))
	h.Write([]byte(chainID))
	return h.Sum(nil)
}

// CanonicalBody builds the length-prefixed wire format
func CanonicalBody(tenantID string, seq int64, prevHash []byte, kind string, kindFields []string, actor, tsText string) []byte {
	items := make([][]byte, 0, 6+len(kindFields))
	items = append(items,
		[]byte("sendora-control-v1\x00"),
		[]byte(tenantID),
		[]byte(strconv.FormatInt(seq, 10)),
		prevHash,
		[]byte(kind),
	)
	for _, f := range kindFields {
		items = append(items, []byte(f))
	}
	items = append(items, []byte(actor), []byte(tsText))

	totalLen := 0
	for _, it := range items {
		totalLen += binary.MaxVarintLen64 + len(it)
	}

	buf := make([]byte, 0, totalLen)
	var vbuf [binary.MaxVarintLen64]byte
	for _, it := range items {
		n := binary.PutUvarint(vbuf[:], uint64(len(it)))
		buf = append(buf, vbuf[:n]...)
		buf = append(buf, it...)
	}
	return buf
}

// ComputeEventHash returns SHA-256(body)
func ComputeEventHash(body []byte) []byte {
	h := sha256.Sum256(body)
	return h[:]
}

// KeyFingerprint returns HMAC-SHA256(dek, "sendora key fingerprint v1")
func KeyFingerprint(dek []byte) []byte {
	mac := hmac.New(sha256.New, dek)
	mac.Write([]byte("sendora key fingerprint v1"))
	return mac.Sum(nil)
}

// WrapAAD returns the length-prefixed AAD for wrapping a tenant DEK
func WrapAAD(tenantID, purpose string, version int) []byte {
	return []byte(fmt.Sprintf("sendora-wrap-v1/%s/%s/%d", tenantID, purpose, version))
}

// Body is a decoded canonical event body.
type Body struct {
	TenantID string
	Seq      int64
	PrevHash []byte
	Kind     string
	Fields   []string // the kind's fields, in order
	Actor    string
	TS       string
}

// DecodeBody parses the canonical encoding written by CanonicalBody. It
// refuses anything that is not exactly that encoding (trailing bytes, a
// missing field, another prefix), so a verifier never accepts a body it could
// not have produced itself.
func DecodeBody(body []byte) (Body, error) {
	var items [][]byte
	for rest := body; len(rest) > 0; {
		n, k := binary.Uvarint(rest)
		if k <= 0 || n > uint64(len(rest)-k) {
			return Body{}, errors.New("control log body: bad length prefix")
		}
		items = append(items, rest[k:k+int(n)])
		rest = rest[k+int(n):]
	}
	// prefix, tenant, seq, prev, kind, ..., actor, ts
	if len(items) < 7 || string(items[0]) != "sendora-control-v1\x00" {
		return Body{}, errors.New("control log body: not a control-log body")
	}
	seq, err := strconv.ParseInt(string(items[2]), 10, 64)
	if err != nil || seq < 1 {
		return Body{}, errors.New("control log body: bad sequence number")
	}
	b := Body{TenantID: string(items[1]), Seq: seq, PrevHash: items[3], Kind: string(items[4]),
		Actor: string(items[len(items)-2]), TS: string(items[len(items)-1])}
	for _, f := range items[5 : len(items)-2] {
		b.Fields = append(b.Fields, string(f))
	}
	return b, nil
}
