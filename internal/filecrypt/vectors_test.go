// SPDX-License-Identifier: AGPL-3.0-or-later

package filecrypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
)

// The vectors in testdata/vectors.json are normative (docs/FILE-FORMAT.md) and
// are regenerated independently by docs/tools/verify_vectors.py. Regenerate the
// file with: SENDORA_UPDATE_VECTORS=1 go test ./internal/filecrypt -run TestVectors

const vectorsPath = "testdata/vectors.json"

var vectorSizes = []int{0, 1, 65535, 65536, 65537, 131072, 196609}

type vectorOp struct {
	Op     string `json:"op"` // flip | set_byte | truncate | swap_chunks | drop_chunk
	Offset int    `json:"offset,omitempty"`
	Bit    int    `json:"bit,omitempty"`
	Value  int    `json:"value,omitempty"`
	A      int    `json:"a,omitempty"`
	B      int    `json:"b,omitempty"`
}

type positiveVector struct {
	PlainSize  int    `json:"plain_size"`
	StoredSize int    `json:"stored_size"`
	PlainSHA   string `json:"plain_sha256"`
	FileSHA    string `json:"file_sha256"`
	FileHex    string `json:"file_hex,omitempty"`
}

type negativeVector struct {
	Name       string     `json:"name"`
	Base       int        `json:"base_plain_size"`
	Ops        []vectorOp `json:"ops"`
	PlainSize  int        `json:"row_plain_size"`
	RowFileID  string     `json:"row_file_id_hex"`
	RootKey    string     `json:"root_key_hex"`
	MutatedSHA string     `json:"mutated_file_sha256"`
	Expect     string     `json:"expect"` // bad-header | size-mismatch | id-mismatch | chunk:N
}

type vectorFile struct {
	Description string           `json:"description"`
	Rule        string           `json:"plaintext_rule"`
	RootKey     string           `json:"root_key_hex"`
	MasterKey   string           `json:"master_key_hex"`
	Salt        string           `json:"salt_hex"`
	FileID      string           `json:"file_id_hex"`
	FileKey     string           `json:"file_key_hex"`
	Positive    []positiveVector `json:"vectors"`
	Negative    []negativeVector `json:"negative_vectors"`
}

func seq(start, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(start + i)
	}
	return b
}

func vecPlain(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func vecParams(t *testing.T) (root, master, salt, id, fkey []byte) {
	t.Helper()
	root, salt, id = seq(0, 32), seq(0xa0, 32), seq(0xc0, 16)
	master, err := MasterKey(root)
	if err != nil {
		t.Fatal(err)
	}
	fkey, err = fileKey(master, salt)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func vecEncrypt(t *testing.T, master, salt, id []byte, size int) []byte {
	t.Helper()
	var out bytes.Buffer
	if _, err := encryptWithParams(&out, bytes.NewReader(vecPlain(size)), master, nil, salt, id); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func applyOps(file []byte, ops []vectorOp) []byte {
	f := bytes.Clone(file)
	const chunk = ChunkSize + tagSize
	for _, op := range ops {
		switch op.Op {
		case "flip":
			f[op.Offset] ^= 1 << op.Bit
		case "set_byte":
			f[op.Offset] = byte(op.Value)
		case "truncate":
			f = f[:op.Offset]
		case "swap_chunks":
			a, b := headerSizeV2+op.A*chunk, headerSizeV2+op.B*chunk
			x := bytes.Clone(f[a : a+chunk])
			copy(f[a:a+chunk], f[b:b+chunk])
			copy(f[b:b+chunk], x)
		case "drop_chunk":
			a := headerSizeV2 + op.A*chunk
			f = append(f[:a:a], f[a+chunk:]...)
		}
	}
	return f
}

// expectOf classifies a reader failure the same way the vector file does.
func expectOf(err error) string {
	var ce *ChunkError
	switch {
	case err == nil:
		return "accepted"
	case errors.Is(err, ErrBadHeader):
		return "bad-header"
	case errors.Is(err, ErrSizeMismatch):
		return "size-mismatch"
	case errors.Is(err, ErrIDMismatch):
		return "id-mismatch"
	case errors.As(err, &ce):
		return fmt.Sprintf("chunk:%d", ce.Index)
	}
	return "other:" + err.Error()
}

func readAllWith(file []byte, plain int, master []byte, rowID string) error {
	r, err := NewReader(memFile{bytes.NewReader(file)}, int64(len(file)), int64(plain), master, rowID)
	if err != nil {
		return err
	}
	_, err = io.ReadAll(r)
	return err
}

func buildVectors(t *testing.T) vectorFile {
	root, master, salt, id, fkey := vecParams(t)
	v := vectorFile{
		Description: "Sendora share file format v2 test vectors (docs/FILE-FORMAT.md). All vectors share one salt and file id; real files never do.",
		Rule:        "plaintext byte i = i mod 251",
		RootKey:     hex.EncodeToString(root), MasterKey: hex.EncodeToString(master),
		Salt: hex.EncodeToString(salt), FileID: hex.EncodeToString(id), FileKey: hex.EncodeToString(fkey),
	}
	for _, size := range vectorSizes {
		f := vecEncrypt(t, master, salt, id, size)
		p := positiveVector{PlainSize: size, StoredSize: len(f), PlainSHA: sha(vecPlain(size)), FileSHA: sha(f)}
		if size <= 1 {
			p.FileHex = hex.EncodeToString(f)
		}
		v.Positive = append(v.Positive, p)
	}
	const base, chunk = 196609, ChunkSize + tagSize
	baseFile := vecEncrypt(t, master, salt, id, base)
	wrongRoot := hex.EncodeToString(seq(1, 32))
	rootHex, idHex := hex.EncodeToString(root), hex.EncodeToString(id)
	neg := []negativeVector{
		{Name: "flipped tag bit (chunk 0)", Ops: []vectorOp{{Op: "flip", Offset: headerSizeV2 + chunk - 1, Bit: 0}}, Expect: "chunk:0"},
		{Name: "flipped ciphertext bit (chunk 3)", Ops: []vectorOp{{Op: "flip", Offset: headerSizeV2 + 3*chunk, Bit: 7}}, Expect: "chunk:3"},
		{Name: "last chunk dropped at the boundary, size adjusted", Ops: []vectorOp{{Op: "truncate", Offset: headerSizeV2 + 3*chunk}}, PlainSize: 3 * ChunkSize, Expect: "chunk:2"},
		{Name: "middle chunk dropped, size adjusted", Ops: []vectorOp{{Op: "drop_chunk", A: 1}}, PlainSize: base - ChunkSize, Expect: "chunk:1"},
		{Name: "chunks 0 and 1 swapped", Ops: []vectorOp{{Op: "swap_chunks", A: 0, B: 1}}, Expect: "chunk:0"},
		{Name: "wrong magic", Ops: []vectorOp{{Op: "set_byte", Offset: 0, Value: 'X'}}, Expect: "bad-header"},
		{Name: "wrong version", Ops: []vectorOp{{Op: "set_byte", Offset: 4, Value: 3}}, Expect: "bad-header"},
		{Name: "version 1 header with a v2 row id", Ops: []vectorOp{{Op: "set_byte", Offset: 4, Value: 1}}, Expect: "bad-header"},
		{Name: "flipped salt bit", Ops: []vectorOp{{Op: "flip", Offset: 5, Bit: 0}}, Expect: "chunk:0"},
		{Name: "flipped file id bit in the header", Ops: []vectorOp{{Op: "flip", Offset: headerSizeV1, Bit: 0}}, Expect: "id-mismatch"},
		{Name: "wrong key", Ops: nil, RootKey: wrongRoot, Expect: "chunk:0"},
		{Name: "wrong file id in the row", Ops: nil, RowFileID: hex.EncodeToString(seq(0xd0, 16)), Expect: "id-mismatch"},
		{Name: "empty file id in the row (v1 expected)", Ops: nil, RowFileID: "-", Expect: "bad-header"},
	}
	for _, n := range neg {
		n.Base = base
		n.Ops = append([]vectorOp{}, n.Ops...)
		if n.PlainSize == 0 {
			n.PlainSize = base
		}
		if n.RootKey == "" {
			n.RootKey = rootHex
		}
		switch n.RowFileID {
		case "":
			n.RowFileID = idHex
		case "-":
			n.RowFileID = ""
		}
		n.MutatedSHA = sha(applyOps(baseFile, n.Ops))
		v.Negative = append(v.Negative, n)
	}
	return v
}

func TestVectors(t *testing.T) {
	want := buildVectors(t)
	if os.Getenv("SENDORA_UPDATE_VECTORS") == "1" {
		b, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(vectorsPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var got vectorFile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if !bytes.Equal(a, b) {
		t.Fatal("testdata/vectors.json differs from what this implementation produces; format change or stale vectors")
	}

	// The committed file is checked on its own terms: decode, read, refuse.
	rootB, _ := hex.DecodeString(got.RootKey)
	master, err := MasterKey(rootB)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(master) != got.MasterKey {
		t.Fatal("master key vector")
	}
	salt, _ := hex.DecodeString(got.Salt)
	id, _ := hex.DecodeString(got.FileID)
	for _, p := range got.Positive {
		f := vecEncrypt(t, master, salt, id, p.PlainSize)
		if int64(len(f)) != CipherSize(int64(p.PlainSize)) || len(f) != p.StoredSize {
			t.Fatalf("size %d: stored size", p.PlainSize)
		}
		if p.FileHex != "" && hex.EncodeToString(f) != p.FileHex {
			t.Fatalf("size %d: file bytes differ", p.PlainSize)
		}
		r, err := NewReader(memFile{bytes.NewReader(f)}, int64(len(f)), int64(p.PlainSize), master, got.FileID)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := io.ReadAll(r)
		if err != nil || sha(plain) != p.PlainSHA || !bytes.Equal(plain, vecPlain(p.PlainSize)) {
			t.Fatalf("size %d: decrypt failed (%v)", p.PlainSize, err)
		}
	}
	baseFile := vecEncrypt(t, master, salt, id, got.Negative[0].Base)
	for _, n := range got.Negative {
		f := applyOps(baseFile, n.Ops)
		if sha(f) != n.MutatedSHA {
			t.Fatalf("%s: mutated file hash", n.Name)
		}
		root, _ := hex.DecodeString(n.RootKey)
		m, _ := MasterKey(root)
		if e := expectOf(readAllWith(f, n.PlainSize, m, n.RowFileID)); e != n.Expect {
			t.Errorf("%s: got %s, want %s", n.Name, e, n.Expect)
		}
	}
}
