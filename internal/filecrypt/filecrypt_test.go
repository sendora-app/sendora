// SPDX-License-Identifier: AGPL-3.0-or-later

package filecrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
)

type memFile struct{ *bytes.Reader }

func (memFile) Close() error { return nil }

func testMaster(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	m, err := MasterKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func seal(t *testing.T, master, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	h := sha256.New()
	n, _, err := Encrypt(&out, bytes.NewReader(plain), master, h)
	if err != nil || n != int64(len(plain)) {
		t.Fatalf("encrypt: n=%d err=%v", n, err)
	}
	if want := sha256.Sum256(plain); !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("checksum mismatch")
	}
	if int64(out.Len()) != CipherSize(int64(len(plain))) {
		t.Fatalf("size %d, want %d", out.Len(), CipherSize(int64(len(plain))))
	}
	return out.Bytes()
}

func open(t *testing.T, master, stored []byte, plain int64) (*Reader, error) {
	t.Helper()
	return NewReader(memFile{bytes.NewReader(stored)}, int64(len(stored)), plain, master, idOf(stored))
}

func TestRoundTripSizes(t *testing.T) {
	master := testMaster(t)
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + 17, 4 * ChunkSize} {
		plain := make([]byte, size)
		rand.Read(plain)
		stored := seal(t, master, plain)
		r, err := open(t, master, stored, int64(size))
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("size %d: round trip failed (%v)", size, err)
		}
	}
}

func TestSeekAndRange(t *testing.T) {
	master := testMaster(t)
	plain := make([]byte, 5*ChunkSize+123)
	rand.Read(plain)
	r, err := open(t, master, seal(t, master, plain), int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{0, 1, ChunkSize - 1, ChunkSize, 2*ChunkSize + 5, int64(len(plain)) - 10} {
		if _, err := r.Seek(off, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 200)
		n, err := io.ReadFull(r, buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:n], plain[off:off+int64(n)]) {
			t.Fatalf("offset %d mismatch", off)
		}
	}
	end, _ := r.Seek(0, io.SeekEnd)
	if end != int64(len(plain)) {
		t.Fatalf("seek end %d", end)
	}
}

func TestTamperTruncateWrongKey(t *testing.T) {
	master := testMaster(t)
	plain := make([]byte, 3*ChunkSize)
	rand.Read(plain)
	stored := seal(t, master, plain)

	flipped := bytes.Clone(stored)
	flipped[headerSizeV2+100] ^= 1
	r, _ := open(t, master, flipped, int64(len(plain)))
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("modified ciphertext was accepted")
	}

	// Dropping the last chunk and claiming a shorter file must fail: the new
	// last chunk was sealed as "not last".
	short := stored[:headerSizeV2+2*(ChunkSize+tagSize)]
	r, err := open(t, master, short, 2*ChunkSize)
	if err == nil {
		if _, err = io.ReadAll(r); err == nil {
			t.Fatal("truncated file was accepted")
		}
	}

	if _, err := open(t, master, stored, int64(len(plain))-1); err == nil {
		t.Fatal("wrong plaintext size accepted")
	}

	other := testMaster(t)
	r, _ = open(t, other, stored, int64(len(plain)))
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestUniqueKeyPerFile(t *testing.T) {
	master := testMaster(t)
	plain := []byte("same content")
	if bytes.Equal(seal(t, master, plain), seal(t, master, plain)) {
		t.Fatal("two encryptions of the same data are identical")
	}
}
