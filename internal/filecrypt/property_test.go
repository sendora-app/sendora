// SPDX-License-Identifier: AGPL-3.0-or-later

package filecrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	mrand "math/rand"
	"testing"
	"testing/iotest"
)

// idOf is the row value for a freshly written v2 file (hex of the header id).
func idOf(stored []byte) string {
	if len(stored) >= headerSizeV2 && stored[4] == 2 {
		return hex.EncodeToString(stored[headerSizeV1:headerSizeV2])
	}
	return ""
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// sealV1 writes the legacy 0.1.2 - 0.1.4 layout (no file id, AAD = flag only).
func sealV1(t *testing.T, master, plain []byte) []byte {
	t.Helper()
	salt := randBytes(saltSize)
	aead, err := fileAEAD(master, salt)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte("SNDF\x01"), salt...)
	chunks := chunkCount(int64(len(plain)))
	for i := int64(0); i < chunks; i++ {
		end := min((i+1)*ChunkSize, int64(len(plain)))
		last := i == chunks-1
		out = aead.Seal(out, nonce(aead, uint64(i)), plain[i*ChunkSize:end], aad(nil, nil, last))
	}
	return out
}

func TestRoundTripAwkwardSources(t *testing.T) {
	master := testMaster(t)
	plain := randBytes(2*ChunkSize + 321)
	for name, wrap := range map[string]func(io.Reader) io.Reader{
		"onebyte":  iotest.OneByteReader,
		"dataerr":  iotest.DataErrReader,
		"halfread": iotest.HalfReader,
	} {
		var out bytes.Buffer
		n, id, err := Encrypt(&out, wrap(bytes.NewReader(plain)), master, nil)
		if err != nil || n != int64(len(plain)) || len(id) != 32 {
			t.Fatalf("%s: n=%d err=%v", name, n, err)
		}
		r, err := NewReader(memFile{bytes.NewReader(out.Bytes())}, int64(out.Len()), n, master, id)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(iotest.OneByteReader(r))
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%s: read back failed (%v)", name, err)
		}
	}
}

func TestEveryBitFlipRefused(t *testing.T) {
	master := testMaster(t)
	for _, size := range []int{0, 1, 65536, 65537} {
		plain := randBytes(size)
		stored := seal(t, master, plain)
		id := idOf(stored)
		for bit := 0; bit < len(stored)*8; bit++ {
			// Small files: every bit. Large ones: every bit of the header and of the
			// first and last 64 bytes of each chunk (incl. tags), then every 61st.
			if size > 1 {
				off := bit / 8
				edge := off < headerSizeV2
				if !edge {
					in := (off - headerSizeV2) % (ChunkSize + tagSize)
					edge = in < 64 || in >= ChunkSize+tagSize-64 || off >= len(stored)-64
				}
				if !edge && bit%61 != 0 {
					continue
				}
			}
			stored[bit/8] ^= 1 << (bit % 8)
			if readAllWith(stored, size, master, id) == nil {
				t.Fatalf("size %d: flipping bit %d was accepted", size, bit)
			}
			stored[bit/8] ^= 1 << (bit % 8)
		}
		if err := readAllWith(stored, size, master, id); err != nil {
			t.Fatalf("size %d: restored file refused: %v", size, err)
		}
	}
}

func TestRandomSeekRead(t *testing.T) {
	master := testMaster(t)
	plain := randBytes(4*ChunkSize + 777)
	stored := seal(t, master, plain)
	r, err := open(t, master, stored, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	rng := mrand.New(mrand.NewSource(1))
	for i := 0; i < 500; i++ {
		off := rng.Int63n(int64(len(plain)) + 10)
		if _, err := r.Seek(off, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, rng.Intn(3*ChunkSize))
		n, err := io.ReadFull(r, buf)
		want := int64(0)
		if off < int64(len(plain)) {
			want = min(int64(len(buf)), int64(len(plain))-off)
		}
		if int64(n) != want || (n > 0 && !bytes.Equal(buf[:n], plain[off:off+int64(n)])) {
			t.Fatalf("off=%d len=%d: read %d bytes (%v), want %d", off, len(buf), n, err, want)
		}
	}
}

func TestCipherSizeMatchesOutput(t *testing.T) {
	master := testMaster(t)
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 2 * ChunkSize, 3*ChunkSize + 5} {
		stored := seal(t, master, randBytes(size))
		if int64(len(stored)) != CipherSize(int64(size)) || int64(len(stored)) != CipherSizeVersion(2, int64(size)) {
			t.Fatalf("size %d: stored %d, CipherSize %d", size, len(stored), CipherSize(int64(size)))
		}
		v1 := sealV1(t, master, randBytes(size))
		if int64(len(v1)) != CipherSizeVersion(1, int64(size)) {
			t.Fatalf("size %d: v1 stored %d, CipherSizeVersion %d", size, len(v1), CipherSizeVersion(1, int64(size)))
		}
	}
	if CipherSizeVersion(1, 0) != 37+16 || CipherSizeVersion(2, 0) != 53+16 {
		t.Fatal("header sizes")
	}
}

func TestRepeatedEncryptionsDiffer(t *testing.T) {
	master := testMaster(t)
	plain := []byte("same")
	a, b := seal(t, master, plain), seal(t, master, plain)
	if bytes.Equal(a, b) || idOf(a) == idOf(b) || bytes.Equal(a[5:37], b[5:37]) {
		t.Fatal("salt or file id repeated")
	}
}

func TestV1CompatibilityRules(t *testing.T) {
	master := testMaster(t)
	for _, size := range []int{0, 1, ChunkSize, 2*ChunkSize + 3} {
		plain := randBytes(size)
		v1 := sealV1(t, master, plain)
		r, err := NewReader(memFile{bytes.NewReader(v1)}, int64(len(v1)), int64(size), master, "")
		if err != nil {
			t.Fatalf("v1 size %d: %v", size, err)
		}
		if got, err := io.ReadAll(r); err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("v1 size %d: read back failed (%v)", size, err)
		}
		// v1 file with a row id, or v2 file without one, is refused.
		if _, err := NewReader(memFile{bytes.NewReader(v1)}, int64(len(v1)), int64(size), master, hex.EncodeToString(randBytes(16))); !errors.Is(err, ErrBadHeader) {
			t.Fatalf("v1 with row id: %v", err)
		}
		v2 := seal(t, master, plain)
		if _, err := NewReader(memFile{bytes.NewReader(v2)}, int64(len(v2)), int64(size), master, ""); !errors.Is(err, ErrBadHeader) {
			t.Fatalf("v2 without row id: %v", err)
		}
	}
}

func TestSwappedCiphertextRefused(t *testing.T) {
	master := testMaster(t)
	a, b := seal(t, master, randBytes(5000)), seal(t, master, randBytes(5000))
	if err := readAllWith(a, 5000, master, idOf(b)); !errors.Is(err, ErrIDMismatch) {
		t.Fatalf("A under B's row: %v", err)
	}
	// Even with B's header id forged into A, the chunks are bound to A's id.
	forged := bytes.Clone(a)
	copy(forged[headerSizeV1:headerSizeV2], b[headerSizeV1:headerSizeV2])
	if err := readAllWith(forged, 5000, master, idOf(b)); err == nil {
		t.Fatal("forged header id accepted")
	}
}

func TestFailureCounter(t *testing.T) {
	master := testMaster(t)
	before, _ := Failures()
	stored := seal(t, master, []byte("x"))
	stored[headerSizeV2] ^= 1
	if readAllWith(stored, 1, master, idOf(stored)) == nil {
		t.Fatal("accepted")
	}
	after, last := Failures()
	if after != before+1 || last.IsZero() {
		t.Fatalf("counter %d -> %d", before, after)
	}
}

func TestEncryptWithParamsRejectsBadLengths(t *testing.T) {
	if _, err := encryptWithParams(io.Discard, bytes.NewReader(nil), testMaster(t), nil, make([]byte, 5), make([]byte, 16)); err == nil {
		t.Fatal("short salt accepted")
	}
}

func FuzzReader(f *testing.F) {
	k := bytes.Repeat([]byte{7}, 32)
	master, _ := MasterKey(k)
	var seeds [][]byte
	for _, n := range []int{0, 1, 100} {
		var out bytes.Buffer
		_, _, _ = Encrypt(&out, bytes.NewReader(bytes.Repeat([]byte{9}, n)), master, nil)
		seeds = append(seeds, out.Bytes())
	}
	// The fuzzer must be able to hit the valid path: fixed salt and id make the
	// seeds reproducible, so valid stored bytes are known for each size.
	valid := map[int][]byte{}
	for _, n := range []int{0, 1, 100} {
		var out bytes.Buffer
		_, _ = encryptWithParams(&out, bytes.NewReader(bytes.Repeat([]byte{9}, n)), master, nil, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 16))
		valid[n] = out.Bytes()
		f.Add(out.Bytes(), n, hex.EncodeToString(bytes.Repeat([]byte{2}, 16)))
	}
	for _, s := range seeds {
		f.Add(s, 1, "")
	}
	f.Fuzz(func(t *testing.T, stored []byte, plain int, rowID string) {
		if plain < 0 || plain > 1<<20 {
			return
		}
		r, err := NewReader(memFile{bytes.NewReader(stored)}, int64(len(stored)), int64(plain), master, rowID)
		if err != nil {
			return
		}
		got, err := io.ReadAll(r)
		if err != nil {
			return
		}
		want, ok := valid[plain]
		if !ok || !bytes.Equal(stored, want) || !bytes.Equal(got, bytes.Repeat([]byte{9}, plain)) {
			sum := sha256.Sum256(stored)
			t.Fatalf("corrupt input returned %d bytes (sha %x)", len(got), sum[:4])
		}
	})
}
