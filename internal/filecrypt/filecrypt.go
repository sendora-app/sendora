// SPDX-License-Identifier: AGPL-3.0-or-later

// Package filecrypt encrypts stored share files with chunked AES-256-GCM.
//
// Design goals: cheap (one streaming pass, hardware AES), seekable (HTTP Range
// and media preview keep working) and tamper/truncation evident. The normative
// description is docs/FILE-FORMAT.md.
//
// File layout, format version 2 (written by this package):
//
//	magic "SNDF" | version (2) | salt (32) | fileID (16) | chunk 0 | chunk 1 | ...
//
// Version 1 (0.1.2 - 0.1.4, read only) has no fileID:
//
//	magic "SNDF" | version (1) | salt (32) | chunk 0 | chunk 1 | ...
//
// Every chunk holds up to ChunkSize plaintext bytes followed by a 16 byte GCM
// tag. Only the last chunk may be shorter; an empty file is one empty chunk.
// Each file has its own key: HKDF-SHA256(master, salt). The nonce is the chunk
// index; the additional data is a one byte "last chunk" flag (v2: followed by
// the fileID), so chunks cannot be reordered, dropped or appended, and in v2 a
// file cannot be moved to another database row (the row stores the fileID and
// the reader checks it against the header).
package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync/atomic"
	"time"
)

const (
	ChunkSize    = 64 << 10
	tagSize      = 16
	saltSize     = 32
	idSize       = 16
	headerSizeV1 = 4 + 1 + saltSize
	headerSizeV2 = headerSizeV1 + idSize
	// CurrentVersion is the format version Encrypt writes.
	CurrentVersion = 2
)

var (
	magic = [4]byte{'S', 'N', 'D', 'F'}

	ErrCorrupt = errors.New("encrypted file is corrupt or has been modified")

	// Specific causes. All of them satisfy errors.Is(err, ErrCorrupt) and none
	// carries key material, plaintext or file names.
	ErrBadHeader    error = &corrupt{"bad header"}
	ErrSizeMismatch error = &corrupt{"size mismatch"}
	ErrIDMismatch   error = &corrupt{"file id mismatch"}
)

type corrupt struct{ what string }

func (e *corrupt) Error() string        { return ErrCorrupt.Error() + " (" + e.what + ")" }
func (e *corrupt) Is(target error) bool { return target == ErrCorrupt }

// ChunkError reports the first chunk that failed authentication.
type ChunkError struct{ Index int64 }

func (e *ChunkError) Error() string        { return ErrCorrupt.Error() }
func (e *ChunkError) Is(target error) bool { return target == ErrCorrupt }

// Failure counters: every refused header, size, file id or chunk tag.
var (
	failures    atomic.Uint64
	lastFailure atomic.Int64 // unix nanoseconds, 0 = never
)

// Failures returns how many decrypt/authentication failures this process has
// seen and when the last one happened (zero time if none).
func Failures() (count uint64, last time.Time) {
	count = failures.Load()
	if n := lastFailure.Load(); n != 0 {
		last = time.Unix(0, n)
	}
	return
}

func fail(err error) error {
	failures.Add(1)
	lastFailure.Store(time.Now().UnixNano())
	return err
}

// MasterKey derives the file-encryption master key from the 32 byte database key.
func MasterKey(dbKey []byte) ([]byte, error) {
	if len(dbKey) != 32 {
		return nil, errors.New("database key must contain 32 bytes")
	}
	return hkdf.Key(sha256.New, dbKey, nil, "sendora share file encryption v1", 32)
}

func fileKey(master, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, master, salt, "sendora share file key", 32)
}

func fileAEAD(master, salt []byte) (cipher.AEAD, error) {
	k, err := fileKey(master, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func nonce(aead cipher.AEAD, idx uint64) []byte {
	n := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint64(n[len(n)-8:], idx)
	return n
}

// aad is the additional data of a chunk: last flag, then (v2) the file id.
func aad(buf []byte, id []byte, last bool) []byte {
	buf = buf[:0]
	if last {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	return append(buf, id...)
}

func chunkCount(plain int64) int64 {
	chunks := plain / ChunkSize
	if plain%ChunkSize != 0 || plain == 0 {
		chunks++
	}
	return chunks
}

func headerSize(ver int) int64 {
	if ver == 1 {
		return headerSizeV1
	}
	return headerSizeV2
}

// CipherSizeVersion is the stored size of plain plaintext bytes in format ver (1 or 2).
func CipherSizeVersion(ver int, plain int64) int64 {
	return headerSize(ver) + plain + chunkCount(plain)*tagSize
}

// CipherSize is the stored size in the current format (version 2).
func CipherSize(plain int64) int64 { return CipherSizeVersion(CurrentVersion, plain) }

// Encrypt streams src into dst in format v2 with a fresh random salt and file
// id. It returns the plaintext length and the file id (hex) that the caller
// must store in the database row; when h is not nil every plaintext byte is
// also written to h so callers get a checksum in the same pass.
func Encrypt(dst io.Writer, src io.Reader, master []byte, h hash.Hash) (int64, string, error) {
	salt := make([]byte, saltSize)
	id := make([]byte, idSize)
	if _, err := rand.Read(salt); err != nil {
		return 0, "", err
	}
	if _, err := rand.Read(id); err != nil {
		return 0, "", err
	}
	n, err := encryptWithParams(dst, src, master, h, salt, id)
	if err != nil {
		return n, "", err
	}
	return n, hex.EncodeToString(id), nil
}

// encryptWithParams is the only place that accepts a salt and file id. It is
// unexported: only this package's tests (reproducible vectors) can choose them.
func encryptWithParams(dst io.Writer, src io.Reader, master []byte, h hash.Hash, salt, id []byte) (int64, error) {
	if len(salt) != saltSize || len(id) != idSize {
		return 0, errors.New("filecrypt: bad salt or file id length")
	}
	aead, err := fileAEAD(master, salt)
	if err != nil {
		return 0, err
	}
	hdr := make([]byte, 0, headerSizeV2)
	hdr = append(hdr, magic[:]...)
	hdr = append(hdr, CurrentVersion)
	hdr = append(hdr, salt...)
	hdr = append(hdr, id...)
	if _, err := dst.Write(hdr); err != nil {
		return 0, err
	}
	cur := make([]byte, ChunkSize)
	next := make([]byte, ChunkSize)
	out := make([]byte, 0, ChunkSize+tagSize)
	ad := make([]byte, 0, 1+idSize)
	n, err := io.ReadFull(src, cur)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return 0, err
	}
	var total int64
	for idx := uint64(0); ; idx++ {
		last := n < ChunkSize
		nn := 0
		if !last {
			nn, err = io.ReadFull(src, next)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				return total, err
			}
			last = nn == 0
		}
		if h != nil {
			h.Write(cur[:n])
		}
		out = aead.Seal(out[:0], nonce(aead, idx), cur[:n], aad(ad, id, last))
		if _, err := dst.Write(out); err != nil {
			return total, err
		}
		total += int64(n)
		if last {
			return total, nil
		}
		cur, next = next, cur
		n = nn
	}
}

// File is the random-access source Reader needs (an *os.File).
type File interface {
	io.ReaderAt
	io.Closer
}

// Reader is a seekable plaintext view of an encrypted file.
type Reader struct {
	f      File
	aead   cipher.AEAD
	id     []byte // file id (v2), nil for v1
	hdr    int64
	plain  int64
	chunks int64
	pos    int64
	idx    int64 // cached chunk index, -1 when empty
	buf    []byte
	raw    []byte
	ad     []byte
}

// NewReader validates the header and the stored length against plain, the
// plaintext size recorded in the database, and against encID, the file id
// recorded in the same row (hex; empty for version 1 files written by
// 0.1.2 - 0.1.4). A v2 header needs a matching non-empty encID; a v1 header is
// accepted only with an empty encID.
func NewReader(f File, storedSize, plain int64, master []byte, encID string) (*Reader, error) {
	r, err := newReader(f, storedSize, plain, master, encID)
	if err != nil {
		return nil, fail(err)
	}
	return r, nil
}

func newReader(f File, storedSize, plain int64, master []byte, encID string) (*Reader, error) {
	if plain < 0 {
		return nil, ErrSizeMismatch
	}
	hdr := make([]byte, headerSizeV2)
	n, err := f.ReadAt(hdr, 0)
	if n < 5 || (err != nil && err != io.EOF) {
		return nil, ErrBadHeader
	}
	if [4]byte(hdr[:4]) != magic {
		return nil, ErrBadHeader
	}
	ver := int(hdr[4])
	if (ver != 1 && ver != 2) || (ver == 1) != (encID == "") {
		return nil, ErrBadHeader
	}
	if int64(n) < headerSize(ver) {
		return nil, ErrBadHeader
	}
	if storedSize != CipherSizeVersion(ver, plain) {
		return nil, ErrSizeMismatch
	}
	var id []byte
	if ver == 2 {
		want, err := hex.DecodeString(encID)
		if err != nil || len(want) != idSize || subtle.ConstantTimeCompare(hdr[headerSizeV1:headerSizeV2], want) != 1 {
			return nil, ErrIDMismatch
		}
		id = want
	}
	aead, err := fileAEAD(master, hdr[5:5+saltSize])
	if err != nil {
		return nil, err
	}
	r := &Reader{f: f, aead: aead, id: id, hdr: headerSize(ver), plain: plain, chunks: chunkCount(plain), idx: -1,
		raw: make([]byte, ChunkSize+tagSize), ad: make([]byte, 0, 1+idSize)}
	if plain == 0 {
		// An empty file has no plaintext to read, so Read would never touch its
		// single (empty) chunk; authenticate it here so it cannot be altered.
		if err := r.loadChunk(0); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Reader) load(idx int64) error {
	if err := r.loadChunk(idx); err != nil {
		return fail(err)
	}
	return nil
}

func (r *Reader) loadChunk(idx int64) error {
	if r.idx == idx {
		return nil
	}
	size := int64(ChunkSize)
	last := idx == r.chunks-1
	if last {
		size = r.plain - idx*ChunkSize
	}
	raw := r.raw[:size+tagSize]
	if _, err := r.f.ReadAt(raw, r.hdr+idx*(ChunkSize+tagSize)); err != nil {
		r.idx = -1
		return &ChunkError{idx}
	}
	plain, err := r.aead.Open(r.buf[:0], nonce(r.aead, uint64(idx)), raw, aad(r.ad, r.id, last))
	if err != nil {
		r.idx = -1
		return &ChunkError{idx}
	}
	r.buf, r.idx = plain, idx
	return nil
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.pos >= r.plain {
		return 0, io.EOF
	}
	total := 0
	for len(p) > 0 && r.pos < r.plain {
		idx := r.pos / ChunkSize
		if err := r.load(idx); err != nil {
			return total, err
		}
		n := copy(p, r.buf[r.pos-idx*ChunkSize:])
		p = p[n:]
		r.pos += int64(n)
		total += n
	}
	return total, nil
}

func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.pos + offset
	case io.SeekEnd:
		abs = r.plain + offset
	default:
		return 0, fmt.Errorf("filecrypt: invalid whence %d", whence)
	}
	if abs < 0 {
		return 0, errors.New("filecrypt: negative position")
	}
	r.pos = abs
	return abs, nil
}

func (r *Reader) Close() error { return r.f.Close() }

// Size is the plaintext size.
func (r *Reader) Size() int64 { return r.plain }
