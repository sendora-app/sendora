// SPDX-License-Identifier: AGPL-3.0-or-later

// Package storage stores share files and remote backup copies on a pluggable
// object store: the local data directory, S3-compatible services, Azure Blob
// Storage or Google Cloud Storage.
//
// The package only moves opaque bytes. Sendora encrypts every share file
// (internal/filecrypt) before it reaches a Backend, so an object store only ever
// holds ciphertext under random keys that reveal neither share links nor file
// names (see docs/STORAGE.md).
//
// A Backend is opened from a Config. Keys are relative to the Config's prefix;
// the backend adds the prefix itself, so a later multi-tenant layer can give
// each tenant the platform default with its own prefix (Config.WithPrefix) or a
// configuration of its own without any change here.
package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ErrNotExist is returned (wrapped) by Open and Stat for a missing object.
var ErrNotExist = errors.New("storage: object does not exist")

// Info describes one stored object.
type Info struct {
	Key     string // relative to the backend's prefix
	Size    int64
	ModTime time.Time
}

// Object is random-access read access to one stored object. ReadAt may be
// served by ranged requests; sequential reads reuse one open stream, so reading
// an object from start to end costs one request, and a seek (HTTP Range,
// preview) costs one more. Close releases the stream.
type Object interface {
	io.ReaderAt
	io.Closer
	Size() int64
	ModTime() time.Time
}

// Backend is one configured object store.
type Backend interface {
	// Kind is "local", "s3", "azure" or "gcs".
	Kind() string
	// Put stores exactly size bytes read from r under key, replacing an existing
	// object. A failed Put leaves no partial object behind (multipart uploads are
	// aborted, uncommitted blocks are never committed).
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	// Open opens key for reading. ctx bounds every request the object makes.
	Open(ctx context.Context, key string) (Object, error)
	Stat(ctx context.Context, key string) (Info, error)
	// Delete removes key; a missing object is not an error.
	Delete(ctx context.Context, key string) error
	// List calls fn for every object whose key starts with prefix.
	List(ctx context.Context, prefix string, fn func(Info) error) error
}

// FilePrefix holds share files, BackupPrefix the remote copies of database
// backups, ProbePrefix the short-lived objects of connection tests.
const (
	FilePrefix   = "files/"
	BackupPrefix = "backups/"
	ProbePrefix  = "probe/"
)

var fileKeyRe = regexp.MustCompile(`^files/[a-f0-9]{32}$`)

// NewFileKey returns a fresh random object key for a share file: 128 random
// bits, unrelated to the share link, the file name or the database row.
func NewFileKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return FilePrefix + hex.EncodeToString(b), nil
}

// ValidFileKey reports whether key has the form NewFileKey generates. Keys read
// from the database are checked before use, so a tampered row cannot reach
// other objects (backups, probes) of the same bucket.
func ValidFileKey(key string) bool { return fileKeyRe.MatchString(key) }

// validKey rejects keys that could escape a prefix or a local root.
func validKey(key string) error {
	if key == "" || len(key) > 512 || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") || strings.Contains(key, "//") {
		return fmt.Errorf("storage: invalid object key")
	}
	for _, part := range strings.Split(key, "/") {
		if part == "." || part == ".." {
			return fmt.Errorf("storage: invalid object key")
		}
	}
	for _, r := range key {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("storage: invalid object key")
		}
	}
	return nil
}

// Probe writes, reads back and deletes a small random object under
// ProbePrefix: the connection test of the admin screen and the readiness check.
func Probe(ctx context.Context, b Backend) error {
	payload := make([]byte, 64)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	key := ProbePrefix + hex.EncodeToString(payload[:8])
	if err := b.Put(ctx, key, strings.NewReader(string(payload)), int64(len(payload))); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	defer b.Delete(context.WithoutCancel(ctx), key)
	obj, err := b.Open(ctx, key)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	got := make([]byte, len(payload))
	_, err = obj.ReadAt(got, 0)
	obj.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read: %w", err)
	}
	if string(got) != string(payload) || obj.Size() != int64(len(payload)) {
		return errors.New("read: content differs from what was written")
	}
	if err := b.Delete(ctx, key); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	if _, err := b.Stat(ctx, key); !errors.Is(err, ErrNotExist) {
		return errors.New("delete: object still exists")
	}
	return nil
}

// DeletePrefix deletes every object under prefix and returns how many it deleted.
func DeletePrefix(ctx context.Context, b Backend, prefix string) (int, error) {
	var keys []string
	if err := b.List(ctx, prefix, func(i Info) error { keys = append(keys, i.Key); return nil }); err != nil {
		return 0, err
	}
	n := 0
	for _, k := range keys {
		if err := b.Delete(ctx, k); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// rangeOpener opens a stream of the object from off to its end.
type rangeOpener func(ctx context.Context, off int64) (io.ReadCloser, error)

// remoteObject implements Object over ranged GET requests. One stream stays
// open while reads are sequential; a read elsewhere reopens it at the new
// offset. A stream that breaks mid-way is reopened once per read.
type remoteObject struct {
	ctx  context.Context
	open rangeOpener
	size int64
	mod  time.Time

	mu   sync.Mutex
	body io.ReadCloser
	pos  int64
}

func newRemoteObject(ctx context.Context, size int64, mod time.Time, open rangeOpener) *remoteObject {
	return &remoteObject{ctx: ctx, open: open, size: size, mod: mod}
}

func (o *remoteObject) Size() int64        { return o.size }
func (o *remoteObject) ModTime() time.Time { return o.mod }

func (o *remoteObject) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("storage: negative offset")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if off >= o.size {
		return 0, io.EOF
	}
	want := p
	if rest := o.size - off; int64(len(want)) > rest {
		want = want[:rest]
	}
	total := 0
	for attempt := 0; total < len(want); attempt++ {
		if o.body == nil || o.pos != off+int64(total) {
			o.closeBody()
			body, err := o.open(o.ctx, off+int64(total))
			if err != nil {
				return total, err
			}
			o.body, o.pos = body, off+int64(total)
		}
		n, err := io.ReadFull(o.body, want[total:])
		total += n
		o.pos += int64(n)
		if err != nil {
			o.closeBody()
			if attempt >= 1 || o.ctx.Err() != nil {
				if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
					err = io.ErrUnexpectedEOF
				}
				return total, err
			}
		}
	}
	if len(want) < len(p) {
		return total, io.EOF
	}
	return total, nil
}

func (o *remoteObject) closeBody() {
	if o.body != nil {
		o.body.Close()
		o.body = nil
	}
}

func (o *remoteObject) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closeBody()
	return nil
}

// exactReader fails when r yields more or fewer than n bytes, so a Put never
// stores a truncated or overlong object.
type exactReader struct {
	r    io.Reader
	left int64
}

var errSizeMismatch = errors.New("storage: source size differs from the announced size")

func (e *exactReader) Read(p []byte) (int, error) {
	if e.left <= 0 {
		var one [1]byte
		n, err := e.r.Read(one[:])
		if n > 0 {
			return 0, errSizeMismatch
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
		return 0, io.EOF
	}
	if int64(len(p)) > e.left {
		p = p[:e.left]
	}
	n, err := e.r.Read(p)
	e.left -= int64(n)
	if err == io.EOF && e.left > 0 {
		return n, errSizeMismatch
	}
	if err == io.EOF {
		err = nil
	}
	return n, err
}

// drain confirms that the source ends exactly at the announced size.
func (e *exactReader) drain() error {
	var b [1]byte
	n, err := e.Read(b[:])
	if n > 0 {
		return errSizeMismatch
	}
	if err == io.EOF {
		return nil
	}
	return err
}

// readPart fills buf as far as the source allows (a short read is the last part).
func readPart(r io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(r, buf)
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		return n, nil
	}
	return n, err
}
