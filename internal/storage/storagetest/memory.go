// SPDX-License-Identifier: AGPL-3.0-or-later

// Package storagetest has an in-memory backend and a conformance suite that
// every storage backend must pass (run against the real emulators in CI).
package storagetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sendora-app/sendora/internal/storage"
)

// Memory is a storage.Backend in memory, with counters and failure injection.
type Memory struct {
	mu      sync.Mutex
	objects map[string]memObject
	// FailPut makes Put fail (after reading the body) while set.
	FailPut atomic.Bool
	// FailOpen makes Open fail while set.
	FailOpen atomic.Bool
	Puts     atomic.Int64
	Deletes  atomic.Int64
	Opens    atomic.Int64
	// RangeReads counts the streams opened by ReadAt.
	RangeReads atomic.Int64
}

type memObject struct {
	data []byte
	mod  time.Time
}

func NewMemory() *Memory { return &Memory{objects: map[string]memObject{}} }

func (m *Memory) Kind() string { return "memory" }

func (m *Memory) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, r)
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("memory: got %d bytes, announced %d", n, size)
	}
	if m.FailPut.Load() {
		return errors.New("memory: injected put failure")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	m.mu.Lock()
	m.objects[key] = memObject{buf.Bytes(), time.Now()}
	m.mu.Unlock()
	m.Puts.Add(1)
	return nil
}

func (m *Memory) get(key string) (memObject, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.objects[key]
	return o, ok
}

type memReader struct {
	m    *Memory
	data []byte
	mod  time.Time
}

func (r *memReader) ReadAt(p []byte, off int64) (int, error) {
	r.m.RangeReads.Add(1)
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (r *memReader) Close() error       { return nil }
func (r *memReader) Size() int64        { return int64(len(r.data)) }
func (r *memReader) ModTime() time.Time { return r.mod }

func (m *Memory) Open(_ context.Context, key string) (storage.Object, error) {
	if m.FailOpen.Load() {
		return nil, errors.New("memory: injected open failure")
	}
	o, ok := m.get(key)
	if !ok {
		return nil, storage.ErrNotExist
	}
	m.Opens.Add(1)
	return &memReader{m: m, data: o.data, mod: o.mod}, nil
}

func (m *Memory) Stat(_ context.Context, key string) (storage.Info, error) {
	o, ok := m.get(key)
	if !ok {
		return storage.Info{}, storage.ErrNotExist
	}
	return storage.Info{Key: key, Size: int64(len(o.data)), ModTime: o.mod}, nil
}

func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	delete(m.objects, key)
	m.mu.Unlock()
	m.Deletes.Add(1)
	return nil
}

func (m *Memory) List(_ context.Context, prefix string, fn func(storage.Info) error) error {
	m.mu.Lock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	m.mu.Unlock()
	sort.Strings(keys)
	for _, k := range keys {
		o, ok := m.get(k)
		if !ok {
			continue
		}
		if err := fn(storage.Info{Key: k, Size: int64(len(o.data)), ModTime: o.mod}); err != nil {
			return err
		}
	}
	return nil
}

// Keys lists the stored keys.
func (m *Memory) Keys() []string {
	var out []string
	m.List(context.Background(), "", func(i storage.Info) error { out = append(out, i.Key); return nil })
	return out
}

// Bytes returns an object's content.
func (m *Memory) Bytes(key string) []byte {
	o, _ := m.get(key)
	return o.data
}

// Corrupt flips one byte of an object.
func (m *Memory) Corrupt(key string, off int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.objects[key]
	d := append([]byte(nil), o.data...)
	d[off] ^= 0xff
	m.objects[key] = memObject{d, o.mod}
}
