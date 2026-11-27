// SPDX-License-Identifier: AGPL-3.0-or-later

package storagetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/storage"
)

// Options tunes Run for a backend.
type Options struct {
	// Large is the size of the multipart/large object test (0 = 20 MiB).
	Large int
}

type failingReader struct {
	r     io.Reader
	after int
	read  int
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.read >= f.after {
		return 0, errors.New("source failed")
	}
	if len(p) > f.after-f.read {
		p = p[:f.after-f.read]
	}
	n, err := f.r.Read(p)
	f.read += n
	return n, err
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// Run checks the storage.Backend contract against b. Keys are written under a
// unique folder and removed again.
func Run(t *testing.T, b storage.Backend, opt Options) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	base := "conformance/" + time.Now().UTC().Format("20060102T150405") + "-" + strings.ToLower(storageHex(4)) + "/"
	t.Cleanup(func() { storage.DeletePrefix(context.Background(), b, base) })

	t.Run("probe", func(t *testing.T) {
		if err := storage.Probe(ctx, b); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("put-open-stat-delete", func(t *testing.T) {
		data := random(200_000)
		key := base + "a.bin"
		if err := b.Put(ctx, key, bytes.NewReader(data), int64(len(data))); err != nil {
			t.Fatal(err)
		}
		info, err := b.Stat(ctx, key)
		if err != nil || info.Size != int64(len(data)) || info.Key != key {
			t.Fatalf("stat: %+v %v", info, err)
		}
		obj, err := b.Open(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if obj.Size() != int64(len(data)) {
			t.Fatalf("size %d", obj.Size())
		}
		// Sequential reads, a jump back, a read past the end.
		buf := make([]byte, 65_552)
		for _, off := range []int64{0, 65_552, 131_104, 10, 199_990} {
			n, err := obj.ReadAt(buf, off)
			want := data[off:min(int(off)+len(buf), len(data))]
			if n != len(want) || !bytes.Equal(buf[:n], want) {
				t.Fatalf("ReadAt(%d): n=%d err=%v", off, n, err)
			}
			if n < len(buf) && !errors.Is(err, io.EOF) {
				t.Fatalf("ReadAt(%d) short without EOF: %v", off, err)
			}
		}
		if n, err := obj.ReadAt(buf, int64(len(data))); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt(end): %d %v", n, err)
		}
		obj.Close()
		// Replacing an object.
		data2 := random(1000)
		if err := b.Put(ctx, key, bytes.NewReader(data2), int64(len(data2))); err != nil {
			t.Fatal(err)
		}
		obj, err = b.Open(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(io.NewSectionReader(obj, 0, obj.Size()))
		obj.Close()
		if !bytes.Equal(got, data2) {
			t.Fatal("replace: content differs")
		}
		if err := b.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Stat(ctx, key); !errors.Is(err, storage.ErrNotExist) {
			t.Fatalf("stat after delete: %v", err)
		}
		if _, err := b.Open(ctx, key); !errors.Is(err, storage.ErrNotExist) {
			t.Fatalf("open after delete: %v", err)
		}
		if err := b.Delete(ctx, key); err != nil {
			t.Fatalf("deleting a missing object: %v", err)
		}
	})

	t.Run("empty-object", func(t *testing.T) {
		key := base + "empty"
		if err := b.Put(ctx, key, bytes.NewReader(nil), 0); err != nil {
			t.Fatal(err)
		}
		obj, err := b.Open(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if obj.Size() != 0 {
			t.Fatalf("size %d", obj.Size())
		}
		if n, err := obj.ReadAt(make([]byte, 4), 0); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt: %d %v", n, err)
		}
		obj.Close()
	})

	t.Run("large", func(t *testing.T) {
		size := opt.Large
		if size == 0 {
			size = 20 << 20
		}
		data := random(size)
		key := base + "large.bin"
		if err := b.Put(ctx, key, bytes.NewReader(data), int64(size)); err != nil {
			t.Fatal(err)
		}
		obj, err := b.Open(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.NewSectionReader(obj, 0, obj.Size()))
		obj.Close()
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("large object differs (%d bytes, %v)", len(got), err)
		}
	})

	t.Run("failed-put-leaves-nothing", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			src   io.Reader
			size  int64
			total int
		}{
			{"source-error", &failingReader{r: bytes.NewReader(random(1 << 20)), after: 300_000}, 1 << 20, 0},
			{"source-short", bytes.NewReader(random(1000)), 2000, 0},
			{"source-long", bytes.NewReader(random(3000)), 2000, 0},
			{"multipart-source-error", &failingReader{r: bytes.NewReader(random(20 << 20)), after: 12 << 20}, 20 << 20, 0},
		} {
			key := base + "fail-" + tc.name
			if err := b.Put(ctx, key, tc.src, tc.size); err == nil {
				t.Fatalf("%s: Put succeeded", tc.name)
			}
			if _, err := b.Stat(ctx, key); !errors.Is(err, storage.ErrNotExist) {
				t.Fatalf("%s: object exists after a failed Put: %v", tc.name, err)
			}
		}
	})

	t.Run("list-and-prefix-delete", func(t *testing.T) {
		dir := base + "list/"
		want := []string{dir + "x/1", dir + "x/2", dir + "y"}
		for _, k := range want {
			if err := b.Put(ctx, k, strings.NewReader("abc"), 3); err != nil {
				t.Fatal(err)
			}
		}
		var got []string
		if err := b.List(ctx, dir, func(i storage.Info) error {
			if i.Size != 3 {
				t.Errorf("%s: size %d", i.Key, i.Size)
			}
			got = append(got, i.Key)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("list: %v", got)
		}
		var sub []string
		b.List(ctx, dir+"x/", func(i storage.Info) error { sub = append(sub, i.Key); return nil })
		if len(sub) != 2 {
			t.Fatalf("sub list: %v", sub)
		}
		n, err := storage.DeletePrefix(ctx, b, dir)
		if err != nil || n != 3 {
			t.Fatalf("delete prefix: %d %v", n, err)
		}
		left := 0
		b.List(ctx, dir, func(storage.Info) error { left++; return nil })
		if left != 0 {
			t.Fatalf("%d objects left", left)
		}
	})

	t.Run("invalid-keys", func(t *testing.T) {
		for _, k := range []string{"", "/abs", "a/../b", "a//b", "a\\b", "sp ace"} {
			if err := b.Put(ctx, k, strings.NewReader("x"), 1); err == nil {
				t.Fatalf("key %q accepted", k)
			}
		}
	})
}

func storageHex(n int) string {
	const digits = "0123456789abcdef"
	b := random(n)
	out := make([]byte, 0, 2*n)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
