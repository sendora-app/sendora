// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type breakingBody struct {
	r       io.Reader
	breakAt int
	n       int
}

func (b *breakingBody) Read(p []byte) (int, error) {
	if b.breakAt >= 0 && b.n >= b.breakAt {
		return 0, errors.New("connection reset")
	}
	if b.breakAt >= 0 && len(p) > b.breakAt-b.n {
		p = p[:b.breakAt-b.n]
	}
	n, err := b.r.Read(p)
	b.n += n
	return n, err
}
func (b *breakingBody) Close() error { return nil }

func TestRemoteObjectStreamsAndRecovers(t *testing.T) {
	data := make([]byte, 300_000)
	for i := range data {
		data[i] = byte(i * 7)
	}
	opens := 0
	breakNext := -1
	o := newRemoteObject(context.Background(), int64(len(data)), time.Now(), func(_ context.Context, off int64) (io.ReadCloser, error) {
		opens++
		b := &breakingBody{r: bytes.NewReader(data[off:]), breakAt: breakNext}
		breakNext = -1
		return b, nil
	})
	defer o.Close()
	buf := make([]byte, 65_552)
	// Sequential reads use one stream.
	for off := int64(0); off < int64(len(data)); off += int64(len(buf)) {
		n, err := o.ReadAt(buf, off)
		if !bytes.Equal(buf[:n], data[off:off+int64(n)]) {
			t.Fatalf("content differs at %d", off)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	}
	if opens != 1 {
		t.Fatalf("sequential read opened %d streams, want 1", opens)
	}
	// A jump reopens at the new offset.
	if _, err := o.ReadAt(buf[:10], 5); err != nil || !bytes.Equal(buf[:10], data[5:15]) {
		t.Fatal("jump read", err)
	}
	if opens != 2 {
		t.Fatalf("opens %d, want 2", opens)
	}
	// A stream that breaks mid-read is reopened once.
	breakNext = 1000
	if n, err := o.ReadAt(buf, 100_000); err != nil || n != len(buf) || !bytes.Equal(buf, data[100_000:100_000+len(buf)]) {
		t.Fatalf("recovered read: n=%d err=%v", n, err)
	}
	if opens != 4 {
		t.Fatalf("opens %d, want 4", opens)
	}
}

func TestExactReader(t *testing.T) {
	for _, tc := range []struct {
		src  string
		size int64
		ok   bool
	}{{"abc", 3, true}, {"ab", 3, false}, {"abcd", 3, false}, {"", 0, true}} {
		_, err := io.ReadAll(&exactReader{r: bytes.NewReader([]byte(tc.src)), left: tc.size})
		if (err == nil) != tc.ok {
			t.Errorf("%q/%d: %v", tc.src, tc.size, err)
		}
	}
}
