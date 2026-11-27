// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Local stores objects as files below a root directory. Sendora uses it with
// the data directory as root, where a share file's key is
// "shares/<share id>/<file name on disk>": exactly the layout of every earlier
// release, so existing data directories need no change.
type Local struct{ root string }

func NewLocal(root string) (*Local, error) {
	if root == "" {
		return nil, errors.New("storage: local root required")
	}
	return &Local{root: filepath.Clean(root)}, nil
}

func (l *Local) Kind() string { return KindLocal }

// Path is the file of key below the root.
func (l *Local) Path(key string) (string, error) {
	if err := validKey(key); err != nil {
		return "", err
	}
	return filepath.Join(l.root, filepath.FromSlash(key)), nil
}

// Put writes to a temporary file in the target directory and renames it into
// place, so a failed or interrupted Put never leaves a partial file under key.
// The directory must exist (share directories are created by the caller).
func (l *Local) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	p, err := l.Path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	rnd := make([]byte, 6)
	rand.Read(rnd)
	tmp := filepath.Join(filepath.Dir(p), ".put-"+hex.EncodeToString(rnd))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := io.Copy(f, ctxReader{ctx, &exactReader{r: r, left: size}}); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	ok = true
	return nil
}

type localObject struct {
	*os.File
	size int64
	mod  time.Time
}

func (o *localObject) Size() int64        { return o.size }
func (o *localObject) ModTime() time.Time { return o.mod }

func (l *Local) Open(_ context.Context, key string) (Object, error) {
	p, err := l.Path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w", ErrNotExist)
		}
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: not a regular file", ErrNotExist)
	}
	return &localObject{File: f, size: st.Size(), mod: st.ModTime()}, nil
}

func (l *Local) Stat(_ context.Context, key string) (Info, error) {
	p, err := l.Path(key)
	if err != nil {
		return Info{}, err
	}
	st, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Info{}, ErrNotExist
		}
		return Info{}, err
	}
	if !st.Mode().IsRegular() {
		return Info{}, ErrNotExist
	}
	return Info{Key: key, Size: st.Size(), ModTime: st.ModTime()}, nil
}

func (l *Local) Delete(_ context.Context, key string) error {
	p, err := l.Path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (l *Local) List(ctx context.Context, prefix string, fn func(Info) error) error {
	start := l.root
	if dir := prefix[:strings.LastIndex(prefix, "/")+1]; dir != "" {
		start = filepath.Join(l.root, filepath.FromSlash(dir))
	}
	err := filepath.WalkDir(start, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(l.root, p)
		if err != nil {
			return nil
		}
		key := filepath.ToSlash(rel)
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		return fn(Info{Key: key, Size: info.Size(), ModTime: info.ModTime()})
	})
	return err
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
