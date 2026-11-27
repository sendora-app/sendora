// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/keyclient"
	"github.com/sendora-app/sendora/internal/keyserver"
	"github.com/sendora-app/sendora/internal/store"
)

func bufStdout(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = old })
	return &buf
}

func TestKEKGenerate(t *testing.T) {
	out := bufStdout(t)
	if err := run([]string{"kek-generate", "-shares", "3-of-5"}); err != nil {
		t.Fatal(err)
	}
	var key, fp string
	var shares []string
	for _, l := range strings.Split(out.String(), "\n") {
		switch {
		case strings.HasPrefix(l, "Key: "):
			key = strings.TrimPrefix(l, "Key: ")
		case strings.HasPrefix(l, "Fingerprint: "):
			fp = strings.TrimPrefix(l, "Fingerprint: ")
		case strings.HasPrefix(l, "Share "):
			shares = append(shares, strings.SplitN(l, ": ", 2)[1])
		}
	}
	raw, err := store.ParseTenantKEK(key)
	if err != nil {
		t.Fatalf("the generated key is not accepted: %v", err)
	}
	if fp != store.TenantKEKFingerprint(raw) || len(shares) != 5 {
		t.Fatalf("fingerprint %q, %d shares", fp, len(shares))
	}
	got, err := colenc.Combine(shares[:3])
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("3 shares do not rebuild the key: %v", err)
	}
	if !strings.Contains(out.String(), "lose") {
		t.Fatal("the output does not warn that losing the key loses the data")
	}
	// Two runs give different keys; bad -shares is refused.
	out.Reset()
	run([]string{"kek-generate"})
	if strings.Contains(out.String(), key) {
		t.Fatal("same key twice")
	}
	for _, bad := range []string{"5-of-3", "x", "1-of-3", "3of5"} {
		if err := run([]string{"kek-generate", "-shares", bad}); err == nil {
			t.Fatalf("-shares %q accepted", bad)
		}
	}
}

type fakeUnlocker struct {
	tenant, kek string
	err         error
}

func (f *fakeUnlocker) Unlock(_ context.Context, tenant, kek string) (keyserver.Response, error) {
	f.tenant, f.kek = tenant, kek
	return keyserver.Response{Fingerprint: "abcd"}, f.err
}
func (f *fakeUnlocker) Close() error { return nil }

func TestTenantUnlock(t *testing.T) {
	out := bufStdout(t)
	f := &fakeUnlocker{}
	old := newKEKClient
	newKEKClient = func(keyclient.Config) (kekUnlocker, error) { return f, nil }
	defer func() { newKEKClient = old }()
	tok := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tok, []byte("t"), 0o600)
	base := []string{"tenant-unlock", "-tenant", "abcdefghijklmnopqrstuvwxyz", "-url", "https://x:8443", "-token-file", tok}

	raw := bytes.Repeat([]byte{0}, 32)
	for i := range raw {
		raw[i] = byte(i*7 + 3)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	dir := t.TempDir()
	textFile, rawFile := filepath.Join(dir, "k.txt"), filepath.Join(dir, "k.bin")
	os.WriteFile(textFile, []byte(b64+"\n"), 0o600)
	os.WriteFile(rawFile, raw, 0o600)
	shares, _ := colenc.Split(raw, 3, 5)

	for name, extra := range map[string][]string{
		"text file":  {"-kek-file", textFile},
		"raw file":   {"-kek-file", rawFile},
		"shares":     {"-shares", strings.Join(shares[:3], ",")},
		"other 3 of": {"-shares", strings.Join(shares[2:], ",")},
	} {
		out.Reset()
		f.tenant, f.kek = "", ""
		if err := run(append(append([]string{}, base...), extra...)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if f.kek != b64 || f.tenant != "abcdefghijklmnopqrstuvwxyz" {
			t.Fatalf("%s: presented %q for %q", name, f.kek, f.tenant)
		}
		if !strings.Contains(out.String(), "unlocked") || strings.Contains(out.String(), b64) {
			t.Fatalf("%s: output %q", name, out.String())
		}
	}
	// Refusals: no key, both, too few shares, weak key, bad tenant, controller error.
	for name, args := range map[string][]string{
		"no key":      base,
		"both":        append(append([]string{}, base...), "-kek-file", textFile, "-shares", shares[0]),
		"few shares":  append(append([]string{}, base...), "-shares", strings.Join(shares[:2], ",")),
		"bad tenant":  {"tenant-unlock", "-tenant", "../x", "-kek-file", textFile},
		"no endpoint": {"tenant-unlock", "-tenant", "abcdefghijklmnopqrstuvwxyz", "-kek-file", textFile, "-url", ""},
	} {
		if err := run(args); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	weak := filepath.Join(dir, "weak")
	os.WriteFile(weak, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))), 0o600)
	if err := run(append(append([]string{}, base...), "-kek-file", weak)); err == nil {
		t.Fatal("a weak key was presented")
	}
	f.err = keyclient.ErrKEKRefused
	err := run(append(append([]string{}, base...), "-kek-file", textFile))
	if !errors.Is(err, keyclient.ErrKEKRefused) {
		t.Fatalf("refused key: %v", err)
	}
}
