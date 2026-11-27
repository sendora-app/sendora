// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/store"
)

func TestRotateKeyCommand(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	keyFile := filepath.Join(dir, "db.key")
	key := bytes.Repeat([]byte{9}, 32)
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenEncrypted(data, key, true)
	if err != nil {
		t.Fatal(err)
	}
	source := st.Path
	st.Close()

	var out bytes.Buffer
	old := stdout
	stdout = &out
	defer func() { stdout = old }()
	for _, p := range []string{"data", "index"} {
		if err := run([]string{"rotate-key", "-purpose", p, "-source", source, "-data-dir", data, "-key-file", keyFile}); err != nil {
			t.Fatalf("rotate-key %s: %v", p, err)
		}
	}
	if !strings.Contains(out.String(), "data key version 2") || !strings.Contains(out.String(), "index key version 2") {
		t.Fatalf("output: %s", out.String())
	}
	if m, _ := filepath.Glob(source + ".pre-key-rotation-*"); len(m) != 2 {
		t.Fatalf("safety copies: %v", m)
	}
	// The database opens with its keys and every setting is on the new version.
	st, err = store.OpenEncrypted(data, key, false)
	if err != nil {
		t.Fatalf("open after the rotation: %v", err)
	}
	defer st.Close()
	if d, i := st.ColumnKeyring().Versions(); d != 2 || i != 2 {
		t.Fatalf("active versions %d/%d, want 2/2", d, i)
	}
	rows, err := st.DB.Query(`SELECT value FROM settings WHERE value LIKE 'e1:%'`)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		var raw string
		rows.Scan(&raw)
		if v, ok := colenc.TextVersion(raw); !ok || v != 2 {
			t.Fatalf("a setting is on version %d", v)
		}
		n++
	}
	rows.Close()
	if n == 0 {
		t.Fatal("no encrypted settings to check")
	}
	// Nothing uses data version 1 any more (no audit records in this database):
	// it retires once, and not again.
	st.Close()
	if err := run([]string{"retire-key", "-purpose", "data", "-version", "1", "-source", source, "-data-dir", data, "-key-file", keyFile}); err != nil {
		t.Fatalf("retire-key data: %v", err)
	}
	if err := run([]string{"retire-key", "-purpose", "data", "-version", "1", "-source", source, "-data-dir", data, "-key-file", keyFile}); err == nil || !strings.Contains(err.Error(), "already retired") {
		t.Fatalf("retiring twice = %v", err)
	}
	if err := run([]string{"retire-key", "-purpose", "data", "-version", "2", "-source", source, "-data-dir", data, "-key-file", keyFile}); err == nil {
		t.Fatal("the active version was retired")
	}
	if err := run([]string{"retire-key", "-purpose", "index", "-version", "1", "-source", source, "-data-dir", data, "-key-file", keyFile}); err != nil {
		t.Fatalf("retire-key index: %v", err)
	}
	if err := run([]string{"rotate-key", "-purpose", "audit-mac", "-source", source, "-data-dir", data, "-key-file", keyFile}); err == nil || !strings.Contains(err.Error(), "audit-mac") {
		t.Fatalf("rotate-key audit-mac = %v, want a refusal", err)
	}
}
