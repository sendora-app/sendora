// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/store"
)

func TestUpgradeEncryptionCommand(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	keyFile := filepath.Join(dir, "db.key")
	key := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenEncrypted(data, key, true)
	if err != nil {
		t.Fatal(err)
	}
	// Leave what 0.2 would have left: plaintext in an encrypted column, no keys.
	st.DB.Exec(`INSERT INTO storage_locations(backend,identity,config) VALUES('s3','legacy-id','{"secret":"plain-secret"}')`)
	legacyPlaintext(t, st)
	st.DB.Exec(`DROP TABLE control_log`)
	st.DB.Exec(`DROP TABLE tenant_keyring`)
	source := st.Path
	st.Close()

	var out bytes.Buffer
	old := stdout
	stdout = &out
	defer func() { stdout = old }()
	if err := run([]string{"upgrade-encryption", "-source", source, "-data-dir", data, "-key-file", keyFile}); err != nil {
		t.Fatalf("upgrade-encryption: %v", err)
	}
	matches, _ := filepath.Glob(source + ".pre-column-encryption-*")
	if len(matches) != 1 {
		t.Fatalf("expected one safety copy, found %v", matches)
	}
	st, err = store.OpenEncrypted(data, key, false)
	if err != nil {
		t.Fatalf("open after the upgrade: %v", err)
	}
	defer st.Close()
	var raw string
	st.DB.QueryRow(`SELECT config FROM storage_locations WHERE identity='legacy-id'`).Scan(&raw)
	if !strings.HasPrefix(raw, "e1:") || strings.Contains(raw, "plain-secret") {
		t.Fatalf("the table holds %q", raw)
	}
}

// legacyPlaintext writes the sealed setting values and audit columns back as
// plaintext, the state of a database from before column encryption.
func legacyPlaintext(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	rows, err := st.DB.Query(`SELECT key FROM settings WHERE value<>''`)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for rows.Next() {
		var k string
		rows.Scan(&k)
		keys = append(keys, k)
	}
	rows.Close()
	for _, k := range keys {
		v, err := st.Repos().Settings().Get(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.DB.Exec(`UPDATE settings SET value=? WHERE key=?`, v, k); err != nil {
			t.Fatal(err)
		}
	}
	var recs []store.AuditRecord
	if err := st.Repos().AuditChain().All(ctx, func(r store.AuditRecord) error { recs = append(recs, r); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if _, err := st.DB.Exec(`UPDATE audit_log SET actor_name=?,target=?,detail=? WHERE seq=?`, r.ActorName, r.Target, r.Detail, r.Seq); err != nil {
			t.Fatal(err)
		}
	}
}
