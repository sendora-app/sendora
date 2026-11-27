// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/store"
)

// captureStdout runs fn and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

// auditDB builds an encrypted database holding n audit records, applies tamper
// (SQL; may be empty) and returns its path and key file.
func auditDB(t *testing.T, n int, tamper string) (path, keyFile string, key []byte) {
	t.Helper()
	dir := t.TempDir()
	key = bytes.Repeat([]byte{0x5a}, 32)
	keyFile = filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenEncrypted(filepath.Join(dir, "data"), key, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := st.AuditAppend(store.AuditRecord{Category: "admin", ActorName: "a", ActorRole: "admin", Action: "test_event", Outcome: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if tamper != "" {
		if _, err := st.DB.Exec(tamper); err != nil {
			t.Fatal(tamper, err)
		}
	}
	path = st.Path
	st.DB.Close()
	return
}

func TestAuditVerifyCommand(t *testing.T) {
	cases := []struct {
		name, sql string
		n         int
		broken    int64 // 0 = intact
	}{
		{"intact", "", 12, 0},
		{"empty log", "", 0, 0},
		{"edited", `UPDATE audit_log SET detail='x' WHERE seq=4`, 12, 4},
		{"deleted middle", `DELETE FROM audit_log WHERE seq=5`, 12, 5},
		{"inserted", `INSERT INTO audit_log(seq,ts,category,actor_name,action,prev_hash,hash) VALUES(13,'2026-01-01T00:00:00.000000Z','admin','evil','forged','00','00')`, 12, 13},
		{"swapped", `UPDATE audit_log SET action=CASE seq WHEN 2 THEN 'b' ELSE 'a' END, detail=CASE seq WHEN 2 THEN 'y' ELSE 'x' END WHERE seq IN (2,3)`, 12, 2},
		{"tail removed", `DELETE FROM audit_log WHERE seq>10`, 12, 11},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path, keyFile, key := auditDB(t, c.n, c.sql)
			var runErr error
			out := captureStdout(t, func() {
				runErr = run([]string{"audit-verify", "-source", path, "-key-file", keyFile, "-json"})
			})
			var st store.AuditStatus
			if err := json.Unmarshal([]byte(out), &st); err != nil {
				t.Fatalf("json output %q: %v", out, err)
			}
			if c.broken == 0 {
				if runErr != nil || !st.OK || st.Count != int64(c.n) {
					t.Fatalf("%v %+v", runErr, st)
				}
			} else if runErr == nil || st.OK || st.FirstBroken != c.broken {
				t.Fatalf("want a break at %d: err=%v %+v", c.broken, runErr, st)
			}
			if strings.Contains(out, string(key)) || strings.Contains(out, "5a5a5a5a") {
				t.Fatal("key printed")
			}
			// Text output reports the same and never prints the key.
			text := captureStdout(t, func() {
				runErr = run([]string{"audit-verify", "-source", path, "-key-file", keyFile})
			})
			if (c.broken == 0) != (runErr == nil) || (c.broken != 0 && !strings.Contains(text, "BROKEN")) || strings.Contains(text, "5a5a5a5a") {
				t.Fatalf("%v %q", runErr, text)
			}
		})
	}
}

func TestAuditVerifyCommandAfterPurgeAndErrors(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x5b}, 32)
	keyFile := filepath.Join(dir, "key")
	os.WriteFile(keyFile, key, 0600)
	st, err := store.OpenEncrypted(filepath.Join(dir, "data"), key, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		st.AuditAppend(store.AuditRecord{TS: "2020-01-01T00:00:00.000000Z", Category: "admin", Action: "old", Outcome: "ok"})
	}
	for i := 0; i < 3; i++ {
		st.AuditAppend(store.AuditRecord{Category: "admin", Action: "new", Outcome: "ok"})
	}
	if n, err := st.AuditPurge(time.Now().UTC().AddDate(0, 0, -90)); err != nil || n != 6 {
		t.Fatal(n, err)
	}
	path := st.Path
	st.DB.Close()
	var runErr error
	out := captureStdout(t, func() { runErr = run([]string{"audit-verify", "-source", path, "-key-file", keyFile, "-json"}) })
	var s store.AuditStatus
	if json.Unmarshal([]byte(out), &s) != nil || runErr != nil || !s.OK || s.Count != 3 || s.CheckpointSeq != 6 {
		t.Fatal(out, runErr)
	}
	// Wrong key, missing flags.
	wrong := filepath.Join(dir, "wrong")
	os.WriteFile(wrong, bytes.Repeat([]byte{0x01}, 32), 0600)
	if err := run([]string{"audit-verify", "-source", path, "-key-file", wrong}); err == nil {
		t.Fatal("wrong key must fail")
	}
	if err := run([]string{"audit-verify", "-key-file", keyFile}); err == nil {
		t.Fatal("source required")
	}
}
