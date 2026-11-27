// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func auditTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenEncrypted(filepath.Join(t.TempDir(), "data"), bytes.Repeat([]byte{0x31}, 32), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	return st
}

func auditFill(t *testing.T, st *Store, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if _, err := st.AuditAppend(AuditRecord{Category: "admin", ActorID: int64(i), ActorName: fmt.Sprintf("u%d", i), ActorRole: "admin",
			Action: "test_event", Target: fmt.Sprintf("t%d", i), Outcome: "ok", Detail: "d"}); err != nil {
			t.Fatal(err)
		}
	}
}

func mustVerify(t *testing.T, st *Store) AuditStatus {
	t.Helper()
	s, err := st.AuditVerify()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAuditChainValid(t *testing.T) {
	st := auditTestStore(t)
	if s := mustVerify(t, st); !s.OK || s.Count != 0 {
		t.Fatalf("empty chain: %+v", s)
	}
	auditFill(t, st, 20)
	s := mustVerify(t, st)
	if !s.OK || s.Count != 20 || s.LastSeq != 20 || s.OldestTS == "" {
		t.Fatalf("%+v", s)
	}
	var prev, hash string
	rows, err := st.DB.Query(`SELECT prev_hash,hash FROM audit_log ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	first := true
	for rows.Next() {
		var p, h string
		rows.Scan(&p, &h)
		if first && p != AuditGenesisHash {
			t.Fatal("genesis prev_hash")
		}
		if !first && p != hash {
			t.Fatal("chain link")
		}
		first, prev, hash = false, p, h
	}
	_ = prev
}

func TestAuditTamperDetected(t *testing.T) {
	cases := map[string]struct {
		sql    string
		broken int64
	}{
		"edited row":   {`UPDATE audit_log SET detail='changed' WHERE seq=5`, 5},
		"deleted row":  {`DELETE FROM audit_log WHERE seq=6`, 6},
		"inserted row": {`INSERT INTO audit_log(seq,ts,category,actor_name,action,prev_hash,hash) SELECT 21,ts,category,'evil','forged',hash,'00' FROM audit_log WHERE seq=10`, 21},
		"deleted tail": {`DELETE FROM audit_log WHERE seq>=19`, 19},
		"swapped rows": {`UPDATE audit_log SET actor_name=CASE seq WHEN 7 THEN 'u8' WHEN 8 THEN 'u7' END, actor_id=CASE seq WHEN 7 THEN 8 WHEN 8 THEN 7 END WHERE seq IN (7,8)`, 7},
		"reseq":        {`UPDATE audit_log SET seq=seq+100 WHERE seq=9`, 9},
		"all deleted":  {`DELETE FROM audit_log`, 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			st := auditTestStore(t)
			auditFill(t, st, 20)
			if _, err := st.DB.Exec(c.sql); err != nil {
				t.Fatal(err)
			}
			s := mustVerify(t, st)
			if s.OK || s.FirstBroken != c.broken {
				t.Fatalf("want first broken %d, got %+v", c.broken, s)
			}
		})
	}
}

func TestAuditPurgeKeepsChainVerifiable(t *testing.T) {
	st := auditTestStore(t)
	old := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(AuditTimeLayout)
	for i := 0; i < 5; i++ {
		if _, err := st.AuditAppend(AuditRecord{TS: old, Category: "admin", Action: "old", Outcome: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	auditFill(t, st, 5)
	n, err := st.AuditPurge(time.Now().UTC().AddDate(0, 0, -90))
	if err != nil || n != 5 {
		t.Fatal(n, err)
	}
	s := mustVerify(t, st)
	if !s.OK || s.Count != 5 || s.CheckpointSeq != 5 || s.CheckpointHash == "" {
		t.Fatalf("%+v", s)
	}
	// New records continue after the checkpoint.
	auditFill(t, st, 2)
	if s := mustVerify(t, st); !s.OK || s.LastSeq != 12 {
		t.Fatalf("%+v", s)
	}
	// Purging everything leaves an empty but verifiable chain.
	if n, err := st.AuditPurge(time.Now().UTC().Add(time.Hour)); err != nil || n != 7 {
		t.Fatal(n, err)
	}
	if s := mustVerify(t, st); !s.OK || s.Count != 0 || s.CheckpointSeq != 12 {
		t.Fatalf("%+v", s)
	}
	auditFill(t, st, 1)
	if s := mustVerify(t, st); !s.OK || s.LastSeq != 13 {
		t.Fatalf("%+v", s)
	}
	// A forged checkpoint (to hide removed records) is detected.
	if _, err := st.DB.Exec(`UPDATE audit_checkpoint SET last_deleted_seq=11`); err != nil {
		t.Fatal(err)
	}
	if s := mustVerify(t, st); s.OK {
		t.Fatal("forged checkpoint not detected")
	}
}

func TestAuditPurgeRefusedWhenBroken(t *testing.T) {
	st := auditTestStore(t)
	old := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(AuditTimeLayout)
	for i := 0; i < 3; i++ {
		st.AuditAppend(AuditRecord{TS: old, Category: "admin", Action: "old", Outcome: "ok"})
	}
	st.DB.Exec(`UPDATE audit_log SET detail='x' WHERE seq=2`)
	if _, err := st.AuditPurge(time.Now().UTC().AddDate(0, 0, -90)); err == nil {
		t.Fatal("purge must not destroy evidence of tampering")
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
	if n != 3 {
		t.Fatal(n)
	}
}

func TestAuditConcurrentWritersKeepChain(t *testing.T) {
	st := auditTestStore(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if _, err := st.AuditAppend(AuditRecord{Category: "admin", ActorName: fmt.Sprint(g), Action: "c", Outcome: "ok"}); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
	if s := mustVerify(t, st); !s.OK || s.Count != 200 {
		t.Fatalf("%+v", s)
	}
}

func TestAuditKeyDoesNotLeakAndFingerprint(t *testing.T) {
	st := auditTestStore(t)
	key := bytes.Repeat([]byte{0x31}, 32)
	fp := st.KeyFingerprint()
	if len(fp) != 16 || bytes.Contains([]byte(fp), key[:4]) {
		t.Fatal(fp)
	}
	if fp != KeyFingerprint(key) || fp == KeyFingerprint(bytes.Repeat([]byte{0x32}, 32)) {
		t.Fatal("fingerprint must be stable and key dependent")
	}
	mac := st.AuditMAC()
	if bytes.Equal(mac([]byte("x")), auditMAC(bytes.Repeat([]byte{0x32}, 32))([]byte("x"))) {
		t.Fatal("different keys must give different MACs")
	}
}

func TestAuditMigrationDropsEventLogAndSettings(t *testing.T) {
	st := auditTestStore(t)
	st.DB.Exec(`CREATE TABLE event_log (id INTEGER)`)
	st.DB.Exec(`INSERT INTO settings(key,value,grp) VALUES('logging_enabled','true','system'),('log_retention_hours','5','system')`)
	if err := st.migrateAudit(); err != nil {
		t.Fatal(err)
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='event_log'`).Scan(&n)
	if n != 0 {
		t.Fatal("event_log kept")
	}
	st.DB.QueryRow(`SELECT COUNT(*) FROM settings WHERE key IN ('logging_enabled','log_retention_hours')`).Scan(&n)
	if n != 0 {
		t.Fatal("old settings kept")
	}
	if st.Setting("audit_retention_days") != "90" || st.Setting("audit_log_ip") != "false" {
		t.Fatal("defaults", st.Setting("audit_retention_days"), st.Setting("audit_log_ip"))
	}
}

func TestVerifyAuditDatabaseFile(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x44}, 32)
	st, err := OpenEncrypted(filepath.Join(dir, "data"), key, true)
	if err != nil {
		t.Fatal(err)
	}
	auditFill(t, st, 6)
	path := st.Path
	st.DB.Exec(`UPDATE audit_log SET action='tampered' WHERE seq=3`)
	st.DB.Close()
	s, err := VerifyAuditDatabase(path, key)
	if err != nil || s.OK || s.FirstBroken != 3 {
		t.Fatal(s, err)
	}
	if _, err := VerifyAuditDatabase(path, bytes.Repeat([]byte{0x45}, 32)); err == nil {
		t.Fatal("wrong key must fail")
	}
}

func TestCarryAuditLogIntoImport(t *testing.T) {
	// The copy is a backup of this installation (same keyring, so the same
	// audit-mac key) taken when the log was shorter.
	st := auditTestStore(t)
	auditFill(t, st, 2)
	st.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	copyPath := filepath.Join(t.TempDir(), "copy.db")
	if err := ExportDatabase(st.Path, copyPath, st.cipherKey, st.cipherKey); err != nil {
		t.Fatal(err)
	}
	auditFill(t, st, 2)
	if err := st.CarryAuditLog(copyPath); err != nil {
		t.Fatal(err)
	}
	s, err := VerifyAuditDatabase(copyPath, st.cipherKey)
	if err != nil || !s.OK || s.Count != 4 || s.LastSeq != 4 {
		t.Fatal(s, err)
	}
}
