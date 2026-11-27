// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func mustIncremental(t *testing.T, st *Store) AuditStatus {
	t.Helper()
	s, err := st.AuditVerifyIncremental(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The incremental check must always give the same answer as a full walk,
// including after tampering with records it has already verified.
func TestAuditIncrementalEqualsFullCheck(t *testing.T) {
	cases := map[string]string{
		"edited row":       `UPDATE audit_log SET detail='changed' WHERE seq=5`,
		"deleted row":      `DELETE FROM audit_log WHERE seq=6`,
		"appended forgery": `INSERT INTO audit_log(seq,ts,category,actor_name,action,prev_hash,hash) SELECT 21,ts,category,'evil','forged',hash,'00' FROM audit_log WHERE seq=20`,
		"gap forgery":      `INSERT INTO audit_log(seq,ts,category,actor_name,action,prev_hash,hash) SELECT 40,ts,category,'evil','forged',hash,'00' FROM audit_log WHERE seq=20`,
		"inserted below":   `INSERT INTO audit_log(seq,ts,category,actor_name,action,prev_hash,hash) VALUES(-1,'x','admin','evil','forged','','00')`,
		"deleted tail":     `DELETE FROM audit_log WHERE seq>=19`,
		"swapped rows":     `UPDATE audit_log SET actor_name=CASE seq WHEN 7 THEN 'u8' WHEN 8 THEN 'u7' END, actor_id=CASE seq WHEN 7 THEN 8 WHEN 8 THEN 7 END WHERE seq IN (7,8)`,
		"reseq":            `UPDATE audit_log SET seq=seq+100 WHERE seq=9`,
		"all deleted":      `DELETE FROM audit_log`,
		"checkpoint":       `UPDATE audit_checkpoint SET last_deleted_seq=3`,
		"sequence lowered": `UPDATE sqlite_sequence SET seq=25 WHERE name='audit_log'`,
		"guard dropped":    `DROP TRIGGER audit_log_guard_update; UPDATE audit_log SET detail='changed' WHERE seq=5`,
		"guard row reset":  `DELETE FROM audit_guard; UPDATE audit_log SET detail='changed' WHERE seq=5`,
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			defer func(n int) { auditVerifyChunk = n }(auditVerifyChunk)
			auditVerifyChunk = 3 // several snapshots per walk
			st := auditTestStore(t)
			auditFill(t, st, 20)
			if s := mustIncremental(t, st); !s.OK || s.Count != 20 {
				t.Fatalf("%+v", s)
			}
			if _, err := st.DB.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			full, inc := mustVerify(t, st), mustIncremental(t, st)
			if full != inc {
				t.Fatalf("incremental %+v differs from full %+v", inc, full)
			}
			if full.OK {
				t.Fatalf("tampering not detected: %+v", full)
			}
			// Records appended afterwards keep both answers equal.
			auditFill(t, st, 2)
			if full, inc := mustVerify(t, st), mustIncremental(t, st); full != inc {
				t.Fatalf("after append: incremental %+v differs from full %+v", inc, full)
			}
		})
	}
}

func TestAuditIncrementalFollowsAppendsAndPurges(t *testing.T) {
	defer func(n int) { auditVerifyChunk = n }(auditVerifyChunk)
	auditVerifyChunk = 7
	st := auditTestStore(t)
	old := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(AuditTimeLayout)
	for i := 0; i < 30; i++ {
		if _, err := st.AuditAppend(AuditRecord{TS: old, Category: "admin", Action: "old", Outcome: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	auditFill(t, st, 20)
	if s := mustIncremental(t, st); !s.OK || s.Count != 50 || s.LastSeq != 50 {
		t.Fatalf("%+v", s)
	}
	// The purge reuses the verified state and moves it with the checkpoint.
	if n, err := st.AuditPurge(time.Now().UTC().AddDate(0, 0, -90)); err != nil || n != 30 {
		t.Fatal(n, err)
	}
	st.auditVer.mu.Lock()
	moved := st.auditVer.w != nil && st.auditVer.cpSeq == 30 && st.auditVer.w.st.Count == 20
	st.auditVer.mu.Unlock()
	if !moved {
		t.Fatal("the verified state was not carried over the purge")
	}
	full, inc := mustVerify(t, st), mustIncremental(t, st)
	if full != inc || !inc.OK || inc.Count != 20 || inc.CheckpointSeq != 30 {
		t.Fatalf("incremental %+v full %+v", inc, full)
	}
	auditFill(t, st, 9)
	if full, inc := mustVerify(t, st), mustIncremental(t, st); full != inc || inc.Count != 29 || inc.LastSeq != 59 {
		t.Fatalf("incremental %+v full %+v", inc, full)
	}
	// A purge of everything leaves an empty verified chain.
	if _, err := st.AuditPurge(time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if full, inc := mustVerify(t, st), mustIncremental(t, st); full != inc || inc.Count != 0 || inc.OldestTS != "" || !inc.OK {
		t.Fatalf("incremental %+v full %+v", inc, full)
	}
}

// A purge consults a verified state that already knows the part to be removed
// is broken.
func TestAuditPurgeRefusedFromVerifiedState(t *testing.T) {
	st := auditTestStore(t)
	old := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(AuditTimeLayout)
	for i := 0; i < 3; i++ {
		st.AuditAppend(AuditRecord{TS: old, Category: "admin", Action: "old", Outcome: "ok"})
	}
	st.DB.Exec(`UPDATE audit_log SET detail='x' WHERE seq=2`)
	if s := mustIncremental(t, st); s.OK {
		t.Fatal("tamper not seen")
	}
	if _, err := st.AuditPurge(time.Now().UTC().AddDate(0, 0, -90)); !errors.Is(err, ErrAuditPurgeRefused) {
		t.Fatalf("want a refused purge, got %v", err)
	}
}

// Verification reads checkpoint, records and sqlite_sequence in one snapshot:
// concurrent appends and purges never produce a false alarm.
func TestAuditVerifyConsistentUnderConcurrentWrites(t *testing.T) {
	defer func(n int) { auditVerifyChunk = n }(auditVerifyChunk)
	auditVerifyChunk = 5
	st := auditTestStore(t)
	old := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(AuditTimeLayout)
	var stop atomic.Bool
	var wg sync.WaitGroup
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				rec := AuditRecord{Category: "admin", ActorName: fmt.Sprint(g), Action: "c", Outcome: "ok"}
				if i%3 == 0 {
					rec.TS = old
				}
				if _, err := st.AuditAppend(rec); err != nil {
					t.Error(err)
					return
				}
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			if _, err := st.AuditPurge(time.Now().UTC().AddDate(0, 0, -90)); err != nil {
				t.Error(err)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	defer func() { stop.Store(true); wg.Wait() }() // writers end before the store closes
	deadline := time.Now().Add(1500 * time.Millisecond)
	checks := 0
	for time.Now().Before(deadline) {
		full, err := st.AuditVerify()
		if err != nil || !full.OK {
			t.Fatalf("false alarm from the full check: %+v %v", full, err)
		}
		inc, err := st.AuditVerifyIncremental(context.Background())
		if err != nil || !inc.OK {
			t.Fatalf("false alarm from the incremental check: %+v %v", inc, err)
		}
		checks++
	}
	stop.Store(true)
	wg.Wait()
	if checks < 5 {
		t.Fatalf("only %d checks ran", checks)
	}
	if full, inc := mustVerify(t, st), mustIncremental(t, st); full != inc || !full.OK {
		t.Fatalf("incremental %+v full %+v", inc, full)
	}
}

func TestAuditRetentionBelowMinimumRaisedByMigration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	key := bytes.Repeat([]byte{0x31}, 32)
	st, err := OpenEncrypted(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("audit_retention_days", "7"); err != nil {
		t.Fatal(err)
	}
	st.DB.Close()
	st, err = OpenEncrypted(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	if v := st.Setting("audit_retention_days"); v != "90" {
		t.Fatalf("retention below the minimum kept: %q", v)
	}
	// Values at or above the minimum are left alone.
	st.SetSetting("audit_retention_days", "120")
	if err := st.migrateAudit(); err != nil {
		t.Fatal(err)
	}
	if v := st.Setting("audit_retention_days"); v != "120" {
		t.Fatalf("valid retention changed: %q", v)
	}
}

func TestClipAuditCutsAtCharacterBoundary(t *testing.T) {
	long := strings.Repeat("é", AuditFieldMax) // 2 bytes each
	got := clipAudit(long)
	if len(got) > AuditFieldMax || !utf8.ValidString(got) || len(got) < AuditFieldMax-1 {
		t.Fatalf("len %d valid %v", len(got), utf8.ValidString(got))
	}
	odd := "a" + strings.Repeat("€", AuditFieldMax) // 3 bytes each after one byte
	if got := clipAudit(odd); len(got) > AuditFieldMax || !utf8.ValidString(got) || len(got) < AuditFieldMax-2 {
		t.Fatalf("len %d", len(got))
	}
	if clipAudit("short\xff") != "short" {
		t.Fatal("invalid UTF-8 must be removed")
	}
}

// The write deadline covers the wait for the append lock.
func TestAuditAppendDeadlineIncludesLockWait(t *testing.T) {
	defer func(d time.Duration) { auditWriteWait = d }(auditWriteWait)
	auditWriteWait = 100 * time.Millisecond
	st := auditTestStore(t)
	if err := st.auditMu.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := st.AuditAppend(AuditRecord{Category: "admin", Action: "x", Outcome: "ok"})
	st.auditMu.unlock()
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
	if _, err := st.AuditAppend(AuditRecord{Category: "admin", Action: "x", Outcome: "ok"}); err != nil {
		t.Fatal(err)
	}
}

// Carrying an empty (fully purged) log keeps the high-water mark, so the next
// record continues the sequence and a removed tail stays detectable.
func TestCarryAuditLogKeepsSequenceOfEmptyLog(t *testing.T) {
	st := auditTestStore(t)
	auditFill(t, st, 5)
	st.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	copyPath := filepath.Join(t.TempDir(), "copy.db")
	if err := ExportDatabase(st.Path, copyPath, st.cipherKey, st.cipherKey); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuditPurge(time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.CarryAuditLog(copyPath); err != nil {
		t.Fatal(err)
	}
	db, err := openCipherDB(copyPath, st.cipherKey, false)
	if err != nil {
		t.Fatal(err)
	}
	var seq int64
	var rows int
	db.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name='audit_log'`).Scan(&seq)
	db.QueryRow(`SELECT COUNT(*) FROM sqlite_sequence WHERE name='audit_log'`).Scan(&rows)
	db.Close()
	if seq != 5 || rows != 1 {
		t.Fatalf("sqlite_sequence after carry: seq=%d rows=%d", seq, rows)
	}
	s, err := VerifyAuditDatabase(copyPath, st.cipherKey)
	if err != nil || !s.OK || s.Count != 0 || s.CheckpointSeq != 5 {
		t.Fatal(s, err)
	}
}
