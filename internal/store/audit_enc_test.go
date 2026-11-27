// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"testing"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/ports"
)

// The audit log's text fields are sealed under the audit-enc key: rotating
// data does not touch them, a data version is retirable although audit rows
// exist, rotating audit-enc keeps old records readable and verifiable, and a
// re-keyed copy carries the audit-enc key.
func TestAuditTextIsSealedUnderAuditEnc(t *testing.T) {
	e := newVFEnv(t)
	ctx := context.Background()
	appendN := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := e.st.AuditAppend(AuditRecord{Category: "admin", ActorName: "Alice Secret", ActorRole: "admin", Action: "x", Target: "target-t", Outcome: "ok", Detail: "detail-d"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	detailVersion := func(seq int64) int {
		t.Helper()
		var v string
		if err := e.st.DB.QueryRow(`SELECT detail FROM audit_log WHERE seq=?`, seq).Scan(&v); err != nil {
			t.Fatal(err)
		}
		n, ok := colenc.TextVersion(v)
		if !ok {
			t.Fatalf("audit_log.detail of %d holds %q", seq, v)
		}
		return n
	}
	appendN(3)
	eng := e.engine(t)

	// Counted against audit-enc, not data.
	counts, err := eng.Store.ColumnKeys().ColumnVersions(ctx)
	if err != nil || counts.Audit[1] == 0 {
		t.Fatalf("ColumnVersions = %+v, %v", counts, err)
	}
	status, err := eng.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range status.Purposes {
		for _, v := range p.Versions {
			if p.Purpose == keyring.PurposeAuditEnc && v.Version == 1 && v.AuditRows == 0 {
				t.Fatalf("audit-enc v1 shows no rows in use: %+v", v)
			}
			if p.Purpose == keyring.PurposeData && v.AuditRows != 0 {
				t.Fatalf("data v%d counts audit rows: %+v", v.Version, v)
			}
		}
	}

	// Rotate data (job) and retire v1: audit rows do not block it.
	if _, err := eng.Execute(ctx, ports.KeyJob{Op: ports.KeyJobRotate, Purpose: keyring.PurposeData}); err != nil {
		t.Fatal(err)
	}
	if v := detailVersion(1); v != 1 {
		t.Fatalf("a data rotation moved an audit row to version %d", v)
	}
	if _, err := eng.Execute(ctx, ports.KeyJob{Op: ports.KeyJobRetire, Purpose: keyring.PurposeData, Version: 1}); err != nil {
		t.Fatalf("retiring data v1: %v", err)
	}
	appendN(1)
	if s, err := e.st.AuditVerify(); err != nil || !s.OK {
		t.Fatalf("audit chain after retiring data v1: %+v, %v", s, err)
	}

	// Rotate audit-enc: old rows stay readable and on version 1, v1 is kept.
	res, err := eng.Execute(ctx, ports.KeyJob{Op: ports.KeyJobRotate, Purpose: keyring.PurposeAuditEnc})
	if err != nil || res.Version != 2 {
		t.Fatalf("rotate audit-enc: %+v, %v", res, err)
	}
	appendN(2)
	if v1, v5 := detailVersion(1), detailVersion(5); v1 != 1 || v5 != 2 {
		t.Fatalf("audit rows on versions %d (old) and %d (new), want 1 and 2", v1, v5)
	}
	if err := eng.CheckRetire(ctx, keyring.PurposeAuditEnc, 1); err == nil {
		t.Fatal("audit-enc v1 is retirable while audit rows use it")
	}
	if s, err := e.st.AuditVerify(); err != nil || !s.OK || s.Count != 6 {
		t.Fatalf("audit chain after rotating audit-enc: %+v, %v", s, err)
	}

	// A re-keyed copy carries the audit-enc DEK (both versions) and verifies.
	e.st.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	key2 := bytes.Repeat([]byte{0x78}, 32)
	dst := e.dir + "/rekeyed-audit-enc.db"
	if err := ExportDatabase(e.st.Path, dst, e.key, key2); err != nil {
		t.Fatal(err)
	}
	if s, err := VerifyAuditDatabaseRoot(dst, key2, e.key); err != nil || !s.OK || s.Count != 6 {
		t.Fatalf("copy's audit chain: %+v, %v", s, err)
	}
	db, err := openCipherDB(dst, key2, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc, _, err := columnServiceFor(db, key2)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := svc.Verify(ctx, ColumnKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if ks.Active[keyring.PurposeAuditEnc] != 2 || ks.States[keyring.PurposeAuditEnc][1] != keyring.StateDecryptOnly {
		t.Fatalf("the copy's audit-enc keys: active %v, states %v", ks.Active, ks.States[keyring.PurposeAuditEnc])
	}
}
