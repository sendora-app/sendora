// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/ports"
)

// The audit log's free-text columns and every setting value are encrypted
// columns. The hash chain stays computed over the plaintext, so verification
// (live, incremental and offline) works on the opened values.

func rawAudit(t *testing.T, st *Store, seq int64, column string) string {
	t.Helper()
	v, err := st.Repos().(interface {
		RawColumn(ctx context.Context, table, column, key string) (string, error)
	}).RawColumn(context.Background(), "audit_log", column, strconv.FormatInt(seq, 10))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAuditColumnsAreSealedAndTheChainVerifies(t *testing.T) {
	key := colKey(0x41)
	dir := filepath.Join(t.TempDir(), "data")
	st, err := OpenEncrypted(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	auditFill(t, st, 6)
	for _, col := range []string{"actor_name", "target", "detail"} {
		if v := rawAudit(t, st, 3, col); !strings.HasPrefix(v, "e1:") {
			t.Fatalf("audit_log.%s holds %q, want ciphertext", col, v)
		}
	}
	// The plaintext columns stay searchable in the table.
	var action string
	if err := st.DB.QueryRow(`SELECT action FROM audit_log WHERE seq=3`).Scan(&action); err != nil || action != "test_event" {
		t.Fatalf("action = %q, %v", action, err)
	}
	s, err := st.AuditVerify()
	if err != nil || !s.OK || s.Count != 6 {
		t.Fatalf("verify: %+v, %v", s, err)
	}
	if s, err = st.AuditVerifyIncremental(context.Background()); err != nil || !s.OK {
		t.Fatalf("incremental verify: %+v, %v", s, err)
	}
	// Search by actor, target and detail on the opened values.
	q := st.Repos().AuditQuery()
	for filter, want := range map[string]int{"u3": 1, "t5": 1, "test_event": 6} {
		got, err := q.Find(context.Background(), ports.AuditFilter{Terms: []string{filter}}, true, 0, 0)
		if err != nil || len(got) != want {
			t.Fatalf("search %q: %d records, %v, want %d", filter, len(got), err, want)
		}
	}
	if got, err := q.Find(context.Background(), ports.AuditFilter{Actor: "U2"}, true, 0, 0); err != nil || len(got) != 1 || got[0].Target != "t2" || got[0].Detail != "d" {
		t.Fatalf("actor search: %+v, %v", got, err)
	}
	path := st.Path
	st.Close()

	// The offline verifier opens the sealed columns with the database's keys.
	if s, err = VerifyAuditDatabase(path, key); err != nil || !s.OK || s.Count != 6 {
		t.Fatalf("offline verify: %+v, %v", s, err)
	}
	st, err = OpenEncrypted(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	// A new record continues the chain after a restart.
	auditFill(t, st, 1)
	if s, err = st.AuditVerify(); err != nil || !s.OK || s.Count != 7 {
		t.Fatalf("verify after a restart: %+v, %v", s, err)
	}
	// Moving a ciphertext to another record, and writing plaintext into a
	// sealed column, are tampering the chain reports at that record.
	raw := st.Repos().(interface {
		RawSetColumn(ctx context.Context, table, column, key, value string) error
	})
	if err := raw.RawSetColumn(context.Background(), "audit_log", "target", "2", rawAudit(t, st, 5, "target")); err != nil {
		t.Fatal(err)
	}
	if s, err = st.AuditVerify(); err != nil || s.OK || s.FirstBroken != 2 {
		t.Fatalf("a moved ciphertext: %+v, %v", s, err)
	}
	st.Close()
	if s, err = VerifyAuditDatabase(path, key); err != nil || s.OK || s.FirstBroken != 2 {
		t.Fatalf("offline, a moved ciphertext: %+v, %v", s, err)
	}
}

func TestSettingsAreSealedAndMigrationsKeepWorking(t *testing.T) {
	key := colKey(0x42)
	dir := filepath.Join(t.TempDir(), "data")
	st, err := OpenEncrypted(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := func() int {
		var n int
		if err := st.DB.QueryRow(`SELECT COUNT(*) FROM settings WHERE value<>'' AND value NOT LIKE 'e1:%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	var total int
	st.DB.QueryRow(`SELECT COUNT(*) FROM settings WHERE value<>''`).Scan(&total)
	if total < 50 || plaintext() != 0 {
		t.Fatalf("a new database holds %d values, %d of them plaintext (seed and migrations seal them)", total, plaintext())
	}
	if st.Setting("application_name") != "Sendora" || st.Setting(SettingPasswordMaxAgeDays) != "365" || st.Setting(DefaultStorageQuotaKey) == "" {
		t.Fatal("the sealed defaults do not read back")
	}
	// The migrations that compare values do it on the opened value: a retention
	// below the minimum and a minimum password length below the floor are
	// raised, higher values stay, and the next start finds the values sealed.
	st.SetSetting("audit_retention_days", "30")
	st.SetSetting("account_password_min_length", "4")
	st.SetSetting("smtp_reply_to", "<noreply@example.org>")
	st.SetSetting("ui_application_note", "kept")
	st.Close()
	st, err = OpenEncrypted(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Setting("audit_retention_days") != "90" || st.Setting("account_password_min_length") != "8" {
		t.Fatalf("not raised: %q %q", st.Setting("audit_retention_days"), st.Setting("account_password_min_length"))
	}
	if st.Setting("smtp_reply_to") != "noreply@example.org" || st.Setting("ui_application_note") != "kept" {
		t.Fatalf("reply-to = %q, note = %q", st.Setting("smtp_reply_to"), st.Setting("ui_application_note"))
	}
	st.SetSetting("audit_retention_days", "120")
	st.SetSetting("application_name", "Acme")
	st.Close()
	st, err = OpenEncrypted(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.Setting("audit_retention_days") != "120" || st.Setting("application_name") != "Acme" {
		t.Fatal("a restart changed a stored value")
	}
	if n := plaintext(); n != 0 {
		t.Fatalf("%d plaintext values after the restarts", n)
	}

	// The compare-and-set of the mail migration: an untouched historical
	// default is replaced, a customised template stays.
	oldSubject, _ := legacyMailDefaults("share_downloaded", "en")
	_, oldBody := legacyMailDefaults("share_downloaded", "nl")
	st.SetSetting("subj_share_downloaded_en", oldSubject)
	st.SetSetting("tpl_share_downloaded_nl", oldBody)
	st.SetSetting("tpl_share_downloaded_en", "my own text")
	if err := st.migrateMailLocalization(); err != nil {
		t.Fatal(err)
	}
	subject, _ := MailDefaults("share_downloaded", "en")
	_, body := MailDefaults("share_downloaded", "nl")
	if got := st.Setting("subj_share_downloaded_en"); got != subject {
		t.Fatalf("the untouched historical subject = %q", got)
	}
	if got := st.Setting("tpl_share_downloaded_nl"); got != body {
		t.Fatalf("the untouched historical body = %q", got)
	}
	if got := st.Setting("tpl_share_downloaded_en"); got != "my own text" {
		t.Fatalf("a customised template was replaced: %q", got)
	}
	if n := plaintext(); n != 0 {
		t.Fatalf("%d plaintext values after the mail migration", n)
	}
	// Re-keying the database re-keys the settings and audit columns too.
	auditFill(t, st, 2)
	dst, key2 := filepath.Join(t.TempDir(), "copy.db"), colKey(0x43)
	if err := ExportDatabase(st.Path, dst, key, key2); err != nil {
		t.Fatalf("export: %v", err)
	}
	// The chain key stays the root the log was written with.
	if s, err := VerifyAuditDatabaseRoot(dst, key2, key); err != nil || !s.OK || s.Count != 2 {
		t.Fatalf("the copy's audit log: %+v, %v", s, err)
	}
	cp, err := openCipherDB(dst, key2, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	var sealed, other int
	cp.QueryRow(`SELECT COUNT(*) FROM settings WHERE value LIKE 'e1:%'`).Scan(&sealed)
	cp.QueryRow(`SELECT COUNT(*) FROM settings WHERE value<>'' AND value NOT LIKE 'e1:%'`).Scan(&other)
	if sealed < 50 || other != 0 {
		t.Fatalf("the copy holds %d sealed and %d plaintext values", sealed, other)
	}
}
