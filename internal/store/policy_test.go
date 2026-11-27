// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"math"
	"path/filepath"
	"testing"

	"github.com/sendora-app/sendora/internal/ports"
)

func legacyPolicyStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return &Store{DB: db}
}

func policyExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.DB.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyMigrationBackfillAndDefaults(t *testing.T) {
	s := legacyPolicyStore(t)
	policyExec(t, s, `INSERT INTO users(id,username,is_guest) VALUES(1,'owner',0),(2,'guest',1)`)
	policyExec(t, s, `INSERT INTO reverse_invites(id,token,user_id,guest_user_id,expires_at) VALUES(1,'invite',1,2,datetime('now','+1 day'))`)
	policyExec(t, s, `INSERT INTO upload_sessions(id,user_id,invite_id) VALUES('normal',1,NULL),('reverse',2,1)`)
	policyExec(t, s, `INSERT INTO upload_files(session_id,idx,name,full_path,size,received) VALUES('normal',0,'a','a',3,1),('reverse',0,'b','b',7,0)`)
	if err := migratePolicyAll(s); err != nil {
		t.Fatal(err)
	}
	if err := migratePolicyAll(s); err != nil {
		t.Fatal("idempotency:", err)
	}
	for _, id := range []string{"normal", "reverse"} {
		var owner int64
		if err := s.DB.QueryRow(`SELECT quota_owner_id FROM upload_sessions WHERE id=?`, id).Scan(&owner); err != nil || owner != 1 {
			t.Fatalf("%s owner=%d err=%v", id, owner, err)
		}
	}
	var quota, failures, locked int64
	if err := s.DB.QueryRow(`SELECT quota_bytes,login_failures,login_locked_until FROM users WHERE id=1`).Scan(&quota, &failures, &locked); err != nil || quota != LegacyQuotaBytes || failures != 0 || locked != 0 {
		t.Fatalf("defaults %d %d %d %v", quota, failures, locked, err)
	}
	usage, err := s.UserStorageUsage(1)
	if err != nil || usage.ReservedBytes != 10 {
		t.Fatalf("usage=%+v err=%v", usage, err)
	}
	if _, err := s.DB.Exec(`UPDATE upload_sessions SET quota_owner_id=2 WHERE id='normal'`); err == nil {
		t.Fatal("reservation owner mutable")
	}
	if _, err := s.DB.Exec(`INSERT INTO upload_sessions(id,user_id) VALUES('missing',1)`); err == nil {
		t.Fatal("missing reservation owner admitted")
	}
	policyExec(t, s, `UPDATE users SET quota_inherits_default=0,quota_bytes=3,login_failures=5,login_locked_until=123 WHERE id=1`)
	if err := migratePolicyAll(s); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT quota_bytes,login_failures,login_locked_until FROM users WHERE id=1`).Scan(&quota, &failures, &locked); err != nil || quota != 3 || failures != 5 || locked != 123 {
		t.Fatalf("migration reset policy %d %d %d %v", quota, failures, locked, err)
	}
	policyExec(t, s, `PRAGMA foreign_keys=ON`)
	policyExec(t, s, `DELETE FROM users WHERE id=1`)
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM upload_sessions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("owner cascade count=%d err=%v", count, err)
	}
}

func TestPolicyMigrationRejectsUnattributableReservations(t *testing.T) {
	for _, kind := range []string{"orphan", "guest-without-invite", "ambiguous"} {
		t.Run(kind, func(t *testing.T) {
			s := legacyPolicyStore(t)
			policyExec(t, s, `INSERT INTO users(id,username,is_guest) VALUES(1,'owner',0),(2,'guest',1)`)
			switch kind {
			case "orphan":
				policyExec(t, s, `INSERT INTO upload_sessions(id,user_id) VALUES('pending',99)`)
			case "guest-without-invite":
				policyExec(t, s, `INSERT INTO upload_sessions(id,user_id) VALUES('pending',2)`)
			case "ambiguous":
				policyExec(t, s, `INSERT INTO reverse_invites(id,token,user_id,guest_user_id,expires_at) VALUES(1,'a',1,2,datetime('now','+1 day')),(2,'b',1,2,datetime('now','+1 day'))`)
				policyExec(t, s, `INSERT INTO upload_sessions(id,user_id,invite_id) VALUES('pending',2,1)`)
			}
			if err := migratePolicyAll(s); err == nil {
				t.Fatal("unattributed reservation accepted")
			}
			var count int
			if err := s.DB.QueryRow(`SELECT COUNT(*) FROM upload_sessions`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("legacy data removed %d %v", count, err)
			}
		})
	}
}

func TestPolicyUsageRetainedAndOverflow(t *testing.T) {
	s := legacyPolicyStore(t)
	policyExec(t, s, `INSERT INTO users(id,username) VALUES(1,'owner')`)
	if err := migratePolicyAll(s); err != nil {
		t.Fatal(err)
	}
	policyExec(t, s, `UPDATE users SET quota_inherits_default=0,quota_bytes=10 WHERE id=1`)
	policyExec(t, s, `INSERT INTO shares(id,user_id,long_id,status) VALUES(1,1,'expired','expired')`)
	policyExec(t, s, `INSERT INTO files(share_id,name,full_path,size,disk_path) VALUES(1,'a','a',4,'/retained')`)
	policyExec(t, s, `INSERT INTO upload_sessions(id,user_id,quota_owner_id) VALUES('pending',1,1)`)
	policyExec(t, s, `INSERT INTO upload_files(session_id,idx,name,full_path,size,received) VALUES('pending',0,'b','b',6,1)`)
	usage, err := s.UserStorageUsage(1)
	if err != nil || *usage != (StorageUsage{QuotaBytes: 10, StoredBytes: 4, ReservedBytes: 6}) {
		t.Fatalf("usage=%+v err=%v", usage, err)
	}
	policyExec(t, s, `UPDATE users SET quota_inherits_default=0,quota_bytes=0`)
	usage, err = s.UserStorageUsage(1)
	if err != nil || usage.AvailableBytes != 0 || usage.QuotaBytes != 0 {
		t.Fatalf("zero quota=%+v err=%v", usage, err)
	}
	policyExec(t, s, `UPDATE files SET size=?`, math.MaxInt64)
	if _, err := s.UserStorageUsage(1); err == nil {
		t.Fatal("combined overflow accepted")
	}
	policyExec(t, s, `UPDATE files SET size=-1`)
	if _, err := s.UserStorageUsage(1); err == nil {
		t.Fatal("negative retained size accepted")
	}
	policyExec(t, s, `UPDATE files SET size=0`)
	policyExec(t, s, `UPDATE upload_files SET size=-1`)
	if _, err := s.UserStorageUsage(1); err == nil {
		t.Fatal("negative reservation accepted")
	}
}

func TestPolicyQuotaInheritanceMigrationAndRestart(t *testing.T) {
	s := legacyPolicyStore(t)
	// Model the previous release: quota exists but the inheritance marker does not.
	policyExec(t, s, `ALTER TABLE users ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 10737418240`)
	policyExec(t, s, `INSERT INTO users(id,username,quota_bytes) VALUES(1,'legacy-default',?),(2,'legacy-override',17),(3,'legacy-zero',0)`, LegacyQuotaBytes)
	if err := migratePolicyAll(s); err != nil {
		t.Fatal(err)
	}
	policyExec(t, s, `UPDATE settings SET value='23' WHERE key=?`, DefaultStorageQuotaKey)
	policyExec(t, s, `INSERT INTO users(id,username) VALUES(4,'new')`)
	check := func(id, quota int64, inherits bool) {
		t.Helper()
		u, err := s.UserStorageUsage(id)
		if err != nil || u.QuotaBytes != quota || u.QuotaInheritsDefault != inherits {
			t.Fatalf("id=%d usage=%+v err=%v", id, u, err)
		}
	}
	check(1, 23, true)
	check(2, 17, false)
	check(3, 0, false)
	check(4, 23, true)
	// Even overrides equal to the legacy default must remain overrides on restart.
	policyExec(t, s, `UPDATE users SET quota_bytes=?,quota_inherits_default=0 WHERE id=4`, LegacyQuotaBytes)
	if err := migratePolicyAll(s); err != nil {
		t.Fatal(err)
	}
	check(1, 23, true)
	check(4, LegacyQuotaBytes, false)
	policyExec(t, s, `UPDATE settings SET value='0' WHERE key=?`, DefaultStorageQuotaKey)
	check(1, 0, true)
	check(2, 17, false)
	// Resolver sees writes within its caller transaction, with one pooled
	// connection (on a current schema, which repository writes need).
	cur, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cur.DB.Close()
	tx, err := cur.Repos().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	quota := int64(31)
	id, err := tx.Users().Create(context.Background(), ports.NewUser{Username: "in-tx", Language: "en", UILanguage: "en", QuotaBytes: &quota})
	if err != nil {
		t.Fatal(err)
	}
	u, err := cur.StorageUsageTx(tx, id)
	if err != nil || u.QuotaBytes != 31 || u.QuotaInheritsDefault {
		t.Fatal(u, err)
	}
}

func TestPolicyQuotaStrictResolver(t *testing.T) {
	raw := func(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
	for _, v := range []string{"", " ", "1 ", " 1", "1x", "1.0", "1e3", "NaN", "-1", "-0", "+1", "9007199254740992", "9223372036854775808"} {
		if _, err := ParseQuotaBytes(v); err == nil {
			t.Errorf("accepted %q", v)
		}
		for _, marker := range []string{"0", "1"} {
			if _, _, err := ResolveQuota(raw("17"), raw(marker), raw(v)); err == nil {
				t.Errorf("accepted corrupt default %q marker=%s", v, marker)
			}
			if _, _, err := ResolveQuota(raw(v), raw(marker), raw("17")); err == nil {
				t.Errorf("accepted corrupt quota %q marker=%s", v, marker)
			}
		}
	}
	for _, v := range []string{"", "true", "2", "-1", "1.0", "01"} {
		if _, _, err := ResolveQuota(raw("17"), raw(v), raw("23")); err == nil {
			t.Errorf("accepted corrupt inheritance %q", v)
		}
	}
	for i := 0; i < 3; i++ {
		fields := []sql.NullString{raw("17"), raw("1"), raw("23")}
		fields[i] = sql.NullString{}
		if _, _, err := ResolveQuota(fields[0], fields[1], fields[2]); err == nil {
			t.Errorf("accepted missing field %d", i)
		}
	}
	q, inherited, err := ResolveQuota(raw("0"), raw("0"), raw("9007199254740991"))
	if err != nil || q != 0 || inherited {
		t.Fatal(q, inherited, err)
	}
	q, inherited, err = ResolveQuota(raw("0"), raw("1"), raw("9007199254740991"))
	if err != nil || q != MaxSafeQuotaBytes || !inherited {
		t.Fatal(q, inherited, err)
	}
}

func TestPolicyQuotaCorruptionFailsClosed(t *testing.T) {
	for _, statement := range []string{
		`UPDATE settings SET value='7x' WHERE key='default_storage_quota_bytes'`,
		`DELETE FROM settings WHERE key='default_storage_quota_bytes'`,
		`UPDATE users SET quota_bytes='7x'`,
		`UPDATE users SET quota_inherits_default=2`,
	} {
		t.Run(statement, func(t *testing.T) {
			s := legacyPolicyStore(t)
			if err := migratePolicyAll(s); err != nil {
				t.Fatal(err)
			}
			policyExec(t, s, `INSERT INTO users(id,username) VALUES(1,'owner')`)
			policyExec(t, s, statement)
			if _, err := s.UserStorageUsage(1); err == nil {
				t.Fatal("corrupt storage policy accepted")
			}
		})
	}
}

// migratePolicyAll runs both parts of the policy migration (the schema part and
// the settings part, which the store runs apart: see runMigrations).
func migratePolicyAll(s *Store) error {
	if err := s.MigratePolicy(); err != nil {
		return err
	}
	return s.migratePolicySettings()
}
