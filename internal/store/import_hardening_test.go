// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareImportedDropsForeignObjects(t *testing.T) {
	p := preparedCopy(t, func(st *Store) {
		for _, stmt := range []string{
			`CREATE TRIGGER evil AFTER INSERT ON downloads BEGIN UPDATE users SET admin=1 WHERE username='importedadmin'; END`,
			`CREATE VIEW sneaky AS SELECT * FROM users`,
			`CREATE INDEX idx_attacker ON users(name)`,
			// weakened copy of one of this binary's own guards
			`DROP INDEX IF EXISTS users_email_bi`,
		} {
			if _, err := st.DB.Exec(stmt); err != nil {
				t.Fatal(stmt, err)
			}
		}
	})
	dest := t.TempDir()
	if _, err := PrepareImported(p, impKeyA, dest); err != nil {
		t.Fatal(err)
	}
	db, err := openCipherDB(p, impKeyA, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, name := range []string{"evil", "sneaky", "idx_attacker"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name=?`, name).Scan(&n); err != nil || n != 0 {
			t.Fatalf("foreign object %s survived (%d, %v)", name, n, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='users_email_bi'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("our own email uniqueness index was not recreated (%d, %v)", n, err)
	}
}

func TestPrepareImportedRefusesVirtualTables(t *testing.T) {
	p := preparedCopy(t, func(st *Store) {
		if _, err := st.DB.Exec(`CREATE VIRTUAL TABLE fts USING fts5(body)`); err != nil {
			t.Skip("fts5 unavailable in this SQLCipher build:", err)
		}
	})
	if _, err := PrepareImported(p, impKeyA, t.TempDir()); err == nil || !strings.Contains(err.Error(), "virtual") {
		t.Fatal("virtual table accepted:", err)
	}
}

func TestPrepareImportedClearsSessionsAndSecret(t *testing.T) {
	p := preparedCopy(t, func(st *Store) {
		for _, stmt := range []string{
			`INSERT INTO refresh_tokens(hash,user_id,expires_at) VALUES('planted',1,'2999-01-01')`,
			`INSERT INTO revoked_access_tokens(hash,expires_at) VALUES('x','2999-01-01')`,
			`INSERT OR REPLACE INTO settings(key,value,grp) VALUES('jwt_secret','attacker-known','secret')`,
		} {
			if _, err := st.DB.Exec(stmt); err != nil {
				t.Fatal(stmt, err)
			}
		}
	})
	if _, err := PrepareImported(p, impKeyA, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	db, err := openCipherDB(p, impKeyA, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{`SELECT COUNT(*) FROM refresh_tokens`, `SELECT COUNT(*) FROM revoked_access_tokens`, `SELECT COUNT(*) FROM settings WHERE key='jwt_secret'`} {
		var n int
		if err := db.QueryRow(q).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s = %d (%v)", q, n, err)
		}
	}
}

func TestPrepareImportedRefusesBadShareIDs(t *testing.T) {
	for _, lid := range []string{"..", "../x", "a/b", "", "AAAAAAAAAAAAAAAA", strings.Repeat("a", 200)} {
		p := preparedCopy(t, func(st *Store) {
			st.DB.Exec(`INSERT INTO shares(user_id,long_id) VALUES(1,?)`, lid)
		})
		if _, err := PrepareImported(p, impKeyA, t.TempDir()); err == nil || !strings.Contains(err.Error(), "invalid link ID") {
			t.Fatalf("long_id %q accepted: %v", lid, err)
		}
	}
}

func TestPrepareImportedRebasesDiskPaths(t *testing.T) {
	dataDir := t.TempDir()
	const lid = "cccccccccccccccc"
	p := preparedCopy(t, func(st *Store) {
		st.DB.Exec(`INSERT INTO shares(user_id,long_id) VALUES(1,?)`, lid)
		st.DB.Exec(`INSERT INTO files(share_id,name,full_path,disk_path) VALUES(1,'a','a','/etc/hosts')`)
		st.DB.Exec(`INSERT INTO files(share_id,name,full_path,disk_path) VALUES(1,'b','b','../../sendora.db')`)
		st.DB.Exec(`INSERT INTO files(share_id,name,full_path,disk_path) VALUES(1,'c','c','/old/env/data/shares/cccccccccccccccc/0_c.txt')`)
	})
	if _, err := PrepareImported(p, impKeyA, dataDir); err != nil {
		t.Fatal(err)
	}
	db, err := openCipherDB(p, impKeyA, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT disk_path FROM files ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := []string{"hosts", "sendora.db", "0_c.txt"}
	i := 0
	for rows.Next() {
		var got string
		if err := rows.Scan(&got); err != nil {
			t.Fatal(err)
		}
		if exp := filepath.Join(dataDir, "shares", lid, want[i]); got != exp {
			t.Fatalf("disk_path %d = %q, want %q", i, got, exp)
		}
		i++
	}
	if i != 3 {
		t.Fatal("rows", i)
	}
}

func TestPrepareImportedRefusesEmptyDiskPath(t *testing.T) {
	p := preparedCopy(t, func(st *Store) {
		st.DB.Exec(`INSERT INTO shares(user_id,long_id) VALUES(1,'dddddddddddddddd')`)
		st.DB.Exec(`INSERT INTO files(share_id,name,full_path,disk_path) VALUES(1,'a','a','')`)
	})
	if _, err := PrepareImported(p, impKeyA, t.TempDir()); err == nil || !strings.Contains(err.Error(), "unsafe storage path") {
		t.Fatal("empty disk_path accepted:", err)
	}
}

func TestSharePathContainment(t *testing.T) {
	base := "/data"
	good := "aaaaaaaaaaaaaaaa"
	cases := []struct {
		lid, disk string
		ok        bool
	}{
		{good, "/anywhere/else/0_file.txt", true},
		{good, "0_file.txt", true},
		{"..", "x", false},
		{"../x", "x", false},
		{"", "x", false},
		{good, "", false},
		{good, "..", false},
		{good, ".", false},
		{good, "/", false},
		{good, "/etc/passwd/..", false},
	}
	for _, c := range cases {
		got, err := SharePath(base, c.lid, c.disk)
		if (err == nil) != c.ok {
			t.Errorf("SharePath(%q,%q) err=%v", c.lid, c.disk, err)
			continue
		}
		if err == nil && filepath.Dir(got) != filepath.Join(base, "shares", c.lid) {
			t.Errorf("escaped: %s", got)
		}
	}
}

func TestPrepareImportedRefusesGeneratedColumns(t *testing.T) {
	p := preparedCopy(t, func(st *Store) {
		if _, err := st.DB.Exec(`ALTER TABLE settings ADD COLUMN boom BLOB GENERATED ALWAYS AS (zeroblob(1000)) VIRTUAL`); err != nil {
			t.Skip("generated columns unavailable:", err)
		}
	})
	if _, err := PrepareImported(p, impKeyA, t.TempDir()); err == nil || !strings.Contains(err.Error(), "generated") {
		t.Fatal("generated column accepted:", err)
	}
}
