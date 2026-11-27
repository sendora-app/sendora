// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "testing"

func TestShareAppendMigrationIdempotent(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('upload_sessions') WHERE name='share_id'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("share_id column: %d %v", n, err)
		}
		var fk int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_foreign_key_list('upload_sessions') WHERE "from"='share_id' AND "table"='shares' AND on_delete='CASCADE'`).Scan(&fk); err != nil || fk != 1 {
			t.Fatalf("share_id fk: %d %v", fk, err)
		}
		s.DB.Close()
	}
}
