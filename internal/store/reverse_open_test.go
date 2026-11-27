// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "testing"

func TestMigrateReverseOpenIdempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	for i := 0; i < 2; i++ {
		if err := s.migrateReverseOpen(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`INSERT INTO users(id,username) VALUES(1,'u')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO reverse_invites(token,user_id,expires_at) VALUES('t',1,datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	var re, mx int
	var parent *int64
	if err := s.DB.QueryRow(`SELECT reusable,max_uploads,parent_id FROM reverse_invites`).Scan(&re, &mx, &parent); err != nil || re != 0 || mx != 0 || parent != nil {
		t.Fatal(err, re, mx, parent)
	}
}
