// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "testing"

func TestUsernameCaseMigrationToleratesExistingCollisions(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	if _, err := st.DB.Exec(`DROP INDEX users_username_nocase`); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"Bob", "bob"} {
		if _, err := st.DB.Exec(`INSERT INTO users(username,name) VALUES(?,?)`, n, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.migrateUsernameCase(); err != nil {
		t.Fatalf("startup must not fail on legacy collisions: %v", err)
	}
	var idx int
	st.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='users_username_nocase'`).Scan(&idx)
	if idx != 0 {
		t.Fatal("index must not exist while collisions remain")
	}
}
