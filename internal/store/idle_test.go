// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"testing"
	"time"
)

func TestMigrateIdleBackfillsExistingTokens(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	// Simulate a database from before the column existed.
	if _, err := st.DB.Exec(`INSERT INTO users(id,username) VALUES(1,'u')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`ALTER TABLE refresh_tokens DROP COLUMN issued_at`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO refresh_tokens(hash,user_id,expires_at) VALUES('old',1,'2999-01-01')`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // idempotent
		if err := st.migrateIdle(); err != nil {
			t.Fatal(err)
		}
	}
	var issued time.Time
	if err := st.DB.QueryRow(`SELECT issued_at FROM refresh_tokens WHERE hash='old'`).Scan(&issued); err != nil {
		t.Fatal("legacy rows must be backfilled:", err)
	}
	if time.Since(issued) > time.Minute || issued.After(time.Now().Add(time.Minute)) {
		t.Fatal("backfill must use the upgrade time so nobody is signed out", issued)
	}
	if st.Setting("idle_logout_minutes") != "60" {
		t.Fatal("default must be seeded as 60")
	}
}
