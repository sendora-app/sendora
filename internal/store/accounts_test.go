// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "testing"

func TestMigrateAccountsIsAdditiveAndAssignsSessionIDs(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB.Exec(`INSERT INTO users(username,password_hash) VALUES('old','x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO refresh_tokens(hash,user_id,expires_at,session_id) VALUES('h1',1,'2999-01-01',NULL),('h2',1,'2999-01-01','')`); err != nil {
		t.Fatal(err)
	}
	// Running again (as at every start) keeps existing columns and fills in the
	// missing session ids of tokens issued by an older release.
	if err := s.migrateAccounts(); err != nil {
		t.Fatal(err)
	}
	var missing, distinct int
	s.DB.QueryRow(`SELECT COUNT(*) FROM refresh_tokens WHERE session_id IS NULL OR session_id=''`).Scan(&missing)
	s.DB.QueryRow(`SELECT COUNT(DISTINCT session_id) FROM refresh_tokens`).Scan(&distinct)
	if missing != 0 || distinct != 2 {
		t.Fatalf("missing=%d distinct=%d", missing, distinct)
	}
	var createdBy string
	var disabled bool
	if err := s.DB.QueryRow(`SELECT created_by, disabled_at IS NOT NULL FROM users WHERE username='old'`).Scan(&createdBy, &disabled); err != nil {
		t.Fatal(err)
	}
	if createdBy != "" || disabled {
		t.Fatalf("existing account changed: %q %v", createdBy, disabled)
	}
	if s.Setting("provider_session_max_hours") != "24" {
		t.Fatalf("default: %q", s.Setting("provider_session_max_hours"))
	}
}
