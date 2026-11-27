// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "testing"

func TestMFAMigrationIsIdempotentAndCascades(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	for i := 0; i < 3; i++ {
		if err := st.migrateMFA(); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"user_totp", "user_recovery_codes", "user_webauthn"} {
		var n int
		if err := st.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil || n != 1 {
			t.Fatal("missing table", table, err)
		}
	}
	if _, err := st.DB.Exec(`INSERT INTO users(id,username) VALUES(1,'u')`); err != nil {
		t.Fatal(err)
	}
	var policy string
	var epoch int
	if err := st.DB.QueryRow(`SELECT mfa_policy,mfa_epoch FROM users WHERE id=1`).Scan(&policy, &epoch); err != nil || policy != "inherit" || epoch != 0 {
		t.Fatal("defaults", policy, epoch, err)
	}
	for _, q := range []string{
		`INSERT INTO user_totp(user_id,secret,confirmed) VALUES(1,'S',1)`,
		`INSERT INTO user_recovery_codes(user_id,code_hash) VALUES(1,'h')`,
		`INSERT INTO user_webauthn(user_id,cred_id,public_key,alg) VALUES(1,x'01',x'02',-7)`,
	} {
		if _, err := st.DB.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	if _, err := st.DB.Exec(`INSERT INTO user_recovery_codes(user_id,code_hash) VALUES(1,'h')`); err == nil {
		t.Fatal("recovery code hashes are unique per user")
	}
	if _, err := st.DB.Exec(`INSERT INTO user_webauthn(user_id,cred_id,public_key,alg) VALUES(1,x'01',x'03',-7)`); err == nil {
		t.Fatal("credential ids are unique")
	}
	if _, err := st.DB.Exec(`DELETE FROM users WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var left int
	st.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM user_totp)+(SELECT COUNT(*) FROM user_recovery_codes)+(SELECT COUNT(*) FROM user_webauthn)`).Scan(&left)
	if left != 0 {
		t.Fatal("factors must cascade with the user", left)
	}
	if st.Setting("mfa_policy") != "optional" || st.Setting("mfa_totp_enabled") != "true" || st.Setting("mfa_webauthn_enabled") != "true" {
		t.Fatal("defaults seeded")
	}
}
