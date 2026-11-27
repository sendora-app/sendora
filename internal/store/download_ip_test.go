// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import "testing"

// Opening a store blanks download addresses kept from before, unless
// audit_log_ip is on.
func TestMigrationBlanksDownloadIPsUnlessAuditIPIsOn(t *testing.T) {
	for _, on := range []bool{false, true} {
		dir := t.TempDir()
		st, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		mustExec := func(q string, args ...any) {
			if _, err := st.DB.Exec(q, args...); err != nil {
				t.Fatal(err)
			}
		}
		mustExec(`INSERT INTO users(username,email,password_hash) VALUES('u','u@x.io','h')`)
		mustExec(`INSERT INTO shares(user_id,long_id) VALUES(1,'aaaaaaaaaaaaaaaa')`)
		mustExec(`INSERT INTO downloads(share_id,ip) VALUES(1,'203.0.113.7')`)
		if on {
			mustExec(`UPDATE settings SET value='true' WHERE key='audit_log_ip'`)
		}
		st.Close()
		if st, err = Open(dir); err != nil {
			t.Fatal(err)
		}
		var ip string
		if err := st.DB.QueryRow(`SELECT ip FROM downloads`).Scan(&ip); err != nil {
			t.Fatal(err)
		}
		if want := map[bool]string{false: "", true: "203.0.113.7"}[on]; ip != want {
			t.Fatalf("audit_log_ip=%v: ip %q, want %q", on, ip, want)
		}
		st.Close()
	}
}
