// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"testing"
	"time"
)

// A pending MFA-reset confirmation link in an imported database must not survive
// the import: it would let whoever holds the link remove a user's second factor.
func TestImportClearsPendingMFAResetRequests(t *testing.T) {
	st, err := OpenEncrypted(t.TempDir(), bytes.Repeat([]byte{7}, 32), true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.DB.Exec(`INSERT INTO users(username) VALUES('u')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO mfa_reset_requests(hash,user_id,expires_at) VALUES('h',1,?)`, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := clearImportedSecrets(st.DB); err != nil {
		t.Fatal(err)
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM mfa_reset_requests`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d pending MFA reset requests survived the import", n)
	}
}
