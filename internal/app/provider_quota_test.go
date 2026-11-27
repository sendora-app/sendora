// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"testing"

	"github.com/sendora-app/sendora/internal/store"
)

func TestQuotaProviderCorruptionDoesNotCreateAccounts(t *testing.T) {
	e := newEnv(t)
	e.setup()
	if _, err := e.s.St.DB.Exec(`INSERT INTO auth_providers(id,uuid,name,type) VALUES(1,'provider-quota-check','quota-check','oidc')`); err != nil {
		t.Fatal(err)
	}
	p := &Provider{ID: 1, Type: "oidc", AllowRegistration: true}
	linked := extIdentity{Sub: "linked-subject", Username: "linked-user"}
	if u, msg := e.s.resolveExternalUser(p, linked); u == nil || msg != "" {
		t.Fatal(u, msg)
	}
	if err := e.s.St.SetSetting(store.DefaultStorageQuotaKey, "corrupt"); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []extIdentity{linked, {Sub: "new-subject", Username: "new-user"}} {
		u, msg := e.s.resolveExternalUser(p, identity)
		if u != nil || msg == "" {
			t.Fatal("corrupt policy did not produce an explicit failure", u, msg)
		}
	}
	var users, links int
	if err := e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM user_auth_providers`).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if users != 2 || links != 1 {
		t.Fatal("failed provider login changed accounts or links", users, links)
	}
}
