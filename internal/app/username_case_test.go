// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import "testing"

func TestUsernamesAreCaseInsensitive(t *testing.T) {
	e := newEnv(t)
	admin := e.setup()
	for _, name := range []string{"ADMIN", "Admin", "aDmIn"} {
		e.want(e.login(name, "password123"), 200, "login as "+name)
	}
	e.mkUser(admin, "Alice", false)
	for _, name := range []string{"alice", "ALICE", "aLiCe"} {
		r := e.do("POST", "/api/users", admin, map[string]any{"username": name, "password": "password123", "email": name + "@y.io"})
		e.want(r, 400, "duplicate by case "+name)
		e.want(e.login(name, "password123"), 200, "login as "+name)
	}
	var stored string
	if err := qByName(e.s.St, `SELECT username FROM users WHERE username='Alice'`).Scan(&stored); err != nil || stored != "Alice" {
		t.Fatalf("display case must be kept as typed: %q %v", stored, err)
	}
	// wrong password must still fail for any case variant
	if r := e.login("ALICE", "wrong-password"); r.Code == 200 {
		t.Fatal("wrong password accepted")
	}
}
