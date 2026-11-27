// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

func TestEnvDefaults(t *testing.T) {
	t.Setenv("HOST", "")
	if got := env("HOST", "127.0.0.1"); got != "127.0.0.1" {
		t.Fatalf("unsafe default bind host: %q", got)
	}
	t.Setenv("HOST", "0.0.0.0")
	if got := env("HOST", "127.0.0.1"); got != "0.0.0.0" {
		t.Fatalf("explicit deployment bind host ignored: %q", got)
	}
}

func TestDispatchDBTool(t *testing.T) {
	var got []string
	old := dbTool
	dbTool = func(args []string) int { got = args; return 7 }
	defer func() { dbTool = old }()
	cases := []struct {
		argv []string
		ok   bool
		want []string
	}{
		{[]string{"/usr/local/bin/sendora-db", "verify", "-source", "x"}, true, []string{"verify", "-source", "x"}},
		{[]string{"sendora-db"}, true, []string{}},
		{[]string{"/sendora", "db", "keygen", "-key-file", "k"}, true, []string{"keygen", "-key-file", "k"}},
		{[]string{"/sendora", "healthcheck"}, false, nil},
		{[]string{"/sendora"}, false, nil},
		{[]string{"/sendora", "--db"}, false, nil},
	}
	for _, c := range cases {
		got = nil
		code, ok := dispatchDBTool(c.argv)
		if ok != c.ok || (ok && (code != 7 || len(got) != len(c.want))) {
			t.Fatalf("%v: ok=%v code=%d args=%v", c.argv, ok, code, got)
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Fatalf("%v: args=%v", c.argv, got)
			}
		}
	}
}
