// SPDX-License-Identifier: AGPL-3.0-or-later

package nosql

import (
	"os"
	"path/filepath"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// TestNoSQLOutsideAdapters enforces design 2A.3: no database SQL outside
// internal/adapters. Phase 1 emptied the allowlist of 0.2 call sites, so
// there are no exceptions: every finding fails the test.
func TestNoSQLOutsideAdapters(t *testing.T) {
	root := repoRoot(t)
	sites, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sites {
		t.Errorf("%s:%d: %s outside internal/adapters; move it into a repository (docs/cluster/REPOSITORY-PATTERN.md)", s.File, s.Line, s.What)
	}
	if _, err := os.Stat(filepath.Join(root, ".nosql-allowlist")); err == nil {
		t.Error(".nosql-allowlist exists again: there is no allowlist any more; SQL belongs in internal/adapters")
	}
}

func TestSQLLiteral(t *testing.T) {
	cases := map[string]bool{
		"`SELECT id FROM users`":               true,
		"\"  \\n\\tCREATE TABLE x(a)\"":        true,
		"`INSERT INTO t VALUES(?)`":            true,
		"\"WITH(x) AS (SELECT 1) SELECT 1\"":   true,
		"\"DELETE /api/ip-bans\"":              false, // route pattern
		"\"DELETE\"":                           false, // HTTP method
		"\"Select a file\"":                    false, // UI text
		"\"SELECTED\"":                         false,
		"\"update your password\"":             false,
		"\"BEGINNING of the text\"":            false,
		"`PRAGMA cipher_version`":              true,
		"\"internal/adapters SELECT is fine\"": false,
	}
	for lit, want := range cases {
		if _, got := sqlLiteral(lit); got != want {
			t.Errorf("sqlLiteral(%s) = %v, want %v", lit, got, want)
		}
	}
}

// TestScanFindsCallsAndLiterals checks the scanner on a small tree, including
// the directories it must skip.
func TestScanFindsCallsAndLiterals(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/app/a.go", `package app
const q = "SELECT 1"
func f(db interface{ Exec(string, ...any) (any, error); QueryRow(string, ...any) any }, r interface{ Query() any }) {
	db.Exec("UPDATE t SET a=1")
	db.QueryRow(q)
	_ = r.Query() // no arguments: url.URL.Query, not SQL
	_ = syscall.Exec("/bin/true", nil, nil) // process replacement, not SQL
	_ = "DELETE /api/x"
}
`)
	write("internal/app/a_test.go", "package app\nconst t = \"SELECT 1\"\n")
	write("internal/adapters/sqlite/s.go", "package sqlite\nconst t = \"SELECT 1\"\n")
	write("third_party/x/x.go", "package x\nconst t = \"SELECT 1\"\n")
	sites, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if c := Count(sites); len(c) != 1 || c["internal/app/a.go"] != 3 {
		t.Fatalf("counts %v (sites %v), want internal/app/a.go: 3", c, sites)
	}
}
