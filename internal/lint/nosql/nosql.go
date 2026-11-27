// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nosql finds database SQL outside the adapter packages
// (docs/cluster/DESIGN.md section 2A.3, docs/adr/0003). Its test,
// TestNoSQLOutsideAdapters, runs in CI with go test ./... and fails on every
// finding: phase 1 moved the last 0.2 call sites into internal/adapters, so
// the allowlist (.nosql-allowlist) that tracked them is gone.
//
// A site is either
//   - a call x.M(...) with at least one argument, where M is a database/sql
//     query method (Exec, Query, QueryRow, Prepare and their Context forms)
//     and x is not the syscall package, or
//   - a string literal, outside such a call, whose text starts with an SQL
//     keyword in upper case followed by white space or "(" (CREATE TABLE ...,
//     SELECT ...), which catches SQL kept in constants and variables.
//
// Test files (_test.go), internal/adapters/... and third_party/... are not
// scanned. HTTP route patterns such as "DELETE /api/x" are not SQL.
package nosql

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Site is one finding.
type Site struct {
	File string // slash-separated, relative to the scanned root
	Line int
	What string
}

var queryMethods = map[string]bool{
	"Exec": true, "ExecContext": true,
	"Query": true, "QueryContext": true,
	"QueryRow": true, "QueryRowContext": true,
	"Prepare": true, "PrepareContext": true,
}

// notSQLPackages are package names whose Exec and friends are not database
// calls (a call through such a package identifier is never a site).
var notSQLPackages = map[string]bool{"syscall": true}

var sqlKeywords = []string{
	"SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "WITH", "CREATE", "ALTER", "DROP",
	"PRAGMA", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "ATTACH", "DETACH", "VACUUM",
}

// skipDir reports directories that are never scanned (relative, slash form).
func skipDir(rel string) bool {
	switch {
	case rel == "third_party", rel == "web", rel == "internal/adapters":
		return true
	case strings.HasPrefix(rel, ".") && rel != ".":
		return true
	}
	return false
}

// Scan walks the Go sources under root and returns the sites, ordered by file
// and line.
func Scan(root string) ([]Site, error) {
	var sites []Site
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipDir(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		sites = append(sites, scanFile(fset, rel, f)...)
		return nil
	})
	sort.SliceStable(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites, err
}

func scanFile(fset *token.FileSet, rel string, f *ast.File) []Site {
	var sites []Site
	inCall := map[*ast.BasicLit]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !queryMethods[sel.Sel.Name] {
			return true
		}
		if pkg, isIdent := sel.X.(*ast.Ident); isIdent && notSQLPackages[pkg.Name] {
			return true // syscall.Exec replaces the process; it runs no SQL
		}
		sites = append(sites, Site{File: rel, Line: fset.Position(call.Pos()).Line, What: sel.Sel.Name + " call"})
		for _, a := range call.Args {
			ast.Inspect(a, func(n ast.Node) bool {
				if bl, ok := n.(*ast.BasicLit); ok {
					inCall[bl] = true
				}
				return true
			})
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		bl, ok := n.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING || inCall[bl] {
			return true
		}
		if kw, ok := sqlLiteral(bl.Value); ok {
			sites = append(sites, Site{File: rel, Line: fset.Position(bl.Pos()).Line, What: kw + " literal"})
		}
		return true
	})
	return sites
}

// sqlLiteral reports whether the Go string literal lit starts with an SQL
// statement, and with which keyword.
func sqlLiteral(lit string) (string, bool) {
	s, err := strconv.Unquote(lit)
	if err != nil {
		return "", false
	}
	s = strings.TrimLeft(s, " \t\r\n")
	for _, kw := range sqlKeywords {
		if !strings.HasPrefix(s, kw) || len(s) == len(kw) {
			continue
		}
		rest := s[len(kw):]
		if rest[0] != ' ' && rest[0] != '\t' && rest[0] != '\n' && rest[0] != '\r' && rest[0] != '(' {
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(rest, " \t"), "/") {
			continue // an HTTP route pattern ("DELETE /api/...")
		}
		return kw, true
	}
	return "", false
}

// Count groups sites per file.
func Count(sites []Site) map[string]int {
	m := map[string]int{}
	for _, s := range sites {
		m[s.File]++
	}
	return m
}
