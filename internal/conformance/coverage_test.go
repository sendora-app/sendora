// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// notYetAdapted lists ports with no adapter yet, so no contract can be run
// (docs/cluster/DESIGN.md: the Journal arrives in phase 4). An entry
// must be removed when its adapter lands.
var notYetAdapted = map[string]bool{"Journal": true}

// notDatabasePorts are ports no database adapter implements: the controller's
// key endpoint (internal/keyserver, internal/keyclient) and the Kubernetes
// TokenReview adapter. They are tested next to their implementations.
var notDatabasePorts = map[string]bool{"ClusterKeys": true, "TokenReviewer": true}

const portsPath = "github.com/sendora-app/sendora/internal/ports"

// TestEveryPortMethodHasConformanceCoverage fails when a method of a port
// interface (internal/ports) is never called by the conformance suite: a
// method added to ports.Store without a contract test, which would let the
// adapters drift apart unnoticed. It type-checks this package's non-test
// sources against internal/ports and records every call whose method belongs
// to a ports interface (directly or through embedding).
func TestEveryPortMethodHasConformanceCoverage(t *testing.T) {
	if _, err := os.Stat("../ports"); err != nil {
		t.Skip("source tree not available (test binary run outside the repository)")
	}
	fset := token.NewFileSet()
	std := importer.Default()

	_, _, portsPkg := parseAndCheck(t, fset, "../ports", portsPath, fakeImporter{std: std})
	all := map[string]bool{}
	scope := portsPkg.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || !tn.Exported() || notYetAdapted[name] || notDatabasePorts[name] {
			continue
		}
		iface, ok := tn.Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}
		for i := 0; i < iface.NumExplicitMethods(); i++ {
			all[name+"."+iface.ExplicitMethod(i).Name()] = true
		}
	}
	if len(all) < 300 {
		t.Fatalf("found only %d port methods; the scan is broken", len(all))
	}

	files, info, _ := parseAndCheck(t, fset, ".", "github.com/sendora-app/sendora/internal/conformance", fakeImporter{std: std, ports: portsPkg})
	called := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			s := info.Selections[sel]
			if s == nil || s.Kind() != types.MethodVal {
				return true
			}
			fn, ok := s.Obj().(*types.Func)
			if !ok || fn.Pkg() == nil || fn.Pkg().Path() != portsPath {
				return true
			}
			recv := fn.Type().(*types.Signature).Recv()
			if recv == nil {
				return true
			}
			if named, ok := recv.Type().(*types.Named); ok {
				called[named.Obj().Name()+"."+fn.Name()] = true
			}
			return true
		})
	}
	var missing []string
	for m := range all {
		if !called[m] {
			missing = append(missing, m)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d port methods have no conformance test (add one to internal/conformance, see docs/cluster/REPOSITORY-PATTERN.md):\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// fakeImporter resolves the standard library from export data, internal/ports
// from the package type-checked above, and every other import as an empty
// package: calls on adapter types are not port calls, so their types may stay
// unresolved.
type fakeImporter struct {
	std   types.Importer
	ports *types.Package
}

func (f fakeImporter) Import(path string) (*types.Package, error) {
	if path == portsPath && f.ports != nil {
		return f.ports, nil
	}
	if !strings.Contains(strings.SplitN(path, "/", 2)[0], ".") {
		if p, err := f.std.Import(path); err == nil {
			return p, nil
		}
	}
	p := types.NewPackage(path, filepath.Base(path))
	p.MarkComplete()
	return p, nil
}

func parseAndCheck(t *testing.T, fset *token.FileSet, dir, path string, imp types.Importer) ([]*ast.File, *types.Info, *types.Package) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}}
	conf := types.Config{Importer: imp, Error: func(error) {}} // unresolved adapter types are expected
	pkg, _ := conf.Check(path, fset, files, info)
	return files, info, pkg
}
