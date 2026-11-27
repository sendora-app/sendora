// SPDX-License-Identifier: AGPL-3.0-or-later

package platform

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/sendora-app/sendora/internal/store"
)

// treeHash fingerprints every file (path, size, content, mode) under dir.
func treeHash(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		fi, _ := d.Info()
		sum := sha256.Sum256(b)
		rel, _ := filepath.Rel(dir, p)
		lines = append(lines, rel+" "+fi.Mode().String()+" "+string(sum[:]))
		return nil
	})
	sort.Strings(lines)
	h := sha256.Sum256([]byte(fmtLines(lines)))
	return string(h[:])
}

func fmtLines(l []string) string {
	var b bytes.Buffer
	for _, s := range l {
		b.WriteString(s + "\n")
	}
	return b.String()
}

// A single-tenant data directory of another host is COPIED into a platform
// that already has tenants: the source stays byte-for-byte unchanged, the
// tenant keeps the old key as its root, and resume/abort work.
func TestCopyImportFromAnotherInstallation(t *testing.T) {
	master, oldKey := key32(t), key32(t)
	src := singleTenantDir(t, oldKey)
	os.Chmod(src, 0o500) // read-only source (as when mounted read-only)
	t.Cleanup(func() { os.Chmod(src, 0o700) })
	before := treeHash(t, src)

	dir := t.TempDir()
	p, err := Open(dir, master, true)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	other, err := p.CreateTenant("existing", "Existing", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ImportSingleTenant(ImportOptions{Slug: "moved", From: src}); err == nil {
		t.Fatal("source readable with the master key?")
	}
	if _, err := p.ImportSingleTenant(ImportOptions{Slug: "moved", From: dir, SourceKey: oldKey}); err == nil {
		t.Fatal("importing the platform's own directory accepted")
	}
	// Interrupted after copying, aborted: nothing left, source unchanged.
	importFailAfter = phaseMoved
	if _, err := p.ImportSingleTenant(ImportOptions{Slug: "moved", From: src, SourceKey: oldKey}); !errors.Is(err, errImportInjected) {
		t.Fatal(err)
	}
	importFailAfter = ""
	if res, err := p.ImportSingleTenant(ImportOptions{Abort: true, SourceKey: oldKey}); err != nil || !res.Aborted {
		t.Fatal("abort", err)
	}
	if _, err := p.TenantBySlug("moved"); err == nil {
		t.Fatal("tenant left after abort")
	}
	if treeHash(t, src) != before {
		t.Fatal("abort changed the source")
	}
	// Interrupted, then resumed to the end.
	importFailAfter = phaseDatabase
	if _, err := p.ImportSingleTenant(ImportOptions{Slug: "moved", Name: "Moved", From: src, SourceKey: oldKey}); !errors.Is(err, errImportInjected) {
		t.Fatal(err)
	}
	importFailAfter = ""
	res, err := p.ImportSingleTenant(ImportOptions{SourceKey: oldKey})
	if err != nil {
		t.Fatal("resume:", err)
	}
	if res.Archive != "" || res.Backups != 1 || res.Files != 0 {
		t.Fatalf("result %+v", res)
	}
	if treeHash(t, src) != before {
		t.Fatal("the copy import changed the source")
	}
	tn, _ := p.Tenant(res.TenantID)
	if tn.Status != StatusActive || tn.KeyMode != KeyLegacy || tn.Name != "Moved" {
		t.Fatalf("tenant %+v", tn)
	}
	dbKey, root, _ := p.TenantKeys(tn)
	if !bytes.Equal(root, oldKey) {
		t.Fatal("the old key must stay the tenant's file/audit root")
	}
	tdir, _ := p.TenantDir(tn.ID)
	if b, err := os.ReadFile(filepath.Join(tdir, "shares", "some-share", "blob")); err != nil || string(b) != "x" {
		t.Fatal("share files not copied", err)
	}
	if _, err := os.Stat(filepath.Join(tdir, ".import-source")); !os.IsNotExist(err) {
		t.Fatal("private copy of the source database left behind")
	}
	if st, err := store.VerifyAuditDatabaseRoot(filepath.Join(tdir, store.DBFile), dbKey, root); err != nil || !st.OK {
		t.Fatalf("audit chain %+v %v", st, err)
	}
	if sc, _ := p.Storage(tn.ID); sc.Offer != OfferLocal {
		t.Fatalf("imported tenant storage %+v", sc)
	}
	if o, err := p.Tenant(other.ID); err != nil || o.Status != StatusActive {
		t.Fatal("existing tenant affected")
	}
}
