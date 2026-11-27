// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/keyops"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/ports"
)

func (e *vfEnv) engine(t *testing.T) *keyops.Engine {
	t.Helper()
	svc, err := e.st.KeyringService()
	if err != nil {
		t.Fatal(err)
	}
	return &keyops.Engine{KeyID: ColumnKeyID, Svc: svc, Codec: e.st.ColumnKeyring(), Store: e.st.Repos(), Files: e.st, Actor: "test", Batch: 2}
}

// read opens file id through the store's own key lookup, as the application does.
func (e *vfEnv) read(t *testing.T, id int64) ([]byte, error) {
	t.Helper()
	f, err := e.st.Repos().ObjectStorage().MigrationFile(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	master, hid, err := e.st.FileMaster(f.EncID)
	if err != nil {
		return nil, err
	}
	key, err := FileObjectKey(f.LocationID, f.ShareLongID, f.DiskPath, f.ObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := e.st.Backends().OpenFile(context.Background(), f.LocationID, f.ShareLongID, f.DiskPath, f.ObjectKey)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	defer obj.Close()
	r, err := filecrypt.NewReader(obj, obj.Size(), f.Size, master, hid)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// A new store's files are under version 1 of the keyring's files DEK, not under
// anything derived from the root.
func TestFilesKeyComesFromTheKeyring(t *testing.T) {
	e := newVFEnv(t)
	if e.ver != 1 {
		t.Fatalf("active files version %d", e.ver)
	}
	if bytes.Equal(e.master, e.legacy) {
		t.Fatal("the files master equals the root-derived master")
	}
	id, _ := e.add("a.bin", "v2", []byte("file content under the DEK"))
	got, err := e.read(t, id)
	if err != nil || string(got) != "file content under the DEK" {
		t.Fatalf("read: %q %v", got, err)
	}
	// The audit MAC key is not the root-derived one either.
	if bytes.Equal(e.st.AuditMAC()([]byte("x")), auditMAC(e.st.rootKey)([]byte("x"))) {
		t.Fatal("the audit chain is MACed under a root-derived key")
	}
	// Reference values: root-derived keys decrypt nothing written under the DEK.
	f, _ := os.ReadFile(e.disk("a.bin"))
	r, err := filecrypt.NewReader(nopCloser{bytes.NewReader(f)}, int64(len(f)), 26, e.legacy, mustID(t, e, id))
	if err == nil {
		_, err = io.ReadAll(r)
	}
	if err == nil {
		t.Fatal("a file under the DEK opened with the root-derived master")
	}
}

func mustID(t *testing.T, e *vfEnv, id int64) string {
	t.Helper()
	f, err := e.st.Repos().ObjectStorage().MigrationFile(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	hid, _ := ParseEncRef(f.EncID)
	return hid
}

// A file under the old root-derived key is refused (fail closed) until
// files-reencrypt converted it; the conversion keeps content, checksum and
// readability and removes the old object.
func TestLegacyFilesRefusedUntilReencrypted(t *testing.T) {
	e := newVFEnv(t)
	plain := make([]byte, 3*filecrypt.ChunkSize+5)
	for i := range plain {
		plain[i] = byte(i * 7)
	}
	legacyV2, _ := e.add("1_legacy", "legacy", plain)
	legacyV1, _ := e.add("2_v1", "v1", []byte("a version one file"))
	current, _ := e.add("3_current", "v2", []byte("already fine"))
	for _, id := range []int64{legacyV2, legacyV1} {
		if _, err := e.read(t, id); !errors.Is(err, ErrLegacyFile) {
			t.Fatalf("file %d: %v, want ErrLegacyFile", id, err)
		}
	}
	counts, err := e.st.FileKeyCounts(context.Background())
	if err != nil || counts[0] != 2 || counts[1] != 1 {
		t.Fatalf("counts %v %v", counts, err)
	}
	before, _ := os.ReadDir(e.disk(""))

	eng := e.engine(t)
	res, err := eng.Execute(context.Background(), ports.KeyJob{Op: ports.KeyJobRekeyFiles, Purpose: keyring.PurposeFiles})
	if err != nil {
		t.Fatalf("%v (%s)", err, res.Detail)
	}
	got, err := e.read(t, legacyV2)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("converted v2 file: %v", err)
	}
	if got, err := e.read(t, legacyV1); err != nil || string(got) != "a version one file" {
		t.Fatalf("converted v1 file: %q %v", got, err)
	}
	if got, err := e.read(t, current); err != nil || string(got) != "already fine" {
		t.Fatalf("untouched file: %q %v", got, err)
	}
	after, _ := os.ReadDir(e.disk(""))
	if len(after) != len(before) {
		t.Fatalf("directory has %d entries after the conversion, %d before (old copies must go)", len(after), len(before))
	}
	sum, err := e.st.VerifyStoredFiles(VerifyOptions{})
	if err != nil || sum.OK != 3 || sum.LegacyKey != 0 || sum.Failed != 0 || sum.Orphans != 0 {
		t.Fatalf("verify: %+v %v", sum, err)
	}
	// Repeating does nothing.
	if st, err := e.st.RekeyFiles(context.Background(), RekeyOptions{}); err != nil || st.Rewritten != 0 {
		t.Fatalf("second run: %+v %v", st, err)
	}
}

// Rotation of the files key: new uploads use the new version, old files stay
// readable meanwhile, the job rewrites them, retire works once none remain and
// a retired version is refused afterwards.
func TestFilesKeyRotationRewritesAndRetires(t *testing.T) {
	e := newVFEnv(t)
	ctx := context.Background()
	idOld, _ := e.add("old", "v2", []byte("written before the rotation"))
	eng := e.engine(t)

	svc := eng.Svc
	v2, err := svc.Rotate(ctx, ColumnKeyID, keyring.PurposeFiles, "test")
	if err != nil || v2 != 2 {
		t.Fatalf("rotate: %d %v", v2, err)
	}
	if _, err := e.st.ColumnKeyring().Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if m, v, err := e.st.NewFileKey(); err != nil || v != 2 || bytes.Equal(m, e.master) {
		t.Fatalf("new uploads: v%d %v", v, err)
	}
	// Old files are readable while the job has not run.
	if got, err := e.read(t, idOld); err != nil || string(got) != "written before the rotation" {
		t.Fatalf("old file after rotation: %q %v", got, err)
	}
	// A file written now is under version 2.
	m2, ver2, _ := e.st.NewFileKey()
	var out bytes.Buffer
	_, fid, _ := filecrypt.Encrypt(&out, bytes.NewReader([]byte("written after")), m2, nil)
	os.WriteFile(e.disk("new"), out.Bytes(), 0o600)
	idNew, err := e.st.Repos().Shares().AddFile(ctx, ports.NewShareFile{ShareID: 1, Name: "new", FullPath: "new", Size: 13, DiskPath: e.disk("new"),
		SHA256: "", Integrity: "server_baseline", Encrypted: true, EncID: EncRef(fid, ver2)})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.CheckRetire(ctx, keyring.PurposeFiles, 1); err == nil {
		t.Fatal("version 1 can be retired while a file is under it")
	}
	res, err := eng.Execute(ctx, ports.KeyJob{Op: ports.KeyJobRekeyFiles, Purpose: keyring.PurposeFiles})
	if err != nil {
		t.Fatalf("%v %s", err, res.Detail)
	}
	for id, want := range map[int64]string{idOld: "written before the rotation", idNew: "written after"} {
		if got, err := e.read(t, id); err != nil || string(got) != want {
			t.Fatalf("file %d: %q %v", id, got, err)
		}
	}
	counts, _ := e.st.FileKeyCounts(ctx)
	if counts[1] != 0 || counts[2] != 2 {
		t.Fatalf("counts after the job: %v", counts)
	}
	if _, err := eng.Execute(ctx, ports.KeyJob{Op: ports.KeyJobRetire, Purpose: keyring.PurposeFiles, Version: 1}); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := e.st.ColumnKeyring().Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.st.FileMaster(EncRef(mustID(t, e, idOld), 1)); !errors.Is(err, keyring.ErrKeyRetired) {
		t.Fatalf("retired version: %v", err)
	}
	if got, err := e.read(t, idOld); err != nil || string(got) != "written before the rotation" {
		t.Fatalf("file after the retirement: %q %v", got, err)
	}
	// audit-mac cannot be rotated.
	if _, err := eng.Execute(ctx, ports.KeyJob{Op: ports.KeyJobRotate, Purpose: keyring.PurposeAuditMAC}); !errors.Is(err, keyops.ErrAuditMACFixed) {
		t.Fatalf("rotate audit-mac: %v", err)
	}
}

// A job started by the Engine for the files purpose rotates and rewrites in
// one run (what the admin API and sendora-db rotate-key -purpose files do).
func TestFilesRotateJobEndToEnd(t *testing.T) {
	e := newVFEnv(t)
	var ids []int64
	for i := 0; i < 5; i++ {
		id, _ := e.add("f"+strconv.Itoa(i), "v2", []byte("content "+strconv.Itoa(i)))
		ids = append(ids, id)
	}
	eng := e.engine(t)
	res, err := eng.Execute(context.Background(), ports.KeyJob{Op: ports.KeyJobRotate, Purpose: keyring.PurposeFiles})
	if err != nil || res.Version != 2 {
		t.Fatalf("job: %+v %v", res, err)
	}
	for i, id := range ids {
		if got, err := e.read(t, id); err != nil || string(got) != "content "+strconv.Itoa(i) {
			t.Fatalf("file %d: %q %v", id, got, err)
		}
	}
	if c, _ := e.st.FileKeyCounts(context.Background()); c[1] != 0 || c[2] != 5 {
		t.Fatalf("counts %v", c)
	}
	st, err := eng.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range st.Purposes {
		if p.Purpose != keyring.PurposeFiles {
			continue
		}
		if p.Active != 2 || !p.Rotatable || p.Versions[0].Files != 0 || p.Versions[1].Files != 5 {
			t.Fatalf("status %+v", p)
		}
	}
}

// Re-keying the database file (a tenant import, a restore under another key)
// carries the files and audit-mac DEKs: files still verify and the audit chain
// still verifies, without rewriting either.
func TestRekeyedDatabaseKeepsFilesAndAuditChain(t *testing.T) {
	e := newVFEnv(t)
	e.add("keep.bin", "v2", []byte("kept across the re-keying"))
	for i := 0; i < 3; i++ {
		if _, err := e.st.AuditAppend(AuditRecord{Category: "admin", ActorName: "a", ActorRole: "admin", Action: "x", Target: "t", Outcome: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	e.st.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	key2 := bytes.Repeat([]byte{0x77}, 32)
	dst := e.dir + "/rekeyed.db"
	if err := ExportDatabase(e.st.Path, dst, e.key, key2); err != nil {
		t.Fatal(err)
	}
	if s, err := VerifyAuditDatabase(dst, key2); err != nil || !s.OK || s.Count != 3 {
		t.Fatalf("audit chain after the re-keying: %+v %v", s, err)
	}
	sum, err := VerifyFilesStream(dst, e.dir, key2, VerifyOptions{})
	if err != nil || sum.OK != 1 || sum.Failed != 0 {
		t.Fatalf("files after the re-keying: %+v %v", sum, err)
	}
}
