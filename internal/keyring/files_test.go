// SPDX-License-Identifier: AGPL-3.0-or-later

package keyring

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestCodecFilesKeyFollowsRotationAndRetirement(t *testing.T) {
	svc, _, _ := setup(t)
	ctx := context.Background()
	if err := svc.Init(ctx, "t1", "test"); err != nil {
		t.Fatal(err)
	}
	c, err := NewCodec(ctx, svc, "t1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m1, v1, err := c.FileMaster(0)
	if err != nil || v1 != 1 || len(m1) != 32 || c.FilesActive() != 1 {
		t.Fatalf("v1: %d %v", v1, err)
	}
	if _, err := svc.Rotate(ctx, "t1", PurposeFiles, "test"); err != nil {
		t.Fatal(err)
	}
	// The codec still writes under version 1 until it follows the keyring.
	if c.FilesActive() != 1 {
		t.Fatal("the codec switched before it was told")
	}
	if changed, err := c.Refresh(ctx); err != nil || !changed || c.FilesActive() != 2 {
		t.Fatalf("refresh: %v %v active=%d", changed, err, c.FilesActive())
	}
	m2, v2, err := c.FileMaster(0)
	if err != nil || v2 != 2 || bytes.Equal(m1, m2) {
		t.Fatalf("v2: %d %v", v2, err)
	}
	if again, _, err := c.FileMaster(1); err != nil || !bytes.Equal(again, m1) {
		t.Fatalf("version 1 stays readable: %v", err)
	}
	if err := svc.Retire(ctx, "t1", PurposeFiles, 1, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.FileMaster(1); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("a retired version: %v", err)
	}
	if _, _, err := c.FileMaster(9); err == nil {
		t.Fatal("an unknown version opened")
	}
	// A codec opened later cannot read the retired version either.
	c2, err := NewCodec(ctx, svc, "t1")
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, _, err := c2.FileMaster(1); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("a retired version on a new codec: %v", err)
	}
	// The audit MAC key is stable and distinct from the files key.
	mac := c.AuditMAC()([]byte("x"))
	if !bytes.Equal(mac, c2.AuditMAC()([]byte("x"))) || bytes.Equal(mac, m2) {
		t.Fatal("audit MAC differs between codecs of one keyring")
	}
}

// Carrying the files and audit-mac DEKs into a new keyring keeps files
// decryptable and the audit MAC identical, while the data key is new.
func TestInitCarryingKeepsFilesAndAuditKeys(t *testing.T) {
	src, _, _ := setup(t)
	ctx := context.Background()
	if err := src.Init(ctx, "t1", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Rotate(ctx, "t1", PurposeFiles, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Rotate(ctx, "t1", PurposeFiles, "test"); err != nil {
		t.Fatal(err)
	}
	if err := src.Retire(ctx, "t1", PurposeFiles, 1, "test"); err != nil {
		t.Fatal(err)
	}
	from, err := NewCodec(ctx, src, "t1")
	if err != nil {
		t.Fatal(err)
	}
	defer from.Close()
	carried, err := src.Export(ctx, "t1", PurposeFiles, PurposeAuditMAC)
	if err != nil {
		t.Fatal(err)
	}
	if len(carried) != 3 { // files v2, v3 and audit-mac v1; the retired v1 is not carried
		t.Fatalf("carried %d keys", len(carried))
	}
	dst, _, _ := setup(t)
	if err := dst.InitCarrying(ctx, "t2", "reseal", carried); err != nil {
		t.Fatal(err)
	}
	st, err := dst.Verify(ctx, "t2")
	if err != nil {
		t.Fatal(err)
	}
	if st.Active[PurposeFiles] != 3 || st.States[PurposeFiles][2] != StateDecryptOnly || st.Active[PurposeData] != 1 {
		t.Fatalf("state %+v", st)
	}
	to, err := NewCodec(ctx, dst, "t2")
	if err != nil {
		t.Fatal(err)
	}
	defer to.Close()
	for _, v := range []int{2, 3} {
		a, _, err1 := from.FileMaster(v)
		b, _, err2 := to.FileMaster(v)
		if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
			t.Fatalf("files v%d differs after the carry: %v %v", v, err1, err2)
		}
	}
	if _, _, err := to.FileMaster(1); err == nil {
		t.Fatal("the retired version was carried")
	}
	if !bytes.Equal(from.AuditMAC()([]byte("x")), to.AuditMAC()([]byte("x"))) {
		t.Fatal("the audit MAC key changed")
	}
	// The column key is new: a value of the source does not open.
	sealed, _ := from.Seal("settings", "value", "k", "v")
	if _, err := to.Open("settings", "value", "k", sealed); err == nil {
		t.Fatal("the data key was carried over")
	}
}
