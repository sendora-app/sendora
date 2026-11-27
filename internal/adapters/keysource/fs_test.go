// SPDX-License-Identifier: AGPL-3.0-or-later

package keysource

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeySource_WrapUnwrap(t *testing.T) {
	rawKey := make([]byte, 32)
	rand.Read(rawKey)

	ks, err := NewFromKey(rawKey)
	if err != nil {
		t.Fatalf("NewFromKey: %v", err)
	}

	dek := []byte("per-tenant-32-byte-data-enc-key!")
	aad := []byte("tenant-12345/purpose-data/v1")

	wrapped, kekRef, err := ks.Wrap(context.Background(), dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if kekRef == "" {
		t.Fatal("empty kekRef")
	}

	unwrapped, err := ks.Unwrap(context.Background(), wrapped, aad, kekRef)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatalf("unwrapped %q != original %q", unwrapped, dek)
	}

	// Tamper ciphertext
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := ks.Unwrap(context.Background(), tampered, aad, kekRef); err == nil {
		t.Error("tampered ciphertext unwrapped successfully")
	}

	// Wrong AAD
	if _, err := ks.Unwrap(context.Background(), wrapped, []byte("different-aad"), kekRef); err == nil {
		t.Error("wrong AAD unwrapped successfully")
	}

	// Wrong kekRef
	if _, err := ks.Unwrap(context.Background(), wrapped, aad, "nonexistent-ref"); err == nil {
		t.Error("nonexistent kekRef unwrapped successfully")
	}
}

func TestFileKeySource_ControlMAC(t *testing.T) {
	rawKey := make([]byte, 32)
	rand.Read(rawKey)

	ks, err := NewFromKey(rawKey)
	if err != nil {
		t.Fatalf("NewFromKey: %v", err)
	}

	msg := []byte("event-hash-1234567890")
	mac1, err := ks.ControlMAC(context.Background(), "t_acme", msg)
	if err != nil {
		t.Fatalf("ControlMAC: %v", err)
	}
	mac2, err := ks.ControlMAC(context.Background(), "t_acme", msg)
	if err != nil {
		t.Fatalf("ControlMAC: %v", err)
	}
	if !bytes.Equal(mac1, mac2) {
		t.Fatal("deterministic ControlMAC failed")
	}

	// Domain separation by tenant
	macOtherTenant, err := ks.ControlMAC(context.Background(), "t_beta", msg)
	if err != nil {
		t.Fatalf("ControlMAC: %v", err)
	}
	if bytes.Equal(mac1, macOtherTenant) {
		t.Fatal("ControlMAC must differ across tenants")
	}
}

func TestFileKeySource_DirMultiVersion(t *testing.T) {
	dir := t.TempDir()
	k1 := bytes.Repeat([]byte{1}, 32)
	k2 := bytes.Repeat([]byte{2}, 32)

	fp1 := Fingerprint(k1)
	fp2 := Fingerprint(k2)

	if err := os.WriteFile(filepath.Join(dir, "kek-"+fp1), k1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kek-"+fp2), k2, 0o600); err != nil {
		t.Fatal(err)
	}

	ks, err := NewFromDir(dir)
	if err != nil {
		t.Fatalf("NewFromDir: %v", err)
	}

	fps, err := ks.KEKFingerprints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fps) != 2 {
		t.Fatalf("expected 2 fingerprints, got %d", len(fps))
	}

	// Wrap with active (fp1)
	if err := ks.SetActive(fp1); err != nil {
		t.Fatal(err)
	}
	dek := []byte("my-secret-dek-32-byte-string!!!")
	aad := []byte("aad")
	wrapped1, ref1, err := ks.Wrap(context.Background(), dek, aad)
	if err != nil || ref1 != fp1 {
		t.Fatalf("Wrap with fp1: %v, ref: %s", err, ref1)
	}

	// Wrap with new active (fp2)
	if err := ks.SetActive(fp2); err != nil {
		t.Fatal(err)
	}
	wrapped2, ref2, err := ks.Wrap(context.Background(), dek, aad)
	if err != nil || ref2 != fp2 {
		t.Fatalf("Wrap with fp2: %v, ref: %s", err, ref2)
	}

	// Both wraps should unwrap with their respective refs
	u1, err := ks.Unwrap(context.Background(), wrapped1, aad, ref1)
	if err != nil || !bytes.Equal(u1, dek) {
		t.Fatalf("Unwrap 1 failed: %v", err)
	}
	u2, err := ks.Unwrap(context.Background(), wrapped2, aad, ref2)
	if err != nil || !bytes.Equal(u2, dek) {
		t.Fatalf("Unwrap 2 failed: %v", err)
	}
}
