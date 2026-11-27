// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sendora-app/sendora/internal/filecrypt"
)

func TestStageUploadFileEncryptsAndReadsBack(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, 3*filecrypt.ChunkSize+99)
	rand.Read(raw)
	src := filepath.Join(dir, "0.part")
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 32)
	rand.Read(k)
	master, err := filecrypt.MasterKey(k)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "final")
	sum, encID, err := stageUploadFile(context.Background(), src, dest, int64(len(raw)), master, true)
	if err != nil || len(encID) != 32 {
		t.Fatalf("stage: encID=%q err=%v", encID, err)
	}
	want := sha256.Sum256(raw)
	if sum != hex.EncodeToString(want[:]) {
		t.Fatal("checksum is not of the plaintext")
	}
	stored, _ := os.ReadFile(dest)
	if bytes.Contains(stored, raw[:64]) {
		t.Fatal("plaintext found on disk")
	}
	f, _ := os.Open(dest)
	st, _ := f.Stat()
	r, err := filecrypt.NewReader(f, st.Size(), int64(len(raw)), master, encID)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("read back failed: %v", err)
	}
}

func TestStageUploadFilePlainWithoutKeyAndEmptyFile(t *testing.T) {
	dir := t.TempDir()
	sum, encID, err := stageUploadFile(context.Background(), filepath.Join(dir, "missing.part"), filepath.Join(dir, "empty"), 0, nil, false)
	if err != nil || encID != "" {
		t.Fatalf("empty plain: encID=%q err=%v", encID, err)
	}
	if want := sha256.Sum256(nil); sum != hex.EncodeToString(want[:]) {
		t.Fatal("empty checksum wrong")
	}
	k := make([]byte, 32)
	master, _ := filecrypt.MasterKey(k)
	if _, encID, err = stageUploadFile(context.Background(), filepath.Join(dir, "missing.part"), filepath.Join(dir, "empty2"), 0, master, true); err != nil || encID == "" {
		t.Fatalf("empty encrypted: encID=%q err=%v", encID, err)
	}
	if _, _, err = stageUploadFile(context.Background(), filepath.Join(dir, "missing.part"), filepath.Join(dir, "x"), 5, nil, false); err == nil {
		t.Fatal("missing source with size>0 must fail")
	}
}

// An encrypted store without a usable key must never write a plain file, and a
// failed encryption leaves no partial destination behind.
func TestStageUploadFileRefusesPlaintextFallback(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "0.part")
	if err := os.WriteFile(src, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, key := range [][]byte{nil, make([]byte, 5)} {
		dest := filepath.Join(dir, "plain-out")
		if _, _, err := stageUploadFile(context.Background(), src, dest, 6, key, true); err == nil {
			t.Fatal("encrypted store wrote without a file key")
		}
		if _, err := os.Stat(dest); err == nil {
			t.Fatal("destination exists after refusal")
		}
	}
	// Encryption fails midway (source shorter than declared): dest is removed.
	dest := filepath.Join(dir, "partial")
	k, _ := filecrypt.MasterKey(make([]byte, 32))
	if _, _, err := stageUploadFile(context.Background(), src, dest, 5, k, true); err == nil {
		t.Fatal("size mismatch accepted")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("partial destination left behind")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := stageUploadFile(ctx, src, dest, 6, k, true); err == nil {
		t.Fatal("cancelled stage succeeded")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("partial destination left behind after cancel")
	}
}
