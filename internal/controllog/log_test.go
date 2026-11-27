// SPDX-License-Identifier: AGPL-3.0-or-later

package controllog

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sendora-app/sendora/internal/adapters/keysource"
)

func TestControlLogChainAndMAC(t *testing.T) {
	rawKey := make([]byte, 32)
	rand.Read(rawKey)
	ks, err := keysource.NewFromKey(rawKey)
	if err != nil {
		t.Fatal(err)
	}

	fps, _ := ks.KEKFingerprints(context.Background())
	kekRef := fps[0]

	tenantID := "t_customer1"
	chainID := uuid.New().String()

	// Seq 1: genesis
	seq1Prev := GenesisPrevHash(tenantID, chainID)
	body1 := CanonicalBody(tenantID, 1, seq1Prev, "genesis", []string{chainID, "admin"}, "admin", time.Now().UTC().Format(time.RFC3339))
	hash1 := ComputeEventHash(body1)
	mac1, err := ks.ControlMAC(context.Background(), tenantID, hash1)
	if err != nil {
		t.Fatal(err)
	}

	evt1 := Event{
		TenantID:  tenantID,
		Seq:       1,
		PrevHash:  seq1Prev,
		Kind:      "genesis",
		Body:      body1,
		EventHash: hash1,
		MACKEK:    kekRef,
		MAC:       mac1,
	}

	// Verify Event 1 MAC
	macVerify1, err := ks.ControlMAC(context.Background(), tenantID, evt1.EventHash)
	if err != nil || !bytes.Equal(macVerify1, evt1.MAC) {
		t.Fatal("Event 1 MAC verification failed")
	}

	// Seq 2: key_created (purpose data, version 1)
	keyID := uuid.New().String()
	dek := make([]byte, 32)
	rand.Read(dek)
	fp := fmt.Sprintf("%x", KeyFingerprint(dek))

	body2 := CanonicalBody(tenantID, 2, evt1.EventHash, "key_created", []string{"data", "1", keyID, fp}, "admin", time.Now().UTC().Format(time.RFC3339))
	hash2 := ComputeEventHash(body2)
	mac2, err := ks.ControlMAC(context.Background(), tenantID, hash2)
	if err != nil {
		t.Fatal(err)
	}

	evt2 := Event{
		TenantID:  tenantID,
		Seq:       2,
		PrevHash:  evt1.EventHash,
		Kind:      "key_created",
		Purpose:   "data",
		Version:   1,
		Body:      body2,
		EventHash: hash2,
		MACKEK:    kekRef,
		MAC:       mac2,
	}

	// Verify Event 2 chain & MAC
	if !bytes.Equal(evt2.PrevHash, evt1.EventHash) {
		t.Fatal("Chain broken: evt2.PrevHash != evt1.EventHash")
	}

	macVerify2, err := ks.ControlMAC(context.Background(), tenantID, evt2.EventHash)
	if err != nil || !bytes.Equal(macVerify2, evt2.MAC) {
		t.Fatal("Event 2 MAC verification failed")
	}

	// Tampered body must fail hash and MAC
	tamperedBody := append([]byte(nil), body2...)
	tamperedBody[len(tamperedBody)-1] ^= 0x01
	tamperedHash := ComputeEventHash(tamperedBody)
	if bytes.Equal(tamperedHash, evt2.EventHash) {
		t.Fatal("tampered body produced identical hash")
	}
	if bytes.Equal(macVerify2, tamperedHash) {
		t.Fatal("tampered hash matched MAC")
	}
}
