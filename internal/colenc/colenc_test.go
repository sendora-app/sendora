// SPDX-License-Identifier: AGPL-3.0-or-later

package colenc

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestBlindIndexNormalisation(t *testing.T) {
	cases := []struct {
		in1, in2 string
		same     bool
	}{
		// Case folding
		{"alice@example.com", "ALICE@EXAMPLE.COM", true},
		{"Strauß", "strauss", true}, // ß folds to ss
		{"STRIKE", "strike", true},
		// Unicode whitespace
		{"  user  ", "user", true},
		{"user" + string(rune(0x2003)), "user", true}, // em space
		// Default ignorables & zero width
		{"user" + string(rune(0x200B)) + "name", "username", true}, // zero-width space
		{"user" + string(rune(0xFEFF)) + "name", "username", true}, // BOM
		{"user" + string(rune(0x200D)) + "name", "username", true}, // zero-width joiner
		// Distinct values
		{"user1", "user2", false},
		{"alice@example.com", "bob@example.com", false},
	}

	key := make([]byte, 32)
	for i, tc := range cases {
		b1 := BlindIndex(key, "user:email", tc.in1)
		b2 := BlindIndex(key, "user:email", tc.in2)
		if (bytes.Equal(b1, b2)) != tc.same {
			t.Errorf("case %d (%q vs %q): got same=%v, want %v", i, tc.in1, tc.in2, bytes.Equal(b1, b2), tc.same)
		}
	}

	// Label separation
	b1 := BlindIndex(key, "label:a", "test")
	b2 := BlindIndex(key, "label:b", "test")
	if bytes.Equal(b1, b2) {
		t.Error("different labels must yield different blind indexes")
	}
}

func TestColumnEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	var keyID [16]byte
	rand.Read(keyID[:])
	keyVer := uint32(1)

	plaintext := []byte("Sensitive Secret Personal Information 12345!@#$")
	table, col, rowID := "users", "email", "105"

	cipher, err := Encrypt(key, keyID, keyVer, table, col, rowID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Format check: 0x01 + 4 bytes version + 12 bytes nonce + ...
	if cipher[0] != FormatVersion1 {
		t.Fatalf("wrong format byte: %x", cipher[0])
	}

	decrypted, ver, err := Decrypt(key, keyID, table, col, rowID, cipher)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if ver != keyVer {
		t.Errorf("version mismatch: got %d, want %d", ver, keyVer)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted %q != plaintext %q", decrypted, plaintext)
	}

	// Tamper ciphertext
	tamperedCipher := append([]byte(nil), cipher...)
	tamperedCipher[len(tamperedCipher)-1] ^= 0x01
	if _, _, err := Decrypt(key, keyID, table, col, rowID, tamperedCipher); err == nil {
		t.Error("tampered ciphertext decrypted successfully, expected authentication failure")
	}

	// Mismatched AAD: different row ID
	if _, _, err := Decrypt(key, keyID, table, col, "106", cipher); err == nil {
		t.Error("different rowID decrypted successfully, expected AAD failure")
	}

	// Mismatched AAD: different column
	if _, _, err := Decrypt(key, keyID, table, "name", rowID, cipher); err == nil {
		t.Error("different column decrypted successfully, expected AAD failure")
	}

	// Wrong key
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	if _, _, err := Decrypt(wrongKey, keyID, table, col, rowID, cipher); err == nil {
		t.Error("wrong key decrypted successfully, expected authentication failure")
	}
}

func TestShamirSplitAndCombine(t *testing.T) {
	secret := []byte("master-kek-32-byte-secret-key-12") // 32 bytes
	shares, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}

	for _, s := range shares {
		if !VerifyShareFormat(s) {
			t.Errorf("invalid share format: %q", s)
		}
	}

	// Reconstruct with any 3 shares: (0, 1, 2)
	c1, err := Combine([]string{shares[0], shares[1], shares[2]})
	if err != nil {
		t.Fatalf("Combine(0,1,2): %v", err)
	}
	if !bytes.Equal(c1, secret) {
		t.Errorf("reconstructed %q != original %q", c1, secret)
	}

	// Reconstruct with other 3 shares: (1, 3, 4)
	c2, err := Combine([]string{shares[1], shares[3], shares[4]})
	if err != nil {
		t.Fatalf("Combine(1,3,4): %v", err)
	}
	if !bytes.Equal(c2, secret) {
		t.Errorf("reconstructed %q != original %q", c2, secret)
	}

	// Insufficient shares (2 shares when k=3)
	if _, err := Combine([]string{shares[0], shares[1]}); err == nil {
		t.Error("Combine with 2 shares succeeded, expected threshold error")
	}

	// Duplicate shares should not count towards threshold
	if _, err := Combine([]string{shares[0], shares[0], shares[1]}); err == nil {
		t.Error("Combine with duplicate share succeeded, expected threshold error")
	}
}
