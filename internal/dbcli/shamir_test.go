// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShamirCLI(t *testing.T) {
	dir := t.TempDir()
	origKey := filepath.Join(dir, "orig.key")
	reconstructedKey := filepath.Join(dir, "reconstructed.key")

	keyData := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(origKey, keyData, 0o600); err != nil {
		t.Fatal(err)
	}

	// Capture output from shamir-split
	var splitOut bytes.Buffer
	oldStdout := stdout
	stdout = &splitOut
	defer func() { stdout = oldStdout }()

	if err := run([]string{"shamir-split", "-key-file", origKey, "-threshold", "3", "-shares", "5"}); err != nil {
		t.Fatalf("shamir-split: %v", err)
	}

	var shares []string
	for _, line := range strings.Split(splitOut.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Share ") {
			parts := strings.Split(line, ": ")
			if len(parts) == 2 {
				shares = append(shares, parts[1])
			}
		}
	}

	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d. Output: %s", len(shares), splitOut.String())
	}

	// Test combine with 3 shares
	useShares := strings.Join(shares[1:4], ",")
	if err := run([]string{"shamir-combine", "-destination", reconstructedKey, "-shares", useShares}); err != nil {
		t.Fatalf("shamir-combine: %v", err)
	}

	got, err := os.ReadFile(reconstructedKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, keyData) {
		t.Fatalf("reconstructed data %x != original %x", got, keyData)
	}
}
