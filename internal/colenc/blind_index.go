// SPDX-License-Identifier: AGPL-3.0-or-later

package colenc

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// Normalise implements the NFKC_Casefold-style pipeline per DESIGN §6.8:
// 1. NFKC
// 2. Full Unicode case folding (cases.Fold(), length-changing like ß -> ss)
// 3. NFKC again
// 4. Removal of default-ignorable code points and zero-width characters
// 5. Trim Unicode whitespace
func Normalise(s string) string {
	// Step 1: NFKC
	s = norm.NFKC.String(s)

	// Step 2: Full case folding
	folder := cases.Fold()
	s = folder.String(s)

	// Step 3: NFKC again (case folding might de-normalise)
	s = norm.NFKC.String(s)

	// Step 4: Remove default-ignorable & zero-width code points
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isIgnorable(r) {
			continue
		}
		b.WriteRune(r)
	}

	// Step 5: Trim Unicode whitespace
	return strings.TrimFunc(b.String(), unicode.IsSpace)
}

func isIgnorable(r rune) bool {
	// Zero-width characters & default ignorables
	switch r {
	case 0x200B, // Zero-width space
		0x200C, // Zero-width non-joiner
		0x200D, // Zero-width joiner
		0x200E, // LTR mark
		0x200F, // RTL mark
		0xFEFF: // Zero-width no-break space / BOM
		return true
	}
	// Unicode default-ignorable code point ranges
	if r >= 0x2060 && r <= 0x206F { // General punctuation ignorables
		return true
	}
	if r >= 0xFFF0 && r <= 0xFFF8 { // Specials
		return true
	}
	if r >= 0xE0000 && r <= 0xE0FFF { // Tags and variation selectors
		return true
	}
	return false
}

// BlindIndex computes the truncated 16-byte HMAC blind index for an equality query:
// bi = HMAC-SHA256(indexKey, label ‖ normalise(value))[:16]
func BlindIndex(indexKey []byte, label, value string) []byte {
	normVal := Normalise(value)
	mac := hmac.New(sha256.New, indexKey)
	mac.Write([]byte(label))
	mac.Write([]byte(normVal))
	sum := mac.Sum(nil)
	res := make([]byte, 16)
	copy(res, sum[:16])
	return res
}
