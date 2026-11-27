// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxPathSegmentBytes = 200
	maxPathBytes        = 1024
	maxShareNameRunes   = 200
	maxDescriptionRunes = 2000
	maxMessageRunes     = 10000
)

// lookalikeSeparators are characters that render like a path separator but are
// ordinary file name characters to the file system: DIVISION SLASH U+2215,
// FULLWIDTH SOLIDUS U+FF0F and FULLWIDTH REVERSE SOLIDUS U+FF3C.
const lookalikeSeparators = "\u2215\uff0f\uff3c"

// hasFormatRune reports invisible formatting characters (Unicode category Cf),
// which includes the bidirectional overrides (U+202A–202E, U+2066–2069, U+200E/F)
// that make "photo‮gpj.exe" display as an image. Only the zero-width
// (non-)joiners are allowed: emoji sequences and several scripts need them.
func hasFormatRune(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) && r != '‌' && r != '‍' {
			return true
		}
	}
	return false
}

// validateNewPath checks the shape of a path for NEW uploads (never applied to
// stored legacy names): bounded length and no invisible formatting characters.
func validateNewPath(p string) error {
	if len(p) > maxPathBytes || hasFormatRune(p) || strings.ContainsAny(p, lookalikeSeparators) {
		return fmt.Errorf("unsafe file path")
	}
	for _, seg := range strings.Split(strings.ReplaceAll(p, "\\", "/"), "/") {
		if len(seg) > maxPathSegmentBytes {
			return fmt.Errorf("file name too long")
		}
	}
	return nil
}

// validateText bounds a free-text field (counted in characters) and rejects
// invisible formatting characters when strict is set (used for names).
func validateText(s string, maxRunes int, strict bool) error {
	if utf8.RuneCountInString(s) > maxRunes {
		return fmt.Errorf("text too long")
	}
	if strict && hasFormatRune(s) {
		return fmt.Errorf("invalid characters")
	}
	return nil
}

const msgInvalidUsername = "username must be 1 to 64 characters: letters a-z, digits, dot, underscore or hyphen"

// validUsername allows only plain ASCII letters, digits, dot, underscore and
// hyphen: no look-alike letters from other alphabets, no invisible characters,
// nothing that could pass for an email address on the sign-in form. Existing
// accounts keep their names; this applies to new ones.
func validUsername(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
