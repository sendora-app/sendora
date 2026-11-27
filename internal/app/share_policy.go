// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxSharePasswordBytes is the bcrypt input limit.
const maxSharePasswordBytes = 72

// sharePolicy is the password policy applied to newly created, non-guest shares.
type sharePolicy struct {
	Required  bool
	MinLength int
	Upper     bool
	Lower     bool
	Digit     bool
	Symbol    bool
}

var errSharePolicyConfig = errors.New("share password policy is misconfigured")

func parseStrictBool(v string) (bool, bool) {
	switch v {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

func parseStrictInt(v string, lo, hi int) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

// validateShareSetting checks the new settings keys. ok is false for keys it
// does not own.
func validateShareSetting(key, val string) (owned bool, err error) {
	switch key {
	case "require_share_password", "share_password_require_upper", "share_password_require_lower",
		"share_password_require_digit", "share_password_require_symbol", "allow_preview":
		if _, ok := parseStrictBool(val); !ok {
			return true, fmt.Errorf("%s must be true or false", key)
		}
		return true, nil
	case "share_password_min_length":
		if _, ok := parseStrictInt(val, 1, maxSharePasswordBytes); !ok {
			return true, fmt.Errorf("share_password_min_length must be an integer from 1 to %d", maxSharePasswordBytes)
		}
		return true, nil
	}
	return false, nil
}

// loadSharePolicy reads the stored policy and fails closed on corrupt values.
func (s *Server) loadSharePolicy() (sharePolicy, error) {
	var p sharePolicy
	flags := []struct {
		key string
		dst *bool
	}{
		{"require_share_password", &p.Required},
		{"share_password_require_upper", &p.Upper},
		{"share_password_require_lower", &p.Lower},
		{"share_password_require_digit", &p.Digit},
		{"share_password_require_symbol", &p.Symbol},
	}
	for _, f := range flags {
		v, ok := parseStrictBool(s.St.Setting(f.key))
		if !ok {
			return sharePolicy{}, errSharePolicyConfig
		}
		*f.dst = v
	}
	n, ok := parseStrictInt(s.St.Setting("share_password_min_length"), 1, maxSharePasswordBytes)
	if !ok {
		return sharePolicy{}, errSharePolicyConfig
	}
	p.MinLength = n
	return p, nil
}

// validateSharePassword is pure. An empty password is only valid when the
// policy does not require one.
func validateSharePassword(p sharePolicy, pw string) error {
	if pw == "" {
		if p.Required {
			return errors.New("a share password is required")
		}
		return nil
	}
	switch checkPassword(passwordRules{MinLength: p.MinLength, Upper: p.Upper, Lower: p.Lower, Digit: p.Digit, Symbol: p.Symbol}, pw) {
	case pwTooLong:
		return fmt.Errorf("share password must not exceed %d bytes", maxSharePasswordBytes)
	case pwBadUTF8:
		return errors.New("share password must be valid UTF-8")
	case pwTooShort:
		return fmt.Errorf("share password must be at least %d characters", p.MinLength)
	case pwNoUpper:
		return errors.New("share password must contain an uppercase letter")
	case pwNoLower:
		return errors.New("share password must contain a lowercase letter")
	case pwNoDigit:
		return errors.New("share password must contain a digit")
	case pwNoSymbol:
		return errors.New("share password must contain a symbol")
	}
	return nil
}

// passwordRules are the pure rules shared by the share and account validators.
type passwordRules struct {
	MinLength                   int
	Upper, Lower, Digit, Symbol bool
}

type pwViolation int

const (
	pwOK pwViolation = iota
	pwTooLong
	pwBadUTF8
	pwTooShort
	pwNoUpper
	pwNoLower
	pwNoDigit
	pwNoSymbol
)

// checkPassword is pure and reports the first violated rule: the 72-byte
// bcrypt limit, UTF-8 validity, the minimum length (in runes), then classes.
// Symbol means punctuation, symbol or space.
func checkPassword(r passwordRules, pw string) pwViolation {
	if len(pw) > maxSharePasswordBytes {
		return pwTooLong
	}
	if !utf8.ValidString(pw) {
		return pwBadUTF8
	}
	if utf8.RuneCountInString(pw) < r.MinLength {
		return pwTooShort
	}
	var up, low, dig, sym bool
	for _, c := range pw {
		switch {
		case unicode.IsUpper(c):
			up = true
		case unicode.IsLower(c):
			low = true
		case unicode.IsDigit(c):
			dig = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c) || unicode.IsSpace(c):
			sym = true
		}
	}
	switch {
	case r.Upper && !up:
		return pwNoUpper
	case r.Lower && !low:
		return pwNoLower
	case r.Digit && !dig:
		return pwNoDigit
	case r.Symbol && !sym:
		return pwNoSymbol
	}
	return pwOK
}
