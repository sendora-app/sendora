// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/sendora-app/sendora/internal/store"
)

// accountPolicy is the password policy for local user accounts. A password is
// always required; existing accounts are only checked at their next change.
type accountPolicy struct {
	MinLength                   int
	Upper, Lower, Digit, Symbol bool
}

var errAccountPolicyConfig = errors.New("account password policy is misconfigured")

// strictestAccountPolicy is what is advertised (and enforced) on corrupt config.
var strictestAccountPolicy = accountPolicy{MinLength: maxSharePasswordBytes, Upper: true, Lower: true, Digit: true, Symbol: true}

// validateAccountSetting checks the account policy keys. owned is false for keys it does not own.
func validateAccountSetting(key, val string) (owned bool, err error) {
	if owned, err := validatePasswordRotationSetting(key, val); owned {
		return true, err
	}
	switch key {
	case "account_password_require_upper", "account_password_require_lower",
		"account_password_require_digit", "account_password_require_symbol":
		if _, ok := parseStrictBool(val); !ok {
			return true, fmt.Errorf("%s must be true or false", key)
		}
		return true, nil
	case "account_password_min_length":
		if _, ok := parseStrictInt(val, store.AccountPasswordMinFloor, maxSharePasswordBytes); !ok {
			return true, fmt.Errorf("account_password_min_length must be an integer from %d to %d", store.AccountPasswordMinFloor, maxSharePasswordBytes)
		}
		return true, nil
	}
	return false, nil
}

// loadAccountPolicy reads the stored policy and fails closed on corrupt values.
func (s *Server) loadAccountPolicy() (accountPolicy, error) {
	var p accountPolicy
	flags := []struct {
		key string
		dst *bool
	}{
		{"account_password_require_upper", &p.Upper},
		{"account_password_require_lower", &p.Lower},
		{"account_password_require_digit", &p.Digit},
		{"account_password_require_symbol", &p.Symbol},
	}
	for _, f := range flags {
		v, ok := parseStrictBool(s.St.Setting(f.key))
		if !ok {
			return accountPolicy{}, errAccountPolicyConfig
		}
		*f.dst = v
	}
	n, ok := parseStrictInt(s.St.Setting("account_password_min_length"), 1, maxSharePasswordBytes)
	if !ok {
		return accountPolicy{}, errAccountPolicyConfig
	}
	// A value below the floor (written before the floor existed and not yet
	// migrated) never weakens the check.
	p.MinLength = max(n, store.AccountPasswordMinFloor)
	return p, nil
}

// validateAccountPassword is pure. An empty password is never valid.
func validateAccountPassword(p accountPolicy, pw string) error {
	switch checkPassword(passwordRules{MinLength: p.MinLength, Upper: p.Upper, Lower: p.Lower, Digit: p.Digit, Symbol: p.Symbol}, pw) {
	case pwTooLong:
		return fmt.Errorf("password must not exceed %d bytes", maxSharePasswordBytes)
	case pwBadUTF8:
		return errors.New("password must be valid UTF-8")
	case pwTooShort:
		return fmt.Errorf("password must be at least %d characters", p.MinLength)
	case pwNoUpper:
		return errors.New("password must contain an uppercase letter")
	case pwNoLower:
		return errors.New("password must contain a lowercase letter")
	case pwNoDigit:
		return errors.New("password must contain a digit")
	case pwNoSymbol:
		return errors.New("password must contain a symbol")
	}
	return nil
}

// requireAccountPassword writes the error response and returns false when pw
// violates the policy or the screening (400) or the stored policy is corrupt
// (500). who is the account's username and email address (either may be
// missing), so the password cannot simply repeat them (password_check.go).
func (s *Server) requireAccountPassword(w http.ResponseWriter, r *http.Request, pw string, who ...string) bool {
	who = append(who, "", "")
	if code, err := s.checkAccountPassword(r.Context(), pw, who[0], who[1]); err != nil {
		jerr(w, code, err.Error())
		return false
	}
	return true
}
