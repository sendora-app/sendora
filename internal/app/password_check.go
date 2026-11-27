// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Account password screening, on top of the configurable policy
// (account_policy.go). Share passwords are not screened: their rules are
// unchanged.
//
//   - an embedded list of common passwords (internal/app/data, reproducible with
//     gen_common_passwords.go), compared case-insensitively;
//   - the password must not be or contain the username, the local part of the
//     email address or the application name (case-insensitive, parts of 3+
//     characters);
//   - trivial passwords: one short unit repeated, a straight run such as
//     12345678 or abcdefgh (also backwards), or at most two different characters;
//   - optionally (password_breach_check_online, off by default) the Have I Been
//     Pwned range API with k-anonymity: only the first 5 hex characters of the
//     SHA-1 leave the server. Network trouble never blocks a password change
//     (fail open, logged).

//go:embed data/common-passwords.txt.gz
var commonPasswordsGz []byte

const (
	msgPasswordCommon     = "this password is too common; choose a less predictable one"
	msgPasswordPersonal   = "the password must not contain your username, email address or the application name"
	msgPasswordTrivial    = "the password is too simple (repeated characters or a sequence such as 12345678)"
	msgPasswordBreached   = "this password appears in known data breaches; choose another one"
	settingBreachCheck    = "password_breach_check_online"
	breachCheckTimeout    = 3 * time.Second
	breachMaxResponseSize = 1 << 20
)

var commonPasswords = sync.OnceValue(func() map[string]struct{} {
	set := map[string]struct{}{}
	zr, err := gzip.NewReader(bytes.NewReader(commonPasswordsGz))
	if err != nil {
		panic("embedded common password list: " + err.Error())
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		if p := strings.TrimSpace(sc.Text()); p != "" {
			set[p] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		panic("embedded common password list: " + err.Error())
	}
	return set
})

// isCommonPassword reports whether pw (case-insensitive) is on the embedded list.
func isCommonPassword(pw string) bool {
	_, ok := commonPasswords()[strings.ToLower(pw)]
	return ok
}

// containsPersonal reports whether pw contains one of the given identifiers
// (each at least 3 characters), case-insensitively.
func containsPersonal(pw string, parts ...string) bool {
	low := strings.ToLower(pw)
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if utf8.RuneCountInString(p) >= 3 && strings.Contains(low, p) {
			return true
		}
	}
	return false
}

// isTrivialPassword: a repeated unit (aaaaaaaa, abcabcabc, 12121212), a straight
// run up or down (12345678, abcdefgh, 87654321) or at most two distinct characters.
func isTrivialPassword(pw string) bool {
	r := []rune(strings.ToLower(pw))
	n := len(r)
	if n == 0 {
		return true
	}
	distinct := map[rune]bool{}
	for _, c := range r {
		distinct[c] = true
	}
	if len(distinct) <= 2 {
		return true
	}
	for unit := 1; unit <= n/2; unit++ {
		if n%unit != 0 {
			continue
		}
		repeated := true
		for i := unit; i < n; i++ {
			if r[i] != r[i-unit] {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	if n >= 3 {
		step := r[1] - r[0]
		if step == 1 || step == -1 {
			straight := true
			for i := 2; i < n; i++ {
				if r[i]-r[i-1] != step {
					straight = false
					break
				}
			}
			if straight {
				return true
			}
		}
	}
	return false
}

// screenAccountPassword applies the offline rules. username and email may be
// empty (they are then not compared).
func (s *Server) screenAccountPassword(pw, username, email string) error {
	if s.passwordScreenOff {
		return nil
	}
	local := email
	if i := strings.LastIndexByte(email, '@'); i >= 0 {
		local = email[:i]
	}
	switch {
	case isCommonPassword(pw):
		return errors.New(msgPasswordCommon)
	case containsPersonal(pw, username, local, s.St.Setting("application_name")):
		return errors.New(msgPasswordPersonal)
	case isTrivialPassword(pw):
		return errors.New(msgPasswordTrivial)
	}
	return nil
}

// breachRangeURL and breachClient are variables so tests can point the check at
// a local server (the guarded client refuses loopback addresses).
var (
	breachRangeURL = "https://api.pwnedpasswords.com/range/"
	breachClient   = func() *http.Client { return providerClient() }
)

// passwordBreached asks the Have I Been Pwned range API whether pw is known from
// breaches. Only the first five hex characters of the SHA-1 are sent; the
// comparison of the rest happens here. Any failure answers false (fail open)
// with a logged warning: an unreachable service must not block a password change.
func (s *Server) passwordBreached(ctx context.Context, pw string) bool {
	// SHA-1 is mandated by the HIBP k-anonymity range API (it indexes breached
	// passwords by SHA-1); no other algorithm can be queried. This digest is
	// never stored or used for authentication: password storage uses bcrypt.
	// Only the first 5 hex characters (20 bits) leave the server, and the
	// remaining suffix is compared locally against the padded response.
	// (Intentional; see CodeQL go/weak-sensitive-data-hashing.)
	sum := sha1.Sum([]byte(pw))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, rest := hash[:5], hash[5:]
	ctx, cancel := context.WithTimeout(ctx, breachCheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, breachRangeURL+prefix, nil)
	if err != nil {
		log.Printf("password breach check skipped: %v", err)
		return false
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "Sendora-password-check")
	res, err := breachClient().Do(req)
	if err != nil {
		log.Printf("password breach check unavailable (password accepted): %v", err)
		return false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Printf("password breach check unavailable (password accepted): status %d", res.StatusCode)
		return false
	}
	sc := bufio.NewScanner(io.LimitReader(res.Body, breachMaxResponseSize))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		suffix, count, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(suffix, rest) {
			continue
		}
		// Padding entries have a count of 0.
		return strings.TrimLeft(strings.TrimSpace(count), "0") != ""
	}
	if err := sc.Err(); err != nil {
		log.Printf("password breach check unavailable (password accepted): %v", err)
	}
	return false
}

// checkAccountPassword is the full check: policy, offline screening and the
// optional online breach check.
func (s *Server) checkAccountPassword(ctx context.Context, pw, username, email string) (status int, err error) {
	p, perr := s.loadAccountPolicy()
	if perr != nil {
		return http.StatusInternalServerError, fmt.Errorf("password policy unavailable")
	}
	if err := validateAccountPassword(p, pw); err != nil {
		return http.StatusBadRequest, err
	}
	if err := s.screenAccountPassword(pw, username, email); err != nil {
		return http.StatusBadRequest, err
	}
	if v, ok := parseStrictBool(s.St.Setting(settingBreachCheck)); ok && v && s.passwordBreached(ctx, pw) {
		return http.StatusBadRequest, errors.New(msgPasswordBreached)
	}
	return 0, nil
}
