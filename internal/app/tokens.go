// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the work factor for new account and share password hashes.
// Older hashes are upgraded transparently after a successful check.
const bcryptCost = 12

// hashCost is the cost actually used; always bcryptCost outside tests (the
// tests lower it so the suite stays fast under -race).
var hashCost = bcryptCost

// Token and version purposes: every purpose signs with its own HKDF subkey, so
// a token (or version string) minted for one purpose can never verify as another.
const (
	keyAccess               = "access"
	keyMFA                  = "mfa"
	keyShareUnlock          = "share-unlock"
	keyCredential           = "credential-version"
	keySharePasswordVersion = "share-password-version"
)

// key derives the HMAC subkey for a purpose from the stored secret (HKDF-SHA256).
func (s *Server) key(purpose string) []byte {
	k, err := hkdf.Key(sha256.New, s.Secret, nil, "sendora/v1/"+purpose, 32)
	if err != nil {
		panic(err) // only possible for an absurd output length
	}
	return k
}

func hashPassword(pw string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pw), hashCost)
}

func passwordHashIsWeak(hash string) bool {
	c, err := bcrypt.Cost([]byte(hash))
	return err == nil && c < hashCost
}

// rehashPassword upgrades an account hash that was made with a lower cost. It
// runs after the password has been verified; failures are harmless (the old
// hash keeps working). The compare-and-set keeps a concurrent change intact.
func (s *Server) rehashPassword(u *User, password string) {
	if u == nil || u.passwordHash == "" || !passwordHashIsWeak(u.passwordHash) {
		return
	}
	h, err := hashPassword(password)
	if err != nil {
		return
	}
	n, err := s.St.Repos().Users().ReplacePasswordHash(context.Background(), u.ID, string(h), u.passwordHash)
	if err != nil {
		return
	}
	if n == 1 {
		u.passwordHash = string(h)
	}
}

// ValidateJWTSecret rejects a configured signing secret that is too short or
// has too little variety to resist guessing.
func ValidateJWTSecret(sec string) error {
	if sec == "" {
		return nil
	}
	if len(sec) < 32 {
		return errors.New("JWT_SECRET must be at least 32 characters (leave it unset to use a generated secret)")
	}
	seen := map[byte]bool{}
	for i := 0; i < len(sec); i++ {
		seen[sec[i]] = true
	}
	if len(seen) < 8 {
		return fmt.Errorf("JWT_SECRET is too predictable (%d distinct characters; use random characters, for example: openssl rand -hex 32)", len(seen))
	}
	return nil
}

// validSetupCode checks an operator-provided SENDORA_SETUP_CODE: at least 16
// characters, not one repeated character and not a sequential run.
func validSetupCode(code string) bool {
	if len(code) < 16 {
		return false
	}
	same, up, down := true, true, true
	for i := 1; i < len(code); i++ {
		d := int(code[i]) - int(code[i-1])
		same = same && d == 0
		up = up && d == 1
		down = down && d == -1
	}
	if same || up || down {
		return false
	}
	distinct := map[byte]bool{}
	for i := 0; i < len(code); i++ {
		distinct[code[i]] = true
	}
	return len(distinct) >= 6
}
