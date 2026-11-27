// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// WebAuthn ceremonies (registration, login, step-up) as sealed tokens.
//
// The server does not keep pending ceremonies. begin returns a challenge_id
// that carries the ceremony state — kind, user, binding (the mfa_token's jti
// for a login), expiry and the server-random challenge — encrypted and
// authenticated with AES-256-GCM under a key derived from the tenant's secret
// (HKDF, purpose keyWACeremony). Every replica of a tenant derives the same
// key, so a ceremony begun on one replica finishes on any other (Cluster), and
// unauthenticated callers cannot fill server memory with pending ceremonies.
//
// Single use: finishing spends the challenge_id. In the Cluster flavour the
// spend is shared by every replica (RateLimiter); otherwise a bounded local
// set of spent ids decides. When the shared state is unavailable the spend is
// refused (fail closed): the user begins again.

const (
	keyWACeremony = "webauthn-ceremony"
	waCeremonyAAD = "sendora/v1/webauthn-ceremony"
)

var errWACeremony = errors.New("invalid webauthn ceremony")

// waCeremonies remembers spent challenge ids until they expire (the Community
// flavours; Cluster spends through the shared RateLimiter as well).
type waCeremonies struct {
	mu    sync.Mutex
	spent map[string]time.Time
	ttl   time.Duration // 0 = waCeremonyTTL (tests shorten it)
	cap   int           // 0 = waCeremonyCap
}

func (c *waCeremonies) lifetime() time.Duration {
	if c.ttl > 0 {
		return c.ttl
	}
	return waCeremonyTTL
}

func (c *waCeremonies) limit() int {
	if c.cap > 0 {
		return c.cap
	}
	return waCeremonyCap
}

// spend records id as used until exp; false when it already was, or when the
// set is full of live entries (refused rather than forgetting a spend).
func (c *waCeremonies) spend(id string, exp time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.spent == nil {
		c.spent = map[string]time.Time{}
	}
	if e, ok := c.spent[id]; ok && now.Before(e) {
		return false
	}
	if len(c.spent) >= c.limit() {
		for k, e := range c.spent {
			if !now.Before(e) {
				delete(c.spent, k)
			}
		}
		if len(c.spent) >= c.limit() {
			return false
		}
	}
	c.spent[id] = exp
	return true
}

func (c *waCeremonies) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.spent)
}

type waSealed struct {
	Kind      string `json:"k"`
	UID       int64  `json:"u"`
	Bind      string `json:"b,omitempty"`
	Exp       int64  `json:"e"` // Unix milliseconds
	Challenge []byte `json:"c"`
}

func (s *Server) waAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.key(keyWACeremony))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// waBeginCeremony seals a new ceremony and returns its challenge_id.
func (s *Server) waBeginCeremony(kind string, uid int64, bind string, challenge []byte) (string, error) {
	aead, err := s.waAEAD()
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(waSealed{Kind: kind, UID: uid, Bind: bind, Exp: time.Now().Add(s.waCeremonies.lifetime()).UnixMilli(), Challenge: challenge})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, []byte(waCeremonyAAD))), nil
}

// waTakeCeremony opens challenge_id, checks kind, user, binding and expiry,
// spends it, and returns the challenge. Every ceremony completes at most once.
func (s *Server) waTakeCeremony(id, kind string, uid int64, bind string) ([]byte, bool) {
	c, err := s.waOpenCeremony(id)
	if err != nil || c.Kind != kind || c.UID != uid || c.Bind != bind {
		return nil, false
	}
	exp := time.UnixMilli(c.Exp)
	if !time.Now().Before(exp) {
		return nil, false
	}
	if !s.waSpend(id, exp) {
		return nil, false
	}
	return c.Challenge, true
}

func (s *Server) waOpenCeremony(id string) (waSealed, error) {
	var c waSealed
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(id) > 1024 {
		return c, errWACeremony
	}
	aead, err := s.waAEAD()
	if err != nil {
		return c, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return c, errWACeremony
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(waCeremonyAAD))
	if err != nil {
		return c, errWACeremony
	}
	if json.Unmarshal(plain, &c) != nil || len(c.Challenge) == 0 {
		return c, errWACeremony
	}
	return c, nil
}

// waSpend spends a challenge id: shared by every replica in the Cluster
// flavour (fail closed), locally otherwise.
func (s *Server) waSpend(id string, exp time.Time) bool {
	sum := sha256.Sum256([]byte(id))
	key := hex.EncodeToString(sum[:])
	if c := s.cl; c != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		first, err := c.spendOnce(ctx, "wa-ceremony", c.key(key), exp)
		if err != nil {
			c.warn("webauthn ceremony single use (refused)", err)
			return false
		}
		return first
	}
	return s.waCeremonies.spend(key, exp)
}
