// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP per RFC 6238 (HMAC-SHA-1, 6 digits, 30 s step), the profile every common
// authenticator app implements.
const (
	totpDigits = 6
	totpPeriod = 30
	totpWindow = 1 // accept the previous and next step for clock drift
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() (secret []byte, encoded string, err error) {
	secret = make([]byte, 20)
	if _, err = rand.Read(secret); err != nil {
		return nil, "", err
	}
	return secret, totpEncoding.EncodeToString(secret), nil
}

func decodeTOTPSecret(encoded string) ([]byte, error) {
	return totpEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(encoded)))
}

// hotp is RFC 4226 dynamic truncation.
func hotp(secret []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, code%mod)
}

func totpCode(secret []byte, t time.Time) string {
	return hotp(secret, uint64(t.Unix()/totpPeriod))
}

// normalizeTOTPInput strips the spaces apps often show ("123 456").
func normalizeTOTPInput(code string) (string, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return "", false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return code, true
}

// totpMatch returns the time-step counter that matches code within the drift
// window. Every candidate is compared in constant time.
func totpMatch(secret []byte, code string, now time.Time) (counter int64, ok bool) {
	code, valid := normalizeTOTPInput(code)
	if !valid {
		return 0, false
	}
	base := now.Unix() / totpPeriod
	for d := int64(-totpWindow); d <= totpWindow; d++ {
		c := base + d
		if c < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(c))), []byte(code)) == 1 && !ok {
			counter, ok = c, true
		}
	}
	return counter, ok
}

// totpURI is the otpauth:// URI authenticator apps import (also shown as a QR code).
func totpURI(issuer, account, encodedSecret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", encodedSecret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
