// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"testing"
	"time"
)

// RFC 6238 appendix B vectors (HMAC-SHA-1, secret "12345678901234567890"); the RFC
// lists 8 digits, an authenticator app shows the last six.
func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if got := totpCode(secret, time.Unix(v.unix, 0)); got != v.code {
			t.Fatalf("t=%d want %s got %s", v.unix, v.code, got)
		}
	}
}

func TestTOTPWindowAndInput(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	cur := totpCode(secret, now)
	if c, ok := totpMatch(secret, cur, now); !ok || c != now.Unix()/30 {
		t.Fatal("current step must match", c, ok)
	}
	for _, d := range []int{-1, 1} {
		code := totpCode(secret, now.Add(time.Duration(d*30)*time.Second))
		if _, ok := totpMatch(secret, code, now); !ok {
			t.Fatalf("step %+d must be inside the drift window", d)
		}
	}
	for _, d := range []int{-2, 2, 10} {
		code := totpCode(secret, now.Add(time.Duration(d*30)*time.Second))
		if _, ok := totpMatch(secret, code, now); ok {
			t.Fatalf("step %+d must be outside the drift window", d)
		}
	}
	if _, ok := totpMatch(secret, cur[:3]+" "+cur[3:], now); !ok {
		t.Fatal("a code shown as '123 456' must be accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "12345a", "١٢٣٤٥٦", "      ", "-12345"} {
		if _, ok := totpMatch(secret, bad, now); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestTOTPSecretAndURI(t *testing.T) {
	raw, enc, err := newTOTPSecret()
	if err != nil || len(raw) != 20 || len(enc) != 32 {
		t.Fatal(len(raw), len(enc), err)
	}
	back, err := decodeTOTPSecret(" " + enc + " ")
	if err != nil || string(back) != string(raw) {
		t.Fatal("secret must round-trip", err)
	}
	uri := totpURI("My App", "ali ce", enc)
	for _, want := range []string{"otpauth://totp/My%20App:ali%20ce?", "secret=" + enc, "issuer=My+App", "algorithm=SHA1", "digits=6", "period=30"} {
		if !contains(uri, want) {
			t.Fatalf("uri %q lacks %q", uri, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestRecoveryCodeFormat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c := newRecoveryCode()
		if len(c) != 19 || c[4] != '-' || c[9] != '-' || c[14] != '-' {
			t.Fatalf("format %q", c)
		}
		n, ok := normalizeRecoveryCode(c)
		if !ok || len(n) != 16 || seen[n] {
			t.Fatalf("code %q ok=%v dup=%v", c, ok, seen[n])
		}
		seen[n] = true
		if lower, ok := normalizeRecoveryCode(" " + toLower(c) + " "); !ok || lower != n {
			t.Fatal("codes are case/space/dash tolerant")
		}
	}
	for _, bad := range []string{"", "ABCD", "ABCD-EFGH-IJKL-MNO0", "0000-0000-0000-0000", "ABCD-EFGH-IJKL-MNOPQ"} {
		if _, ok := normalizeRecoveryCode(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
