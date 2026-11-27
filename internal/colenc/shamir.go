// SPDX-License-Identifier: AGPL-3.0-or-later

package colenc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Shamir 3-of-5 Secret Sharing over GF(256) per DESIGN §6.9
// Field arithmetic uses the Rijndael / AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11b)

const (
	DefaultThreshold = 3
	DefaultShares    = 5
)

// gf256 tables
var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	var x byte = 1
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfExp[i+255] = x
		gfLog[x] = byte(i)
		// multiply by 3 (generator for 0x11b)
		var p byte
		if x&0x80 != 0 {
			p = (x << 1) ^ 0x1b
		} else {
			p = x << 1
		}
		x = p ^ x
	}
	gfExp[255] = gfExp[0]
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(256)")
	}
	if a == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])-int(gfLog[b])+255)%255]
}

func gfAdd(a, b byte) byte {
	return a ^ b
}

func evalPoly(poly []byte, x byte) byte {
	var res byte
	for i := len(poly) - 1; i >= 0; i-- {
		res = gfAdd(gfMul(res, x), poly[i])
	}
	return res
}

// Split splits a secret into n shares with threshold k.
// Each share is formatted as: "shamir-v1-<k>-<index>-<hex(share_data)>"
func Split(secret []byte, k, n int) ([]string, error) {
	if k < 2 || k > n || n > 255 {
		return nil, errors.New("invalid threshold or share count (2 <= k <= n <= 255)")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	// Each share gets an x-coordinate in [1, n]
	sharesData := make([][]byte, n)
	for i := range sharesData {
		sharesData[i] = make([]byte, len(secret))
	}

	coeff := make([]byte, k)
	for byteIdx, secretByte := range secret {
		coeff[0] = secretByte
		if _, err := io.ReadFull(rand.Reader, coeff[1:]); err != nil {
			return nil, fmt.Errorf("generating random coefficients: %w", err)
		}

		for i := 0; i < n; i++ {
			x := byte(i + 1)
			sharesData[i][byteIdx] = evalPoly(coeff, x)
		}
	}

	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = fmt.Sprintf("shamir-v1-%d-%d-%s", k, i+1, hex.EncodeToString(sharesData[i]))
	}
	return out, nil
}

// Combine reconstructs the secret using Lagrange interpolation at x = 0
func Combine(shares []string) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	type parsedShare struct {
		x    byte
		data []byte
	}

	var threshold int
	seenX := make(map[byte]bool)
	parsed := make([]parsedShare, 0, len(shares))
	expectedLen := -1

	for _, s := range shares {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		parts := strings.Split(s, "-")
		if len(parts) != 5 || parts[0] != "shamir" || parts[1] != "v1" {
			return nil, fmt.Errorf("invalid share format: %q", s)
		}
		k, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid threshold in share: %w", err)
		}
		if threshold == 0 {
			threshold = k
		} else if threshold != k {
			return nil, errors.New("shares have mismatched thresholds")
		}

		idx, err := strconv.Atoi(parts[3])
		if err != nil || idx < 1 || idx > 255 {
			return nil, fmt.Errorf("invalid share index: %q", parts[3])
		}
		x := byte(idx)
		if seenX[x] {
			continue // ignore duplicate x
		}
		seenX[x] = true

		data, err := hex.DecodeString(parts[4])
		if err != nil {
			return nil, fmt.Errorf("invalid hex data in share: %w", err)
		}
		if expectedLen == -1 {
			expectedLen = len(data)
		} else if expectedLen != len(data) {
			return nil, errors.New("shares have mismatched secret lengths")
		}

		parsed = append(parsed, parsedShare{x: x, data: data})
	}

	if len(parsed) < threshold {
		return nil, fmt.Errorf("insufficient shares: got %d distinct shares, need at least %d", len(parsed), threshold)
	}

	// Use exactly threshold shares
	useShares := parsed[:threshold]
	secret := make([]byte, expectedLen)

	for byteIdx := 0; byteIdx < expectedLen; byteIdx++ {
		var secretByte byte
		for i := 0; i < threshold; i++ {
			xi := useShares[i].x
			yi := useShares[i].data[byteIdx]

			// Lagrange basis polynomial evaluated at x = 0:
			// L_i(0) = Prod_{j != i} (0 - x_j) / (x_i - x_j) = Prod (x_j) / (x_i ^ x_j)
			var li byte = 1
			for j := 0; j < threshold; j++ {
				if i == j {
					continue
				}
				xj := useShares[j].x
				num := xj
				den := gfAdd(xi, xj)
				term := gfDiv(num, den)
				li = gfMul(li, term)
			}
			termVal := gfMul(yi, li)
			secretByte = gfAdd(secretByte, termVal)
		}
		secret[byteIdx] = secretByte
	}

	return secret, nil
}

// VerifyShareFormat checks if string is valid Shamir share format
func VerifyShareFormat(s string) bool {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) != 5 || parts[0] != "shamir" || parts[1] != "v1" {
		return false
	}
	k, err1 := strconv.Atoi(parts[2])
	idx, err2 := strconv.Atoi(parts[3])
	if err1 != nil || err2 != nil || k < 2 || idx < 1 || idx > 255 {
		return false
	}
	_, err3 := hex.DecodeString(parts[4])
	return err3 == nil
}

func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
