// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"math"
	"testing"
)

// castInt must give what SQLite's CAST(value AS INTEGER) gave the statements
// that moved into Go when the settings values were sealed.
func TestCastIntMatchesSQLite(t *testing.T) {
	for in, want := range map[string]int64{
		"":                      0,
		"8":                     8,
		" 12":                   12,
		"-5":                    -5,
		"+7":                    7,
		"3x":                    3,
		"bogus":                 0,
		"-":                     0,
		"1e3":                   1,
		"007":                   7,
		"99999999999999999999":  math.MaxInt64,
		"-99999999999999999999": math.MinInt64,
	} {
		if got := castInt(in); got != want {
			t.Errorf("castInt(%q) = %d, want %d", in, got, want)
		}
	}
}
