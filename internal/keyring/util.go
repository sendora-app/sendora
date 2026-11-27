// SPDX-License-Identifier: AGPL-3.0-or-later

package keyring

import (
	"crypto/subtle"
	"sort"
)

func hmacEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
