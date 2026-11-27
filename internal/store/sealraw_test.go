// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"testing"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
)

// sealRaw seals the plaintext rows a test wrote with raw SQL into an encrypted
// database (the legacy upgrade path: it also fills the blind indexes).
func sealRaw(t testing.TB, s *Store) {
	t.Helper()
	if _, err := sqlite.New(s.DB).EncryptPlaintextColumns(context.Background(), s.ColumnCodec()); err != nil {
		t.Fatal(err)
	}
}
