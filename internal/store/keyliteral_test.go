// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"testing"
)

func TestHexKeyLiteralFormatAndWipe(t *testing.T) {
	key := bytes.Repeat([]byte{0xab, 0x01}, 16)
	lit := hexKeyLiteral(key)
	want := "x'" + "ab01ab01ab01ab01ab01ab01ab01ab01ab01ab01ab01ab01ab01ab01ab01ab01" + "'"
	if string(lit) != want {
		t.Fatalf("literal %q", lit)
	}
	clear(lit)
	if !bytes.Equal(lit, make([]byte, len(lit))) {
		t.Fatal("literal must be wipeable")
	}
	if len(key) != 32 || key[0] != 0xab {
		t.Fatal("the source key must be untouched")
	}
}

// The encrypted export path (ATTACH ... KEY) wipes its literal after use and must
// keep producing a readable database.
func TestExportStillWorksAfterKeyWipe(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	st, err := OpenEncrypted(t.TempDir(), key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	dest := t.TempDir() + "/export.db"
	if err := exportConnection(st.DB, dest, key); err != nil {
		t.Fatal(err)
	}
	db, err := openCipherDB(dest, key, true)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if !bytes.Equal(key, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("caller's key must not be modified")
	}
}
