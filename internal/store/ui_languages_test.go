// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"fmt"
	"testing"
)

func TestUITranslationStore(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.PutUITranslation("pt-br", "Português", map[string]string{"Save": "Salvar"}); err != nil {
		t.Fatal(err)
	}
	st.DB.Close()
	st, err = Open(dir) // migration is idempotent and data survives a restart
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	l, ok, err := st.UITranslation("pt-br")
	if err != nil || !ok || l.Translations["Save"] != "Salvar" || l.Name != "Português" {
		t.Fatal(l, ok, err)
	}
	if !st.ValidUILanguage("pt-br") || !st.ValidUILanguage("nl") || st.ValidUILanguage("zz") || st.ValidUILanguage("") {
		t.Fatal("ValidUILanguage")
	}
	if ValidLanguage("pt-br") {
		t.Fatal("custom language leaked into the built-in check")
	}
	if _, err = st.DB.Exec(`UPDATE users SET ui_language='x'`); err != nil {
		t.Fatal(err)
	}
	// replacement drops old keys
	if err = st.PutUITranslation("pt-br", "PT", map[string]string{"Cancel": "Cancelar"}); err != nil {
		t.Fatal(err)
	}
	l, _, _ = st.UITranslation("pt-br")
	if _, has := l.Translations["Save"]; has || l.Translations["Cancel"] != "Cancelar" {
		t.Fatal(l.Translations)
	}
	if found, err := st.DeleteUITranslation("pt-br"); err != nil || !found {
		t.Fatal(found, err)
	}
	if found, _ := st.DeleteUITranslation("pt-br"); found {
		t.Fatal("deleted twice")
	}
}

func TestUITranslationLimit(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	for i := 0; i < MaxUILanguages; i++ {
		if err = st.PutUITranslation(fmt.Sprintf("x%c", 'a'+i%26)+map[bool]string{true: "-aa", false: ""}[i >= 26], "n", nil); err != nil {
			t.Fatal(i, err)
		}
	}
	if err = st.PutUITranslation("zz", "n", nil); !errors.Is(err, ErrTooManyUILanguages) {
		t.Fatal("limit not enforced", err)
	}
	if err = st.PutUITranslation("xa", "again", nil); err != nil {
		t.Fatal("replace at cap failed", err)
	}
	if err = st.PutUITranslation("nl", "Nederlands", map[string]string{"Save": "Bewaar"}); err != nil {
		t.Fatal("built-in override counted against cap", err)
	}
}
