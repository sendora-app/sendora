// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"testing"
)

func TestMailLanguagePersistence(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB.Exec(`INSERT INTO mail_languages(code,name) VALUES('pt-br','Português (Brasil)')`); err != nil {
		t.Fatal(err)
	}
	if err = st.SetSetting("tpl_verify_email_pt-br", "Código: {{.Code}}"); err != nil {
		t.Fatal(err)
	}
	st.DB.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	if !st.ValidMailLanguage("pt-br") || st.Setting("tpl_verify_email_pt-br") != "Código: {{.Code}}" {
		t.Fatal("language or translation lost on restart")
	}
	languages, err := st.ListMailLanguages()
	if err != nil || len(languages) != 6 {
		t.Fatalf("non-idempotent migration %v %v", languages, err)
	}
	if ValidLanguage("pt-br") {
		t.Fatal("custom email language became UI language")
	}
}
