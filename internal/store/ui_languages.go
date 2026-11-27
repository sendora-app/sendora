// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/ports"
)

// UI languages are bundled in the frontend (en, nl, de, fr, es). Administrators can
// override single texts of those languages and add further languages at runtime
// through JSON; the stored dictionaries live here, keyed by language code.

// BuiltinUILanguage is a language whose dictionary ships with the frontend.
type BuiltinUILanguage struct{ Code, Name string }

var BuiltinUILanguages = []BuiltinUILanguage{
	{"en", "English"}, {"nl", "Nederlands"}, {"de", "Deutsch"}, {"fr", "Français"}, {"es", "Español"},
}

// MaxUILanguages bounds the stored dictionaries (custom languages plus overrides).
const MaxUILanguages = 32

var ErrTooManyUILanguages = errors.New("too many languages")

func BuiltinUILanguageName(code string) (string, bool) {
	for _, l := range BuiltinUILanguages {
		if l.Code == code {
			return l.Name, true
		}
	}
	return "", false
}

// ValidUICodeSyntax is the pure syntax check for a UI language code; it is the
// same bounded locale syntax as the email language codes (e.g. pt-br, zh-hant).
func ValidUICodeSyntax(code string) bool { return ValidMailCode(code) }

func (s *Store) migrateUITranslations() error { return sqlite.MigrateUITranslations(s.DB) }

// StoredUILanguage is one stored dictionary row.
type StoredUILanguage struct {
	Code         string
	Name         string
	Translations map[string]string
	Raw          string // exact stored JSON, used for ETags
}

// ListUITranslations returns all stored dictionaries ordered by code. The rows
// are fully read and closed before it returns (single pooled connection).
func (s *Store) ListUITranslations() ([]StoredUILanguage, error) {
	stored, err := s.Repos().UITranslations().List(context.Background())
	if err != nil {
		return nil, err
	}
	var out []StoredUILanguage
	for _, x := range stored {
		out = append(out, StoredUILanguage{Code: x.Code, Name: x.Name, Raw: x.Data})
	}
	for i := range out {
		out[i].Translations = map[string]string{}
		// A corrupt row serves as an empty dictionary rather than failing the list.
		_ = json.Unmarshal([]byte(out[i].Raw), &out[i].Translations)
		if out[i].Translations == nil {
			out[i].Translations = map[string]string{}
		}
	}
	return out, nil
}

// UITranslation returns one stored dictionary; ok is false when none is stored.
func (s *Store) UITranslation(code string) (StoredUILanguage, bool, error) {
	x, err := s.Repos().UITranslations().Get(context.Background(), code)
	l := StoredUILanguage{Code: x.Code, Name: x.Name, Raw: x.Data}
	if errors.Is(err, ports.ErrNotFound) {
		return l, false, nil
	}
	if err != nil {
		return l, false, err
	}
	l.Translations = map[string]string{}
	_ = json.Unmarshal([]byte(l.Raw), &l.Translations)
	if l.Translations == nil {
		l.Translations = map[string]string{}
	}
	return l, true, nil
}

// PutUITranslation replaces the stored dictionary of a language atomically.
// A new language beyond MaxUILanguages is refused.
func (s *Store) PutUITranslation(code, name string, translations map[string]string) error {
	data, err := json.Marshal(translations)
	if err != nil {
		return err
	}
	ctx := context.Background()
	tx, err := s.Repos().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	exists, err := tx.UITranslations().Count(ctx, code)
	if err != nil {
		return err
	}
	if _, builtin := BuiltinUILanguageName(code); exists == 0 && !builtin {
		// Overrides of built-in languages do not count towards the limit.
		n, err := tx.UITranslations().CountCustom(ctx)
		if err != nil {
			return err
		}
		if n >= MaxUILanguages {
			return ErrTooManyUILanguages
		}
	}
	if err := tx.UITranslations().Put(ctx, code, name, string(data)); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteUITranslation removes a stored dictionary. Users whose menu language was
// the removed custom language fall back to English. Reports whether a row existed.
func (s *Store) DeleteUITranslation(code string) (bool, error) {
	ctx := context.Background()
	tx, err := s.Repos().Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	n, err := tx.UITranslations().Delete(ctx, code)
	if err != nil {
		return false, err
	}
	if _, builtin := BuiltinUILanguageName(code); !builtin && n > 0 {
		if err := tx.UITranslations().ResetUsersLanguage(ctx, code); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

// ValidUILanguage accepts the built-in languages and any stored custom language.
// It queries the database: never call it while a transaction or rows hold the
// single pooled connection.
func (s *Store) ValidUILanguage(code string) bool {
	if _, ok := BuiltinUILanguageName(code); ok {
		return true
	}
	if !ValidUICodeSyntax(code) {
		return false
	}
	n, err := s.Repos().UITranslations().Count(context.Background(), code)
	if err != nil {
		return false
	}
	return n == 1
}
