// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"regexp"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/ports"
)

// Deliberately bounded locale syntax for stable template keys (e.g. pt-br, zh-hant).
var mailCodePattern = regexp.MustCompile(`^[a-z]{2,3}(-[a-z0-9]{2,8}){0,2}$`)

func ValidMailCode(code string) bool { return len(code) <= 24 && mailCodePattern.MatchString(code) }

type MailLanguage = ports.MailLanguage

// mailLanguageNames are the names of the built-in MailLanguages, in order.
var mailLanguageNames = []string{"English", "Nederlands", "Deutsch", "Français", "Español"}

func (s *Store) migrateMailLanguages() error {
	return sqlite.MigrateMailLanguages(s.DB, MailLanguages, mailLanguageNames)
}
func (s *Store) ValidMailLanguage(code string) bool {
	if !ValidMailCode(code) {
		return false
	}
	n, err := s.Repos().Mail().CountLanguage(context.Background(), code)
	return err == nil && n == 1
}
func (s *Store) ListMailLanguages() ([]MailLanguage, error) {
	return s.Repos().Mail().ListLanguages(context.Background())
}
