// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
)

// MailLanguage is an email language.
type MailLanguage struct {
	Code    string `json:"code"`
	Name    string `json:"name"`
	BuiltIn bool   `json:"built_in"`
}

// MailRepository covers email languages (mail_languages) and the email
// template texts (settings of the email_templates group).
type MailRepository interface {
	// LanguageOfUniqueEmail returns the email language of the non-guest
	// account whose trimmed, lower-cased address is email, if no other
	// account has that address; ErrNotFound otherwise.
	LanguageOfUniqueEmail(ctx context.Context, email string) (string, error)
	// LanguageName returns the name of language code; ErrNotFound if unknown.
	LanguageName(ctx context.Context, code string) (string, error)
	// CountLanguage is 1 when language code exists, else 0.
	CountLanguage(ctx context.Context, code string) (int, error)
	// CountLanguages counts the email languages.
	CountLanguages(ctx context.Context) (int, error)
	// AddLanguage stores a custom language; a taken code is an error.
	AddLanguage(ctx context.Context, code, name string) error
	// ListLanguages returns the languages, built-in first, then by code.
	ListLanguages(ctx context.Context) ([]MailLanguage, error)
	// Templates returns every template text (Group empty) ordered by key. A
	// row that cannot be read is returned with the values read so far.
	Templates(ctx context.Context) ([]Setting, error)
	// PutTemplate inserts or replaces a template text; a key of another
	// settings group is left alone.
	PutTemplate(ctx context.Context, key, value string) error
	// SetTemplate changes an existing template text (only in the template
	// group).
	SetTemplate(ctx context.Context, key, value string) error
	// AddEmptyTemplate stores an empty template text; a taken key is an
	// error.
	AddEmptyTemplate(ctx context.Context, key string) error
}

// DownloadMailJob is a pending download notification.
type DownloadMailJob struct {
	ID        int64
	Recipient string
	Language  string
	Data      string
	Attempts  int
}

// UITranslation is a stored UI dictionary (Data: the JSON text).
type UITranslation struct {
	Code, Name, Data string
}

// UITranslationRepository covers stored UI dictionaries (ui_translations).
type UITranslationRepository interface {
	// List returns every dictionary ordered by code.
	List(ctx context.Context) ([]UITranslation, error)
	// Get returns one dictionary; ErrNotFound when none is stored.
	Get(ctx context.Context, code string) (UITranslation, error)
	// Count is 1 when a dictionary for code is stored, else 0.
	Count(ctx context.Context, code string) (int, error)
	// CountCustom counts the dictionaries of codes other than the built-in
	// en, nl, de, fr and es.
	CountCustom(ctx context.Context) (int, error)
	// Put inserts or replaces a dictionary and sets its update time to the
	// current time.
	Put(ctx context.Context, code, name, data string) error
	// Delete removes a dictionary and returns how many rows it removed.
	Delete(ctx context.Context, code string) (int64, error)
	// ResetUsersLanguage moves accounts whose UI language is code to "en".
	ResetUsersLanguage(ctx context.Context, code string) error
}
