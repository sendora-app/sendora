// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/sendora-app/sendora/internal/store"
)

// Runtime UI translations: administrators export/import JSON dictionaries for the
// interface texts (the English text is the key, as in the frontend bundle). The
// bundled dictionaries ship with the frontend; stored dictionaries override them
// per key. Limits keep imports small and safe; values are only ever rendered as text.
const (
	uiMaxKeys       = 3000
	uiMaxValueBytes = 2000
	uiMaxNameBytes  = 80
	uiMaxBodyBytes  = 1 << 20
	uiKeysFile      = "i18n-keys/keys.json"
	uiServerMsgFile = "i18n-keys/server-messages.json"
)

// uiKeyCache holds the known translation keys, loaded lazily from the embedded
// frontend build (the single source of truth: no copy in Go that could drift).
type uiKeyCache struct {
	once sync.Once
	keys map[string]bool
	err  error
}

var uiPlaceholderPattern = regexp.MustCompile(`\{[A-Za-z0-9_]+\}|%[sdqvw]`)

// uiPlaceholders returns the sorted placeholders of a text (as a multiset).
func uiPlaceholders(s string) []string {
	found := uiPlaceholderPattern.FindAllString(s, -1)
	sort.Strings(found)
	return found
}

func samePlaceholders(a, b string) bool {
	x, y := uiPlaceholders(a), uiPlaceholders(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func (s *Server) knownUIKeys() (map[string]bool, error) {
	s.uiKeys.once.Do(func() {
		read := func(name string) ([]byte, error) {
			f, err := s.Static.Open(name)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return io.ReadAll(io.LimitReader(f, 4<<20))
		}
		keys := map[string]bool{}
		raw, err := read(uiKeysFile)
		if err != nil {
			s.uiKeys.err = fmt.Errorf("translation key list unavailable")
			return
		}
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			s.uiKeys.err = fmt.Errorf("translation key list unavailable")
			return
		}
		for _, k := range list {
			keys[k] = true
		}
		if raw, err := read(uiServerMsgFile); err == nil {
			var msgs struct {
				Static  []string `json:"static"`
				Dynamic []string `json:"dynamic"`
			}
			if json.Unmarshal(raw, &msgs) == nil {
				for _, k := range msgs.Static {
					keys[k] = true
				}
				for _, k := range msgs.Dynamic {
					keys[k] = true
				}
			}
		}
		s.uiKeys.keys = keys
	})
	return s.uiKeys.keys, s.uiKeys.err
}

func uiValidName(name string) bool {
	if name == "" || len(name) > uiMaxNameBytes || !utf8.ValidString(name) || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return !hasFormatRune(name)
}

func uiValidValue(v string) bool {
	if len(v) > uiMaxValueBytes || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || (unicode.Is(unicode.Cf, r) && r != '‌' && r != '‍') {
			return false
		}
	}
	return true
}

func clipForMessage(s string) string {
	if len(s) > 60 {
		return strings.ToValidUTF8(s[:60], "") + "…"
	}
	return s
}

// validateUITranslations checks a dictionary against the known key set. The
// returned message is safe to show to the administrator.
func validateUITranslations(tr map[string]string, known map[string]bool) error {
	if len(tr) > uiMaxKeys {
		return fmt.Errorf("too many translations (at most %d)", uiMaxKeys)
	}
	for key, value := range tr {
		if !known[key] {
			return fmt.Errorf("unknown translation key: %q", clipForMessage(key))
		}
		if !uiValidValue(value) {
			return fmt.Errorf("invalid translation (too long or invalid characters) for key %q", clipForMessage(key))
		}
		if !samePlaceholders(key, value) {
			return fmt.Errorf("the placeholders of the translation for %q do not match the original", clipForMessage(key))
		}
	}
	return nil
}

type uiLanguageInfo struct {
	Code       string `json:"code"`
	Name       string `json:"name"`
	BuiltIn    bool   `json:"built_in"`
	Stored     bool   `json:"stored"`
	Keys       int    `json:"keys"`
	Translated int    `json:"translated"`
}

func translatedCount(tr map[string]string) int {
	n := 0
	for k, v := range tr {
		if v != "" && v != k {
			n++
		}
	}
	return n
}

// listUILanguages: GET /api/ui-languages (admin).
func (s *Server) listUILanguages(w http.ResponseWriter, r *http.Request) {
	known, err := s.knownUIKeys()
	if err != nil {
		jerr(w, 503, err.Error())
		return
	}
	stored, err := s.St.ListUITranslations()
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	byCode := map[string]store.StoredUILanguage{}
	for _, l := range stored {
		byCode[l.Code] = l
	}
	out := []uiLanguageInfo{}
	for _, b := range store.BuiltinUILanguages {
		info := uiLanguageInfo{Code: b.Code, Name: b.Name, BuiltIn: true}
		if l, ok := byCode[b.Code]; ok {
			info.Stored, info.Keys, info.Translated = true, len(l.Translations), translatedCount(l.Translations)
		}
		out = append(out, info)
	}
	for _, l := range stored {
		if _, builtin := store.BuiltinUILanguageName(l.Code); builtin {
			continue
		}
		out = append(out, uiLanguageInfo{Code: l.Code, Name: l.Name, Stored: true, Keys: len(l.Translations), Translated: translatedCount(l.Translations)})
	}
	jout(w, 200, map[string]any{"limit": store.MaxUILanguages, "total_keys": len(known), "languages": out})
}

// exportUILanguage: GET /api/ui-languages/{code}/export (admin). Exports what is
// stored on the server; the browser builds complete files (bundled + stored).
func (s *Server) exportUILanguage(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	if !store.ValidUICodeSyntax(code) {
		jerr(w, 404, "language not found")
		return
	}
	l, ok, err := s.St.UITranslation(code)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if !ok {
		jerr(w, 404, "language not found")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="sendora-ui-`+code+`.json"`)
	jout(w, 200, map[string]any{"code": l.Code, "name": l.Name, "translations": l.Translations})
}

type uiImportRequest struct {
	Code         string            `json:"code"`
	Name         string            `json:"name"`
	Translations map[string]string `json:"translations"`
}

// importUILanguage: POST /api/ui-languages (admin). Replaces the stored dictionary
// of the code atomically; for built-in codes it stores per-key overrides.
func (s *Server) importUILanguage(w http.ResponseWriter, r *http.Request) {
	known, err := s.knownUIKeys()
	if err != nil {
		jerr(w, 503, err.Error())
		return
	}
	var in uiImportRequest
	if err := decodeMailRequest(w, r, &in); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			jerr(w, 413, "file too large")
			return
		}
		jerr(w, 400, "invalid translation file")
		return
	}
	if !store.ValidUICodeSyntax(in.Code) {
		jerr(w, 400, "invalid language code (for example nl, pt-br or zh-hant)")
		return
	}
	name := in.Name
	if builtinName, builtin := store.BuiltinUILanguageName(in.Code); builtin {
		name = builtinName
	} else if !uiValidName(name) {
		jerr(w, 400, "invalid language name (1 to 80 characters, no control characters)")
		return
	}
	if in.Translations == nil {
		in.Translations = map[string]string{}
	}
	if err := validateUITranslations(in.Translations, known); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	if err := s.St.PutUITranslation(in.Code, name, in.Translations); err != nil {
		if errors.Is(err, store.ErrTooManyUILanguages) {
			jerr(w, 409, fmt.Sprintf("too many languages (at most %d)", store.MaxUILanguages))
			return
		}
		jerr(w, 500, "database error")
		return
	}
	if me := s.ctxUser(r); me != nil {
		s.logEvent(me.ID, me.Username, "ui_language_imported", "lang:"+in.Code, fmt.Sprintf("%d keys", len(in.Translations)))
	}
	jout(w, 200, map[string]any{"ok": true, "code": in.Code, "keys": len(in.Translations), "translated": translatedCount(in.Translations)})
}

// deleteUILanguage: DELETE /api/ui-languages/{code} (admin). A custom language is
// removed; an override of a built-in language is reset to the bundled texts.
func (s *Server) deleteUILanguage(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	if !store.ValidUICodeSyntax(code) {
		jerr(w, 404, "language not found")
		return
	}
	found, err := s.St.DeleteUITranslation(code)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if !found {
		jerr(w, 404, "language not found")
		return
	}
	if me := s.ctxUser(r); me != nil {
		s.logEvent(me.ID, me.Username, "ui_language_deleted", "lang:"+code, "")
	}
	jout(w, 200, map[string]any{"ok": true})
}

// publicUILanguages: GET /api/i18n/languages (no authentication). Only code and
// name of stored languages: the login screen needs them for the language menu.
func (s *Server) publicUILanguages(w http.ResponseWriter, r *http.Request) {
	stored, err := s.St.ListUITranslations()
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	out := make([]map[string]string, 0, len(stored))
	for _, l := range stored {
		out = append(out, map[string]string{"code": l.Code, "name": l.Name})
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	jout(w, 200, out)
}

// publicUIDictionary: GET /api/i18n/{code} (no authentication): the stored
// overrides of one language, with an ETag so browsers revalidate cheaply.
func (s *Server) publicUIDictionary(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	if !store.ValidUICodeSyntax(code) {
		jerr(w, 404, "language not found")
		return
	}
	l, ok, err := s.St.UITranslation(code)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if !ok {
		jerr(w, 404, "language not found")
		return
	}
	sum := sha256.Sum256([]byte(l.Raw))
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	jout(w, 200, map[string]any{"code": l.Code, "translations": l.Translations})
}
