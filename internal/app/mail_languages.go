// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sendora-app/sendora/internal/store"
)

func (s *Server) mailLanguages(w http.ResponseWriter, r *http.Request) {
	languages, err := s.St.ListMailLanguages()
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	jout(w, 200, languages)
}

func (s *Server) createMailLanguage(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}
	if decodeMailRequest(w, r, &input) != nil {
		jerr(w, 400, "bad request")
		return
	}
	input.Code = strings.ToLower(strings.TrimSpace(input.Code))
	input.Name = strings.TrimSpace(input.Name)
	if !store.ValidMailCode(input.Code) || input.Name == "" || len(input.Name) > 80 || !utf8.ValidString(input.Name) || strings.IndexFunc(input.Name, unicode.IsControl) >= 0 {
		jerr(w, 400, "valid language code and name required")
		return
	}
	unlock := s.stripe(&s.identityLocks, "mail-languages")
	defer unlock()
	ctx := context.Background()
	tx, err := s.St.Repos().Begin(ctx)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	var exists, count int
	if exists, err = tx.Mail().CountLanguage(ctx, input.Code); err != nil {
		jerr(w, 500, "database error")
		return
	}
	if exists != 0 {
		jerr(w, 409, "language already exists")
		return
	}
	if count, err = tx.Mail().CountLanguages(ctx); err != nil {
		jerr(w, 500, "database error")
		return
	}
	if count >= 32 {
		jerr(w, 400, "maximum 32 email languages")
		return
	}
	if err = tx.Mail().AddLanguage(ctx, input.Code, input.Name); err != nil {
		jerr(w, 500, "language save failed")
		return
	}
	for _, event := range store.MailEvents {
		for _, prefix := range []string{"tpl_", "subj_"} {
			if err = tx.Mail().AddEmptyTemplate(ctx, prefix+event+"_"+input.Code); err != nil {
				jerr(w, 500, "language save failed")
				return
			}
		}
	}
	if err = tx.Commit(); err != nil {
		jerr(w, 500, "language save failed")
		return
	}
	jout(w, 201, store.MailLanguage{Code: input.Code, Name: input.Name})
}

func (s *Server) templateKey(key string) (string, bool, bool) {
	for _, event := range store.MailEvents {
		if key == "tpl_"+event {
			return key + "_en", false, true
		}
		for _, prefix := range []string{"tpl_", "subj_"} {
			start := prefix + event + "_"
			if strings.HasPrefix(key, start) && s.St.ValidMailLanguage(strings.TrimPrefix(key, start)) {
				return key, prefix == "subj_", true
			}
		}
	}
	return "", false, false
}
