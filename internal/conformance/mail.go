// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// RunMail pins the contract of ports.MailRepository.
func RunMail(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()

	t.Run("Languages", func(t *testing.T) {
		m := open(t).Mail()
		langs, err := m.ListLanguages(ctx)
		if err != nil || len(langs) < 5 || !langs[0].BuiltIn {
			t.Fatalf("ListLanguages = %+v, %v (built-in seeded first)", langs, err)
		}
		n, _ := m.CountLanguages(ctx)
		if n != len(langs) {
			t.Fatalf("CountLanguages = %d, want %d", n, len(langs))
		}
		if c, _ := m.CountLanguage(ctx, "en"); c != 1 {
			t.Fatal("en is not a mail language")
		}
		if err := m.AddLanguage(ctx, "pt", "Português"); err != nil {
			t.Fatal(err)
		}
		if err := m.AddLanguage(ctx, "pt", "again"); err == nil {
			t.Fatal("a taken language code was accepted")
		}
		if name, err := m.LanguageName(ctx, "pt"); err != nil || name != "Português" {
			t.Fatalf("LanguageName = %q, %v", name, err)
		}
		if _, err := m.LanguageName(ctx, "xx"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("LanguageName of an unknown code: %v", err)
		}
		langs, _ = m.ListLanguages(ctx)
		if last := langs[len(langs)-1]; last.Code != "pt" || last.BuiltIn {
			t.Fatalf("custom language not listed last: %+v", last)
		}
	})

	t.Run("Templates", func(t *testing.T) {
		s := open(t)
		m := s.Mail()
		before, err := m.Templates(ctx)
		if err != nil || len(before) == 0 {
			t.Fatalf("Templates on a seeded store = %d, %v", len(before), err)
		}
		if err := m.AddEmptyTemplate(ctx, "tpl_custom_event_xx"); err != nil {
			t.Fatal(err)
		}
		if err := m.AddEmptyTemplate(ctx, "tpl_custom_event_xx"); err == nil {
			t.Fatal("a taken template key was accepted")
		}
		if err := m.PutTemplate(ctx, "tpl_custom_event_xx", "body"); err != nil {
			t.Fatal(err)
		}
		if err := m.PutTemplate(ctx, "subj_new_xx", "new"); err != nil {
			t.Fatal(err)
		}
		// A key of another group is never changed through the template methods.
		if err := m.PutTemplate(ctx, "application_name", "hijack"); err != nil {
			t.Fatal(err)
		}
		if err := m.SetTemplate(ctx, "application_name", "hijack"); err != nil {
			t.Fatal(err)
		}
		if err := m.SetTemplate(ctx, "subj_new_xx", "changed"); err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		list, _ := m.Templates(ctx)
		for i, x := range list {
			if i > 0 && list[i-1].Key > x.Key {
				t.Fatal("Templates not ordered by key")
			}
			got[x.Key] = x.Value
		}
		if got["tpl_custom_event_xx"] != "body" || got["subj_new_xx"] != "changed" {
			t.Fatalf("template values = %q %q", got["tpl_custom_event_xx"], got["subj_new_xx"])
		}
		if _, ok := got["application_name"]; ok {
			t.Fatal("a non-template setting is listed as a template")
		}
		for _, x := range mustSettings(t, s) {
			if x.Key == "application_name" && x.Value == "hijack" {
				t.Fatal("a template method changed a non-template setting")
			}
		}
	})

	t.Run("LanguageOfUniqueEmail", func(t *testing.T) {
		s := open(t)
		nu := newUser("ola", "Ola@Example.org")
		nu.Language = "nl"
		id := mustCreate(t, s.Users(), nu)
		if l, err := s.Mail().LanguageOfUniqueEmail(ctx, "ola@example.org"); err != nil || l != "nl" {
			t.Fatalf("LanguageOfUniqueEmail = %q, %v", l, err)
		}
		if _, err := s.Mail().LanguageOfUniqueEmail(ctx, "nobody@example.org"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("unknown address: %v", err)
		}
		if e, err := s.Users().Email(ctx, id); err != nil || e != "Ola@Example.org" {
			t.Fatalf("Users().Email = %q, %v", e, err)
		}
		if _, err := s.Users().Email(ctx, 999); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Email of a missing account: %v", err)
		}
	})

	t.Run("DownloadMailQueue", func(t *testing.T) {
		s := open(t)
		owner := mustCreate(t, s.Users(), newUser("pia", "pia@example.org"))
		share := mustShare(t, s, ports.NewShare{UserID: owner, LongID: "long-p", Name: "P"})
		dm := s.DownloadMails()
		now := time.Now()
		if _, err := dm.NextDue(ctx, now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("NextDue on an empty queue: %v", err)
		}
		id, err := dm.Reserve(ctx, share, "r@example.org", "en", `{"a":1}`, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dm.NextDue(ctx, now.Add(time.Hour)); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("a reserved job is due")
		}
		if err := dm.Activate(ctx, id, now.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		job, err := dm.NextDue(ctx, now)
		if err != nil || job.ID != id || job.Recipient != "r@example.org" || job.Language != "en" || job.Attempts != 0 {
			t.Fatalf("NextDue = %+v, %v", job, err)
		}
		if err := dm.RecordFailure(ctx, id, 1, "pending", "boom", now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := dm.NextDue(ctx, now); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("a job is due before its next attempt")
		}
		if job, _ := dm.NextDue(ctx, now.Add(time.Hour)); job.Attempts != 1 {
			t.Fatalf("attempts = %d", job.Attempts)
		}
		if err := dm.RecordFailure(ctx, id, 3, "failed", "boom", now); err != nil {
			t.Fatal(err)
		}
		if _, err := dm.NextDue(ctx, now.Add(time.Hour)); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("a failed job is due")
		}
		if err := dm.PruneFailed(ctx); err != nil {
			t.Fatal(err)
		}
		if err := dm.Delete(ctx, id); err != nil {
			t.Fatal(err)
		}
	})
}

func mustSettings(t *testing.T, s ports.Store) []ports.Setting {
	t.Helper()
	l, err := s.Settings().ListEditable(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// RunUITranslations pins the contract of ports.UITranslationRepository.
func RunUITranslations(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	t.Run("Lifecycle", func(t *testing.T) {
		s := open(t)
		ui := s.UITranslations()
		if l, err := ui.List(ctx); err != nil || len(l) != 0 {
			t.Fatalf("List on empty store = %v, %v", l, err)
		}
		if _, err := ui.Get(ctx, "pt"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Get of a missing dictionary: %v", err)
		}
		for _, x := range []ports.UITranslation{{Code: "pt", Name: "Português", Data: `{"a":"b"}`}, {Code: "nl", Name: "Nederlands", Data: `{}`}} {
			if err := ui.Put(ctx, x.Code, x.Name, x.Data); err != nil {
				t.Fatal(err)
			}
		}
		if err := ui.Put(ctx, "pt", "Portugues", `{"a":"c"}`); err != nil {
			t.Fatal(err)
		}
		if got, err := ui.Get(ctx, "pt"); err != nil || got.Name != "Portugues" || got.Data != `{"a":"c"}` {
			t.Fatalf("Get after replace = %+v, %v", got, err)
		}
		if l, _ := ui.List(ctx); len(l) != 2 || l[0].Code != "nl" {
			t.Fatalf("List = %+v (ordered by code)", l)
		}
		if n, _ := ui.Count(ctx, "pt"); n != 1 {
			t.Fatal("Count missed a dictionary")
		}
		if n, _ := ui.CountCustom(ctx); n != 1 {
			t.Fatalf("CountCustom = %d, want 1 (nl is built in)", n)
		}
		nu := newUser("quin", "quin@example.org")
		nu.UILanguage = "pt"
		id := mustCreate(t, s.Users(), nu)
		if n, err := ui.Delete(ctx, "pt"); err != nil || n != 1 {
			t.Fatalf("Delete = %d, %v", n, err)
		}
		if n, _ := ui.Delete(ctx, "pt"); n != 0 {
			t.Fatal("Delete removed a missing dictionary")
		}
		if err := ui.ResetUsersLanguage(ctx, "pt"); err != nil {
			t.Fatal(err)
		}
		if u := mustUser(t, s.Users(), id); u.UILanguage != "en" {
			t.Fatalf("UI language after reset = %q", u.UILanguage)
		}
	})
}
