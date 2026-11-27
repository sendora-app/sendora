// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// RunSeed: a new store holds exactly the core default content
// (store.DefaultSeed): every editable setting with its group, every template
// text, the bundled themes with their IDs and the active one, and the
// built-in mail languages. Run against every backend, it proves that all
// adapters seed identically.
func RunSeed(t *testing.T, open func(testing.TB) ports.Store) {
	ctx := context.Background()
	st := open(t)
	want := store.DefaultSeed()

	var wantEditable, wantTemplates []string
	for _, s := range want.Settings {
		switch {
		case s.Group == "email_templates":
			wantTemplates = append(wantTemplates, s.Key+"="+s.Value)
		case s.Group == "secret" || s.Key == "jwt_secret":
		default:
			wantEditable = append(wantEditable, s.Key+"="+s.Value+" ["+s.Group+"]")
		}
	}
	editable, err := st.Settings().ListEditable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var gotEditable []string
	for _, s := range editable {
		gotEditable = append(gotEditable, s.Key+"="+s.Value+" ["+s.Group+"]")
	}
	templates, err := st.Mail().Templates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var gotTemplates []string
	for _, s := range templates {
		gotTemplates = append(gotTemplates, s.Key+"="+s.Value)
	}
	themes, err := st.Themes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var wantThemes, gotThemes []string
	theme := func(r ports.ThemeRecord) string {
		return fmt.Sprintf("%d %s %s bundled=%v active=%v %s", r.ID, r.Name, r.Category, r.Bundled, r.Active, r.Data)
	}
	for _, r := range want.Themes {
		wantThemes = append(wantThemes, theme(r))
	}
	for _, r := range themes {
		gotThemes = append(gotThemes, theme(r))
	}
	langs, err := st.Mail().ListLanguages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var wantLangs, gotLangs []string
	for _, l := range want.MailLanguages {
		wantLangs = append(wantLangs, fmt.Sprintf("%s %s %v", l.Code, l.Name, l.BuiltIn))
	}
	for _, l := range langs {
		gotLangs = append(gotLangs, fmt.Sprintf("%s %s %v", l.Code, l.Name, l.BuiltIn))
	}
	for _, c := range []struct {
		what      string
		got, want []string
	}{
		{"editable settings", gotEditable, wantEditable},
		{"templates", gotTemplates, wantTemplates},
		{"themes", gotThemes, wantThemes},
		{"mail languages", gotLangs, wantLangs},
	} {
		if d := diff(c.got, c.want); d != "" {
			t.Errorf("%s differ from store.DefaultSeed():\n%s", c.what, d)
		}
	}
	t.Logf("seed: %d editable settings, %d templates, %d themes, %d mail languages", len(gotEditable), len(gotTemplates), len(gotThemes), len(gotLangs))
	if len(wantEditable) == 0 || len(wantTemplates) == 0 || len(wantThemes) == 0 || len(wantLangs) == 0 {
		t.Fatal("store.DefaultSeed() is incomplete")
	}
}

// diff lists the entries only in got (+) or only in want (-), order ignored.
func diff(got, want []string) string {
	count := map[string]int{}
	for _, s := range got {
		count[s]++
	}
	for _, s := range want {
		count[s]--
	}
	var out []string
	for s, n := range count {
		switch {
		case n > 0:
			out = append(out, "+ "+s)
		case n < 0:
			out = append(out, "- "+s)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}
