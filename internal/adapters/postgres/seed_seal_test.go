// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/ports"
)

// tagCodec is a reversible stand-in for the column codec that binds a value to
// its table, column and row key, like the real one.
type tagCodec struct{}

func (tagCodec) Seal(table, column, rowID, v string) (string, error) {
	return "e1:" + table + "." + column + "." + rowID + "|" + v, nil
}

func (tagCodec) BlindIndex(table, column, value string) ([]byte, error) {
	return []byte(table + "." + column + "|" + strings.ToLower(value)), nil
}

func (tagCodec) Open(table, column, rowID, stored string) (string, error) {
	prefix := "e1:" + table + "." + column + "." + rowID + "|"
	if !strings.HasPrefix(stored, "e1:") {
		return "", ports.ErrNotEncrypted
	}
	if !strings.HasPrefix(stored, prefix) {
		return "", errors.New("bound to another row")
	}
	return strings.TrimPrefix(stored, prefix), nil
}

// The seed the provisioner stores as the database owner seals every setting
// value (the keys exist before it, see Provisioner.migrate).
func TestLiveSeedSealsSettingValues(t *testing.T) {
	sc := liveScratch(t, TenantSchema)
	ctx := context.Background()
	seed := ports.SeedData{
		Settings: []ports.Setting{
			{Key: "application_name", Value: "Sendora", Group: "ui"},
			{Key: "smtp_pass", Value: "", Group: "email"},
			{Key: "tpl_welcome", Value: "Hi {{.Name}}", Group: "email_templates"},
		},
		Themes:        []ports.ThemeRecord{{ID: 1, Name: "Light", Data: "{}", Active: true}},
		MailLanguages: []ports.MailLanguage{{Code: "en", Name: "English", BuiltIn: true}},
	}
	if err := Seed(ctx, sc.DB, tagCodec{}, seed); err != nil {
		t.Fatal(err)
	}
	if err := Seed(ctx, sc.DB, tagCodec{}, seed); err != nil { // insert if absent: idempotent
		t.Fatal(err)
	}
	a := New(sc.DB)
	a.SetCodec(tagCodec{})
	for _, s := range seed.Settings {
		raw, err := a.RawColumn(ctx, "settings", "value", s.Key)
		if err != nil {
			t.Fatal(err)
		}
		if s.Value == "" && raw != "" {
			t.Fatalf("%s: an empty value is stored as %q", s.Key, raw)
		}
		if s.Value != "" && (!strings.HasPrefix(raw, "e1:") || strings.Contains(raw, "|") && !strings.HasSuffix(raw, "|"+s.Value)) {
			t.Fatalf("%s is stored as %q", s.Key, raw)
		}
		if got, err := a.Settings().Get(ctx, s.Key); err != nil || got != s.Value {
			t.Fatalf("Get(%s) = %q, %v", s.Key, got, err)
		}
	}
}

// The platform database seeds only the schema version marker.
func TestLivePlatformSeedHasNoThemes(t *testing.T) {
	sc := liveScratch(t, PlatformSchema)
	ctx := context.Background()
	err := Seed(ctx, sc.DB, tagCodec{}, ports.SeedData{Settings: []ports.Setting{{Key: "platform_schema_version", Value: platformSchemaVersion, Group: "system"}}})
	if err != nil {
		t.Fatal(err)
	}
	p := NewPlatform(sc.DB)
	p.SetCodec(tagCodec{})
	if v, err := p.PlatformSettings().Get(ctx, "platform_schema_version"); err != nil || v != platformSchemaVersion {
		t.Fatalf("marker = %q, %v", v, err)
	}
}
