// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"database/sql"
	"strconv"

	"github.com/sendora-app/sendora/internal/ports"
)

// DefaultSeed is the default content of a new tenant database, for every
// Store adapter: exactly the settings, themes and mail languages the SQLite
// migration sequence leaves in a new Community database. It replays the same
// insert-if-absent steps, in the same order and with the same data, on an
// in-memory table (the mail template steps are the functions the SQLite
// migration runs), so the two cannot drift apart; the conformance suite
// checks every backend's new store against it (RunSeed).
func DefaultSeed() ports.SeedData {
	m := newSeedTable()
	// runMigrations order: MigratePolicy, migrateAccountSecurity, then seed,
	// then the mail localisation and the mail languages.
	m.add(DefaultStorageQuotaKey, strconv.FormatInt(DefaultQuotaBytes, 10), "uploads")
	for _, d := range accountSecurityDefaults {
		m.add(d.Key, d.Val, "system")
	}
	for _, d := range defaultSettings() {
		m.add(d.Key, d.Value, d.Group)
	}
	for _, d := range storageDefaultSettings() {
		m.add(d.Key, d.Value, "storage")
	}
	// The steps only fail on database errors; the table has none.
	_ = upgradeMailDefaults(m)
	_ = seedMailTemplates(m)

	var d ports.SeedData
	for _, k := range m.order {
		d.Settings = append(d.Settings, *m.rows[k])
	}
	for i, t := range bundledThemes() {
		t.ID = int64(i + 1) // AUTOINCREMENT in insertion order
		t.Category, t.Bundled, t.Active = "bundled", true, t.Name == activeThemeDefault
		d.Themes = append(d.Themes, t)
	}
	for i, code := range MailLanguages {
		d.MailLanguages = append(d.MailLanguages, ports.MailLanguage{Code: code, Name: mailLanguageNames[i], BuiltIn: true})
	}
	return d
}

// seedTable is an in-memory settings table with INSERT OR IGNORE semantics.
type seedTable struct {
	rows  map[string]*ports.Setting
	order []string
}

func newSeedTable() *seedTable { return &seedTable{rows: map[string]*ports.Setting{}} }

func (m *seedTable) add(key, value, group string) {
	if _, ok := m.rows[key]; ok {
		return
	}
	m.rows[key] = &ports.Setting{Key: key, Value: value, Group: group}
	m.order = append(m.order, key)
}

// mailMigrationTx on the table.

func (m *seedTable) ReplaceIfUnchanged(key, old, value string) error {
	if r, ok := m.rows[key]; ok && r.Value == old {
		r.Value = value
	}
	return nil
}

func (m *seedTable) ReplaceLegacyDownloadedBody(body, old string) error {
	return m.ReplaceIfUnchanged("tpl_share_downloaded", old, body)
}

func (m *seedTable) Value(key string) (string, error) {
	if r, ok := m.rows[key]; ok {
		return r.Value, nil
	}
	return "", sql.ErrNoRows
}

func (m *seedTable) AddTemplateIfMissing(key, value string) error {
	m.add(key, value, "email_templates")
	return nil
}
