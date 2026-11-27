// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"database/sql"
	"sort"

	"github.com/sendora-app/sendora/internal/ports"
)

// Seed stores the missing parts of d (store.DefaultSeed) in one transaction ("insert if
// absent", as sqlite.Seed): stored values, custom themes and the theme
// selection stay. Setting values are sealed with codec (nil: stored as they
// are); a seed without themes and mail languages only stores settings (the
// platform database has no such tables). Themes keep the given IDs (so they match a Community
// database seeded in the same order) and the identity sequence is moved past
// them.
func Seed(ctx context.Context, db *sql.DB, codec ports.ColumnCodec, d ports.SeedData) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := pq{raw: tx, tx: true}
	for _, s := range d.Settings {
		if err := insertSettingIfAbsent(ctx, q, codec, s.Key, s.Value, s.Group); err != nil {
			return err
		}
	}
	if len(d.Themes) == 0 && len(d.MailLanguages) == 0 {
		return tx.Commit()
	}
	var themes int
	if err := q.scan(ctx, `SELECT COUNT(*) FROM themes`, nil, &themes); err != nil {
		return err
	}
	ordered := append([]ports.ThemeRecord(nil), d.Themes...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, t := range ordered {
		active := themes == 0 && t.Active
		if t.ID > 0 {
			_, err = q.ExecContext(ctx, `INSERT INTO themes(id,name,category,bundled,data,active) VALUES(?,?,'bundled',1,?,?) ON CONFLICT DO NOTHING`, t.ID, t.Name, t.Data, active)
		} else {
			_, err = q.ExecContext(ctx, `INSERT INTO themes(name,category,bundled,data,active) VALUES(?,'bundled',1,?,?) ON CONFLICT DO NOTHING`, t.Name, t.Data, active)
		}
		if err != nil {
			return err
		}
	}
	if _, err := q.ExecContext(ctx, `SELECT setval(pg_get_serial_sequence('themes','id'), GREATEST((SELECT COALESCE(MAX(id),0) FROM themes),1), (SELECT COUNT(*)>0 FROM themes))`); err != nil {
		return err
	}
	for _, l := range d.MailLanguages {
		if _, err := q.ExecContext(ctx, `INSERT INTO mail_languages(code,name,built_in) VALUES(?,?,?) ON CONFLICT DO NOTHING`, l.Code, l.Name, l.BuiltIn); err != nil {
			return err
		}
	}
	return tx.Commit()
}
