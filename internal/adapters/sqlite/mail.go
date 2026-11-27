// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// ---------- migrations ----------

// MigrateUITranslations creates the table of stored UI dictionaries.
func MigrateUITranslations(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ui_translations(
  code TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`)
	return err
}

// MigrateMailLanguages creates the email language table and adds the
// built-in languages (codes[i] named names[i]) when missing.
func MigrateMailLanguages(db *sql.DB, codes, names []string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS mail_languages(code TEXT PRIMARY KEY,name TEXT NOT NULL,built_in INTEGER NOT NULL DEFAULT 0)`); err != nil {
		return err
	}
	for i, code := range codes {
		if _, err = tx.Exec(`INSERT OR IGNORE INTO mail_languages(code,name,built_in) VALUES(?,?,1)`, code, names[i]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MailMigrationTx is the mail localisation migration's view of its
// transaction (MigrateMailLocalization). Its setting values are sealed like
// every other setting's.
type MailMigrationTx struct {
	tx    *sql.Tx
	codec ports.ColumnCodec
}

// ReplaceIfUnchanged sets setting key to value only while it still holds old.
func (m MailMigrationTx) ReplaceIfUnchanged(key, old, value string) error {
	cur, err := readSetting(context.Background(), m.tx, m.codec, key)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && cur != old) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = writeSetting(context.Background(), m.tx, m.codec, key, value)
	return err
}

// ReplaceLegacyDownloadedBody sets tpl_share_downloaded to body only while it
// still holds old.
func (m MailMigrationTx) ReplaceLegacyDownloadedBody(body, old string) error {
	return m.ReplaceIfUnchanged("tpl_share_downloaded", old, body)
}

// Value reads a setting (sql.ErrNoRows when missing).
func (m MailMigrationTx) Value(key string) (string, error) {
	return readSetting(context.Background(), m.tx, m.codec, key)
}

// AddTemplateIfMissing stores a template text unless the key exists.
func (m MailMigrationTx) AddTemplateIfMissing(key, value string) error {
	return insertSettingIfAbsent(context.Background(), m.tx, m.codec, key, value, "email_templates")
}

// MigrateMailLocalization adds the language columns of users, runs upgrade
// (historical default texts), creates the download mail outbox and the
// download history index, then runs seed (template texts), all in one
// transaction.
func MigrateMailLocalization(db *sql.DB, codec ports.ColumnCodec, upgrade, seed func(MailMigrationTx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// PRAGMA inspection keeps the schema change additive for existing databases.
	rows, err := tx.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	found, foundUI := false, false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		found = found || name == "language"
		foundUI = foundUI || name == "ui_language"
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if !found {
		if _, err := tx.Exec(`ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT 'en'`); err != nil {
			return err
		}
	}
	if !foundUI {
		if _, err := tx.Exec(`ALTER TABLE users ADD COLUMN ui_language TEXT NOT NULL DEFAULT 'en'`); err != nil {
			return err
		}
	}
	m := MailMigrationTx{tx: tx, codec: codec}
	if err := upgrade(m); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS download_mail_outbox (
		id INTEGER PRIMARY KEY AUTOINCREMENT, share_id INTEGER NOT NULL,
		status TEXT NOT NULL DEFAULT 'reserved', recipient TEXT NOT NULL,
		language TEXT NOT NULL, data TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
		next_attempt DATETIME NOT NULL, last_error TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
		CREATE INDEX IF NOT EXISTS download_mail_pending ON download_mail_outbox(status,next_attempt)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS downloads_share_history ON downloads(share_id,created_at DESC,id DESC)`); err != nil {
		return err
	}
	if err := seed(m); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------- mail repository ----------

type mailRepo struct {
	q     querier
	codec ports.ColumnCodec
}

func (r mailRepo) count(ctx context.Context, query string, args ...any) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, query, args...).Scan(&n)
	return n, err
}

func (r mailRepo) LanguageOfUniqueEmail(ctx context.Context, email string) (string, error) {
	var language string
	bi, err := blindKey(r.codec, "users", "email", email)
	if err != nil {
		return "", err
	}
	err = r.q.QueryRowContext(ctx, `SELECT language FROM users WHERE email_bi=? AND is_guest=0`, bi).Scan(&language)
	return language, notFound(err)
}

func (r mailRepo) LanguageName(ctx context.Context, code string) (string, error) {
	var name string
	err := r.q.QueryRowContext(ctx, `SELECT name FROM mail_languages WHERE code=?`, code).Scan(&name)
	return name, notFound(err)
}

func (r mailRepo) CountLanguage(ctx context.Context, code string) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM mail_languages WHERE code=?`, code)
}

func (r mailRepo) CountLanguages(ctx context.Context) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM mail_languages`)
}

func (r mailRepo) AddLanguage(ctx context.Context, code, name string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO mail_languages(code,name) VALUES(?,?)`, code, name)
	return err
}

func (r mailRepo) ListLanguages(ctx context.Context) ([]ports.MailLanguage, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT code,name,built_in FROM mail_languages ORDER BY built_in DESC,code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ports.MailLanguage{}
	for rows.Next() {
		var l ports.MailLanguage
		if err := rows.Scan(&l.Code, &l.Name, &l.BuiltIn); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (r mailRepo) Templates(ctx context.Context) ([]ports.Setting, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT key,value FROM settings WHERE grp='email_templates' ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.Setting
	for rows.Next() {
		var x ports.Setting
		if rows.Scan(&x.Key, &x.Value) != nil { // contract: partial rows are kept
			out = append(out, x)
			continue
		}
		v, err := openColKey(r.codec, "settings", "value", x.Key, x.Value)
		if err != nil {
			return nil, err
		}
		x.Value = v
		out = append(out, x)
	}
	return out, nil
}

func (r mailRepo) PutTemplate(ctx context.Context, key, value string) error {
	sealed, err := sealColKey(r.codec, "settings", "value", key, value)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `INSERT INTO settings(key,grp,value) VALUES(?,'email_templates',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE settings.grp='email_templates'`, key, sealed)
	return err
}

func (r mailRepo) SetTemplate(ctx context.Context, key, value string) error {
	sealed, err := sealColKey(r.codec, "settings", "value", key, value)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=? AND grp='email_templates'`, sealed, key)
	return err
}

func (r mailRepo) AddEmptyTemplate(ctx context.Context, key string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO settings(key,grp,value) VALUES(?,'email_templates','')`, key)
	return err
}

func (r downloadMailRepo) NextDue(ctx context.Context, now time.Time) (ports.DownloadMailJob, error) {
	var j ports.DownloadMailJob
	err := r.q.QueryRowContext(ctx, `SELECT id,recipient,language,data,attempts FROM download_mail_outbox
		WHERE status='pending' AND next_attempt<=? ORDER BY id LIMIT 1`, now).Scan(&j.ID, &j.Recipient, &j.Language, &j.Data, &j.Attempts)
	return j, notFound(err)
}

// Claim: see ports.DownloadMailRepository.
func (r downloadMailRepo) Claim(ctx context.Context, id int64, now, until time.Time) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE download_mail_outbox SET next_attempt=? WHERE id=? AND status='pending' AND next_attempt<=?`, until, id, now))
}

func (r downloadMailRepo) Delete(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM download_mail_outbox WHERE id=?`, id)
	return err
}

func (r downloadMailRepo) RecordFailure(ctx context.Context, id int64, attempts int, status, lastError string, next time.Time) error {
	_, err := r.q.ExecContext(ctx, `UPDATE download_mail_outbox SET attempts=?,status=?,last_error=?,next_attempt=? WHERE id=?`, attempts, status, lastError, next, id)
	return err
}

func (r downloadMailRepo) PruneFailed(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM download_mail_outbox WHERE status='failed' AND id NOT IN
			(SELECT id FROM download_mail_outbox WHERE status='failed' ORDER BY id DESC LIMIT 1000)`)
	return err
}

func (r userRepo) Email(ctx context.Context, id int64) (string, error) {
	var email string
	if err := r.q.QueryRowContext(ctx, `SELECT email FROM users WHERE id=?`, id).Scan(&email); err != nil {
		return "", notFound(err)
	}
	return openCol(r.codec, "users", "email", id, email)
}

// ---------- UI dictionaries ----------

type uiTranslationRepo struct{ q querier }

func (r uiTranslationRepo) List(ctx context.Context) ([]ports.UITranslation, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT code,name,data FROM ui_translations ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.UITranslation
	for rows.Next() {
		var l ports.UITranslation
		if err := rows.Scan(&l.Code, &l.Name, &l.Data); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (r uiTranslationRepo) Get(ctx context.Context, code string) (ports.UITranslation, error) {
	var l ports.UITranslation
	err := r.q.QueryRowContext(ctx, `SELECT code,name,data FROM ui_translations WHERE code=?`, code).Scan(&l.Code, &l.Name, &l.Data)
	return l, notFound(err)
}

func (r uiTranslationRepo) Count(ctx context.Context, code string) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM ui_translations WHERE code=?`, code).Scan(&n)
	return n, err
}

func (r uiTranslationRepo) CountCustom(ctx context.Context) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM ui_translations WHERE code NOT IN ('en','nl','de','fr','es')`).Scan(&n)
	return n, err
}

func (r uiTranslationRepo) Put(ctx context.Context, code, name, data string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO ui_translations(code,name,data,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP)
  ON CONFLICT(code) DO UPDATE SET name=excluded.name,data=excluded.data,updated_at=CURRENT_TIMESTAMP`, code, name, data)
	return err
}

func (r uiTranslationRepo) Delete(ctx context.Context, code string) (int64, error) {
	return affected(r.q.ExecContext(ctx, `DELETE FROM ui_translations WHERE code=?`, code))
}

func (r uiTranslationRepo) ResetUsersLanguage(ctx context.Context, code string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET ui_language='en' WHERE ui_language=?`, code)
	return err
}
