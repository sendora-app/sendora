// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// ---------- mail repository ----------

type mailRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r mailRepo) count(ctx context.Context, query string, args ...any) (int, error) {
	var n int
	err := r.q.scan(ctx, query, args, &n)
	return n, err
}

func (r mailRepo) LanguageOfUniqueEmail(ctx context.Context, email string) (string, error) {
	var language string
	bi, err := blindKey(r.codec, "users", "email", email)
	if err != nil {
		return "", err
	}
	err = r.q.scan(ctx, `SELECT language FROM users WHERE email_bi=? AND is_guest=0`, []any{bi}, &language)
	return language, err
}

func (r mailRepo) LanguageName(ctx context.Context, code string) (string, error) {
	var name string
	err := r.q.scan(ctx, `SELECT name FROM mail_languages WHERE code=?`, []any{code}, &name)
	return name, err
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
	err := r.q.scan(ctx, `SELECT id,recipient,language,data,attempts FROM download_mail_outbox
		WHERE status='pending' AND next_attempt<=? ORDER BY id LIMIT 1`, []any{now}, &j.ID, &j.Recipient, &j.Language, &j.Data, &j.Attempts)
	return j, err
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
	if err := r.q.scan(ctx, `SELECT email FROM users WHERE id=?`, []any{id}, &email); err != nil {
		return "", err
	}
	return openCol(r.codec, "users", "email", id, email)
}

// ---------- UI dictionaries ----------

type uiTranslationRepo struct{ q pq }

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
	err := r.q.scan(ctx, `SELECT code,name,data FROM ui_translations WHERE code=?`, []any{code}, &l.Code, &l.Name, &l.Data)
	return l, err
}

func (r uiTranslationRepo) Count(ctx context.Context, code string) (int, error) {
	var n int
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM ui_translations WHERE code=?`, []any{code}, &n)
	return n, err
}

func (r uiTranslationRepo) CountCustom(ctx context.Context) (int, error) {
	var n int
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM ui_translations WHERE code NOT IN ('en','nl','de','fr','es')`, nil, &n)
	return n, err
}

// uiTimestamp is SQLite's CURRENT_TIMESTAMP text, which ui_translations keeps.
const uiTimestamp = `to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS')`

func (r uiTranslationRepo) Put(ctx context.Context, code, name, data string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO ui_translations(code,name,data,updated_at) VALUES(?,?,?,`+uiTimestamp+`)
  ON CONFLICT(code) DO UPDATE SET name=excluded.name,data=excluded.data,updated_at=`+uiTimestamp, code, name, data)
	return err
}

func (r uiTranslationRepo) Delete(ctx context.Context, code string) (int64, error) {
	return affected(r.q.ExecContext(ctx, `DELETE FROM ui_translations WHERE code=?`, code))
}

func (r uiTranslationRepo) ResetUsersLanguage(ctx context.Context, code string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET ui_language='en' WHERE ui_language=?`, code)
	return err
}
