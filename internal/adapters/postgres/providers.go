// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

type authProviderRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r authProviderRepo) count(ctx context.Context, query string, args ...any) (int, error) {
	var n int
	err := r.q.scan(ctx, query, args, &n)
	return n, err
}

func (r authProviderRepo) CountEnabled(ctx context.Context) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM auth_providers WHERE enabled=1`)
}

func (r authProviderRepo) CountLinks(ctx context.Context, userID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM user_auth_providers WHERE user_id=?`, userID)
}

func (r authProviderRepo) CountEnabledLinks(ctx context.Context, userID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM user_auth_providers upa JOIN auth_providers ap ON ap.id=upa.provider_id WHERE upa.user_id=? AND ap.enabled=1`, userID)
}

func (r authProviderRepo) CountEnabledLinksOfLocal(ctx context.Context, userID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM user_auth_providers up JOIN auth_providers p ON p.id=up.provider_id
		JOIN users u ON u.id=up.user_id WHERE up.user_id=? AND p.enabled=1 AND u.is_guest=0`, userID)
}

func (r authProviderRepo) CountEnabledLinksExcept(ctx context.Context, userID, providerID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM user_auth_providers up JOIN auth_providers p ON p.id=up.provider_id
			WHERE up.user_id=? AND p.enabled=1 AND p.id<>?`, userID, providerID)
}

func (r authProviderRepo) CountEnabledLink(ctx context.Context, userID, providerID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM user_auth_providers up JOIN auth_providers p ON p.id=up.provider_id
			WHERE up.user_id=? AND p.enabled=1 AND p.id=?`, userID, providerID)
}

func (r authProviderRepo) CountExternalAdmins(ctx context.Context, exclUser, exclProvider, exclLinkUser, exclLinkProvider int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(DISTINCT u.id) FROM users u
		JOIN user_auth_providers up ON up.user_id=u.id JOIN auth_providers p ON p.id=up.provider_id
		WHERE u.admin=1 AND u.is_guest=0 AND p.enabled=1 AND u.id<>? AND p.id<>? AND NOT (u.id=? AND p.id=?)`,
		exclUser, exclProvider, exclLinkUser, exclLinkProvider)
}

func (r authProviderRepo) ListLinked(ctx context.Context, userID int64) ([]ports.LinkedProvider, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT p.id,p.name,p.type FROM user_auth_providers up JOIN auth_providers p ON p.id=up.provider_id WHERE up.user_id=?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.LinkedProvider
	for rows.Next() {
		var p ports.LinkedProvider
		rows.Scan(&p.ID, &p.Name, &p.Type) // contract: an unreadable row is listed with zero values
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r authProviderRepo) ListLinkTypes(ctx context.Context) ([]ports.ProviderLinkType, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT upa.user_id, ap.type FROM user_auth_providers upa JOIN auth_providers ap ON ap.id=upa.provider_id ORDER BY ap.type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.ProviderLinkType
	for rows.Next() {
		var l ports.ProviderLinkType
		if rows.Scan(&l.UserID, &l.Type) == nil {
			out = append(out, l)
		}
	}
	return out, nil // contract: an iteration error ends the list without failing it
}

func (r authProviderRepo) Unlink(ctx context.Context, userID, providerID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM user_auth_providers WHERE user_id=? AND provider_id=?`, userID, providerID)
	return err
}

const provCols = `id,uuid,name,type,enabled,client_id,client_secret,issuer_url,icon,trust_email,allow_registration,managed`

// scanProvider scans one provider row and opens its client secret.
func (r authProviderRepo) scanProvider(row interface{ Scan(...any) error }) (ports.ProviderRecord, error) {
	p, err := scanProviderRecord(row)
	if err != nil {
		return p, err
	}
	p.ClientSecret, err = openCol(r.codec, "auth_providers", "client_secret", p.ID, p.ClientSecret)
	return p, err
}

func scanProviderRecord(row interface{ Scan(...any) error }) (ports.ProviderRecord, error) {
	var p ports.ProviderRecord
	err := row.Scan(&p.ID, &p.UUID, &p.Name, &p.Type, &p.Enabled, &p.ClientID, &p.ClientSecret, &p.IssuerURL, &p.Icon, &p.TrustEmail, &p.AllowRegistration, &p.Managed)
	return p, err
}

func (r authProviderRepo) ByUUID(ctx context.Context, uuid string) (ports.ProviderRecord, error) {
	p, err := r.scanProvider(r.q.QueryRowContext(ctx, `SELECT `+provCols+` FROM auth_providers WHERE uuid=?`, uuid))
	return p, notFound(err)
}

func (r authProviderRepo) List(ctx context.Context, enabledOnly bool) ([]ports.ProviderRecord, error) {
	q := `SELECT ` + provCols + ` FROM auth_providers ORDER BY sort,name`
	if enabledOnly {
		q = `SELECT ` + provCols + ` FROM auth_providers WHERE enabled=1 ORDER BY sort,name`
	}
	rows, err := r.q.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.ProviderRecord
	for rows.Next() {
		p, err := r.scanProvider(rows)
		if err != nil && errors.Is(err, ports.ErrNotEncrypted) {
			return nil, err // plaintext where ciphertext is required: fail closed
		}
		out = append(out, p) // contract: partial rows are listed
	}
	return out, nil
}

func (r authProviderRepo) Create(ctx context.Context, uuid string, p ports.ProviderSettings) (int64, error) {
	secret := p.ClientSecret
	if r.codec != nil {
		secret = "" // sealed below, once the row id exists
	}
	id, err := insertID(ctx, r.q, `INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,icon,trust_email,allow_registration) VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING id`,
		uuid, p.Name, p.Type, p.Enabled, p.ClientID, secret, p.IssuerURL, p.Icon, p.TrustEmail, p.AllowRegistration)
	if err != nil {
		return 0, err
	}
	if r.codec != nil && p.ClientSecret != "" {
		if err := r.SetClientSecret(ctx, id, p.ClientSecret); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (r authProviderRepo) IsManaged(ctx context.Context, id int64) (bool, error) {
	var m bool
	err := r.q.scan(ctx, `SELECT managed FROM auth_providers WHERE id=?`, []any{id}, &m)
	return m, err
}

func (r authProviderRepo) Identity(ctx context.Context, id int64) (string, string, string, error) {
	var typ, client, issuer string
	err := r.q.scan(ctx, `SELECT type,client_id,issuer_url FROM auth_providers WHERE id=?`, []any{id}, &typ, &client, &issuer)
	return typ, client, issuer, err
}

func (r authProviderRepo) CountProviderLinks(ctx context.Context, providerID int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM user_auth_providers WHERE provider_id=?`, providerID)
}

func (r authProviderRepo) Update(ctx context.Context, id int64, p ports.ProviderSettings) error {
	_, err := r.q.ExecContext(ctx, `UPDATE auth_providers SET name=?,type=?,enabled=?,client_id=?,issuer_url=?,icon=?,trust_email=?,allow_registration=? WHERE id=?`,
		p.Name, p.Type, p.Enabled, p.ClientID, p.IssuerURL, p.Icon, p.TrustEmail, p.AllowRegistration, id)
	return err
}

func (r authProviderRepo) SetClientSecret(ctx context.Context, id int64, secret string) error {
	sealed, err := sealCol(r.codec, "auth_providers", "client_secret", id, secret)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `UPDATE auth_providers SET client_secret=? WHERE id=?`, sealed, id)
	return err
}

func (r authProviderRepo) Delete(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM auth_providers WHERE id=?`, id)
	return err
}

func (r authProviderRepo) LinkedUser(ctx context.Context, providerID int64, subject string) (int64, error) {
	var uid int64
	err := r.q.scan(ctx, `SELECT user_id FROM user_auth_providers WHERE provider_id=? AND provider_user_id=?`, []any{providerID, subject}, &uid)
	return uid, err
}

func (r authProviderRepo) Link(ctx context.Context, userID, providerID int64, subject string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO user_auth_providers(user_id,provider_id,provider_user_id) VALUES(?,?,?)`, userID, providerID, subject)
	return err
}

func (r authProviderRepo) ManagedConfig(ctx context.Context, uuid string) (int64, string, string, string, string, error) {
	var id int64
	var typ, client, issuer, secret string
	err := r.q.scan(ctx, `SELECT id,type,client_id,issuer_url,client_secret FROM auth_providers WHERE uuid=?`, []any{uuid}, &id, &typ, &client, &issuer, &secret)
	if err != nil {
		return id, typ, client, issuer, secret, err
	}
	secret, err = openCol(r.codec, "auth_providers", "client_secret", id, secret)
	return id, typ, client, issuer, secret, err
}

func (r authProviderRepo) UpdateManaged(ctx context.Context, id int64, p ports.ProviderSettings) error {
	secret, err := sealCol(r.codec, "auth_providers", "client_secret", id, p.ClientSecret)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `UPDATE auth_providers SET name=?,type=?,enabled=?,client_id=?,client_secret=?,issuer_url=?,icon=?,trust_email=?,allow_registration=?,managed=1 WHERE id=?`,
		p.Name, p.Type, p.Enabled, p.ClientID, secret, p.IssuerURL, p.Icon, p.TrustEmail, p.AllowRegistration, id)
	return err
}

func (r authProviderRepo) CreateManaged(ctx context.Context, uuid string, p ports.ProviderSettings) error {
	secret := p.ClientSecret
	if r.codec != nil {
		secret = "" // sealed below, once the row id exists
	}
	id, err := insertID(ctx, r.q, `INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,icon,trust_email,allow_registration,managed) VALUES(?,?,?,?,?,?,?,?,?,?,1) RETURNING id`,
		uuid, p.Name, p.Type, p.Enabled, p.ClientID, secret, p.IssuerURL, p.Icon, p.TrustEmail, p.AllowRegistration)
	if err != nil || r.codec == nil || p.ClientSecret == "" {
		return err
	}
	return r.SetClientSecret(ctx, id, p.ClientSecret)
}

func (r authProviderRepo) ReleaseUnconfigured(ctx context.Context, configured []string) error {
	q := `UPDATE auth_providers SET managed=0 WHERE managed=1`
	args := []any{}
	if len(configured) > 0 {
		q += ` AND uuid NOT IN (?` + strings.Repeat(",?", len(configured)-1) + `)`
		for _, u := range configured {
			args = append(args, u)
		}
	}
	_, err := r.q.ExecContext(ctx, q, args...)
	return err
}

func (r userRepo) CreateExternal(ctx context.Context, username, name, email string, emailVerified int) (int64, error) {
	i, err := r.ident(username, name, email, "")
	if err != nil {
		return 0, err
	}
	return r.insertSealed(ctx, i, `INSERT INTO users(username,name,email,username_bi,email_bi,email_verified,password_hash) VALUES(?,?,?,?,?,?, '') RETURNING id`, i.storedUsername, i.storedName, i.storedEmail, i.usernameBI, i.emailBI, emailVerified)
}

func (r userRepo) FillEmptyEmail(ctx context.Context, id int64, email string) (int64, error) {
	sealed, err := sealCol(r.codec, "users", "email", id, email)
	if err != nil {
		return 0, err
	}
	bi, err := blindIdx(r.codec, "users", "email", email)
	if err != nil {
		return 0, err
	}
	return changed(r.q.ExecContext(ctx, `UPDATE users SET email=?,email_bi=?::bytea,email_verified=0 WHERE id=? AND email=''`, sealed, bi, id))
}

func (r settingsRepo) EditableKeysOrdered(ctx context.Context) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT key FROM settings WHERE grp NOT IN ('secret','email_templates') ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			out = append(out, k)
		}
	}
	return out, nil
}

func (r settingsRepo) SetApplicationURL(ctx context.Context, url string) error {
	_, err := writeSetting(ctx, r.q, r.codec, "application_url", url)
	return err
}
