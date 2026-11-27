// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

// MigrateManagedProviders marks login providers that come from the server
// configuration (environment / Kubernetes ConfigMap) so the admin screen can
// show them read-only.
func MigrateManagedProviders(db *sql.DB) error {
	found, err := hasColumn(db, "auth_providers", "managed")
	if err != nil || found {
		return err
	}
	_, err = db.Exec(`ALTER TABLE auth_providers ADD COLUMN managed INTEGER NOT NULL DEFAULT 0`)
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
	res, err := r.q.ExecContext(ctx, `INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,icon,trust_email,allow_registration) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		uuid, p.Name, p.Type, p.Enabled, p.ClientID, secret, p.IssuerURL, p.Icon, p.TrustEmail, p.AllowRegistration)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if r.codec != nil && p.ClientSecret != "" {
		if err := r.SetClientSecret(ctx, id, p.ClientSecret); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (r authProviderRepo) IsManaged(ctx context.Context, id int64) (bool, error) {
	var m bool
	err := r.q.QueryRowContext(ctx, `SELECT managed FROM auth_providers WHERE id=?`, id).Scan(&m)
	return m, err
}

func (r authProviderRepo) Identity(ctx context.Context, id int64) (string, string, string, error) {
	var typ, client, issuer string
	err := r.q.QueryRowContext(ctx, `SELECT type,client_id,issuer_url FROM auth_providers WHERE id=?`, id).Scan(&typ, &client, &issuer)
	return typ, client, issuer, notFound(err)
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
	err := r.q.QueryRowContext(ctx, `SELECT user_id FROM user_auth_providers WHERE provider_id=? AND provider_user_id=?`, providerID, subject).Scan(&uid)
	return uid, notFound(err)
}

func (r authProviderRepo) Link(ctx context.Context, userID, providerID int64, subject string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO user_auth_providers(user_id,provider_id,provider_user_id) VALUES(?,?,?)`, userID, providerID, subject)
	return err
}

func (r authProviderRepo) ManagedConfig(ctx context.Context, uuid string) (int64, string, string, string, string, error) {
	var id int64
	var typ, client, issuer, secret string
	err := r.q.QueryRowContext(ctx, `SELECT id,type,client_id,issuer_url,client_secret FROM auth_providers WHERE uuid=?`, uuid).Scan(&id, &typ, &client, &issuer, &secret)
	if err != nil {
		return id, typ, client, issuer, secret, notFound(err)
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
	res, err := r.q.ExecContext(ctx, `INSERT INTO auth_providers(uuid,name,type,enabled,client_id,client_secret,issuer_url,icon,trust_email,allow_registration,managed) VALUES(?,?,?,?,?,?,?,?,?,?,1)`,
		uuid, p.Name, p.Type, p.Enabled, p.ClientID, secret, p.IssuerURL, p.Icon, p.TrustEmail, p.AllowRegistration)
	if err != nil || r.codec == nil || p.ClientSecret == "" {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
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
	res, err := r.q.ExecContext(ctx, `INSERT INTO users(username,name,email,username_bi,email_bi,email_verified,password_hash) VALUES(?,?,?,?,?,?, '')`, i.storedUsername, i.storedName, i.storedEmail, i.usernameBI, i.emailBI, emailVerified)
	if err != nil {
		return 0, userInsertErr(err)
	}
	id, _ := res.LastInsertId()
	return id, r.sealIdent(ctx, id, i)
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
	return changed(r.q.ExecContext(ctx, `UPDATE users SET email=?,email_bi=?,email_verified=0 WHERE id=? AND email=''`, sealed, bi, id))
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
