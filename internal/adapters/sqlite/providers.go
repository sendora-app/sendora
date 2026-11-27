// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"

	"github.com/sendora-app/sendora/internal/ports"
)

type authProviderRepo struct {
	q     querier
	codec ports.ColumnCodec
}

func (r authProviderRepo) count(ctx context.Context, query string, args ...any) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, query, args...).Scan(&n)
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
	return out, nil // contract: like the 0.2 loop, an iteration error ends the list without failing it
}

func (r authProviderRepo) Unlink(ctx context.Context, userID, providerID int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM user_auth_providers WHERE user_id=? AND provider_id=?`, userID, providerID)
	return err
}
