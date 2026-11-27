// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// MigrateIPBans creates the table that keeps address bans across restarts.
// Called from internal/store's migration sequence. Times are Unix seconds.
func MigrateIPBans(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ip_bans (
		ip TEXT PRIMARY KEY,
		banned_until INTEGER NOT NULL,
		strikes INTEGER NOT NULL,
		last_strike INTEGER NOT NULL)`)
	return err
}

type ipBanRepo struct{ db querier }

func (r ipBanRepo) List(ctx context.Context) ([]ports.IPBan, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT ip,banned_until,strikes,last_strike FROM ip_bans`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.IPBan
	for rows.Next() {
		var ip string
		var until, strikes, last int64
		if rows.Scan(&ip, &until, &strikes, &last) != nil {
			continue // contract: unreadable rows are skipped
		}
		out = append(out, ports.IPBan{Key: ip, Until: time.Unix(until, 0), Strikes: int(strikes), LastStrike: time.Unix(last, 0)})
	}
	return out, rows.Err()
}

func (r ipBanRepo) Put(ctx context.Context, b ports.IPBan) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO ip_bans(ip,banned_until,strikes,last_strike) VALUES(?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET banned_until=excluded.banned_until,strikes=excluded.strikes,last_strike=excluded.last_strike`,
		b.Key, b.Until.Unix(), b.Strikes, b.LastStrike.Unix())
	return err
}

func (r ipBanRepo) Delete(ctx context.Context, key string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM ip_bans WHERE ip=?`, key)
	return err
}

func (r ipBanRepo) Prune(ctx context.Context, endedBefore, strikeBefore time.Time) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM ip_bans WHERE banned_until<? AND last_strike<?`, endedBefore.Unix(), strikeBefore.Unix())
	return err
}
