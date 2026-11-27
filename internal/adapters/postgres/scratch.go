// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Scratch is a throw-away schema on a test server: the conformance suite
// opens one per test, so tests never see each other's rows and need no
// database-creation rights (the CNPG test cluster admits one role on one
// database, design 3.4).
type Scratch struct {
	DB     *sql.DB // search_path = Schema; migrated
	Schema string
	admin  *sql.DB
}

// OpenScratch creates a uniquely named schema on dsn, opens a handle whose
// connections use it (search_path as a startup parameter; tests connect
// directly, not through PgBouncer), and migrates it as s. Close drops it.
func OpenScratch(ctx context.Context, dsn string, s Schema) (*Scratch, error) {
	base, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	name := "conf_" + s.String() + "_" + hex.EncodeToString(b[:])
	admin := OpenDB(base)
	admin.SetMaxOpenConns(1)
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		return nil, fmt.Errorf("create scratch schema: %w", err)
	}
	cfg := base.Copy()
	cfg.RuntimeParams["search_path"] = name
	db := OpenDB(cfg)
	db.SetMaxOpenConns(16)
	sc := &Scratch{DB: db, Schema: name, admin: admin}
	if err := Migrate(ctx, db, s); err != nil {
		sc.Close()
		return nil, err
	}
	return sc, nil
}

// Close closes the handle and drops the schema with everything in it.
func (sc *Scratch) Close() error {
	sc.DB.Close()
	_, err := sc.admin.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+pgx.Identifier{sc.Schema}.Sanitize()+` CASCADE`)
	sc.admin.Close()
	return err
}
