// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

// tenantSingletons are the tables whose single row is written by the
// migrations (not by the seed); ResetTenantForTests puts them back to their
// initial values instead of emptying them.
var tenantSingletons = map[string]string{
	"audit_checkpoint": `UPDATE audit_checkpoint SET last_deleted_seq = 0, last_deleted_hash = '', mac = '' WHERE id = 1`,
	"audit_guard":      `UPDATE audit_guard SET gen = 0 WHERE id = 1`,
	"audit_issued":     `UPDATE audit_issued SET seq = 0 WHERE id = 1`,
}

// ResetTenantForTests returns tenant id's database to the state right after
// CreateTenant (migrated, seeded with seed, empty otherwise), as the owner
// role in one transaction. The tenant has no column keys here (its control log
// is emptied too), so the seed is stored unsealed. It exists for the conformance suite, which reuses
// one provisioned tenant for every test instead of creating and dropping a
// database per test: every DROP DATABASE forces a checkpoint, and on slow
// (NFS) volumes a run of them stalled the test cluster's primary into a
// failover (design 3.4a). Never call it on a tenant in use.
func (p *Provisioner) ResetTenantForTests(ctx context.Context, id string, seed *ports.SeedData) error {
	n, err := TenantNamesFor(id)
	if err != nil {
		return err
	}
	db := p.ownerDB(n)
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'sendora' AND tablename <> 'schema_migrations' ORDER BY tablename`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		if _, single := tenantSingletons[t]; !single {
			tables = append(tables, ident(t))
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(tables) > 0 {
		if _, err := tx.ExecContext(ctx, `TRUNCATE `+strings.Join(tables, ", ")+` RESTART IDENTITY CASCADE`); err != nil {
			return fmt.Errorf("reset %s: %w", n.Database, err)
		}
	}
	for _, stmt := range tenantSingletons {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("reset %s: %w", n.Database, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if seed != nil {
		if err := Seed(ctx, db, nil, *seed); err != nil {
			return fmt.Errorf("reset %s: seed: %w", n.Database, err)
		}
	}
	return nil
}
