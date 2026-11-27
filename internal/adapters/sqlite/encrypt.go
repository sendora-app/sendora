// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/ports"
)

// sealCol returns the stored form of an encrypted TEXT column value. Without a
// codec the value is stored as it is. An empty value stays empty: it carries no
// information and the column default is the empty string.
func sealCol(c ports.ColumnCodec, table, column string, id int64, v string) (string, error) {
	return sealColKey(c, table, column, strconv.FormatInt(id, 10), v)
}

// sealColKey is sealCol for a row identified by a text key (a text primary key).
func sealColKey(c ports.ColumnCodec, table, column, key, v string) (string, error) {
	if c == nil || v == "" {
		return v, nil
	}
	return c.Seal(table, column, key, v)
}

// openCol is the inverse of sealCol. With a codec a non-empty value that is
// not encrypted is an error (fail closed): the database holds plaintext where
// ciphertext is required.
func openCol(c ports.ColumnCodec, table, column string, id int64, stored string) (string, error) {
	return openColKey(c, table, column, strconv.FormatInt(id, 10), stored)
}

// openColKey is openCol for a row identified by a text key.
func openColKey(c ports.ColumnCodec, table, column, key, stored string) (string, error) {
	if c == nil || stored == "" {
		return stored, nil
	}
	v, err := c.Open(table, column, key, stored)
	if errors.Is(err, ports.ErrNotEncrypted) {
		return "", fmt.Errorf("%s.%s of row %s is not encrypted: %w", table, column, key, err)
	}
	return v, err
}

// encryptedColumns lists the columns that hold encrypted values and the
// column that identifies their row; RawColumn and RawSetColumn only touch these.
var encryptedColumns = map[string]struct {
	pk      string
	columns map[string]bool
}{
	"shares":            {"id", map[string]bool{"name": true, "description": true, "long_id": true, "password_hash": true}},
	"users":             {"id", map[string]bool{"name": true, "username": true, "email": true, "password_hash": true}},
	"files":             {"id", map[string]bool{"name": true, "sha256": true, "full_path": true}},
	"upload_files":      {"id", map[string]bool{"name": true, "sha256": true, "full_path": true}},
	"password_history":  {"id", map[string]bool{"hash": true}},
	"reverse_invites":   {"id", map[string]bool{"recipient_name": true, "recipient_email": true, "message": true}},
	"refresh_tokens":    {"hash", map[string]bool{"user_agent": true, "ip": true}},
	"auth_providers":    {"id", map[string]bool{"client_secret": true}},
	"storage_locations": {"id", map[string]bool{"config": true}},
	// The platform database (multi-tenant mode): administrators' TOTP secrets
	// and the legacy tenants' database root keys.
	"platform_admins": {"id", map[string]bool{"totp_secret": true, "pending_totp_secret": true}},
	"tenants":         {"id", map[string]bool{"legacy_root": true}},
	// Every database: the audit log's free-text fields (the hash chain stays
	// computed over the plaintext, see auditRepo) and every setting value
	// (settings has a text primary key, the setting's key).
	"audit_log": {"seq", map[string]bool{"actor_name": true, "target": true, "detail": true}},
	"settings":  {"key", map[string]bool{"value": true}},
}

// blindIndexes lists the encrypted columns that SQL looks up by equality: each
// has a deterministic blind-index column (ports.ColumnCodec.BlindIndex) with a
// UNIQUE index, kept next to the ciphertext. An empty value has no index (NULL).
var blindIndexes = []struct{ table, column, index string }{
	{"users", "username", "username_bi"},
	{"users", "email", "email_bi"},
	{"shares", "long_id", "long_id_bi"},
}

// blindIdx returns the blind index of v for (table, column) as the BLOB to
// store or compare: nil (SQL NULL) for an empty value. Without a codec the
// column holds plaintext and the index is the normalised value itself, so the
// lookups stay the same.
func blindIdx(c ports.ColumnCodec, table, column, v string) (any, error) {
	if v == "" {
		return nil, nil
	}
	if c == nil {
		return []byte(colenc.Normalise(v)), nil
	}
	return c.BlindIndex(table, column, v)
}

// blindKey is blindIdx for a lookup, where an empty value matches nothing.
func blindKey(c ports.ColumnCodec, table, column, v string) ([]byte, error) {
	b, err := blindIdx(c, table, column, v)
	if err != nil || b == nil {
		return []byte{}, err
	}
	return b.([]byte), nil
}

func encryptedColumn(table, column string) (pk string, err error) {
	t, ok := encryptedColumns[table]
	if !ok || !t.columns[column] {
		return "", fmt.Errorf("%s.%s is not an encrypted column", table, column)
	}
	return t.pk, nil
}

// RawColumn returns the stored value of an encrypted column exactly as the
// database holds it: what a database administrator would read. key is the
// row's primary key (decimal text for a numeric key). It exists for the
// conformance suite, which checks that no plaintext reaches the table.
func (s *Store) RawColumn(ctx context.Context, table, column, key string) (string, error) {
	return rawColumn(ctx, s.q(), table, column, key)
}

func rawColumn(ctx context.Context, q querier, table, column, key string) (string, error) {
	pk, err := encryptedColumn(table, column)
	if err != nil {
		return "", err
	}
	var v []byte
	err = q.QueryRowContext(ctx, `SELECT `+column+` FROM `+table+` WHERE `+pk+`=?`, rawKeyArg(table, pk, key)).Scan(&v)
	return string(v), err
}

// RawSetColumn overwrites the stored value of an encrypted column without
// encrypting it: what a database administrator with write access could do.
// For the conformance suite (copying a ciphertext to another row, flipping
// bits); the adapter must refuse what it then reads.
func (s *Store) RawSetColumn(ctx context.Context, table, column, key, value string) error {
	return rawSetColumn(ctx, s.q(), table, column, key, value)
}

func rawSetColumn(ctx context.Context, q querier, table, column, key, value string) error {
	pk, err := encryptedColumn(table, column)
	if err != nil {
		return err
	}
	var v any = value
	if column == "legacy_root" {
		v = []byte(value) // a BLOB column
	}
	_, err = q.ExecContext(ctx, `UPDATE `+table+` SET `+column+`=? WHERE `+pk+`=?`, v, rawKeyArg(table, pk, key))
	return err
}

// RawColumn and RawSetColumn of the platform database: see Store.RawColumn.
func (s *PlatformStore) RawColumn(ctx context.Context, table, column, key string) (string, error) {
	return rawColumn(ctx, s.q, table, column, key)
}

func (s *PlatformStore) RawSetColumn(ctx context.Context, table, column, key, value string) error {
	return rawSetColumn(ctx, s.q, table, column, key, value)
}

// rawKeyArg converts the key text to the column's type (tenants has a text id).
func rawKeyArg(table, pk, key string) any {
	if (pk == "id" && table != "tenants") || pk == "seq" {
		n, _ := strconv.ParseInt(key, 10, 64)
		return n
	}
	return key
}

// ClearSealedTables empties the settings and the audit log, whose values the
// store sealed with its own keys while opening. For the conformance suite,
// which installs a codec of its own and starts from empty tables.
func (s *Store) ClearSealedTables(ctx context.Context) error {
	for _, q := range []string{`DELETE FROM settings`, `DELETE FROM audit_log`} {
		if _, err := s.q().ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) q() querier { return s.repos.q }

// PlaintextColumns counts the values in encrypted columns that are not
// encrypted: what a database created before column encryption holds.
func (s *Store) PlaintextColumns(ctx context.Context) (int, error) {
	total := 0
	for _, table := range sortedTables() {
		if !tableExists(ctx, s.q(), table) {
			continue
		}
		for _, col := range sortedColumns(table) {
			var n int
			err := s.q().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE `+col+` IS NOT NULL AND `+col+` <> '' AND `+col+` NOT LIKE 'e1:%'`).Scan(&n)
			if err != nil {
				return 0, err
			}
			total += n
		}
	}
	return total, nil
}

// EncryptPlaintextColumns seals every plaintext value in the encrypted columns
// with c, in one transaction, and returns how many it converted. It is the
// upgrade of a database created before column encryption (offline, after a
// backup).
func (s *Store) EncryptPlaintextColumns(ctx context.Context, c ports.ColumnCodec) (int, error) {
	return s.ResealColumns(ctx, nil, c)
}

// ResealColumns rewrites the encrypted columns in one transaction: an encrypted
// value is opened with from, a plaintext value is taken as it is, and the result
// is sealed with to. With from == nil values that are already encrypted are left
// alone. It returns how many values it rewrote. It re-keys a database that was
// copied under another key (import, restore, key change).
func (s *Store) ResealColumns(ctx context.Context, from, to ports.ColumnCodec) (int, error) {
	// A copy of an older database lacks the blind-index columns; they are
	// recomputed below, so they must exist (idempotent).
	if tableExists(ctx, s.db, "users") {
		if err := MigrateLookupIndexes(s.db); err != nil {
			return 0, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	converted := 0
	for _, table := range sortedTables() {
		if !tableExists(ctx, tx, table) {
			continue
		}
		pk := encryptedColumns[table].pk
		for _, col := range sortedColumns(table) {
			rows, err := tx.QueryContext(ctx, `SELECT `+pk+`, `+col+` FROM `+table+` WHERE `+col+` IS NOT NULL AND `+col+` <> ''`)
			if err != nil {
				return 0, err
			}
			type row struct{ key, value string }
			var todo []row
			for rows.Next() {
				var key any
				var value string
				if err := rows.Scan(&key, &value); err != nil {
					rows.Close()
					return 0, err
				}
				todo = append(todo, row{fmt.Sprint(key), value})
			}
			if err := rows.Close(); err != nil {
				return 0, err
			}
			for _, r := range todo {
				plain := r.value
				if strings.HasPrefix(r.value, "e1:") {
					if from == nil {
						continue // already encrypted
					}
					if plain, err = from.Open(table, col, r.key, r.value); err != nil {
						return 0, fmt.Errorf("opening %s.%s of row %s: %w", table, col, r.key, err)
					}
				}
				sealed, err := to.Seal(table, col, r.key, plain)
				if err != nil {
					return 0, err
				}
				if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET `+col+`=? WHERE `+pk+`=?`, sealed, rawKeyArg(table, pk, r.key)); err != nil {
					return 0, err
				}
				converted++
			}
		}
	}
	if err := reindexBlind(ctx, tx, to); err != nil {
		return 0, err
	}
	return converted, tx.Commit()
}

// ReindexBlindIndexes recomputes every blind-index column from the stored
// values with c (nil: the database holds plaintext). It repairs rows written
// without their index and is what tests that insert rows with raw SQL call.
func (s *Store) ReindexBlindIndexes(ctx context.Context, c ports.ColumnCodec) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := reindexBlind(ctx, tx, c); err != nil {
		return err
	}
	return tx.Commit()
}

// reindexBlind recomputes every blind-index column from the (already sealed)
// values with c: the index key changes with the database's keys.
func reindexBlind(ctx context.Context, tx querier, c ports.ColumnCodec) error {
	for _, b := range blindIndexes {
		if !tableExists(ctx, tx, b.table) {
			continue
		}
		pk := encryptedColumns[b.table].pk
		rows, err := tx.QueryContext(ctx, `SELECT `+pk+`, `+b.column+` FROM `+b.table)
		if err != nil {
			return err
		}
		type row struct{ key, value string }
		var todo []row
		for rows.Next() {
			var key any
			var value string
			if err := rows.Scan(&key, &value); err != nil {
				rows.Close()
				return err
			}
			todo = append(todo, row{fmt.Sprint(key), value})
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, r := range todo {
			plain, err := openColKey(c, b.table, b.column, r.key, r.value)
			if err != nil {
				return err
			}
			bi, err := blindIdx(c, b.table, b.column, plain)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE `+b.table+` SET `+b.index+`=? WHERE `+pk+`=?`, bi, rawKeyArg(b.table, pk, r.key)); err != nil {
				return err
			}
		}
	}
	return nil
}

// DropKeys removes the database's control log and keyring: the keys of a
// database copied under another key, which cannot be verified or unwrapped any
// more. Call ResealColumns before dropping when encrypted values must survive.
func (s *Store) DropKeys(ctx context.Context) error {
	for _, stmt := range []string{`DROP TABLE IF EXISTS control_log`, `DROP TABLE IF EXISTS tenant_keyring`} {
		if _, err := s.q().ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func sortedTables() []string {
	out := make([]string, 0, len(encryptedColumns))
	for t := range encryptedColumns {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func sortedColumns(table string) []string {
	out := make([]string, 0, len(encryptedColumns[table].columns))
	for c := range encryptedColumns[table].columns {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// readSetting reads setting key through q and opens it (sql.ErrNoRows when the
// setting does not exist). The value is bound to its key.
func readSetting(ctx context.Context, q querier, c ports.ColumnCodec, key string) (string, error) {
	var v string
	if err := q.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return "", err
	}
	return openColKey(c, "settings", "value", key, v)
}

// writeSetting replaces the value of an existing setting and returns how many
// rows it changed (0 when the setting does not exist).
func writeSetting(ctx context.Context, q querier, c ports.ColumnCodec, key, value string) (int64, error) {
	sealed, err := sealColKey(c, "settings", "value", key, value)
	if err != nil {
		return 0, err
	}
	return changed(q.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=?`, sealed, key))
}

// insertSettingIfAbsent adds a setting unless the key exists.
func insertSettingIfAbsent(ctx context.Context, q querier, c ports.ColumnCodec, key, value, group string) error {
	sealed, err := sealColKey(c, "settings", "value", key, value)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT OR IGNORE INTO settings(key,value,grp) VALUES(?,?,?)`, key, sealed, group)
	return err
}

// upsertSetting stores value under key, creating the setting in group when it
// does not exist (an existing setting keeps its group).
func upsertSetting(ctx context.Context, q querier, c ports.ColumnCodec, key, value, group string) error {
	sealed, err := sealColKey(c, "settings", "value", key, value)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO settings(key,value,grp) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, sealed, group)
	return err
}
