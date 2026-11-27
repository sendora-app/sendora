// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/ports"
)

// sealCol returns the stored form of an encrypted text column value. Without a
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

// blindIdx returns the blind index of v for (table, column) as the bytea to
// store or compare (ports.ColumnCodec.BlindIndex): nil (SQL NULL) for an empty
// value. Without a codec the column holds plaintext and the index is the
// normalised value itself, so the lookups stay the same.
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

func rawColumn(ctx context.Context, q pq, table, column, key string) (string, error) {
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

func rawSetColumn(ctx context.Context, q pq, table, column, key, value string) error {
	pk, err := encryptedColumn(table, column)
	if err != nil {
		return err
	}
	set := column + `=?`
	var v any = value
	if column == "legacy_root" {
		v, set = []byte(value), column+`=?::bytea` // a bytea column
	}
	_, err = q.ExecContext(ctx, `UPDATE `+table+` SET `+set+` WHERE `+pk+`=?`, v, rawKeyArg(table, pk, key))
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

func (s *Store) q() pq { return s.repos.q }

// readSetting reads setting key through q and opens it (ports.ErrNotFound when
// the setting does not exist). The value is bound to its key.
func readSetting(ctx context.Context, q pq, c ports.ColumnCodec, key string) (string, error) {
	var v string
	if err := q.scan(ctx, `SELECT value FROM settings WHERE key=?`, []any{key}, &v); err != nil {
		return "", err
	}
	return openColKey(c, "settings", "value", key, v)
}

// writeSetting replaces the value of an existing setting and returns how many
// rows it changed (0 when the setting does not exist).
func writeSetting(ctx context.Context, q pq, c ports.ColumnCodec, key, value string) (int64, error) {
	sealed, err := sealColKey(c, "settings", "value", key, value)
	if err != nil {
		return 0, err
	}
	return changed(q.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=?`, sealed, key))
}

// insertSettingIfAbsent adds a setting unless the key exists.
func insertSettingIfAbsent(ctx context.Context, q pq, c ports.ColumnCodec, key, value, group string) error {
	sealed, err := sealColKey(c, "settings", "value", key, value)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO settings(key,value,grp) VALUES(?,?,?) ON CONFLICT DO NOTHING`, key, sealed, group)
	return err
}

// upsertSetting stores value under key, creating the setting in group when it
// does not exist (an existing setting keeps its group).
func upsertSetting(ctx context.Context, q pq, c ports.ColumnCodec, key, value, group string) error {
	sealed, err := sealColKey(c, "settings", "value", key, value)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO settings(key,value,grp) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, sealed, group)
	return err
}
