// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	sqlite3 "github.com/mattn/go-sqlite3"
)

type cipherConnector struct {
	driver *sqlite3.SQLiteDriver
	dsn    string
}

func (c *cipherConnector) Driver() driver.Driver { return c.driver }
func (c *cipherConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := c.driver.Open(c.dsn)
	if err == nil && ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	return conn, err
}

// Errors of OpenCipherDB.
var (
	ErrEngineUnavailable = errors.New("required SQLCipher 4.20.0 engine unavailable")
	ErrCannotRead        = errors.New("database cannot be read with supplied key")
)

// OpenCipherDB opens the SQLCipher database at p with key (empty only for an
// explicit plaintext migration source), on one connection, and proves that
// the engine is SQLCipher 4.20.0 and that the key reads the file.
func OpenCipherDB(p string, key []byte, readonly bool) (*sql.DB, error) {
	if len(key) != 0 && len(key) != 32 {
		return nil, errors.New("database key must contain 32 bytes")
	}
	absolute, err := filepath.Abs(p)
	if err != nil {
		return nil, err
	}
	u := &url.URL{Scheme: "file", Path: absolute}
	q := u.Query()
	q.Set("mode", "rw")
	if readonly {
		q.Set("mode", "ro")
	}
	q.Set("_busy_timeout", "5000")
	q.Set("_foreign_keys", "on")
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	d := &sqlite3.SQLiteDriver{CipherKey: append([]byte(nil), key...)}
	db := sql.OpenDB(&cipherConnector{driver: d, dsn: u.String()})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var version string
	err = db.QueryRow(`PRAGMA cipher_version`).Scan(&version)
	if err != nil {
		db.Close()
		// A wrong or missing key makes SQLite report "file is not a database" while
		// the connection is prepared; that is a key problem, not a missing engine.
		var se sqlite3.Error
		if errors.As(err, &se) && se.Code == sqlite3.ErrNotADB {
			return nil, ErrCannotRead
		}
		return nil, ErrEngineUnavailable
	}
	if !strings.HasPrefix(version, "4.20.0 ") {
		db.Close()
		return nil, ErrEngineUnavailable
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master`).Scan(&count); err != nil {
		db.Close()
		return nil, ErrCannotRead
	}
	if !readonly {
		if _, err := db.Exec(`PRAGMA temp_store=MEMORY`); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}

// CheckCipherIntegrity runs the SQLCipher (when encrypted), SQLite and
// foreign-key integrity checks.
func CheckCipherIntegrity(db *sql.DB, encrypted bool) error {
	if encrypted {
		rows, err := db.Query(`PRAGMA cipher_integrity_check`)
		if err != nil {
			return err
		}
		failed := rows.Next()
		err = rows.Err()
		rows.Close()
		if err != nil || failed {
			return errors.New("cipher integrity verification failed")
		}
	}
	var result string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil || result != "ok" {
		return errors.New("database integrity verification failed")
	}
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	failed := rows.Next()
	err = rows.Err()
	rows.Close()
	if err != nil || failed {
		return errors.New("database foreign key verification failed")
	}
	return nil
}

// ExportDatabase writes a new, keyed database through SQLCipher's export API.
// Source key may be empty only for explicit offline plaintext migration.
func ExportDatabase(source, destination string, sourceKey, destinationKey []byte) error {
	if len(destinationKey) != 32 {
		return errors.New("export requires a 32-byte destination key")
	}
	db, err := OpenCipherDB(source, sourceKey, true)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := CheckCipherIntegrity(db, len(sourceKey) != 0); err != nil {
		return err
	}
	return ExportConnection(db, destination, destinationKey)
}

// ExportConnection writes a verified, keyed copy of db to destination (see
// ExportDatabase).
func ExportConnection(db *sql.DB, destination string, key []byte) error {
	// Exclusive creation avoids overwriting any pre-existing database/backup.
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	f.Close()
	ok := false
	defer func() {
		if !ok {
			os.Remove(destination)
			os.Remove(destination + "-wal")
			os.Remove(destination + "-shm")
		}
	}()
	conn, err := db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	var userVersion, applicationID int
	if err = conn.QueryRowContext(context.Background(), `PRAGMA user_version`).Scan(&userVersion); err != nil {
		return err
	}
	if err = conn.QueryRowContext(context.Background(), `PRAGMA application_id`).Scan(&applicationID); err != nil {
		return err
	}
	// ATTACH ... KEY needs the key as a SQL string. Its bytes live in a slice that
	// is wiped as soon as the statement returns, so the string does not outlive
	// the call (the driver and SQLCipher keep their own working copies; a Go
	// string cannot be wiped otherwise).
	literal := HexKeyLiteral(key)
	_, err = conn.ExecContext(context.Background(), `ATTACH DATABASE ? AS encrypted_export KEY ?`, destination, unsafe.String(&literal[0], len(literal)))
	clear(literal)
	if err != nil {
		return errors.New("cannot attach encrypted export")
	}
	attached := true
	defer func() {
		if attached {
			conn.ExecContext(context.Background(), `DETACH DATABASE encrypted_export`)
		}
	}()
	// Hold one source snapshot across export, metadata and content verification.
	// BEGIN (not BEGIN IMMEDIATE) also permits explicit readonly migration sources.
	if _, err = conn.ExecContext(context.Background(), `BEGIN`); err != nil {
		return err
	}
	inTransaction := true
	defer func() {
		if inTransaction {
			conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	if err = conn.QueryRowContext(context.Background(), `PRAGMA user_version`).Scan(&userVersion); err != nil {
		return err
	}
	if err = conn.QueryRowContext(context.Background(), `PRAGMA application_id`).Scan(&applicationID); err != nil {
		return err
	}
	if _, err = conn.ExecContext(context.Background(), `SELECT sqlcipher_export('encrypted_export')`); err != nil {
		return errors.New("encrypted database export failed")
	}
	if _, err = conn.ExecContext(context.Background(), fmt.Sprintf(`PRAGMA encrypted_export.user_version=%d; PRAGMA encrypted_export.application_id=%d`, userVersion, applicationID)); err != nil {
		return err
	}
	sourceDigest, err := databaseDigest(conn, "main")
	if err != nil {
		return err
	}
	exportDigest, err := databaseDigest(conn, "encrypted_export")
	if err != nil || sourceDigest != exportDigest {
		return errors.New("export schema or contents differ from source")
	}
	if _, err = conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return err
	}
	inTransaction = false
	if _, err = conn.ExecContext(context.Background(), `DETACH DATABASE encrypted_export`); err != nil {
		return err
	}
	attached = false
	verify, err := OpenCipherDB(destination, key, true)
	if err != nil {
		return err
	}
	defer verify.Close()
	if err := CheckCipherIntegrity(verify, true); err != nil {
		return err
	}
	if unkeyed, err := OpenCipherDB(destination, nil, true); err == nil {
		unkeyed.Close()
		return errors.New("export was not encrypted")
	}
	if err := os.Chmod(destination, 0600); err != nil {
		return err
	}
	f, err = os.OpenFile(destination, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return err
	}
	ok = true
	return nil
}

// databaseDigest verifies schema, indexes, triggers, sequence values and every
// stored column, including disk paths, without printing any sensitive contents.
// Both calls use the export connection's single consistent transaction snapshot.
func databaseDigest(conn *sql.Conn, schema string) ([32]byte, error) {
	var zero [32]byte
	if schema != "main" && schema != "encrypted_export" {
		return zero, errors.New("invalid database schema")
	}
	h := sha256.New()
	enc := json.NewEncoder(h)
	rows, err := conn.QueryContext(context.Background(), `SELECT type,name,tbl_name,sql FROM `+schema+`.sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		return zero, err
	}
	for rows.Next() {
		var kind, name, table string
		var statement *string
		if err := rows.Scan(&kind, &name, &table, &statement); err != nil {
			rows.Close()
			return zero, err
		}
		if err := enc.Encode([]any{kind, name, table, statement}); err != nil {
			rows.Close()
			return zero, err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return zero, err
	}
	rows, err = conn.QueryContext(context.Background(), `SELECT name FROM `+schema+`.sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		return zero, err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			rows.Close()
			return zero, err
		}
		tables = append(tables, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return zero, err
	}
	quote := func(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
	for _, table := range tables {
		if err := enc.Encode(table); err != nil {
			return zero, err
		}
		// Discover columns before building a deterministic all-column ordering.
		rows, err = conn.QueryContext(context.Background(), `SELECT * FROM `+schema+`.`+quote(table)+` LIMIT 0`)
		if err != nil {
			return zero, err
		}
		columns, err := rows.Columns()
		rows.Close()
		if err != nil {
			return zero, err
		}
		order := make([]string, len(columns))
		for i := range columns {
			order[i] = quote(columns[i])
		}
		rows, err = conn.QueryContext(context.Background(), `SELECT * FROM `+schema+`.`+quote(table)+` ORDER BY `+strings.Join(order, ","))
		if err != nil {
			return zero, err
		}
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				return zero, err
			}
			if err := enc.Encode(values); err != nil {
				rows.Close()
				return zero, err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return zero, err
		}
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// HexKeyLiteral returns x'<hex key>' in a fresh slice for the caller to wipe.
func HexKeyLiteral(key []byte) []byte {
	lit := make([]byte, 3+2*len(key))
	lit[0], lit[1], lit[len(lit)-1] = 'x', '\'', '\''
	hex.Encode(lit[2:], key)
	return lit
}
