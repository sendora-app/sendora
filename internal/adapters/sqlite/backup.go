// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"errors"
	"os"
)

// SnapshotPlaintext creates a restricted, standalone rollback database. The
// source application MUST be stopped; raw copies of a live DB omit WAL commits.
func SnapshotPlaintext(source, destination string) error {
	db, err := OpenCipherDB(source, nil, true)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := CheckCipherIntegrity(db, false); err != nil {
		return err
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	before, err := databaseDigest(conn, "main")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	f.Close()
	ok := false
	defer func() {
		if !ok {
			os.Remove(destination)
		}
	}()
	if _, err := conn.ExecContext(context.Background(), `VACUUM INTO ?`, destination); err != nil {
		return err
	}
	after, err := databaseDigest(conn, "main")
	if err != nil || before != after {
		return errors.New("source changed during offline snapshot")
	}
	verify, err := OpenCipherDB(destination, nil, true)
	if err != nil {
		return err
	}
	defer verify.Close()
	if err := CheckCipherIntegrity(verify, false); err != nil {
		return err
	}
	vc, err := verify.Conn(context.Background())
	if err != nil {
		return err
	}
	defer vc.Close()
	copied, err := databaseDigest(vc, "main")
	if err != nil || copied != before {
		return errors.New("rollback snapshot contents differ")
	}
	for _, pragma := range []string{"user_version", "application_id"} {
		var a, b int64
		if err := conn.QueryRowContext(context.Background(), "PRAGMA "+pragma).Scan(&a); err != nil {
			return err
		}
		if err := vc.QueryRowContext(context.Background(), "PRAGMA "+pragma).Scan(&b); err != nil {
			return err
		}
		if a != b {
			return errors.New("rollback snapshot metadata differs")
		}
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

// VerifyDatabase opens without schema migrations and reports non-sensitive row
// counts only after SQLCipher, SQLite and foreign-key integrity checks succeed.
func VerifyDatabase(path string, key []byte) (map[string]int64, error) {
	db, err := OpenCipherDB(path, key, true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := CheckCipherIntegrity(db, len(key) != 0); err != nil {
		return nil, err
	}
	counts := make(map[string]int64)
	for _, table := range []string{"users", "shares", "files", "upload_sessions"} {
		var count int64
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			return nil, err
		}
		counts[table] = count
	}
	return counts, nil
}
