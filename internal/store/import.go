// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/ports"
)

// ImportError is a rejection whose message is safe to show to an administrator
// (it never contains key material or file contents).
type ImportError struct{ Msg string }

func (e *ImportError) Error() string { return e.Msg }

// ImportSummary holds counts of an imported (re-keyed, migrated) database.
type ImportSummary struct {
	Users, Admins  int64 // non-guest accounts
	Shares, Files  int64 // shares that are not deleted, and their files
	DroppedUploads int64 // stale upload sessions removed
}

// ImportDatabase validates src (encrypted with srcKey, or with this store's key
// when srcKey is empty) and writes a copy re-keyed with this store's key to dest.
func (s *Store) ImportDatabase(src, dest string, srcKey []byte) error {
	if !s.IsEncrypted() {
		return errors.New("database import requires an encrypted store")
	}
	key := srcKey
	if len(key) == 0 {
		key = s.cipherKey
	}
	if len(key) != 32 {
		return &ImportError{"database key must contain 32 bytes"}
	}
	err := ExportDatabase(src, dest, key, s.cipherKey)
	if err == nil {
		return nil
	}
	var pathErr *fs.PathError
	switch {
	case errors.As(err, &pathErr):
		return err
	// openCipherDB reports a file it cannot decrypt (wrong key, garbage) through
	// the failing first query as either of these; the engine itself is proven
	// available by the live store being open.
	case errors.Is(err, errCannotRead), errors.Is(err, errEngineUnavailable):
		return &ImportError{"the file could not be opened: it is not an encrypted Sendora database, it is damaged, or the key is wrong"}
	default:
		return &ImportError{"the database failed validation (integrity check)"}
	}
}

// PrepareImportedCopy runs PrepareImported with this store's key.
func (s *Store) PrepareImportedCopy(path string) (*ImportSummary, error) {
	return PrepareImported(path, s.cipherKey, s.DataDir)
}

// ScanImportedCopy visits (shareID, disk_path) of files of non-deleted shares
// in a prepared copy, read-only.
func (s *Store) ScanImportedCopy(path string, fn func(shareID int64, diskPath string)) error {
	return sqlite.ScanImportedFiles(path, s.cipherKey, fn)
}

var (
	refOnce   sync.Once
	refTables map[string]map[string]bool
	refErr    error
)

// Tables created outside the store package by the application (server.go).
var externalTables = map[string]bool{"verification_attempts": true}

// referenceSchema builds this binary's own schema in a throw-away encrypted DB.
func referenceSchema() (map[string]map[string]bool, error) {
	refOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sendora-schema-")
		if err != nil {
			refErr = err
			return
		}
		defer os.RemoveAll(dir)
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			refErr = err
			return
		}
		st, err := openStore(dir, key)
		if err != nil {
			refErr = err
			return
		}
		defer st.Close()
		refTables, refErr = readSchema(st.DB)
	})
	return refTables, refErr
}

func readSchema(db *sql.DB) (map[string]map[string]bool, error) { return sqlite.ReadSchema(db) }

func clipName(s string) string {
	s = strings.ToValidUTF8(s, "")
	if r := []rune(s); len(r) > 40 {
		return string(r[:40])
	}
	return s
}

// PrepareImported opens an already re-keyed copy writable, removes stale upload
// reservations, runs this binary's additive migrations, verifies required tables,
// rejects schemas from newer versions and databases without a usable
// administrator, and returns counts. On any error the file is left for the
// caller to delete. The caller must not use the file concurrently.
//
// An imported file is treated as untrusted input. Everything that is not data is
// discarded or rebuilt from this binary's own definitions: triggers, views and
// indexes are dropped (virtual tables are refused), sessions, reset/verification
// codes and the signing secret are cleared, every share ID must have a known
// format, and every file's disk_path is rewritten to this server's
// DataDir/shares/<share id>/<base name> so a crafted file can never point reads
// or deletes outside a share directory.
func PrepareImported(path string, key []byte, dataDir string) (*ImportSummary, error) {
	if len(key) != 32 {
		return nil, errors.New("database key must contain 32 bytes")
	}
	if dataDir == "" {
		return nil, errors.New("data directory required")
	}
	ref, err := referenceSchema()
	if err != nil {
		return nil, err
	}
	db, err := openCipherDB(path, key, false)
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			db.Close()
		}
	}()
	// Never run functions defined by the uploaded schema (views, triggers,
	// generated columns) with elevated trust while the file is inspected.
	if err := sqlite.DistrustSchema(db); err != nil {
		return nil, err
	}
	// Generated (hidden) columns are never part of Sendora's schema; they could
	// make every read of a table expensive.
	generated, err := sqlite.CountGeneratedColumns(db)
	if err != nil {
		return nil, err
	}
	if generated > 0 {
		return nil, &ImportError{"the database contains generated columns, which Sendora never creates"}
	}
	// Required core tables must already exist: the idempotent schema would
	// otherwise silently turn an unrelated database into an empty Sendora one.
	have, err := readSchema(db)
	if err != nil {
		return nil, err
	}
	for _, t := range []string{"users", "settings", "shares", "files"} {
		if have[t] == nil {
			return nil, &ImportError{"the database is not a Sendora database (required table missing: " + t + ")"}
		}
	}
	if err := stripForeignObjects(db); err != nil {
		return nil, err
	}
	if err := initSchema(db); err != nil {
		return nil, err
	}
	sum := &ImportSummary{}
	// Reservations/staging belong to the old environment; drop them before migration
	// (migration refuses unattributable reservations).
	if sum.DroppedUploads, err = sqlite.DropUploadReservations(db); err != nil {
		return nil, err
	}
	tmp := &Store{DB: db, Path: path}
	// The copy was re-sealed under its own keys (resealExport): the settings
	// the migrations add are sealed with them.
	codec, err := columnCodecFor(db, key)
	if err != nil {
		return nil, &ImportError{"the database's keys do not verify"}
	}
	if codec != nil {
		defer codec.Close()
		tmp.codec = codec
		if a, ok := tmp.Repos().(*sqlite.Store); ok {
			a.SetCodec(codec)
		}
	}
	if err := tmp.runMigrations(); err != nil {
		return nil, &ImportError{"the database cannot be migrated to this version of Sendora"}
	}
	if err := clearImportedSecrets(db); err != nil {
		return nil, err
	}
	// Imported table definitions may lack the uniqueness Sendora relies on (two
	// shares with one link ID would share a storage folder). Enforce it here.
	if err := sqlite.EnforceImportUniqueness(db); err != nil {
		return nil, &ImportError{"the database contains duplicate share links or usernames"}
	}
	if err := rebaseImportedFiles(db, dataDir, key); err != nil {
		return nil, err
	}
	got, err := readSchema(db)
	if err != nil {
		return nil, err
	}
	for table, cols := range got {
		known, ok := ref[table]
		if !ok {
			if externalTables[table] {
				continue
			}
			return nil, &ImportError{"the database was created with a newer Sendora version (unknown table " + clipName(table) + ")"}
		}
		for c := range cols {
			if !known[c] {
				return nil, &ImportError{"the database was created with a newer Sendora version (unknown column " + clipName(table) + "." + clipName(c) + ")"}
			}
		}
	}
	if sum.Users, sum.Admins, err = sqlite.CountImportedAccounts(db); err != nil {
		return nil, err
	}
	if sum.Admins < 1 {
		return nil, &ImportError{"the database contains no administrator account; importing it would lock everyone out"}
	}
	if sum.Shares, sum.Files, err = sqlite.CountImportedContent(db); err != nil {
		return nil, err
	}
	// Fold the WAL into the main file so the copy is a single standalone file.
	if err := sqlite.CheckpointTruncate(db); err != nil {
		return nil, err
	}
	closed = true
	if err := db.Close(); err != nil {
		return nil, err
	}
	// Final read-only verification of the prepared file with the live key.
	if _, err := VerifyDatabase(path, key); err != nil {
		return nil, &ImportError{"the prepared database failed verification"}
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		os.Remove(path + suffix)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return sum, nil
}

// RemoveImportFiles deletes a prepared/temporary database and its sidecars.
func RemoveImportFiles(path string) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		os.Remove(path + suffix)
	}
}

// stripForeignObjects refuses virtual tables and drops every trigger, view and
// explicit index found in the file. initSchema then recreates only this
// binary's own objects (all of them are CREATE ... IF NOT EXISTS).
func stripForeignObjects(db *sql.DB) error {
	virtual, err := sqlite.CountVirtualTables(db)
	if err != nil {
		return err
	}
	if virtual > 0 {
		return &ImportError{"the database contains virtual tables, which are not allowed"}
	}
	return sqlite.DropSchemaObjects(db)
}

// clearImportedSecrets removes everything that grants or proves access: sessions,
// reset and verification codes, revocation lists and the stored signing secret
// (a fresh one is generated at startup unless JWT_SECRET is set).
func clearImportedSecrets(db *sql.DB) error { return sqlite.ClearImportedSecrets(db) }

// rebaseImportedFiles validates share IDs and rewrites each local file's
// disk_path to this server's data directory (see PrepareImported). Files in an
// object store keep their location and key: they stay readable as long as the
// imported location's bucket and credentials are.
func rebaseImportedFiles(db *sql.DB, dataDir string, key []byte) error {
	codec, err := columnCodecFor(db, key)
	if err != nil {
		return err
	}
	var c ports.ColumnCodec // nil: a database without keys holds plaintext
	if codec != nil {
		defer codec.Close()
		c = codec
	}
	return sqlite.RebaseLocalFiles(db, c, func(lid string) error {
		if !ValidLongID(lid) {
			return &ImportError{"the database contains a share with an invalid link ID; importing it is refused"}
		}
		return nil
	}, func(lid, disk string) (string, error) {
		safe, perr := SharePath(dataDir, lid, disk)
		if perr != nil {
			return "", &ImportError{"the database contains a file record with an unsafe storage path; importing it is refused"}
		}
		return safe, nil
	})
}
