// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// DBFile is the name of the database inside the data directory.
const DBFile = "sendora.db"

// legacyDBFile is the database name used by earlier releases. It is only read to migrate.
const legacyDBFile = "fileshare.db"

// dbSidecars are the files that belong to the database and move with it.
var dbSidecars = []string{"-wal", "-shm", PreImportSuffix}

// DBPath returns the database path in dataDir, first renaming an old database
// (and its -wal, -shm and .pre-import files) once. Sidecars move before the main
// file, so an interrupted rename resumes at the next start without separating
// the database from its write-ahead log. With both names present it refuses to
// guess which one is current.
func DBPath(dataDir string) (string, error) {
	p := filepath.Join(dataDir, DBFile)
	old := filepath.Join(dataDir, legacyDBFile)
	if _, err := os.Lstat(old); os.IsNotExist(err) {
		return p, nil
	} else if err != nil {
		return "", err
	}
	if _, err := os.Lstat(p); err == nil {
		return "", fmt.Errorf("both %s and %s exist in the data directory; keep the current one and move the other away", DBFile, legacyDBFile)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	for _, suffix := range dbSidecars {
		if err := renameSidecar(old+suffix, p+suffix); err != nil {
			return "", err
		}
	}
	if err := os.Rename(old, p); err != nil {
		return "", err
	}
	if err := syncDir(dataDir); err != nil {
		return "", err
	}
	log.Printf("renamed database %s to %s", legacyDBFile, DBFile)
	return p, nil
}

func renameSidecar(from, to string) error {
	_, fromErr := os.Lstat(from)
	if os.IsNotExist(fromErr) {
		return nil // absent, or already moved by an interrupted earlier run
	} else if fromErr != nil {
		return fromErr
	}
	if _, err := os.Lstat(to); err == nil {
		return fmt.Errorf("cannot rename %s: %s already exists", filepath.Base(from), filepath.Base(to))
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(from, to)
}
