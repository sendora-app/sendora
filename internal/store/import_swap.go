// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"os"
	"path/filepath"
)

const (
	// ImportMarker exists in the data dir from just before the database swap until
	// the first successful start afterwards.
	ImportMarker = "import-pending"
	// PreImportSuffix is appended to sendora.db to keep the previous database.
	PreImportSuffix = ".pre-import"
)

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func syncFile(p string) error {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func removeIfExists(p string) error {
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// SwapImportedDatabase replaces sendora.db by the prepared copy at newPath. The
// live store MUST already be closed. Sequence: write marker, move the old database
// to sendora.db.pre-import, remove the old -wal/-shm, move the new file into
// place (0600, fsync file and directory), then clear DataDir/uploads/*. On failure
// before completion the previous database is put back and the marker removed.
func SwapImportedDatabase(dataDir, newPath string) error {
	db, err := DBPath(dataDir)
	if err != nil {
		return err
	}
	pre := db + PreImportSuffix
	marker := filepath.Join(dataDir, ImportMarker)
	if err := os.WriteFile(marker, []byte("pending\n"), 0o600); err != nil {
		return err
	}
	if f, err := os.OpenFile(marker, os.O_RDWR, 0); err == nil {
		f.Sync()
		f.Close()
	}
	syncDir(dataDir)
	rollback := func() {
		if _, err := os.Stat(db); err != nil {
			os.Rename(pre, db)
		}
		os.Remove(marker)
		syncDir(dataDir)
	}
	if err := removeIfExists(pre); err != nil {
		os.Remove(marker)
		return err
	}
	if err := os.Rename(db, pre); err != nil {
		os.Remove(marker)
		return err
	}
	for _, p := range []string{db + "-wal", db + "-shm", newPath + "-wal", newPath + "-shm"} {
		if err := removeIfExists(p); err != nil {
			rollback()
			return err
		}
	}
	if err := os.Rename(newPath, db); err != nil {
		rollback()
		return err
	}
	if err := os.Chmod(db, 0o600); err != nil {
		os.Rename(db, newPath)
		rollback()
		return err
	}
	if err := syncFile(db); err != nil {
		os.Rename(db, newPath)
		rollback()
		return err
	}
	syncDir(dataDir)
	return clearUploads(dataDir)
}

// clearUploads empties DataDir/uploads (staged/partial uploads belong to the old
// database); the directory itself stays.
func clearUploads(dataDir string) error {
	dir := filepath.Join(dataDir, "uploads")
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var first error
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// OpenEncryptedRecovering is OpenEncrypted plus recovery from an interrupted or
// failed import swap. With the marker present: if the database opens, marker and
// sendora.db.pre-import are removed; if it does not, the previous database is
// restored from sendora.db.pre-import (when present) and opened instead.
func OpenEncryptedRecovering(dataDir string, key []byte, initialize bool, logf func(string, ...any)) (*Store, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	marker := filepath.Join(dataDir, ImportMarker)
	if _, err := os.Stat(marker); err != nil {
		return OpenEncrypted(dataDir, key, initialize)
	}
	db, err := DBPath(dataDir)
	if err != nil {
		return nil, err
	}
	pre := db + PreImportSuffix
	st, err := OpenEncrypted(dataDir, key, false)
	if err == nil {
		os.Remove(marker)
		os.Remove(pre)
		syncDir(dataDir)
		logf("database import completed; cleaned up the import marker and previous-database copy")
		return st, nil
	}
	if _, perr := os.Stat(pre); perr != nil {
		return nil, errors.New("an interrupted database import left the database unusable and no previous copy exists: " + err.Error())
	}
	logf("WARNING: the imported database could not be opened (%v); restoring the previous database", err)
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		if rerr := removeIfExists(p); rerr != nil {
			return nil, rerr
		}
	}
	if rerr := os.Rename(pre, db); rerr != nil {
		return nil, rerr
	}
	os.Remove(marker)
	syncDir(dataDir)
	logf("previous database restored after failed import")
	return OpenEncrypted(dataDir, key, false)
}
