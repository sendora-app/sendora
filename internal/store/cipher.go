// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"database/sql"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
)

// Opening, keying and exporting SQLCipher databases is backend-specific and
// lives in internal/adapters/sqlite (cipher.go, backup.go); these names keep
// the package's callers and tests unchanged.
var (
	errEngineUnavailable = sqlite.ErrEngineUnavailable
	errCannotRead        = sqlite.ErrCannotRead
)

func openCipherDB(p string, key []byte, readonly bool) (*sql.DB, error) {
	return sqlite.OpenCipherDB(p, key, readonly)
}

func exportConnection(db *sql.DB, destination string, key []byte) error {
	return sqlite.ExportConnection(db, destination, key)
}

func hexKeyLiteral(key []byte) []byte { return sqlite.HexKeyLiteral(key) }

func checkCipherIntegrity(db *sql.DB, encrypted bool) error {
	return sqlite.CheckCipherIntegrity(db, encrypted)
}

// ReadDatabaseKey accepts root-owned projected secrets or current-user files,
// never world-accessible or group-writable key material. Group-read is permitted
// for a Kubernetes fsGroup secret mount. The key is never logged or put in a DSN.
func ReadDatabaseKey(p string) ([]byte, error) {
	if p == "" {
		return nil, errors.New("SENDORA_DB_KEY_FILE is required")
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, errors.New("database key file cannot be opened")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0027 != 0 {
		return nil, errors.New("database key must be a restricted regular file")
	}
	if owner, ok := st.Sys().(*syscall.Stat_t); !ok || (owner.Uid != 0 && int(owner.Uid) != os.Getuid()) {
		return nil, errors.New("database key file owner is not trusted")
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return nil, errors.New("database key file must contain exactly 32 raw bytes")
	}
	return key, nil
}

// OpenEncrypted is the sole production opener. Initialization must be explicit;
// existing plaintext, empty or unreadable databases are never overwritten.
func OpenEncrypted(dataDir string, key []byte, initialize bool) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("database key must contain 32 bytes")
	}
	p, err := DBPath(dataDir)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if os.IsNotExist(err) {
		if !initialize {
			return nil, errors.New("database missing; explicit initialization required")
		}
	} else if err != nil {
		return nil, errors.New("database cannot be opened")
	} else {
		header := make([]byte, 16)
		_, readErr := io.ReadFull(f, header)
		f.Close()
		if readErr != nil {
			return nil, errors.New("existing database is empty or invalid")
		}
		if bytes.Equal(header, []byte("SQLite format 3\x00")) {
			return nil, errors.New("plaintext database requires offline SQLCipher migration")
		}
		// Prove readability before chmod, WAL PRAGMAs, schema, or migration writes.
		db, err := openCipherDB(p, key, true)
		if err != nil {
			return nil, err
		}
		db.Close()
	}
	return openStore(dataDir, key)
}

// ExportDatabase writes a new, keyed database through SQLCipher's export API.
// Source key may be empty only for explicit offline plaintext migration.
func ExportDatabase(source, destination string, sourceKey, destinationKey []byte) error {
	if err := sqlite.ExportDatabase(source, destination, sourceKey, destinationKey); err != nil {
		return err
	}
	if len(sourceKey) != 32 || len(destinationKey) != 32 {
		return nil // plaintext migration tools: the columns are upgraded when the copy is opened
	}
	if bytes.Equal(sourceKey, destinationKey) {
		return nil // same key: the copy's keys verify as they are (a backup)
	}
	if err := resealExport(source, destination, sourceKey, destinationKey); err != nil {
		os.Remove(destination)
		return err
	}
	return nil
}

func (s *Store) IsEncrypted() bool { return len(s.cipherKey) == 32 }

func (s *Store) ExportEncryptedBackup(destination string) error {
	if s.DB == nil {
		return ErrRemoteStore
	}
	if len(s.cipherKey) != 32 {
		return errors.New("encrypted backups require an encrypted store")
	}
	return exportConnection(s.DB, destination, s.cipherKey)
}
