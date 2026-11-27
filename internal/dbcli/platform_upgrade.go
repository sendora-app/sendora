// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/store"
)

// upgradePlatformEncryption converts the platform database of a stopped 0.2
// multi-tenant installation to column encryption, after a safety copy next to
// it. The tenants' databases are converted separately (-tenant <id>).
func upgradePlatformEncryption(dataDir, keyFile string) error {
	if dataDir == "" {
		return errors.New("data-dir is required (the DATA_DIR of the stopped multi-tenant installation)")
	}
	p := filepath.Join(dataDir, store.PlatformDBFile)
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("no platform database in %s: %v", dataDir, err)
	}
	master, err := store.ReadDatabaseKey(keyFile)
	if err != nil {
		return err
	}
	defer clear(master)
	key, err := store.PlatformDBKey(master)
	if err != nil {
		return err
	}
	defer clear(key)
	safety := p + ".pre-column-encryption-" + time.Now().UTC().Format("20060102-150405")
	if err := store.ExportDatabase(p, safety, key, key); err != nil {
		return fmt.Errorf("safety copy: %w", err)
	}
	n, err := store.UpgradePlatformColumnEncryption(dataDir, key, sqlite.PlatformSchema)
	if err != nil {
		return fmt.Errorf("%w (safety copy of the platform database: %s)", err, safety)
	}
	fmt.Printf("Platform database column encryption: %d values encrypted. Safety copy of the platform database before the conversion: %s (remove it once you have checked the installation). Convert every tenant too: sendora-db upgrade-encryption -tenant <id> ...\n", n, safety)
	return nil
}
