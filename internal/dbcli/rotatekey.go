// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/sendora-app/sendora/internal/keyops"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// rotateKey is "sendora-db rotate-key" (and retire-key): the offline form of
// the tenant administrator's key rotation (DESIGN 6.4, D43). It opens the
// database, makes a safety copy, creates the next version of purpose and runs
// the re-encryption (or index rebuild) to completion. Stop the application
// first (files-reencrypt rewrites stored files in place: back up the data
// directory too); a running instance would meanwhile keep encrypting under the old
// version with its own codec until it restarts.
func rotateKey(source, dataDir string, key []byte, purpose string, version int, retire, rekeyFiles bool, tc tenantContext) error {
	if rekeyFiles {
		purpose = keyring.PurposeFiles
	}
	if purpose == keyring.PurposeAuditMAC {
		return keyops.ErrAuditMACFixed
	}
	if purpose == "" || !keyops.Rotatable(purpose) {
		return fmt.Errorf("-purpose must be one of the rotatable keys: %v", keyops.Purposes)
	}
	if retire && version < 1 {
		return errors.New("retire-key: -version is required")
	}
	want, err := store.DBPath(dataDir)
	if err != nil {
		return err
	}
	a, _ := filepath.Abs(source)
	b, _ := filepath.Abs(want)
	if a != b {
		return fmt.Errorf("-source must be the database of -data-dir (%s)", want)
	}
	stamp := time.Now().UTC().Format("20060102-150405.000000")
	safety := source + ".pre-key-rotation-" + stamp
	if err := store.ExportDatabase(source, safety, key, key); err != nil {
		return fmt.Errorf("safety copy: %w", err)
	}
	var st *store.Store
	if tc.id != "" {
		st, err = store.OpenTenant(dataDir, key, tc.root, false)
	} else {
		st, err = store.OpenEncrypted(dataDir, key, false)
	}
	if err != nil {
		return err
	}
	defer st.Close()
	svc, err := st.KeyringService()
	if err != nil {
		return err
	}
	e := &keyops.Engine{KeyID: store.ColumnKeyID, Svc: svc, Codec: st.ColumnKeyring(), Store: st.Repos(), Files: st, Actor: "sendora-db", Batch: 500}
	job := ports.KeyJob{Op: ports.KeyJobRotate, Purpose: purpose, Actor: "sendora-db"}
	if retire {
		job.Op, job.Version = ports.KeyJobRetire, version
	}
	if rekeyFiles {
		job.Op = ports.KeyJobRekeyFiles
	}
	res, err := e.Execute(context.Background(), job)
	if err != nil {
		return fmt.Errorf("%w (safety copy of the database before the operation: %s)", err, safety)
	}
	fmt.Fprintf(stdout, "%s. Safety copy of the database before the operation: %s (remove it once you have checked the installation).\n", res.Detail, safety)
	return nil
}
