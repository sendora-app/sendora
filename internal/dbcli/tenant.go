// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/store"
)

// tenantImport converts the single-tenant installation in dataDir into the
// tenant slug of a multi-tenant installation (offline; stop the server first).
// With from, the single-tenant DATA_DIR at that path is copied into the
// multi-tenant dataDir instead (a move to another host; other tenants may
// exist; the source is only read). It resumes an interrupted conversion, and
// -abort undoes an unfinished one.
func tenantImport(dataDir, keyFile, sourceKeyFile, slug, name string, abort bool, from, customDomain string) error {
	if dataDir == "" {
		return errors.New("data-dir is required (the DATA_DIR of the stopped single-tenant installation, or with -from the multi-tenant DATA_DIR to import into)")
	}
	master, err := store.ReadDatabaseKey(keyFile)
	if err != nil {
		return err
	}
	defer clear(master)
	var srcKey []byte
	if sourceKeyFile != "" {
		if srcKey, err = store.ReadDatabaseKey(sourceKeyFile); err != nil {
			return fmt.Errorf("source key: %w", err)
		}
		defer clear(srcKey)
	}
	p, err := platform.Open(dataDir, master, true)
	if err != nil {
		return fmt.Errorf("platform database: %w", err)
	}
	defer p.Close()
	res, err := p.ImportSingleTenant(platform.ImportOptions{Slug: slug, Name: name, SourceKey: srcKey, Abort: abort, From: from,
		Logf: func(f string, a ...any) { fmt.Fprintf(stderr, f+"\n", a...) }})
	if err != nil {
		return err
	}
	if customDomain != "" && !res.Aborted {
		d, err := p.AddCustomDomain(res.TenantID, customDomain, os.Getenv("SENDORA_BASE_DOMAIN"))
		if err == nil {
			err = p.MarkDomainVerified(res.TenantID, d.Domain)
		}
		if err != nil {
			fmt.Fprintf(stderr, "tenant-import: custom domain %s not added: %v (add it in the console)\n", customDomain, err)
		} else {
			p.Audit(0, "sendora-db", "tenant_domain_added", "tenant "+res.Slug+" ("+res.TenantID+")", "ok", "domain="+d.Domain+" (verified by the operator at import)", "")
			fmt.Fprintf(stderr, "tenant-import: %s is a verified custom domain of %s; point its DNS to this platform\n", d.Domain, res.Slug)
		}
	}
	return json.NewEncoder(stdout).Encode(res)
}
