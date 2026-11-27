// SPDX-License-Identifier: AGPL-3.0-or-later

// Package capabilities is the feature registry of design 2A.4 #4: every
// feature declares the adapter capabilities it needs, every flavour declares
// what its adapters provide, and the difference is the capability matrix,
// served at GET /api/capabilities and generated into docs/CAPABILITIES.md.
//
// A feature that does not work in some flavour is listed here with the reason;
// it is never silently missing. Features that need nothing flavour-specific
// are available everywhere.
package capabilities

//go:generate go run ./gen -o ../../docs/CAPABILITIES.md

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sendora-app/sendora/internal/flavour"
)

// Maturity of a feature.
type Maturity string

const (
	Stable  Maturity = "stable"
	Preview Maturity = "preview"
)

// Provide is a capability an adapter set offers.
type Provide string

const (
	StoreSQLite             Provide = "store.sqlite"
	StorePostgres           Provide = "store.postgres"
	StorePITRPerCluster     Provide = "store.pitr_per_cluster"
	TenancySingle           Provide = "tenancy.single"
	TenancyMulti            Provide = "tenancy.multi"
	ProcessSingleReplica    Provide = "process.single_replica"
	CoordinatorMultiReplica Provide = "coordinator.multi_replica"
	FileStoreRWX            Provide = "filestore.rwx"
	// Provided by the Cluster flavour only (controller key endpoint, D44).
	KEKTenantManaged Provide = "keys.tenant_managed_kek"
	// Admin → Keys screen (every flavour with the key endpoints).
	KeyManagementUI Provide = "keys.management_ui"
	// Versioned master key and its rotation by the platform operator (D46).
	MasterKeyRotation Provide = "keys.master_rotation"
	// Not provided by any flavour: not planned.
	JournalAnchors Provide = "journal.anchors"
	ExternalKMS    Provide = "keys.external_kms"
)

// missingReason explains, per provide, why a feature that needs it is absent.
var missingReason = map[Provide]string{
	StoreSQLite:             "needs the SQLite database of the Community flavours",
	StorePostgres:           "needs the PostgreSQL database of the Cluster flavour",
	StorePITRPerCluster:     "needs CloudNativePG point-in-time recovery (Cluster flavour)",
	TenancySingle:           "only in the single-tenant flavour",
	TenancyMulti:            "needs a multi-tenant flavour (multi or cluster)",
	ProcessSingleReplica:    "meaningless with several replicas and an external database",
	CoordinatorMultiReplica: "needs the Cluster coordinator (Kubernetes Lease, shared job table)",
	FileStoreRWX:            "needs the shared-volume (RWX) storage backend of the Cluster flavour",
	KEKTenantManaged:        "only in the Cluster flavour (needs the controller key endpoint)",
	KeyManagementUI:         "needs the Admin → Keys screen of a flavour with the key endpoints",
	MasterKeyRotation:       "only in the Cluster flavour (versioned master key on the controllers)",
	JournalAnchors:          "not planned: no independent journal or WORM anchors; any future journal must be encrypted",
	ExternalKMS:             "not planned: the key encryption key is a key file or a tenant-supplied key",
}

// Feature is one user-visible feature.
type Feature struct {
	ID          string
	Description string
	Maturity    Maturity
	Requires    []Provide
	// Reason, when set, replaces the generic reason of a missing provide.
	Reason string
}

// FlavourInfo is what one flavour's adapters provide.
type FlavourInfo struct {
	Flavour  flavour.Flavour
	Title    string
	Provides []Provide
	// InBuild is false while the flavour's adapters are not part of this
	// build; every feature is then unavailable with that reason.
	InBuild bool
}

// Flavours lists the three flavours in matrix order.
var Flavours = []FlavourInfo{
	{flavour.Single, "Community single-tenant", []Provide{StoreSQLite, TenancySingle, ProcessSingleReplica, KeyManagementUI}, true},
	{flavour.Multi, "Community multi-tenant", []Provide{StoreSQLite, TenancyMulti, ProcessSingleReplica, KeyManagementUI}, true},
	{flavour.Cluster, "Cluster", []Provide{StorePostgres, StorePITRPerCluster, TenancyMulti, CoordinatorMultiReplica, FileStoreRWX, KEKTenantManaged, KeyManagementUI, MasterKeyRotation}, true},
}

// notInBuild is the reason for every feature of a flavour that is not built.
const notInBuild = "the Cluster flavour is not available in this build yet"

// Features is the registry. Keep it sorted by ID (TestRegistryValid).
var Features = []Feature{
	{ID: "column_encryption", Description: "Per-tenant column encryption of personal data, names, settings and audit text", Maturity: Stable},
	{ID: "database_import", Description: "Restore a database backup from Admin → Backups", Maturity: Stable,
		Requires: []Provide{StoreSQLite, TenancySingle, ProcessSingleReplica},
		Reason:   "the import swaps the whole database and restarts the process; a tenant is restored by the platform operator"},
	{ID: "external_kms", Description: "Key encryption key in an external KMS or HSM", Maturity: Preview,
		Requires: []Provide{ExternalKMS}},
	{ID: "horizontal_scaling", Description: "Several web replicas serving every tenant", Maturity: Preview,
		Requires: []Provide{CoordinatorMultiReplica}},
	{ID: "in_app_restart", Description: "Orderly restart from the admin screens", Maturity: Stable,
		Requires: []Provide{ProcessSingleReplica}},
	{ID: "journal_anchors", Description: "Independent journal and WORM anchors for the control log and the audit chain", Maturity: Preview,
		Requires: []Provide{JournalAnchors}},
	{ID: "key_management_ui", Description: "Admin → Keys: key status, rotation, retirement and the tenant-managed key (Cluster)", Maturity: Preview,
		Requires: []Provide{KeyManagementUI}},
	{ID: "key_rotation", Description: "Tenant administrators rotate the data, files, index, secrets and audit-enc keys (API and sendora-db)", Maturity: Stable},
	{ID: "master_key_rotation", Description: "The platform operator rotates the versioned master key; every tenant's key encryption key follows (Key management in the platform console)", Maturity: Preview,
		Requires: []Provide{MasterKeyRotation}},
	{ID: "multi_tenant_conversion", Description: "Convert to multi-tenant from Admin → Multi-tenant", Maturity: Stable,
		Requires: []Provide{StoreSQLite, TenancySingle, ProcessSingleReplica}},
	{ID: "object_storage", Description: "Share files in S3, Azure Blob or Google Cloud Storage", Maturity: Stable},
	{ID: "operator_key_rotation", Description: "The platform operator forces a rotation of the data keys of one or all platform-managed tenants (Key management in the platform console)", Maturity: Stable,
		Requires: []Provide{TenancyMulti}},
	{ID: "pitr", Description: "Point-in-time recovery of the database cluster (CloudNativePG and Barman, set up by the operator; not exercised by the project's tests)", Maturity: Preview,
		Requires: []Provide{StorePITRPerCluster}},
	{ID: "platform_console", Description: "Platform console managing many tenants", Maturity: Stable,
		Requires: []Provide{TenancyMulti}},
	{ID: "rwx_storage", Description: "Shared Kubernetes volume (NFS, CephFS, …) as storage location", Maturity: Preview,
		Requires: []Provide{FileStoreRWX}},
	{ID: "shares", Description: "Encrypted shares, reverse shares and downloads", Maturity: Stable},
	{ID: "tenant_managed_kek", Description: "A tenant uploads its own key encryption key; locked state after a controller restart", Maturity: Preview,
		Requires: []Provide{KEKTenantManaged}},
}

// Status is a feature's state in one flavour.
type Status struct {
	Available bool     `json:"available"`
	Maturity  Maturity `json:"maturity"`
	Reason    string   `json:"reason,omitempty"`
}

// Info returns the FlavourInfo of f (ok false for an unknown flavour).
func Info(f flavour.Flavour) (FlavourInfo, bool) {
	for _, fi := range Flavours {
		if fi.Flavour == f {
			return fi, true
		}
	}
	return FlavourInfo{}, false
}

// Evaluate returns every feature's status in flavour f.
func Evaluate(f flavour.Flavour) map[string]Status {
	fi, known := Info(f)
	has := map[Provide]bool{}
	for _, p := range fi.Provides {
		has[p] = true
	}
	out := make(map[string]Status, len(Features))
	for _, ft := range Features {
		st := Status{Available: true, Maturity: ft.Maturity}
		if f == flavour.Cluster {
			st.Maturity = Preview // Cluster is preview until verified in production-like operation
		}
		switch {
		case !known:
			st = Status{Maturity: st.Maturity, Reason: "unknown flavour"}
		case !fi.InBuild:
			st = Status{Maturity: st.Maturity, Reason: notInBuild}
		default:
			for _, p := range ft.Requires {
				if !has[p] {
					st.Available = false
					st.Reason = ft.Reason
					if st.Reason == "" {
						st.Reason = missingReason[p]
					}
					break
				}
			}
		}
		out[ft.ID] = st
	}
	return out
}

// Matrix renders docs/CAPABILITIES.md.
func Matrix() string {
	var b strings.Builder
	b.WriteString("<!-- Generated by go generate ./internal/capabilities; do not edit. -->\n\n")
	b.WriteString("# Capability matrix\n\n")
	b.WriteString("Which features each flavour offers. The running server reports the same ")
	b.WriteString("data for its own flavour at `GET /api/capabilities`. Source: `internal/capabilities`. ")
	b.WriteString("In the Cluster flavour every feature is `preview` until it has been verified in production-like operation.\n\n")
	b.WriteString("| Feature | Maturity |")
	for _, fi := range Flavours {
		fmt.Fprintf(&b, " %s (`%s`) |", fi.Title, fi.Flavour)
	}
	b.WriteString("\n|---|---|")
	for range Flavours {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	status := map[flavour.Flavour]map[string]Status{}
	for _, fi := range Flavours {
		status[fi.Flavour] = Evaluate(fi.Flavour)
	}
	for _, ft := range Features {
		fmt.Fprintf(&b, "| `%s`: %s | %s |", ft.ID, ft.Description, ft.Maturity)
		for _, fi := range Flavours {
			st := status[fi.Flavour][ft.ID]
			if st.Available {
				b.WriteString(" yes |")
			} else {
				fmt.Fprintf(&b, " no: %s |", st.Reason)
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("\nAdapter capabilities per flavour:\n\n")
	for _, fi := range Flavours {
		ps := make([]string, len(fi.Provides))
		for i, p := range fi.Provides {
			ps[i] = "`" + string(p) + "`"
		}
		sort.Strings(ps)
		note := ""
		if !fi.InBuild {
			note = " (planned; not in this build yet)"
		}
		fmt.Fprintf(&b, "- **%s**%s: %s\n", fi.Title, note, strings.Join(ps, ", "))
	}
	return b.String()
}
