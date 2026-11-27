// SPDX-License-Identifier: AGPL-3.0-or-later

// Package flavour selects and validates the flavour this process runs as
// (docs/cluster/DESIGN.md section 2A, docs/adr/0001): Community single-tenant,
// Community multi-tenant or Cluster. It only reads configuration; main wires the
// adapters for the selected flavour.
package flavour

import (
	"fmt"
	"strings"
)

// Flavour is one of the three supported configurations of the binary.
type Flavour string

const (
	// Single is C1, Community single-tenant (SQLite/SQLCipher, one database).
	Single Flavour = "single"
	// Multi is C2, Community multi-tenant (SQLite/SQLCipher, one database per tenant).
	Multi Flavour = "multi"
	// Cluster is C3 (PostgreSQL on CloudNativePG, N replicas; preview).
	Cluster Flavour = "cluster"
)

// Environment variables read here.
const (
	EnvFlavour     = "SENDORA_FLAVOUR"
	EnvRole        = "SENDORA_ROLE"
	EnvMultiTenant = "SENDORA_MULTI_TENANT"
)

// Roles of a Cluster process (SENDORA_ROLE).
const (
	RoleWeb        = "web"
	RoleController = "controller"
)

// Selection is the validated flavour configuration.
type Selection struct {
	// Flavour is the explicitly configured flavour, or "" when neither
	// SENDORA_FLAVOUR nor SENDORA_MULTI_TENANT decides it. Then the 0.2
	// detection applies unchanged (a mode persisted by a conversion, else
	// single-tenant); see MultiTenantEnv.
	Flavour Flavour
	// Role is SENDORA_ROLE (Cluster only; empty otherwise).
	Role string
	// MultiTenantEnv is the value to use where 0.2 read SENDORA_MULTI_TENANT:
	// "true" for multi, "false" for single, else the raw variable (so an unset
	// SENDORA_FLAVOUR keeps today's behaviour exactly).
	MultiTenantEnv string
}

// FromEnv reads and validates the flavour configuration. getenv is os.Getenv
// outside tests. An error explains the invalid combination and must stop the start.
func FromEnv(getenv func(string) string) (Selection, error) {
	rawFlavour := strings.ToLower(strings.TrimSpace(getenv(EnvFlavour)))
	rawMulti := getenv(EnvMultiTenant)
	multi := strings.ToLower(strings.TrimSpace(rawMulti))
	role := strings.ToLower(strings.TrimSpace(getenv(EnvRole)))

	sel := Selection{MultiTenantEnv: rawMulti}
	switch Flavour(rawFlavour) {
	case "":
		// 0.2 behaviour: SENDORA_MULTI_TENANT=true is the alias of multi; its
		// value is passed through untouched.
		if multi == "true" {
			sel.Flavour = Multi
		} else if multi == "false" {
			sel.Flavour = Single
		}
	case Single:
		if multi == "true" {
			return Selection{}, fmt.Errorf("%s=single contradicts %s=true; remove one of them (%s=true is the 0.2 alias of %s=multi)", EnvFlavour, EnvMultiTenant, EnvMultiTenant, EnvFlavour)
		}
		sel.Flavour, sel.MultiTenantEnv = Single, "false"
	case Multi:
		if multi == "false" {
			return Selection{}, fmt.Errorf("%s=multi contradicts %s=false; remove one of them", EnvFlavour, EnvMultiTenant)
		}
		sel.Flavour, sel.MultiTenantEnv = Multi, "true"
	case Cluster:
		if multi != "" {
			return Selection{}, fmt.Errorf("%s is not used by %s=cluster (the Cluster flavour is always multi-tenant); remove it", EnvMultiTenant, EnvFlavour)
		}
		switch role {
		case RoleWeb, RoleController:
		case "":
			return Selection{}, fmt.Errorf("%s=cluster needs %s=%s or %s=%s", EnvFlavour, EnvRole, RoleWeb, EnvRole, RoleController)
		default:
			return Selection{}, fmt.Errorf("%s=%q is not valid; use %s or %s", EnvRole, clip(role), RoleWeb, RoleController)
		}
		// The rest of the Cluster configuration is read by ClusterFromEnv.
		return Selection{Flavour: Cluster, Role: role}, nil
	default:
		return Selection{}, fmt.Errorf("%s=%q is not valid; use single (default), multi or cluster", EnvFlavour, clip(rawFlavour))
	}
	if role != "" {
		return Selection{}, fmt.Errorf("%s is only used by %s=cluster; remove it for the Community flavours (single, multi)", EnvRole, EnvFlavour)
	}
	return sel, nil
}

// clip keeps an echoed configuration value short in error messages.
func clip(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}
