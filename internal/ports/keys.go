// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"errors"
)

// Key material the Cluster flavour's controller hands to web replicas
// (docs/cluster/DESIGN.md D42). The master key never leaves the controller;
// a web replica holds only what it fetched for the platform and for the
// tenants it served. Keys and passwords are hex strings on the wire.

// PlatformKeys is what a web replica needs for the platform database.
type PlatformKeys struct {
	DBPassword string `json:"db_password"` // app role password of the platform database
	DBKey      string `json:"db_key"`      // column/audit key of the platform database (hex)
	RateKey    string `json:"rate_key"`    // HMAC key of the shared rate limiter (hex)
}

// ErrKEKUnavailable is returned (wrapped) by a KeySource asked to use a KEK
// version it does not hold, for example one that was retired and removed.
var ErrKEKUnavailable = errors.New("KEK version not available")

// TenantKeys is what a web replica needs to open one tenant.
type TenantKeys struct {
	DBPassword string `json:"db_password"` // app role password of the tenant database
	DBKey      string `json:"db_key"`      // hex
	Root       string `json:"root"`        // hex; empty for a native tenant (the caller uses DBKey)
	// KEK is the wrapping key derived from the tenant-supplied KEK (hex); only
	// for a tenant-managed tenant that is unlocked on the answering
	// controller (D44).
	KEK string `json:"kek,omitempty"`
	// MasterVersion is the master key version the material above derives
	// from (D46); a replica that holds a store opened with another version
	// reopens it.
	MasterVersion int `json:"master_version,omitempty"`
}

// ClusterKeys hands out derived key material: the controller derives it from
// the master key, a web replica fetches it from the controller.
type ClusterKeys interface {
	Platform(ctx context.Context) (PlatformKeys, error)
	Tenant(ctx context.Context, id string) (TenantKeys, error)
}

// Identity is an authenticated caller.
type Identity struct {
	User string // for example system:serviceaccount:ns:sendora-web
	Pod  string // calling pod name when the token is bound to a pod; may be empty
}

// TokenReviewer validates a bearer token (Kubernetes TokenReview) for an
// audience. Any error means "not authenticated".
type TokenReviewer interface {
	Review(ctx context.Context, token, audience string) (Identity, error)
}

// ErrLocked is returned for a tenant-managed tenant whose KEK is not held by
// the controller that was asked (D44): the tenant's data cannot be read until
// the tenant presents the KEK again.
var ErrLocked = errors.New("tenant is locked: its key-encryption key has not been presented")

// ErrUnknownKEK is returned when a wrapped key names a KEK that the key source
// does not hold. On a Cluster web replica it means the cached key material
// predates a change of the tenant's KEK (a switch to or replacement of the
// tenant's own key, D44): fetching the keys again resolves it.
var ErrUnknownKEK = errors.New("unknown key-encryption key")
