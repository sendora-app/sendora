// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"errors"
	"time"
)

// ErrControlLogConflict is returned by ControlLogRepository.Append when the
// event does not extend the tenant's chain: the sequence number is taken or
// not the next one, the previous hash does not match the last event, or a
// key version is created twice (design 6.3). Nothing was written.
var ErrControlLogConflict = errors.New("control log: event does not extend the chain")

// ControlLogRepository stores the cryptographic control log per DESIGN §6.3
type ControlLogRepository interface {
	// Append adds an event. Sequence must be strictly sequential per tenant.
	Append(ctx context.Context, e ControlLogEvent) error
	// Latest returns the latest event for tenantID (or ErrNotFound)
	Latest(ctx context.Context, tenantID string) (ControlLogEvent, error)
	// BySeq returns an event by exact sequence number (or ErrNotFound)
	BySeq(ctx context.Context, tenantID string, seq int64) (ControlLogEvent, error)
	// List returns events for tenantID from fromSeq to toSeq inclusive (0 toSeq = unbounded)
	List(ctx context.Context, tenantID string, fromSeq, toSeq int64) ([]ControlLogEvent, error)
}

type ControlLogEvent struct {
	TenantID  string
	Seq       int64
	PrevHash  []byte
	Kind      string
	Purpose   string
	Version   int
	Body      []byte
	EventHash []byte
	MACKEK    string
	MAC       []byte
	CreatedAt time.Time
}

// KeyringRepository stores wrapped tenant DEKs per DESIGN §6.3
type KeyringRepository interface {
	// Add adds a wrapped DEK row. Never updated.
	Add(ctx context.Context, row KeyringRow) error
	// Active returns the latest wrap for (tenantID, purpose, version)
	Active(ctx context.Context, tenantID, purpose string, version int) (KeyringRow, error)
	// ListVersions returns all known versions for (tenantID, purpose)
	ListVersions(ctx context.Context, tenantID, purpose string) ([]int, error)
	// Wraps returns every wrap of (tenantID, purpose, version), newest first.
	// A version has several wraps while it is wrapped under more than one
	// KEK (a hand-over between the platform's and the tenant's KEK, D44).
	Wraps(ctx context.Context, tenantID, purpose string, version int) ([]KeyringRow, error)
	// Remove deletes one wrap (by wrap_id) and reports whether it existed.
	// Only the database owner may do this; the keyring service refuses to
	// remove the last wrap of a version.
	Remove(ctx context.Context, tenantID, wrapID string) (bool, error)
}

type KeyringRow struct {
	TenantID    string
	Purpose     string
	Version     int
	KeyID       string // UUID
	WrapID      string // UUID
	KEKRef      string
	Wrapped     []byte
	Fingerprint []byte
	CreatedAt   time.Time
}

// ErrNotEncrypted is returned by ColumnCodec.Open for a stored value that is
// not an encrypted column value (a plaintext row in an encrypted database).
var ErrNotEncrypted = errors.New("column value is not encrypted")

// ColumnCodec encrypts and decrypts the values of encrypted columns (design
// 6.5). rowID is the row's primary key as decimal text (or the key itself for
// a text primary key); it is part of the authenticated data, so a value
// cannot be moved to another row, column or table. Values are stored as text
// ("e1:" and base64url), so existing TEXT columns keep their type. A nil codec
// on an adapter means the columns hold plaintext (Community databases created
// before column encryption, and tests).
type ColumnCodec interface {
	Seal(table, column, rowID string, plaintext string) (string, error)
	Open(table, column, rowID string, stored string) (string, error)
	// BlindIndex returns the deterministic lookup value of an encrypted
	// column's plaintext: HMAC-SHA256 under the tenant's "index" key, over the
	// normalised (NFKC, case-folded) value, truncated to 16 bytes. Equal
	// values (up to normalisation) give equal indexes, so a UNIQUE index on
	// the blind-index column enforces uniqueness and WHERE col_bi=? finds the
	// row, while the encrypted column itself stays randomised. The index key
	// changes with the database's keys: a re-key recomputes every index.
	BlindIndex(table, column, value string) ([]byte, error)
}
