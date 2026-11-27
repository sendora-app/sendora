// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strconv"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/ports"
)

// DefaultQuotaBytes seeds the global default for new installations: 10 GB.
const DefaultQuotaBytes int64 = 10_000_000_000

// LegacyQuotaBytes was the former fixed per-user allowance (10 GiB). It is only
// used to recognise old rows during the one-time inheritance migration.
const LegacyQuotaBytes int64 = 10 * 1024 * 1024 * 1024
const MaxSafeQuotaBytes int64 = 1<<53 - 1
const DefaultStorageQuotaKey = "default_storage_quota_bytes"

// ParseQuotaBytes accepts a complete base-ten integer, never SQLite's permissive
// numeric coercion. Both persisted policy and API settings use this validator.
func ParseQuotaBytes(raw string) (int64, error) {
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("invalid storage quota")
		}
	}
	q, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || q < 0 || q > MaxSafeQuotaBytes {
		return 0, fmt.Errorf("invalid storage quota")
	}
	return q, nil
}

// ResolveQuota is pure so it can safely be used while holding the only database
// connection. Missing or corrupt policy fails closed, including stale overrides.
func ResolveQuota(quota, inheritance, defaultQuota sql.NullString) (int64, bool, error) {
	if !quota.Valid || !inheritance.Valid || !defaultQuota.Valid || (inheritance.String != "0" && inheritance.String != "1") {
		return 0, false, fmt.Errorf("invalid storage quota policy")
	}
	q, err := ParseQuotaBytes(quota.String)
	if err != nil {
		return 0, false, err
	}
	d, err := ParseQuotaBytes(defaultQuota.String)
	if err != nil {
		return 0, false, err
	}
	inherits := inheritance.String == "1"
	if inherits {
		q = d
	}
	return q, inherits, nil
}

// StorageUsage counts retained metadata, including expired shares and the full
// declared size of pending uploads (not just bytes already received).
type StorageUsage struct {
	QuotaBytes           int64 `json:"quota_bytes"`
	QuotaInheritsDefault bool  `json:"quota_inherits_default"`
	StoredBytes          int64 `json:"storage_used_bytes"`
	ReservedBytes        int64 `json:"storage_reserved_bytes"`
	AvailableBytes       int64 `json:"storage_available_bytes"`
}

// MigratePolicy: see sqlite.MigratePolicy.
func (s *Store) MigratePolicy() error {
	return sqlite.MigratePolicy(s.DB, LegacyQuotaBytes)
}

// migratePolicySettings: see sqlite.MigratePolicySettings.
func (s *Store) migratePolicySettings() error {
	return sqlite.MigratePolicySettings(s.DB, s.ColumnCodec(), DefaultStorageQuotaKey, DefaultQuotaBytes)
}

// StorageUsageTx uses its caller's transaction; it never acquires another DB
// connection. This is also the admission snapshot, not a separate preflight.
func (s *Store) StorageUsageTx(tx ports.Repositories, id int64) (*StorageUsage, error) {
	return storageUsage(tx, id)
}

func storageUsage(r ports.Repositories, id int64) (*StorageUsage, error) {
	ctx := context.Background()
	out := &StorageUsage{}
	quota, inheritance, defaultQuota, err := r.Quota().Policy(ctx, id)
	if err != nil {
		return nil, err
	}
	out.QuotaBytes, out.QuotaInheritsDefault, err = ResolveQuota(nullStringOf(quota), nullStringOf(inheritance), nullStringOf(defaultQuota))
	if err != nil {
		return nil, err
	}
	invalid, err := r.Quota().CountUnattributedReservations(ctx)
	if err != nil {
		return nil, err
	}
	if invalid != 0 {
		return nil, fmt.Errorf("unattributed storage reservation")
	}
	if out.StoredBytes, err = r.Quota().StoredBytes(ctx, id); err != nil {
		return nil, err
	}
	if out.ReservedBytes, err = r.Quota().ReservedBytes(ctx, id); err != nil {
		return nil, err
	}
	if out.StoredBytes > math.MaxInt64-out.ReservedBytes {
		return nil, fmt.Errorf("storage accounting overflow")
	}
	used := out.StoredBytes + out.ReservedBytes
	if used < out.QuotaBytes {
		out.AvailableBytes = out.QuotaBytes - used
	}
	return out, nil
}

// nullStringOf is the nullable-string form ResolveQuota takes.
func nullStringOf(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

func (s *Store) UserStorageUsage(id int64) (*StorageUsage, error) {
	tx, err := s.Repos().Begin(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out, err := storageUsage(tx, id)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
