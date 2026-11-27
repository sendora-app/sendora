// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"os"
	"testing"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// TestMain drops the postgres-tenant slot's shared tenant after the run.
func TestMain(m *testing.M) {
	code := m.Run()
	CloseTenantSlot()
	os.Exit(code)
}

// TestStoreConformance runs the repository contracts against every Store
// backend: sqlite always, postgres when SENDORA_TEST_PG_DSN is set.
func TestStoreConformance(t *testing.T) {
	for _, b := range StoreBackends() {
		t.Run(b.Name, func(t *testing.T) {
			if reason := b.Unavailable(); reason != "" {
				t.Skip(reason)
			}
			RunStore(t, b.Open)
		})
	}
}

func TestLockConformance(t *testing.T) {
	for _, b := range RuntimeBackends() {
		t.Run(b.Name, func(t *testing.T) {
			if reason := b.Unavailable(); reason != "" {
				t.Skip(reason)
			}
			RunLock(t, func(tb testing.TB) ports.Lock { l, _ := b.Lock(tb); return l })
			t.Run("Shared", func(t *testing.T) { RunLockShared(t, b.Lock) })
		})
	}
}

func TestRateLimiterConformance(t *testing.T) {
	for _, b := range RuntimeBackends() {
		t.Run(b.Name, func(t *testing.T) {
			if reason := b.Unavailable(); reason != "" {
				t.Skip(reason)
			}
			RunRateLimiter(t, func(tb testing.TB, now func() time.Time) ports.RateLimiter { r, _ := b.Limiter(tb, now); return r })
			t.Run("Shared", func(t *testing.T) { RunRateLimiterShared(t, b.Limiter) })
		})
	}
}

func TestCoordinatorConformance(t *testing.T) {
	for _, b := range RuntimeBackends() {
		t.Run(b.Name, func(t *testing.T) {
			if reason := b.Unavailable(); reason != "" {
				t.Skip(reason)
			}
			RunCoordinator(t, func(tb testing.TB) ports.Coordinator { c, _ := b.Coordinator(tb); return c })
			t.Run("Shared", func(t *testing.T) { RunCoordinatorShared(t, b.Coordinator) })
		})
	}
}

// TestEncryptedColumnsConformance runs the encrypted-column contract on every
// adapter that implements it.
func TestEncryptedColumnsConformance(t *testing.T) {
	for _, b := range EncryptedBackends() {
		t.Run(b.Name, func(t *testing.T) {
			if reason := b.Unavailable(); reason != "" {
				t.Skip(reason)
			}
			RunEncryptedColumns(t, b.Open)
			t.Run("Codec", func(t *testing.T) { RunColumnCodec(t, b.Open) })
			t.Run("Lookups", func(t *testing.T) { RunEncryptedLookups(t, b.Open) })
			t.Run("KeyRotation", func(t *testing.T) { RunKeyRotation(t, b.Open) })
		})
	}
}

// TestEncryptedPlatformColumnsConformance runs the encrypted-column contract of
// the platform database on every adapter that implements it.
func TestEncryptedPlatformColumnsConformance(t *testing.T) {
	for _, b := range EncryptedPlatformBackends() {
		t.Run(b.Name, func(t *testing.T) {
			if reason := b.Unavailable(); reason != "" {
				t.Skip(reason)
			}
			RunEncryptedPlatformColumns(t, b.Open)
		})
	}
}

// TestKeySourceConformance runs the KEK contract against every KeySource.
func TestKeySourceConformance(t *testing.T) {
	t.Run("file", func(t *testing.T) { RunKeySource(t, openFileKeySource) })
}

// TestPlatformStoreConformance runs the platform repository contracts against
// every PlatformStore backend.
func TestPlatformStoreConformance(t *testing.T) {
	for _, b := range PlatformBackends() {
		t.Run(b.Name, func(t *testing.T) {
			if reason := b.Unavailable(); reason != "" {
				t.Skip(reason)
			}
			RunPlatform(t, b.Open)
		})
	}
}
