// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/storage"
)

// Storage locations. Every files row names where its (encrypted) bytes live:
//
//	storage_id = 0   the local data directory in the layout of every earlier
//	                 release: DATA_DIR/shares/<long id>/<base name of disk_path>
//	storage_id = n   storage_locations row n (an S3 bucket, Azure container or
//	                 GCS bucket with a prefix) under object_key "files/<random>"
//
// A location keeps the configuration (including credentials; the database is
// SQLCipher-encrypted) it was last used with, so switching the backend or the
// bucket never makes earlier files unreadable: they stay where they are until
// they are migrated.

// LocalLocation is the storage_id of the local data directory.
const LocalLocation int64 = 0

func (s *Store) migrateStorage() error { return sqlite.MigrateStorage(s.DB) }

// EnsureLocation returns the id of the location with cfg's identity, creating
// it or refreshing its stored configuration (rotated credentials). The local
// backend is always LocalLocation.
func EnsureLocation(db ports.Store, cfg storage.Config) (int64, error) {
	if cfg.Backend == storage.KindLocal || cfg.Backend == "" {
		return LocalLocation, nil
	}
	js, err := cfg.Marshal()
	if err != nil {
		return 0, err
	}
	return db.ObjectStorage().EnsureLocation(context.Background(), cfg.Backend, cfg.Identity(), js)
}

// LoadLocation returns the configuration of location id.
func LoadLocation(db ports.Store, dataDir string, id int64) (storage.Config, error) {
	if id == LocalLocation {
		return storage.Config{Backend: storage.KindLocal, LocalRoot: dataDir}, nil
	}
	js, err := db.ObjectStorage().LocationConfig(context.Background(), id)
	if err != nil {
		return storage.Config{}, fmt.Errorf("storage location %d unavailable", id)
	}
	return storage.Unmarshal(js)
}

// FileObjectKey is the object key of a files row in its location. For local
// files it is derived like SharePath (validated long ID, base name only); a
// remote key must have the generated form. Anything else is refused.
func FileObjectKey(location int64, longID, diskPath, objectKey string) (string, error) {
	if location == LocalLocation {
		if !ValidLongID(longID) {
			return "", errUnsafeSharePath
		}
		base := filepath.Base(diskPath)
		if diskPath == "" || base == "." || base == ".." || base == string(filepath.Separator) || base != filepath.Clean(base) || strings.ContainsAny(base, "/\\") {
			return "", errUnsafeSharePath
		}
		return "shares/" + longID + "/" + base, nil
	}
	if !storage.ValidFileKey(objectKey) {
		return "", errUnsafeSharePath
	}
	return objectKey, nil
}

// Backends opens and caches the backend of each location. A location's
// backend is reopened when its stored configuration changed.
type Backends struct {
	db      ports.Store
	dataDir string
	mu      sync.Mutex
	open    map[int64]cachedBackend
	// OpenFn opens a backend (tests replace it).
	OpenFn func(context.Context, storage.Config) (storage.Backend, error)
	// Guard, when set, is the dialer of every configuration a tenant
	// administrator entered (storage.Config.TenantManaged): the multi-tenant
	// SSRF guard (internal/netguard). Platform-configured locations do not use it.
	Guard func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Open opens a backend for cfg (not cached), through the guard when cfg is
// tenant-managed.
func (b *Backends) Open(ctx context.Context, cfg storage.Config) (storage.Backend, error) {
	if cfg.TenantManaged && b.Guard != nil {
		cfg.DialContext = b.Guard
	}
	return b.OpenFn(ctx, cfg)
}

type cachedBackend struct {
	config string
	b      storage.Backend
}

func NewBackends(db ports.Store, dataDir string) *Backends {
	return &Backends{db: db, dataDir: dataDir, open: map[int64]cachedBackend{}, OpenFn: storage.Open}
}

// Backends of this store.
func (s *Store) Backends() *Backends {
	s.backendsOnce.Do(func() { s.backends = NewBackends(s.Repos(), s.DataDir) })
	return s.backends
}

// Get returns the backend of location id.
func (b *Backends) Get(ctx context.Context, id int64) (storage.Backend, error) {
	cfg, err := LoadLocation(b.db, b.dataDir, id)
	if err != nil {
		return nil, err
	}
	js, _ := cfg.Marshal()
	b.mu.Lock()
	c, ok := b.open[id]
	b.mu.Unlock()
	if ok && c.config == js {
		return c.b, nil
	}
	be, err := b.Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.open[id] = cachedBackend{js, be}
	b.mu.Unlock()
	return be, nil
}

// OpenFile opens the stored bytes of a files row.
func (b *Backends) OpenFile(ctx context.Context, location int64, longID, diskPath, objectKey string) (storage.Object, error) {
	key, err := FileObjectKey(location, longID, diskPath, objectKey)
	if err != nil {
		return nil, err
	}
	be, err := b.Get(ctx, location)
	if err != nil {
		return nil, err
	}
	return be.Open(ctx, key)
}

// ---------- queued deletion of remote objects ----------

// QueueDelete records a remote object for deletion not before the given time.
func QueueDelete(db ports.Store, location int64, key string, notBefore time.Time) error {
	if location == LocalLocation {
		return nil
	}
	return db.ObjectStorage().QueueDelete(context.Background(), location, key, notBefore.UTC())
}

// PendingDeletes is the number of remote objects still to be deleted.
func PendingDeletes(db ports.Store) int64 {
	n, _ := db.ObjectStorage().CountPendingDeletes(context.Background())
	return n
}

// ProcessPendingDeletes deletes due queued objects (at most limit) and returns
// how many were deleted and how many failed. A failure is retried later with a
// growing delay; deleting a missing object counts as success.
func ProcessPendingDeletes(ctx context.Context, db ports.Store, backends *Backends, limit int) (done, failed int) {
	queue := db.ObjectStorage()
	jobs, err := queue.DuePendingDeletes(context.Background(), time.Now().UTC(), limit)
	if err != nil {
		return 0, 0
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		err := errors.New("invalid object key")
		if storage.ValidFileKey(j.ObjectKey) {
			var be storage.Backend
			if be, err = backends.Get(ctx, j.LocationID); err == nil {
				err = be.Delete(ctx, j.ObjectKey)
			}
		}
		if err == nil {
			queue.DeletePendingDelete(context.Background(), j.ID)
			done++
			continue
		}
		failed++
		delay := time.Duration(min(j.Attempts+1, 36)) * 10 * time.Minute
		queue.DeferPendingDelete(context.Background(), j.ID, time.Now().UTC().Add(delay))
	}
	return done, failed
}

// LocationUsage is how many files (and plaintext bytes) live in one location.
type LocationUsage struct {
	ID          int64  `json:"id"`
	Backend     string `json:"backend"`
	Description string `json:"description"`
	Files       int64  `json:"files"`
	Bytes       int64  `json:"bytes"`
	Current     bool   `json:"current"`
}

// StorageUsageByLocation lists every location that holds files, plus current.
func StorageUsageByLocation(db ports.Store, current int64) ([]LocationUsage, error) {
	counts, err := db.ObjectStorage().UsageByLocation(context.Background())
	if err != nil {
		return nil, err
	}
	var out []LocationUsage
	seen := map[int64]bool{}
	for _, c := range counts {
		out = append(out, LocationUsage{ID: c.ID, Files: c.Files, Bytes: c.Bytes})
		seen[c.ID] = true
	}
	if !seen[current] {
		out = append(out, LocationUsage{ID: current})
	}
	for i := range out {
		out[i].Current = out[i].ID == current
		cfg, err := LoadLocation(db, "", out[i].ID)
		if err != nil {
			out[i].Backend, out[i].Description = "unknown", "unknown location"
			continue
		}
		out[i].Backend, out[i].Description = cfg.Backend, cfg.Describe()
	}
	return out, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
