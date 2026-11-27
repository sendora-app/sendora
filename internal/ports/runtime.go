// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"errors"
	"time"

	"github.com/sendora-app/sendora/internal/storage"
)

// Coordinator runs work exactly once across replicas (design 4.3): leader
// election, periodic jobs, change notifications for caches and work signals.
// The in-process adapter is always the leader; the Cluster adapter uses a
// Kubernetes Lease for leadership and PostgreSQL tables plus LISTEN/NOTIFY
// with version polling for notifications and signals.
type Coordinator interface {
	// IsLeader reports whether this process currently runs singleton work.
	IsLeader() bool
	// Epoch is the fencing token of the current leadership (design 4.3,
	// review M7): it grows with every change of leader and is 0 while this
	// process is not the leader. Jobs that mutate tenant state pass it to
	// JobFenceRepository.Advance in the transaction of their effects.
	Epoch() int64
	// RunPeriodic calls fn every interval until ctx ends, on the leader only.
	// It returns at once; fn is never run concurrently with itself.
	RunPeriodic(ctx context.Context, name string, interval time.Duration, fn func(context.Context))
	// Notify signals every subscriber of topic (in every replica) that
	// something changed. Delivery may coalesce and is best effort; readers
	// re-check a version, they do not rely on the message.
	Notify(ctx context.Context, topic string) error
	// Subscribe returns a channel that receives a value after Notify(topic);
	// cancel stops the subscription and closes the channel.
	Subscribe(topic string) (ch <-chan struct{}, cancel func())
	// Signal records that tenant has work of kind (an outbox row committed in
	// the tenant's database) and wakes the subscribers of WorkTopic(kind).
	// Signals of one (kind, tenant) coalesce until taken.
	Signal(ctx context.Context, kind, tenant string) error
	// TakeSignals removes and returns up to limit tenants with work of kind,
	// oldest first. A signal taken by a worker that then fails is lost: a
	// periodic sweep of the outboxes catches it (design 4.3, review M8).
	TakeSignals(ctx context.Context, kind string, limit int) ([]string, error)
}

// WorkTopic is the notification topic Signal wakes for kind.
func WorkTopic(kind string) string { return "work:" + kind }

// Lock provides named critical sections (design 2A.2): an in-process mutex in
// the Community flavours; in Cluster a lease row in the platform database
// (taken and released in short transactions of their own, renewed while fn
// runs), so no pooled connection is held while fn does I/O. Names are global
// across tenants: callers include the tenant ID.
type Lock interface {
	// WithLock runs fn while holding the lock name. It returns ctx.Err() if
	// the lock could not be taken before ctx ended, else fn's error.
	WithLock(ctx context.Context, name string, fn func(context.Context) error) error
}

// RateLimiter keeps shared counters, blocks and lockouts for throttles
// (design 4.2). The Community adapter is in memory; Cluster uses UNLOGGED
// PostgreSQL counters (lost on failover, acceptable for windows of minutes)
// and a logged table for blocks. Bans themselves are persisted through
// Store.IPBans. MFA replay, WebAuthn ceremonies and step-up grants join this
// port as they migrate.
type RateLimiter interface {
	// Hit records one event for (scope, key) in the current fixed window of
	// length window and returns the number of events in that window.
	Hit(ctx context.Context, scope, key string, window time.Duration) (int, error)
	// HitN is Hit for n events at once; a negative n gives events back (a
	// reserved attempt that succeeded). The count never drops below 0.
	HitN(ctx context.Context, scope, key string, n int, window time.Duration) (int, error)
	// Block refuses (scope, key) until until (Blocked reports it). A later
	// block never shortens an earlier one.
	Block(ctx context.Context, scope, key string, until time.Time) error
	// Blocked reports whether (scope, key) is blocked now, and until when.
	Blocked(ctx context.Context, scope, key string) (until time.Time, blocked bool, err error)
	// Reset forgets the counters and the block of (scope, key).
	Reset(ctx context.Context, scope, key string) error
}

// KeySource performs KEK operations only; the KEK never leaves the adapter
// (design 2A.2, 6.9, docs/adr/0005). No adapter exists yet: the wrap format
// and the control-log MAC are specified in phase 4.
type KeySource interface {
	// Wrap encrypts a DEK under the active KEK version, bound to aad.
	Wrap(ctx context.Context, dek, aad []byte) (wrapped []byte, kekRef string, err error)
	// Unwrap decrypts a wrapped DEK; kekRef names the KEK version used.
	Unwrap(ctx context.Context, wrapped, aad []byte, kekRef string) ([]byte, error)
	// ControlMAC authenticates a tenant control-log event.
	ControlMAC(ctx context.Context, tenantID string, msg []byte) ([]byte, error)
	// ControlMACWith is ControlMAC under a named KEK version (the mac_kek of
	// an event), so a chain written under an older KEK can be verified after
	// a KEK rotation.
	ControlMACWith(ctx context.Context, kekRef, tenantID string, msg []byte) ([]byte, error)
	// KEKFingerprints lists the fingerprints of the usable KEK versions,
	// active first.
	KEKFingerprints(ctx context.Context) ([]string, error)
}

// FileStore is one configured location for share files (design 7.2). Today it
// is exactly storage.Backend; the multipart extension (Multipart, part tokens)
// is added in phase 5.
type FileStore = storage.Backend

// ErrJournalExists is returned by Journal.Append for a name already stored.
var ErrJournalExists = errors.New("journal entry already exists")

// Journal is the write-once sink for control-log events, snapshots and anchors
// (design 6.3, 8.6). Optional in the Community flavours, required in Cluster.
// No adapter exists yet (phase 4).
type Journal interface {
	// Append stores data under name; an existing name is never overwritten
	// (ErrJournalExists).
	Append(ctx context.Context, name string, data []byte) error
	// Read returns the data stored under name.
	Read(ctx context.Context, name string) ([]byte, error)
	// List calls fn with every name that starts with prefix, in lexical order.
	List(ctx context.Context, prefix string, fn func(name string) error) error
	// WORM reports whether the sink enforces immutability itself (Object
	// Lock, immutable container) rather than by convention.
	WORM() bool
}
