// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import "context"

// AuditRecord is one entry of the hash-chained audit log.
type AuditRecord struct {
	Seq       int64  `json:"seq"`
	TS        string `json:"ts"`
	Category  string `json:"category"`
	ActorID   int64  `json:"actor_id"`
	ActorName string `json:"actor_name"`
	ActorRole string `json:"actor_role"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Outcome   string `json:"outcome"`
	Detail    string `json:"detail"`
	IP        string `json:"ip"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// AuditChainRepository stores the audit chain: the records (audit_log), the
// checkpoint that anchors the chain after a purge (one row), the change
// guard and the highest sequence number ever issued. Chain logic (hashes,
// MACs, verification) stays in core code; this is storage only.
//
// Inside a Tx, the first read of the chain head (Checkpoint, CheckpointHead,
// Last, Issued) holds the chain's append lock until the Tx ends, so
// concurrent appenders (in any replica) serialise and each sees the head the
// previous one committed (SQLite: its single writer).
type AuditChainRepository interface {
	// HasChain reports whether the database has the audit tables at all (a
	// database from before the audit log has not).
	HasChain(ctx context.Context) (bool, error)
	// Checkpoint returns the last purged sequence number, its hash and the
	// checkpoint MAC; ErrNotFound when the checkpoint row is missing.
	Checkpoint(ctx context.Context) (seq int64, hash, mac string, err error)
	// CheckpointHead is Checkpoint without the MAC.
	CheckpointHead(ctx context.Context) (seq int64, hash string, err error)
	// SetCheckpoint moves the checkpoint.
	SetCheckpoint(ctx context.Context, seq int64, hash, mac string) error
	// Last returns the newest record's sequence number and hash; ErrNotFound
	// when the log is empty.
	Last(ctx context.Context) (seq int64, hash string, err error)
	// LastBefore returns the newest record whose timestamp (text in the
	// audit time layout) sorts before ts; ErrNotFound when there is none.
	LastBefore(ctx context.Context, ts string) (seq int64, hash string, err error)
	// OldestTS returns the oldest record's timestamp, "" when the log is empty.
	OldestTS(ctx context.Context) (string, error)
	// Issued returns the highest sequence number ever issued (also for
	// records removed since), 0 when none.
	Issued(ctx context.Context) (int64, error)
	// SetIssued sets the highest sequence number ever issued to seq.
	SetIssued(ctx context.Context, seq int64) error
	// Guard returns the change guard's generation, which moves on every
	// change to the log other than an append at the end; -1 when the guard is
	// not installed (only a full walk can be trusted then).
	Guard(ctx context.Context) (int64, error)
	// Insert appends r with its given sequence number.
	Insert(ctx context.Context, r AuditRecord) error
	// Walk calls fn for each record with after < seq (and seq <= upTo when
	// upTo > 0) in ascending order, at most limit records when limit > 0. It
	// returns how many records it passed to fn; records are streamed, so on a
	// read error fn has seen the records before it.
	Walk(ctx context.Context, after, upTo int64, limit int, fn func(*AuditRecord)) (int, error)
	// All streams every record in ascending order; an error from fn stops it.
	All(ctx context.Context, fn func(AuditRecord) error) error
	// DeleteThrough removes the records with seq <= seq and returns how many.
	DeleteThrough(ctx context.Context, seq int64) (int64, error)
	// Clear removes every record and forgets the highest issued number.
	Clear(ctx context.Context) error
}

// AuditFilter selects audit records. Empty strings and nil pointers do not
// filter. Text matches are case-insensitive for ASCII.
type AuditFilter struct {
	// Terms: every term must occur (as a substring) in the action, actor,
	// target, detail or category.
	Terms []string
	// Category, Action and Outcome match exactly.
	Category, Action, Outcome string
	// Actor matches as a substring of the actor name.
	Actor string
	// From and To bound the timestamp inclusively (audit time layout text).
	From, To string
	// MaxSeq (seq <= *MaxSeq), BeforeSeq (seq < *BeforeSeq) and AfterSeq
	// (seq > *AfterSeq) bound the sequence number.
	MaxSeq, BeforeSeq, AfterSeq *int64
}

// AuditQueryRepository reads the audit log for the API and exports.
type AuditQueryRepository interface {
	// Find returns the matching records ordered by seq (newest first when
	// newestFirst), limit records after skipping offset when limit > 0.
	Find(ctx context.Context, f AuditFilter, newestFirst bool, limit, offset int) ([]AuditRecord, error)
	// CountCapped counts the matching records but stops at limit+1, so a
	// result above limit only means "more than limit".
	CountCapped(ctx context.Context, f AuditFilter, limit int) (int64, error)
	// MaxSeq returns the highest stored sequence number, 0 when empty.
	MaxSeq(ctx context.Context) (int64, error)
}
