// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/ports"
)

// Tamper-evident audit log.
//
// Every record carries hash = HMAC-SHA256(auditKey, canonical(all fields,
// including seq and prev_hash)). prev_hash is the hash of the record before it,
// so editing, deleting, inserting or reordering a record breaks the chain at a
// definite sequence number. auditKey is derived from the database key with
// HKDF; anyone holding only the database file (and not the key) cannot forge a
// valid record.
//
// Records are only ever added. The one deletion path is AuditPurge, which
// removes the oldest records (retention) and stores the last removed record's
// seq and hash in audit_checkpoint inside the same transaction, so the
// remaining chain still verifies.
//
// Verification of the live store is incremental (AuditVerifyIncremental): the
// last verified position is kept in memory and only newer records are checked.
// Triggers count every UPDATE or DELETE of audit_log, and every INSERT that is
// not an append at the end, in audit_guard.gen; a changed counter or checkpoint
// makes the next check start again from the checkpoint, so the result always
// equals that of a full walk (verifyChain), which audit-verify runs offline.

// AuditGenesisHash is the prev_hash of the very first record.
var AuditGenesisHash = strings.Repeat("0", 64)

// AuditTimeLayout is the fixed-width UTC layout of audit timestamps, so text
// comparison equals time comparison.
const AuditTimeLayout = "2006-01-02T15:04:05.000000Z"

// Variables so tests can shorten them.
var (
	auditWriteWait = 4 * time.Second
	// auditVerifyChunk is how many records one read transaction of the
	// incremental verification checks before it frees the connection.
	auditVerifyChunk = 5000
)

const (
	auditKeyInfo = "sendora audit chain v1"
	// AuditRetentionMinDays is the shortest retention that can be configured, so
	// lowering the setting cannot be used to remove recent evidence.
	AuditRetentionMinDays = 90
)

// AuditFieldMax is the longest stored text field in bytes; longer values are cut
// at a character boundary.
const AuditFieldMax = 2000

// ErrAuditPurgeRefused marks a retention purge that was refused because the
// records to be removed do not verify.
var ErrAuditPurgeRefused = errors.New("retention purge refused")

// ctxMutex is a mutex whose lock gives up when the context ends, so a write
// deadline also covers the wait for the lock. The zero value is ready to use.
type ctxMutex struct {
	once sync.Once
	ch   chan struct{}
}

func (m *ctxMutex) lock(ctx context.Context) error {
	m.once.Do(func() { m.ch = make(chan struct{}, 1) })
	select {
	case m.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *ctxMutex) unlock() { <-m.ch }

// AuditRecord is one stored (or to be stored) audit entry.
type AuditRecord = ports.AuditRecord

// AuditStatus is the result of verifying the whole chain.
type AuditStatus struct {
	OK             bool   `json:"ok"`
	FirstBroken    int64  `json:"first_broken_seq,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Count          int64  `json:"count"`
	OldestTS       string `json:"oldest_ts,omitempty"`
	LastSeq        int64  `json:"last_seq"`
	CheckpointSeq  int64  `json:"checkpoint_seq"`
	CheckpointHash string `json:"checkpoint_hash"`
}

func auditKey(dbKey []byte) []byte {
	k := dbKey
	if len(k) == 0 { // plaintext fixture store only
		k = make([]byte, 32)
	}
	out, err := hkdf.Key(sha256.New, k, nil, auditKeyInfo, 32)
	if err != nil {
		panic(err) // cannot happen for these parameters
	}
	return out
}

// auditMAC returns the HMAC function of the chain without exposing the key.
func auditMAC(dbKey []byte) func([]byte) []byte {
	k := auditKey(dbKey)
	return func(data []byte) []byte {
		m := hmac.New(sha256.New, k)
		m.Write(data)
		return m.Sum(nil)
	}
}

// AuditMAC exposes the chain's HMAC as a closure; the key itself never leaves
// the store package. On an encrypted database the key comes from the tenant's
// "audit-mac" DEK in its keyring (version 1: the key is not rotatable, D45), so
// an operator who knows only the platform's keys cannot forge the chain. The
// plaintext fixture store (no keyring) derives it from the root.
func (s *Store) AuditMAC() func([]byte) []byte {
	if s.codec != nil {
		s.auditOnce.Do(func() { s.auditMacFn = s.codec.AuditMAC() })
		return s.auditMacFn
	}
	root := s.rootKey
	if root == nil {
		root = s.cipherKey
	}
	return auditMAC(root)
}

func appendField(b []byte, v string) []byte {
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

// canonicalAudit is the exact byte string that is authenticated.
func canonicalAudit(r *AuditRecord) []byte {
	b := []byte("sendora-audit-v1\x00")
	for _, f := range []string{
		strconv.FormatInt(r.Seq, 10), r.TS, r.Category, strconv.FormatInt(r.ActorID, 10), r.ActorName,
		r.ActorRole, r.Action, r.Target, r.Outcome, r.Detail, r.IP, r.PrevHash,
	} {
		b = appendField(b, f)
	}
	return b
}

func recordHash(mac func([]byte) []byte, r *AuditRecord) string {
	return hex.EncodeToString(mac(canonicalAudit(r)))
}

func checkpointMAC(mac func([]byte) []byte, seq int64, hash string) string {
	b := []byte("sendora-audit-checkpoint-v1\x00")
	b = appendField(b, strconv.FormatInt(seq, 10))
	b = appendField(b, hash)
	return hex.EncodeToString(mac(b))
}

// migrateAudit creates the audit tables, drops the retired optional event log
// and its settings, and adds the auditor flag. It is additive and idempotent;
// it never needs the database key (MACs are only computed when writing). See
// sqlite.MigrateAudit.
func (s *Store) migrateAudit() error { return sqlite.MigrateAudit(s.DB) }

// migrateAuditSettings raises a stored retention below the minimum (the
// setting is sealed, so this runs once the column codec exists). See
// sqlite.MigrateAuditSettings.
func (s *Store) migrateAuditSettings() error {
	return sqlite.MigrateAuditSettings(s.DB, s.ColumnCodec(), AuditRetentionMinDays)
}

// auditTail returns the seq and hash the next record must chain from, and the
// highest seq ever issued, which exposes removed tail records.
func auditTail(ctx context.Context, q ports.AuditChainRepository) (lastSeq int64, lastHash string, issued int64, err error) {
	var cpSeq int64
	var cpHash string
	if cpSeq, cpHash, err = q.CheckpointHead(ctx); err != nil {
		return
	}
	lastSeq, lastHash = cpSeq, cpHash
	if lastSeq == 0 {
		lastHash = AuditGenesisHash
	}
	switch seq, hash, e := q.Last(ctx); {
	case e == nil:
		lastSeq, lastHash = seq, hash
	case errors.Is(e, ports.ErrNotFound):
	default:
		err = e
		return
	}
	issued = lastSeq
	n, e := q.Issued(ctx)
	if e != nil {
		err = e
		return
	}
	if n > issued {
		issued = n
	}
	return
}

// clipAudit makes v valid UTF-8 and cuts it to AuditFieldMax bytes at a
// character boundary, in one pass.
func clipAudit(v string) string {
	v = strings.ToValidUTF8(v, "")
	if len(v) <= AuditFieldMax {
		return v
	}
	i := AuditFieldMax
	for i > 0 && !utf8.RuneStart(v[i]) {
		i--
	}
	return v[:i]
}

// AuditAppend writes one record to the end of the chain. It is serialised and
// synchronous. seq, ts (when empty), prev_hash and hash are assigned here. The
// write deadline includes the wait for the lock.
func (s *Store) AuditAppend(rec AuditRecord) (AuditRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), auditWriteWait)
	defer cancel()
	if err := s.auditMu.lock(ctx); err != nil {
		return rec, err
	}
	defer s.auditMu.unlock()
	tx, err := s.Repos().Begin(ctx)
	if err != nil {
		return rec, err
	}
	defer tx.Rollback()
	_, lastHash, issued, err := auditTail(ctx, tx.AuditChain())
	if err != nil {
		return rec, err
	}
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(AuditTimeLayout)
	}
	for _, p := range []*string{&rec.Category, &rec.ActorName, &rec.ActorRole, &rec.Action, &rec.Target, &rec.Outcome, &rec.Detail, &rec.IP} {
		*p = clipAudit(*p)
	}
	rec.Seq = issued + 1
	rec.PrevHash = lastHash
	rec.Hash = recordHash(s.AuditMAC(), &rec)
	if err = tx.AuditChain().Insert(ctx, rec); err != nil {
		return rec, err
	}
	return rec, tx.Commit()
}

// readSnapshot runs fn inside one read snapshot of db, so every query of fn
// sees the same state of the database (concurrent appends or purges cannot
// make a verification report removed or missing records).
func readSnapshot(ctx context.Context, db ports.Store, fn func(q ports.AuditChainRepository) error) error {
	return db.ReadSnapshot(ctx, func(r ports.Repositories) error { return fn(r.AuditChain()) })
}

func readCheckpoint(ctx context.Context, q ports.AuditChainRepository) (seq int64, hash, mac string, found bool, err error) {
	seq, hash, mac, err = q.Checkpoint(ctx)
	if errors.Is(err, ports.ErrNotFound) {
		return 0, "", "", false, nil
	}
	return seq, hash, mac, err == nil, err
}

// chainWalker checks records in seq order; verifyChain and the incremental
// verification share it, so both give the same answer.
type chainWalker struct {
	st     AuditStatus
	mac    func([]byte) []byte
	prev   string
	expect int64
	cursor int64 // seq of the last record read; math.MinInt64 before the first
}

func newChainWalker(mac func([]byte) []byte, cpSeq int64, cpHash, cpMAC string) *chainWalker {
	w := &chainWalker{st: AuditStatus{OK: true, CheckpointSeq: cpSeq, CheckpointHash: cpHash, LastSeq: cpSeq},
		mac: mac, prev: cpHash, expect: cpSeq + 1, cursor: math.MinInt64}
	if cpSeq == 0 {
		w.prev = AuditGenesisHash
		if cpHash != "" {
			w.broke(1, "checkpoint modified")
		}
	} else if !hmac.Equal([]byte(cpMAC), []byte(checkpointMAC(mac, cpSeq, cpHash))) {
		w.broke(cpSeq, "checkpoint modified")
	}
	return w
}

func (w *chainWalker) broke(seq int64, reason string) {
	if w.st.OK {
		w.st.OK, w.st.FirstBroken, w.st.Reason = false, seq, reason
	}
}

func (w *chainWalker) add(r *AuditRecord) {
	w.st.Count++
	if w.st.OldestTS == "" {
		w.st.OldestTS = r.TS
	}
	switch {
	case r.Seq < w.expect:
		w.broke(r.Seq, "record out of sequence")
	case r.Seq > w.expect:
		w.broke(w.expect, "record missing")
	}
	if r.PrevHash != w.prev {
		w.broke(r.Seq, "chain link broken")
	}
	if !hmac.Equal([]byte(r.Hash), []byte(recordHash(w.mac, r))) {
		w.broke(r.Seq, "record modified or forged")
	}
	w.prev = r.Hash
	w.expect = r.Seq + 1
	w.st.LastSeq = r.Seq
	w.cursor = r.Seq
}

// result is the status so far; with the highest issued seq it also reports a
// removed tail. The walker itself is not changed.
func (w *chainWalker) result(issued int64, checkTail bool) AuditStatus {
	st := w.st
	if checkTail && issued > st.LastSeq && st.OK {
		st.OK, st.FirstBroken, st.Reason = false, st.LastSeq+1, "newest records removed"
	}
	return st
}

// walk feeds the records after the walker's cursor (and up to upTo when > 0) to
// the walker, at most limit of them when limit > 0. It returns how many it read.
func (w *chainWalker) walk(ctx context.Context, db ports.AuditChainRepository, upTo int64, limit int) (int, error) {
	return db.Walk(ctx, w.cursor, upTo, limit, w.add)
}

// verifyChain walks the chain from the checkpoint. upTo > 0 limits the walk to
// records with seq <= upTo (used before purging) and skips the tail checks. The
// caller provides a consistent view (a transaction or a read snapshot).
func verifyChain(ctx context.Context, db ports.AuditChainRepository, mac func([]byte) []byte, upTo int64) (AuditStatus, error) {
	cpSeq, cpHash, cpMAC, found, err := readCheckpoint(ctx, db)
	if err != nil {
		return AuditStatus{}, err
	}
	if !found {
		return AuditStatus{OK: false, FirstBroken: 1, Reason: "checkpoint row missing"}, nil
	}
	w := newChainWalker(mac, cpSeq, cpHash, cpMAC)
	if _, err := w.walk(ctx, db, upTo, 0); err != nil {
		return w.st, err
	}
	if upTo > 0 {
		return w.result(0, false), nil
	}
	issued, err := db.Issued(ctx)
	if err != nil {
		return w.st, err
	}
	return w.result(issued, true), nil
}

// AuditVerify verifies the whole chain of the live store in one read snapshot.
func (s *Store) AuditVerify() (AuditStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var st AuditStatus
	err := readSnapshot(ctx, s.Repos(), func(q ports.AuditChainRepository) error {
		var e error
		st, e = verifyChain(ctx, q, s.AuditMAC(), 0)
		return e
	})
	return st, err
}

// auditVerifyState is the in-memory progress of the incremental verification:
// the walker has checked every record up to its cursor, starting from the
// checkpoint (cpSeq, cpHash, cpMAC), while audit_guard.gen was gen.
type auditVerifyState struct {
	mu     sync.Mutex
	w      *chainWalker
	gen    int64
	cpSeq  int64
	cpHash string
	cpMAC  string
}

func (v *auditVerifyState) matches(gen, cpSeq int64, cpHash, cpMAC string) bool {
	return v.w != nil && gen >= 0 && v.gen == gen && v.cpSeq == cpSeq && v.cpHash == cpHash && v.cpMAC == cpMAC
}

// readGuard returns audit_guard.gen, or -1 when the guard (row or triggers) is
// missing, in which case only a full walk can be trusted.
func readGuard(ctx context.Context, q ports.AuditChainRepository) (int64, error) {
	return q.Guard(ctx)
}

// AuditVerifyIncremental returns the same status as a full verification of the
// live chain, but only checks the records added since the last call (the first
// call, and any call after a change to existing records or to the checkpoint,
// walks from the checkpoint). Long walks run in read transactions of
// auditVerifyChunk records, freeing the connection in between.
func (s *Store) AuditVerifyIncremental(ctx context.Context) (AuditStatus, error) {
	v := &s.auditVer
	v.mu.Lock()
	defer v.mu.Unlock()
	mac := s.AuditMAC()
	for {
		var st AuditStatus
		done := false
		err := readSnapshot(ctx, s.Repos(), func(q ports.AuditChainRepository) error {
			gen, err := readGuard(ctx, q)
			if err != nil {
				return err
			}
			if gen < 0 {
				v.w = nil
				st, err = verifyChain(ctx, q, mac, 0)
				done = true
				return err
			}
			cpSeq, cpHash, cpMAC, found, err := readCheckpoint(ctx, q)
			if err != nil {
				return err
			}
			if !found {
				v.w = nil
				st, done = AuditStatus{OK: false, FirstBroken: 1, Reason: "checkpoint row missing"}, true
				return nil
			}
			if !v.matches(gen, cpSeq, cpHash, cpMAC) {
				v.w = newChainWalker(mac, cpSeq, cpHash, cpMAC)
				v.gen, v.cpSeq, v.cpHash, v.cpMAC = gen, cpSeq, cpHash, cpMAC
			}
			n, err := v.w.walk(ctx, q, 0, auditVerifyChunk)
			if err != nil {
				return err
			}
			if n == auditVerifyChunk {
				return nil // more records: continue in a new snapshot
			}
			issued, err := q.Issued(ctx)
			if err != nil {
				return err
			}
			st, done = v.w.result(issued, true), true
			return nil
		})
		if err != nil {
			v.w = nil // a half-read chunk cannot be trusted
			return st, err
		}
		if done {
			return st, nil
		}
	}
}

// VerifyAuditDatabase opens a database read-only (no migrations) and verifies
// its audit chain. A database from before the audit log has an empty chain.
func VerifyAuditDatabase(path string, key []byte) (AuditStatus, error) {
	return VerifyAuditDatabaseRoot(path, key, key)
}

// VerifyAuditDatabaseRoot is VerifyAuditDatabase; root only matters for a
// plaintext fixture database (an encrypted one takes the key from its keyring).
func VerifyAuditDatabaseRoot(path string, key, root []byte) (AuditStatus, error) {
	db, err := openCipherDB(path, key, true)
	if err != nil {
		return AuditStatus{}, err
	}
	defer db.Close()
	if err := checkCipherIntegrity(db, len(key) != 0); err != nil {
		return AuditStatus{}, err
	}
	repos := sqlite.New(db)
	mac := auditMAC(root) // plaintext fixture database only
	// The audit columns are sealed: open them before the records are hashed.
	// The chain's MAC key is the keyring's audit-mac key.
	if len(key) == 32 {
		codec, err := columnCodecFor(db, key)
		if err != nil {
			return AuditStatus{}, fmt.Errorf("the database's keys do not verify: %w", err)
		}
		if codec != nil {
			defer codec.Close()
			repos.SetCodec(codec)
			mac = codec.AuditMAC()
		}
	}
	has, err := repos.AuditChain().HasChain(context.Background())
	if err != nil {
		return AuditStatus{}, err
	}
	if !has {
		return AuditStatus{}, errors.New("the database has no audit log (created before the audit log existed)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var st AuditStatus
	err = readSnapshot(ctx, repos, func(q ports.AuditChainRepository) error {
		var e error
		st, e = verifyChain(ctx, q, mac, 0)
		return e
	})
	return st, err
}

// AuditPurge removes records older than cutoff (a time in UTC) and moves the
// checkpoint to the newest removed record in one transaction. It refuses to
// purge when the part to be removed does not verify (ErrAuditPurgeRefused), so
// evidence of tampering is never destroyed by retention. It returns the number
// of records removed.
//
// A refused purge is not repaired automatically, and there is deliberately no
// command that re-anchors the chain. Recovery: verify the database offline
// (sendora-db audit-verify), investigate what changed, then restore a backup
// taken before the damage.
func (s *Store) AuditPurge(cutoff time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.auditMu.lock(ctx); err != nil {
		return 0, err
	}
	defer s.auditMu.unlock()
	seq, hash, err := s.Repos().AuditChain().LastBefore(ctx, cutoff.UTC().Format(AuditTimeLayout))
	if errors.Is(err, ports.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	mac := s.AuditMAC()
	tx, err := s.Repos().Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	chain := tx.AuditChain()
	genBefore, err := readGuard(ctx, chain)
	if err != nil {
		return 0, err
	}
	cpSeq, cpHash, cpMAC, _, err := readCheckpoint(ctx, chain)
	if err != nil {
		return 0, err
	}
	// The incremental verification may already cover the part to be removed. It
	// is only consulted when free (TryLock): this transaction holds the single
	// connection, which a running verification may be waiting for.
	v := &s.auditVer
	haveV := v.mu.TryLock()
	if haveV {
		defer v.mu.Unlock()
	}
	covered := haveV && v.matches(genBefore, cpSeq, cpHash, cpMAC) && v.w.cursor >= seq
	if covered && !v.w.st.OK && v.w.st.FirstBroken <= seq {
		return 0, fmt.Errorf("%w: audit chain broken at seq %d (%s)", ErrAuditPurgeRefused, v.w.st.FirstBroken, v.w.st.Reason)
	}
	if !covered {
		st, err := verifyChain(ctx, chain, mac, seq)
		if err != nil {
			return 0, err
		}
		if !st.OK {
			return 0, fmt.Errorf("%w: audit chain broken at seq %d (%s)", ErrAuditPurgeRefused, st.FirstBroken, st.Reason)
		}
	}
	n, err := chain.DeleteThrough(ctx, seq)
	if err != nil {
		return 0, err
	}
	newMAC := checkpointMAC(mac, seq, hash)
	if err := chain.SetCheckpoint(ctx, seq, hash, newMAC); err != nil {
		return 0, err
	}
	genAfter, err := readGuard(ctx, chain)
	if err != nil {
		return 0, err
	}
	oldest, err := chain.OldestTS(ctx)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if covered && genAfter >= 0 {
		// Every removed record had been verified: move the verified state along
		// with the checkpoint instead of walking the whole chain again.
		v.w.st.Count -= n
		v.w.st.CheckpointSeq, v.w.st.CheckpointHash, v.w.st.OldestTS = seq, hash, oldest
		v.gen, v.cpSeq, v.cpHash, v.cpMAC = genAfter, seq, hash, newMAC
	}
	return n, nil
}

// CarryAuditLog replaces the audit tables of the database file at path (a
// prepared import that uses this store's key) by this store's live log, so that
// importing a backup can neither erase nor roll back the audit trail.
func (s *Store) CarryAuditLog(path string) error {
	if err := s.auditMu.lock(context.Background()); err != nil {
		return err
	}
	defer s.auditMu.unlock()
	dst, err := openCipherDB(path, s.cipherKey, false)
	if err != nil {
		return err
	}
	defer func() {
		dst.Close()
		for _, suffix := range []string{"-wal", "-shm"} {
			os.Remove(path + suffix)
		}
	}()
	ctx := context.Background()
	// The copy's audit columns are sealed with the copy's own keys.
	dstRepos := sqlite.New(dst)
	codec, err := columnCodecFor(dst, s.cipherKey)
	if err != nil {
		return fmt.Errorf("the copy's keys do not verify: %w", err)
	}
	if codec != nil {
		defer codec.Close()
		dstRepos.SetCodec(codec)
	}
	tx, err := dstRepos.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.AuditChain().Clear(ctx); err != nil {
		return err
	}
	src := s.Repos().AuditChain()
	cpSeq, cpHash, cpMAC, err := src.Checkpoint(ctx)
	if err != nil {
		return err
	}
	issued, err := src.Issued(ctx)
	if err != nil {
		return err
	}
	if err := tx.AuditChain().SetCheckpoint(ctx, cpSeq, cpHash, cpMAC); err != nil {
		return err
	}
	maxSeq := cpSeq
	if err := src.All(ctx, func(r AuditRecord) error {
		if err := tx.AuditChain().Insert(ctx, r); err != nil {
			return err
		}
		maxSeq = max(maxSeq, r.Seq)
		return nil
	}); err != nil {
		return err
	}
	// Keep the high-water mark so a removed tail stays detectable and the next
	// record continues the sequence (an empty or fully purged log included).
	if hw := max(issued, maxSeq); hw > 0 {
		if err := tx.AuditChain().SetIssued(ctx, hw); err != nil {
			return err
		}
	}
	return tx.Commit()
}
