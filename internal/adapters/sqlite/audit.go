// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

// AuditSchema creates the chain's tables, indexes and guard triggers. The
// platform database of multi-tenant mode uses the same schema.
var AuditSchema = []string{
	`CREATE TABLE IF NOT EXISTS audit_log (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL,
			category TEXT NOT NULL,
			actor_id INTEGER NOT NULL DEFAULT 0,
			actor_name TEXT NOT NULL DEFAULT '',
			actor_role TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL,
			target TEXT NOT NULL DEFAULT '',
			outcome TEXT NOT NULL DEFAULT 'ok',
			detail TEXT NOT NULL DEFAULT '',
			ip TEXT NOT NULL DEFAULT '',
			prev_hash TEXT NOT NULL,
			hash TEXT NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_log_category ON audit_log(category)`,
	// Filtered pages are read newest first by seq.
	`CREATE INDEX IF NOT EXISTS idx_audit_log_category_seq ON audit_log(category, seq)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_log_action_seq ON audit_log(action, seq)`,
	// The actor name is sealed: an index on it would serve nothing.
	`DROP INDEX IF EXISTS idx_audit_log_actor`,
	`CREATE INDEX IF NOT EXISTS idx_audit_log_outcome_seq ON audit_log(outcome, seq)`,
	`CREATE TABLE IF NOT EXISTS audit_checkpoint (
			id INTEGER PRIMARY KEY CHECK (id=1),
			last_deleted_seq INTEGER NOT NULL DEFAULT 0,
			last_deleted_hash TEXT NOT NULL DEFAULT '',
			mac TEXT NOT NULL DEFAULT '')`,
	`INSERT OR IGNORE INTO audit_checkpoint(id,last_deleted_seq,last_deleted_hash,mac) VALUES(1,0,'','')`,
	`CREATE TABLE IF NOT EXISTS audit_guard (
			id INTEGER PRIMARY KEY CHECK (id=1),
			gen INTEGER NOT NULL DEFAULT 0)`,
	`INSERT OR IGNORE INTO audit_guard(id,gen) VALUES(1,0)`,
	`CREATE TRIGGER IF NOT EXISTS audit_log_guard_update AFTER UPDATE ON audit_log BEGIN UPDATE audit_guard SET gen=gen+1 WHERE id=1; END`,
	`CREATE TRIGGER IF NOT EXISTS audit_log_guard_delete AFTER DELETE ON audit_log BEGIN UPDATE audit_guard SET gen=gen+1 WHERE id=1; END`,
	`CREATE TRIGGER IF NOT EXISTS audit_log_guard_insert AFTER INSERT ON audit_log WHEN EXISTS(SELECT 1 FROM audit_log WHERE seq>NEW.seq) BEGIN UPDATE audit_guard SET gen=gen+1 WHERE id=1; END`,
}

// auditGuardTriggers count every change to audit_log other than an append at
// the end; the incremental verification restarts when the count moves.
var auditGuardTriggers = []string{"audit_log_guard_update", "audit_log_guard_delete", "audit_log_guard_insert"}

// MigrateAudit creates the audit tables, drops the retired optional event log
// and its settings and adds the auditor flag. It is additive and idempotent.
func MigrateAudit(db *sql.DB) error {
	for _, q := range append(append([]string{}, AuditSchema...),
		`DROP TABLE IF EXISTS event_log`,
		`DELETE FROM settings WHERE key IN ('logging_enabled','log_retention_hours')`,
	) {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	found, err := hasColumn(db, "users", "is_auditor")
	if err != nil {
		return err
	}
	if !found {
		if _, err = db.Exec(`ALTER TABLE users ADD COLUMN is_auditor INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	return nil
}

// MigrateAuditSettings raises a stored retention below retentionMinDays (the
// settings part of the audit migration, which needs the column codec). The
// retention minimum is 90 days; a shorter stored value (from before the
// minimum existed) is raised, so nobody can wipe recent evidence with it.
func MigrateAuditSettings(db *sql.DB, codec ports.ColumnCodec, retentionMinDays int) error {
	raised, err := raiseSettingFloor(context.Background(), db, codec, "audit_retention_days", retentionMinDays)
	if err != nil {
		return err
	}
	if raised {
		log.Printf("audit_retention_days was below the minimum of %d days and was raised to %d", retentionMinDays, retentionMinDays)
	}
	return nil
}

// ReadSnapshot runs fn inside one read transaction on a dedicated connection.
func (s *Store) ReadSnapshot(ctx context.Context, fn func(ports.Repositories) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN DEFERRED`); err != nil {
		return err
	}
	defer func() {
		if _, err := conn.ExecContext(context.Background(), `ROLLBACK`); err != nil && !strings.Contains(err.Error(), "no transaction is active") {
			// Never hand a connection with an open transaction back to the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	return fn(repos{q: conn, codec: s.codec})
}

// auditRepo stores the chain. The hash chain and the checkpoint MAC are
// computed by the caller over the plaintext fields; this repository seals the
// free-text columns (actor_name, target, detail) bound to the record's
// sequence number, which is known before the insert, and opens them on every
// read, so the callers only ever see plaintext.
type auditRepo struct {
	q     querier
	codec ports.ColumnCodec
}

// sealAudit returns rec with its encrypted columns sealed.
func sealAudit(c ports.ColumnCodec, rec ports.AuditRecord) (ports.AuditRecord, error) {
	var err error
	if rec.ActorName, err = sealCol(c, "audit_log", "actor_name", rec.Seq, rec.ActorName); err != nil {
		return rec, err
	}
	if rec.Target, err = sealCol(c, "audit_log", "target", rec.Seq, rec.Target); err != nil {
		return rec, err
	}
	rec.Detail, err = sealCol(c, "audit_log", "detail", rec.Seq, rec.Detail)
	return rec, err
}

// openAudit opens the encrypted columns of a stored record (fail closed).
func openAudit(c ports.ColumnCodec, rec *ports.AuditRecord) error {
	var err error
	if rec.ActorName, err = openCol(c, "audit_log", "actor_name", rec.Seq, rec.ActorName); err != nil {
		return err
	}
	if rec.Target, err = openCol(c, "audit_log", "target", rec.Seq, rec.Target); err != nil {
		return err
	}
	rec.Detail, err = openCol(c, "audit_log", "detail", rec.Seq, rec.Detail)
	return err
}

// auditUnreadable replaces a column of a record that cannot be opened (a
// ciphertext that was changed, moved or replaced by plaintext) when the chain
// is walked: the record then fails its hash, so verification reports it as
// modified at its sequence number instead of stopping without an answer.
const auditUnreadable = "\x00unreadable"

// openAuditLenient is openAudit that marks a column it cannot open.
func openAuditLenient(c ports.ColumnCodec, rec *ports.AuditRecord) {
	for _, f := range []struct {
		col string
		p   *string
	}{{"actor_name", &rec.ActorName}, {"target", &rec.Target}, {"detail", &rec.Detail}} {
		v, err := openCol(c, "audit_log", f.col, rec.Seq, *f.p)
		if err != nil {
			v = auditUnreadable
		}
		*f.p = v
	}
}

func (r auditRepo) HasChain(ctx context.Context) (bool, error) {
	var n int
	if err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name IN ('audit_log','audit_checkpoint')`).Scan(&n); err != nil {
		return false, err
	}
	return n == 2, nil
}

func (r auditRepo) Checkpoint(ctx context.Context) (int64, string, string, error) {
	var seq int64
	var hash, mac string
	err := r.q.QueryRowContext(ctx, `SELECT last_deleted_seq,last_deleted_hash,mac FROM audit_checkpoint WHERE id=1`).Scan(&seq, &hash, &mac)
	return seq, hash, mac, notFound(err)
}

func (r auditRepo) CheckpointHead(ctx context.Context) (int64, string, error) {
	var seq int64
	var hash string
	err := r.q.QueryRowContext(ctx, `SELECT last_deleted_seq,last_deleted_hash FROM audit_checkpoint WHERE id=1`).Scan(&seq, &hash)
	return seq, hash, notFound(err)
}

func (r auditRepo) SetCheckpoint(ctx context.Context, seq int64, hash, mac string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE audit_checkpoint SET last_deleted_seq=?,last_deleted_hash=?,mac=? WHERE id=1`, seq, hash, mac)
	return err
}

func (r auditRepo) Last(ctx context.Context) (int64, string, error) {
	var seq int64
	var hash string
	err := r.q.QueryRowContext(ctx, `SELECT seq,hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	return seq, hash, notFound(err)
}

func (r auditRepo) LastBefore(ctx context.Context, ts string) (int64, string, error) {
	var seq int64
	var hash string
	err := r.q.QueryRowContext(ctx, `SELECT seq,hash FROM audit_log WHERE ts<? ORDER BY seq DESC LIMIT 1`, ts).Scan(&seq, &hash)
	return seq, hash, notFound(err)
}

func (r auditRepo) OldestTS(ctx context.Context) (string, error) {
	var oldest sql.NullString
	if err := r.q.QueryRowContext(ctx, `SELECT ts FROM audit_log ORDER BY seq ASC LIMIT 1`).Scan(&oldest); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	return oldest.String, nil
}

func (r auditRepo) Issued(ctx context.Context) (int64, error) {
	var n sql.NullInt64
	if err := r.q.QueryRowContext(ctx, `SELECT seq FROM sqlite_sequence WHERE name='audit_log'`).Scan(&n); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return n.Int64, nil
}

// SetIssued: sqlite_sequence has no unique key, so the row the inserts created
// is updated, or added when there is none (INSERT OR REPLACE semantics).
func (r auditRepo) SetIssued(ctx context.Context, seq int64) error {
	res, err := r.q.ExecContext(ctx, `UPDATE sqlite_sequence SET seq=? WHERE name='audit_log'`, seq)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := r.q.ExecContext(ctx, `INSERT INTO sqlite_sequence(name,seq) VALUES('audit_log',?)`, seq); err != nil {
			return err
		}
	}
	return nil
}

func (r auditRepo) Guard(ctx context.Context) (int64, error) {
	var triggers int
	if err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log' AND name IN (?,?,?)`,
		auditGuardTriggers[0], auditGuardTriggers[1], auditGuardTriggers[2]).Scan(&triggers); err != nil {
		return 0, err
	}
	if triggers != len(auditGuardTriggers) {
		return -1, nil
	}
	var gen int64
	switch err := r.q.QueryRowContext(ctx, `SELECT gen FROM audit_guard WHERE id=1`).Scan(&gen); {
	case errors.Is(err, sql.ErrNoRows):
		return -1, nil
	case err != nil:
		return 0, err
	}
	return gen, nil
}

func (r auditRepo) Insert(ctx context.Context, rec ports.AuditRecord) error {
	rec, err := sealAudit(r.codec, rec)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `INSERT INTO audit_log(seq,ts,category,actor_id,actor_name,actor_role,action,target,outcome,detail,ip,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.Seq, rec.TS, rec.Category, rec.ActorID, rec.ActorName, rec.ActorRole, rec.Action, rec.Target, rec.Outcome, rec.Detail, rec.IP, rec.PrevHash, rec.Hash)
	return err
}

func (r auditRepo) Walk(ctx context.Context, after, upTo int64, limit int, fn func(*ports.AuditRecord)) (int, error) {
	q := `SELECT seq,ts,category,actor_id,actor_name,actor_role,action,target,outcome,detail,ip,prev_hash,hash FROM audit_log WHERE seq>?`
	args := []any{after}
	if upTo > 0 {
		q += ` AND seq<=?`
		args = append(args, upTo)
	}
	q += ` ORDER BY seq ASC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := r.q.QueryContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var rec ports.AuditRecord
		if err := rows.Scan(&rec.Seq, &rec.TS, &rec.Category, &rec.ActorID, &rec.ActorName, &rec.ActorRole, &rec.Action, &rec.Target, &rec.Outcome, &rec.Detail, &rec.IP, &rec.PrevHash, &rec.Hash); err != nil {
			return n, err
		}
		openAuditLenient(r.codec, &rec)
		fn(&rec)
		n++
	}
	return n, rows.Err()
}

func (r auditRepo) All(ctx context.Context, fn func(ports.AuditRecord) error) error {
	rows, err := r.q.QueryContext(ctx, `SELECT seq,ts,category,actor_id,actor_name,actor_role,action,target,outcome,detail,ip,prev_hash,hash FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var rec ports.AuditRecord
		if err := rows.Scan(&rec.Seq, &rec.TS, &rec.Category, &rec.ActorID, &rec.ActorName, &rec.ActorRole, &rec.Action, &rec.Target, &rec.Outcome, &rec.Detail, &rec.IP, &rec.PrevHash, &rec.Hash); err != nil {
			return err
		}
		if err := openAudit(r.codec, &rec); err != nil {
			return err
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (r auditRepo) DeleteThrough(ctx context.Context, seq int64) (int64, error) {
	return changed(r.q.ExecContext(ctx, `DELETE FROM audit_log WHERE seq<=?`, seq))
}

func (r auditRepo) Clear(ctx context.Context) error {
	for _, q := range []string{`DELETE FROM audit_log`, `DELETE FROM sqlite_sequence WHERE name='audit_log'`} {
		if _, err := r.q.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
