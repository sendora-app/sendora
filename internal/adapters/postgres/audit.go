// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

// auditGuardTriggers count every change to audit_log other than an append at
// the end; the incremental verification restarts when the count moves.
var auditGuardTriggers = []string{"audit_log_guard_update", "audit_log_guard_delete", "audit_log_guard_insert"}

// auditRepo stores the chain. Inside a write transaction the first read of
// the chain head (Checkpoint, CheckpointHead, Last, Issued) takes the audit
// append lock, so concurrent appenders on any replica serialise and each
// computes its sequence number from the committed head (SQLite: the single
// writer plus core's in-process mutex).
//
// The hash chain and the checkpoint MAC are computed by the caller over the
// plaintext fields; this repository seals the free-text columns (actor_name,
// target, detail) bound to the record's sequence number, which is known before
// the insert (the application role cannot UPDATE audit_log), and opens them on
// every read, so the callers only ever see plaintext.
type auditRepo struct {
	q     pq
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
	var ok bool
	err := r.q.scan(ctx, `SELECT to_regclass('audit_log') IS NOT NULL AND to_regclass('audit_checkpoint') IS NOT NULL`, nil, &ok)
	return ok, err
}

func (r auditRepo) Checkpoint(ctx context.Context) (int64, string, string, error) {
	if err := r.q.lockAudit(ctx); err != nil {
		return 0, "", "", err
	}
	var seq int64
	var hash, mac string
	err := r.q.scan(ctx, `SELECT last_deleted_seq,last_deleted_hash,mac FROM audit_checkpoint WHERE id=1`, nil, &seq, &hash, &mac)
	return seq, hash, mac, err
}

func (r auditRepo) CheckpointHead(ctx context.Context) (int64, string, error) {
	if err := r.q.lockAudit(ctx); err != nil {
		return 0, "", err
	}
	var seq int64
	var hash string
	err := r.q.scan(ctx, `SELECT last_deleted_seq,last_deleted_hash FROM audit_checkpoint WHERE id=1`, nil, &seq, &hash)
	return seq, hash, err
}

func (r auditRepo) SetCheckpoint(ctx context.Context, seq int64, hash, mac string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE audit_checkpoint SET last_deleted_seq=?,last_deleted_hash=?,mac=? WHERE id=1`, seq, hash, mac)
	return err
}

func (r auditRepo) Last(ctx context.Context) (int64, string, error) {
	if err := r.q.lockAudit(ctx); err != nil {
		return 0, "", err
	}
	var seq int64
	var hash string
	err := r.q.scan(ctx, `SELECT seq,hash FROM audit_log ORDER BY seq DESC LIMIT 1`, nil, &seq, &hash)
	return seq, hash, err
}

func (r auditRepo) LastBefore(ctx context.Context, ts string) (int64, string, error) {
	var seq int64
	var hash string
	err := r.q.scan(ctx, `SELECT seq,hash FROM audit_log WHERE ts<? ORDER BY seq DESC LIMIT 1`, []any{ts}, &seq, &hash)
	return seq, hash, err
}

func (r auditRepo) OldestTS(ctx context.Context) (string, error) {
	var oldest string
	if err := r.q.scan(ctx, `SELECT ts FROM audit_log ORDER BY seq ASC LIMIT 1`, nil, &oldest); err != nil && !errors.Is(err, ports.ErrNotFound) {
		return "", err
	}
	return oldest, nil
}

func (r auditRepo) Issued(ctx context.Context) (int64, error) {
	if err := r.q.lockAudit(ctx); err != nil {
		return 0, err
	}
	var n int64
	if err := r.q.scan(ctx, `SELECT seq FROM audit_issued WHERE id=1`, nil, &n); err != nil && !errors.Is(err, ports.ErrNotFound) {
		return 0, err
	}
	return n, nil
}

func (r auditRepo) SetIssued(ctx context.Context, seq int64) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO audit_issued(id,seq) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET seq=excluded.seq`, seq)
	return err
}

// Guard reads the generation only while all three guard triggers exist and
// are enabled on audit_log (-1 otherwise).
func (r auditRepo) Guard(ctx context.Context) (int64, error) {
	var triggers int
	if err := r.q.scan(ctx, `SELECT COUNT(*) FROM pg_catalog.pg_trigger WHERE tgrelid=to_regclass('audit_log') AND NOT tgisinternal AND tgenabled<>'D' AND tgname IN (?,?,?)`,
		[]any{auditGuardTriggers[0], auditGuardTriggers[1], auditGuardTriggers[2]}, &triggers); err != nil {
		return 0, err
	}
	if triggers != len(auditGuardTriggers) {
		return -1, nil
	}
	var gen int64
	switch err := r.q.scan(ctx, `SELECT gen FROM audit_guard WHERE id=1`, nil, &gen); {
	case errors.Is(err, ports.ErrNotFound):
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
	for _, q := range []string{`DELETE FROM audit_log`, `UPDATE audit_issued SET seq=0 WHERE id=1`} {
		if _, err := r.q.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// auditQueryRepo reads the log. The text columns actor_name, target and detail
// are sealed, so with a codec the text filters (Terms, Actor) are applied in Go
// on opened rows, in ordered windows; the columns that stay plaintext
// (category, action, outcome, ts, actor_id, seq) filter in SQL.
type auditQueryRepo struct {
	q     pq
	codec ports.ColumnCodec
}

// likeEscape escapes the LIKE wildcards of v (ESCAPE '\').
func likeEscape(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `%`, `\%`)
	return strings.ReplaceAll(v, `_`, `\_`)
}

const auditCols = `seq,ts,category,actor_id,actor_name,actor_role,action,target,outcome,detail,ip,prev_hash,hash`

// auditWhere builds the WHERE clause of a log query, condition by condition in
// the order of the SQLite adapter. ILIKE on "C"-collated columns folds ASCII
// letters only, like SQLite's LIKE.
func auditWhere(f ports.AuditFilter, textInSQL bool) (string, []any) {
	conds := []string{"1=1"}
	var args []any
	if !textInSQL {
		f.Terms, f.Actor = nil, ""
	}
	for _, term := range f.Terms {
		p := "%" + likeEscape(term) + "%"
		conds = append(conds, `(action ILIKE ? ESCAPE '\' OR actor_name ILIKE ? ESCAPE '\' OR target ILIKE ? ESCAPE '\' OR detail ILIKE ? ESCAPE '\' OR category ILIKE ? ESCAPE '\')`)
		args = append(args, p, p, p, p, p)
	}
	if f.Category != "" {
		conds = append(conds, "category=?")
		args = append(args, f.Category)
	}
	if f.Action != "" {
		conds = append(conds, "action=?")
		args = append(args, f.Action)
	}
	if f.Actor != "" {
		conds = append(conds, `actor_name ILIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(f.Actor)+"%")
	}
	if f.Outcome != "" {
		conds = append(conds, "outcome=?")
		args = append(args, f.Outcome)
	}
	if f.From != "" {
		conds = append(conds, "ts>=?")
		args = append(args, f.From)
	}
	if f.To != "" {
		conds = append(conds, "ts<=?")
		args = append(args, f.To)
	}
	where := strings.Join(conds, " AND ")
	if f.MaxSeq != nil {
		where += " AND seq<=?"
		args = append(args, *f.MaxSeq)
	}
	if f.BeforeSeq != nil {
		where += " AND seq<?"
		args = append(args, *f.BeforeSeq)
	}
	if f.AfterSeq != nil {
		where += " AND seq>?"
		args = append(args, *f.AfterSeq)
	}
	return where, args
}

// textFiltered reports whether f filters on a sealed column, which only Go can
// do once the columns are sealed.
func (r auditQueryRepo) textFiltered(f ports.AuditFilter) bool {
	return r.codec != nil && (len(f.Terms) > 0 || f.Actor != "")
}

// foldASCII lower-cases the ASCII letters only, as ILIKE on "C"-collated
// columns folds.
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// matchText applies the Terms and Actor filters of f to an opened record: every
// term must occur in the action, actor, target, detail or category.
func matchText(f ports.AuditFilter, x *ports.AuditRecord) bool {
	fields := [...]string{foldASCII(x.Action), foldASCII(x.ActorName), foldASCII(x.Target), foldASCII(x.Detail), foldASCII(x.Category)}
	for _, term := range f.Terms {
		t, found := foldASCII(term), false
		for _, v := range fields {
			if strings.Contains(v, t) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return f.Actor == "" || strings.Contains(fields[1], foldASCII(f.Actor))
}

const auditWindow = 256

func scanAudit(rows *sql.Rows) ([]ports.AuditRecord, error) {
	var out []ports.AuditRecord
	for rows.Next() {
		var x ports.AuditRecord
		if err := rows.Scan(&x.Seq, &x.TS, &x.Category, &x.ActorID, &x.ActorName, &x.ActorRole, &x.Action, &x.Target, &x.Outcome, &x.Detail, &x.IP, &x.PrevHash, &x.Hash); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// each calls fn for every record matching f in seq order (newest first when
// newestFirst) until fn returns false. The text filters run in Go: the records
// are read in windows of auditWindow rows by seq, opened and filtered.
func (r auditQueryRepo) each(ctx context.Context, f ports.AuditFilter, newestFirst bool, fn func(*ports.AuditRecord) bool) error {
	where, args := auditWhere(f, false)
	order, cmp := "ASC", ">"
	if newestFirst {
		order, cmp = "DESC", "<"
	}
	var cursor *int64
	for {
		q, a := `SELECT `+auditCols+` FROM audit_log WHERE `+where, append([]any{}, args...)
		if cursor != nil {
			q += ` AND seq` + cmp + `?`
			a = append(a, *cursor)
		}
		q += ` ORDER BY seq ` + order + ` LIMIT ?`
		rows, err := r.q.QueryContext(ctx, q, append(a, auditWindow)...)
		if err != nil {
			return err
		}
		recs, err := scanAudit(rows)
		rows.Close()
		if err != nil {
			return err
		}
		for i := range recs {
			if err := openAudit(r.codec, &recs[i]); err != nil {
				return err
			}
			if matchText(f, &recs[i]) && !fn(&recs[i]) {
				return nil
			}
		}
		if len(recs) < auditWindow {
			return nil
		}
		last := recs[len(recs)-1].Seq
		cursor = &last
	}
}

func (r auditQueryRepo) Find(ctx context.Context, f ports.AuditFilter, newestFirst bool, limit, offset int) ([]ports.AuditRecord, error) {
	if r.textFiltered(f) {
		var out []ports.AuditRecord
		skip := offset
		err := r.each(ctx, f, newestFirst, func(x *ports.AuditRecord) bool {
			if limit <= 0 {
				out = append(out, *x)
				return true
			}
			if skip > 0 {
				skip--
				return true
			}
			out = append(out, *x)
			return len(out) < limit
		})
		return out, err
	}
	where, args := auditWhere(f, r.codec == nil)
	order := "ASC"
	if newestFirst {
		order = "DESC"
	}
	q := `SELECT ` + auditCols + ` FROM audit_log WHERE ` + where + ` ORDER BY seq ` + order
	if limit > 0 {
		q += ` LIMIT ? OFFSET ?`
		args = append(append([]any{}, args...), limit, offset)
	}
	rows, err := r.q.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanAudit(rows)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if err := openAudit(r.codec, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r auditQueryRepo) CountCapped(ctx context.Context, f ports.AuditFilter, limit int) (int64, error) {
	if r.textFiltered(f) {
		var n int64
		err := r.each(ctx, f, true, func(*ports.AuditRecord) bool {
			n++
			return n <= int64(limit)
		})
		return n, err
	}
	where, args := auditWhere(f, r.codec == nil)
	var n int64
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM audit_log WHERE `+where+` LIMIT ?) capped`, append(append([]any{}, args...), limit+1), &n)
	return n, err
}

func (r auditQueryRepo) MaxSeq(ctx context.Context) (int64, error) {
	var last int64
	err := r.q.scan(ctx, `SELECT COALESCE(MAX(seq),0) FROM audit_log`, nil, &last)
	return last, err
}
