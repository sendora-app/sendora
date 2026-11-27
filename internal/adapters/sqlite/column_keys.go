// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/ports"
)

// Online key rotation (DESIGN 6.4, D43): the key jobs table and the batch
// operations of the re-encryption job. Like job_fences, key_jobs is created on
// first use so that databases that never rotate stay unchanged.
const keyJobsDDL = `CREATE TABLE IF NOT EXISTS key_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op TEXT NOT NULL,
  purpose TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT '',
  requested_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL)`

const keyJobCols = `id, op, purpose, version, status, detail, actor, requested_at, updated_at`

type columnKeyRepo struct{ q querier }

func (r repos) ColumnKeys() ports.ColumnKeyRepository { return columnKeyRepo{q: r.q} }

func (r columnKeyRepo) ensure(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, keyJobsDDL)
	return err
}

// CreateKeyJob: see ports.ColumnKeyRepository.
func (r columnKeyRepo) CreateKeyJob(ctx context.Context, j ports.KeyJob) (int64, error) {
	if err := r.ensure(ctx); err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	res, err := r.q.ExecContext(ctx, `INSERT INTO key_jobs(op, purpose, version, status, detail, actor, requested_at, updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		j.Op, j.Purpose, j.Version, ports.KeyJobPending, "", j.Actor, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func scanKeyJob(sc interface{ Scan(...any) error }) (ports.KeyJob, error) {
	var j ports.KeyJob
	err := sc.Scan(&j.ID, &j.Op, &j.Purpose, &j.Version, &j.Status, &j.Detail, &j.Actor, &j.RequestedAt, &j.UpdatedAt)
	return j, err
}

// KeyJobs: see ports.ColumnKeyRepository.
func (r columnKeyRepo) KeyJobs(ctx context.Context, limit int) ([]ports.KeyJob, error) {
	if !tableExists(ctx, r.q, "key_jobs") {
		return []ports.KeyJob{}, nil
	}
	rows, err := r.q.QueryContext(ctx, `SELECT `+keyJobCols+` FROM key_jobs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ports.KeyJob{}
	for rows.Next() {
		j, err := scanKeyJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// NextKeyJob: see ports.ColumnKeyRepository.
func (r columnKeyRepo) NextKeyJob(ctx context.Context) (ports.KeyJob, error) {
	if !tableExists(ctx, r.q, "key_jobs") {
		return ports.KeyJob{}, ports.ErrNotFound
	}
	j, err := scanKeyJob(r.q.QueryRowContext(ctx, `SELECT `+keyJobCols+` FROM key_jobs WHERE status IN (?, ?) ORDER BY id ASC LIMIT 1`, ports.KeyJobPending, ports.KeyJobRunning))
	return j, notFound(err)
}

// UpdateKeyJob: see ports.ColumnKeyRepository.
func (r columnKeyRepo) UpdateKeyJob(ctx context.Context, id int64, status string, version int, detail string) error {
	if err := r.ensure(ctx); err != nil {
		return err
	}
	n, err := affected(r.q.ExecContext(ctx, `UPDATE key_jobs SET status=?, version=?, detail=?, updated_at=? WHERE id=? AND status NOT IN (?, ?)`,
		status, version, detail, time.Now().UTC(), id, ports.KeyJobDone, ports.KeyJobFailed))
	if err == nil && n == 0 {
		return ports.ErrNotFound
	}
	return err
}

// resealPair is one encrypted column the re-encryption job rewrites.
type resealPair struct{ table, column string }

// resealExcluded are the tables the job leaves alone: the audit log is
// append-only and hash-guarded (an UPDATE raises the tamper counter), and the
// platform tables belong to the operator's keys, not the tenant's.
var resealExcluded = map[string]bool{"audit_log": true, "tenants": true, "platform_admins": true}

func resealPairs(ctx context.Context, q querier) []resealPair {
	var out []resealPair
	for _, t := range sortedTables() {
		if resealExcluded[t] || !tableExists(ctx, q, t) {
			continue
		}
		for _, c := range sortedColumns(t) {
			out = append(out, resealPair{t, c})
		}
	}
	return out
}

func countVersions(ctx context.Context, q querier, table, column string, into map[int]int64) error {
	rows, err := q.QueryContext(ctx, `SELECT SUBSTR(`+column+`, 4, 8), COUNT(*) FROM `+table+` WHERE `+column+` LIKE 'e1:%' GROUP BY 1`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		var n int64
		if err := rows.Scan(&p, &n); err != nil {
			return err
		}
		if v, ok := colenc.VersionOfPrefix(p); ok {
			into[v] += n
		}
	}
	return rows.Err()
}

// ColumnVersions: see ports.ColumnKeyRepository.
func (r columnKeyRepo) ColumnVersions(ctx context.Context) (ports.ColumnVersions, error) {
	out := ports.ColumnVersions{Columns: map[int]int64{}, Audit: map[int]int64{}}
	for _, p := range resealPairs(ctx, r.q) {
		if err := countVersions(ctx, r.q, p.table, p.column, out.Columns); err != nil {
			return out, err
		}
	}
	if tableExists(ctx, r.q, "audit_log") {
		for _, c := range sortedColumns("audit_log") {
			if err := countVersions(ctx, r.q, "audit_log", c, out.Audit); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

// ResealBatch: see ports.ColumnKeyRepository.
func (r columnKeyRepo) ResealBatch(ctx context.Context, c ports.ColumnCodec, newest int, cur ports.ResealCursor, limit int) (ports.ResealCursor, int, bool, error) {
	pairs := resealPairs(ctx, r.q)
	start := 0
	if cur.Table != "" {
		start = sort.Search(len(pairs), func(i int) bool {
			return pairs[i].table > cur.Table || (pairs[i].table == cur.Table && pairs[i].column >= cur.Column)
		})
	}
	budget, resealed := limit, 0
	for i := start; i < len(pairs); i++ {
		p := pairs[i]
		pk := encryptedColumns[p.table].pk
		after := ""
		hasAfter := cur.Table == p.table && cur.Column == p.column
		if hasAfter {
			after = cur.After
		}
		for budget > 0 {
			q := `SELECT ` + pk + `, ` + p.column + ` FROM ` + p.table + ` WHERE ` + p.column + ` LIKE 'e1:%'`
			args := []any{}
			if hasAfter {
				q += ` AND ` + pk + ` > ?`
				args = append(args, rawKeyArg(p.table, pk, after))
			}
			q += ` ORDER BY ` + pk + ` LIMIT ?`
			asked := budget
			args = append(args, asked)
			rows, err := r.q.QueryContext(ctx, q, args...)
			if err != nil {
				return cur, resealed, false, err
			}
			type row struct{ key, value string }
			var batch []row
			for rows.Next() {
				var key any
				var value string
				if err := rows.Scan(&key, &value); err != nil {
					rows.Close()
					return cur, resealed, false, err
				}
				batch = append(batch, row{keyText(key), value})
			}
			if err := rows.Close(); err != nil {
				return cur, resealed, false, err
			}
			for _, rw := range batch {
				budget--
				after, hasAfter = rw.key, true
				if v, ok := colenc.TextVersion(rw.value); !ok || v >= newest {
					continue
				}
				plain, err := c.Open(p.table, p.column, rw.key, rw.value)
				if err != nil {
					return cur, resealed, false, fmt.Errorf("opening %s.%s of row %s: %w", p.table, p.column, rw.key, err)
				}
				sealed, err := c.Seal(p.table, p.column, rw.key, plain)
				if err != nil {
					return cur, resealed, false, err
				}
				// Compare-and-swap: a concurrent update (which sealed the value
				// under the new key itself) is never overwritten.
				n, err := affected(r.q.ExecContext(ctx, `UPDATE `+p.table+` SET `+p.column+`=? WHERE `+pk+`=? AND `+p.column+`=?`, sealed, rawKeyArg(p.table, pk, rw.key), rw.value))
				if err != nil {
					return cur, resealed, false, err
				}
				resealed += int(n)
			}
			if len(batch) < asked {
				break // this column is exhausted
			}
		}
		if budget <= 0 {
			return ports.ResealCursor{Table: p.table, Column: p.column, After: after}, resealed, false, nil
		}
		cur = ports.ResealCursor{}
	}
	return ports.ResealCursor{}, resealed, true, nil
}

// keyText renders a scanned primary key as the text the codec binds values to.
func keyText(k any) string {
	if b, ok := k.([]byte); ok {
		return string(b)
	}
	return fmt.Sprint(k)
}

// ReindexBlind: see ports.ColumnKeyRepository. SQLite has one writer, so the
// transaction needs no table lock.
func (r columnKeyRepo) ReindexBlind(ctx context.Context, c ports.ColumnCodec) error {
	return reindexBlind(ctx, r.q, c)
}
