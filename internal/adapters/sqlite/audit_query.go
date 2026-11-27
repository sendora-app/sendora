// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

// auditQueryRepo reads the log. The text columns actor_name, target and detail
// are sealed, so with a codec the text filters (Terms, Actor) are applied in Go
// on opened rows, in ordered windows; the columns that stay plaintext
// (category, action, outcome, ts, actor_id, seq) filter in SQL.
type auditQueryRepo struct {
	q     querier
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
// the order of the 0.2 code. Text matching uses LIKE on the bare columns (no
// lower() around them, which would defeat the indexes): SQLite's LIKE is
// case-insensitive for ASCII, which is also all that lower() folded.
func auditWhere(f ports.AuditFilter, textInSQL bool) (string, []any) {
	conds := []string{"1=1"}
	var args []any
	if !textInSQL {
		f.Terms, f.Actor = nil, ""
	}
	for _, term := range f.Terms {
		p := "%" + likeEscape(term) + "%"
		conds = append(conds, `(action LIKE ? ESCAPE '\' OR actor_name LIKE ? ESCAPE '\' OR target LIKE ? ESCAPE '\' OR detail LIKE ? ESCAPE '\' OR category LIKE ? ESCAPE '\')`)
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
		conds = append(conds, `actor_name LIKE ? ESCAPE '\'`)
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

// foldASCII lower-cases the ASCII letters only, as SQLite's LIKE folds.
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
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM audit_log WHERE `+where+` LIMIT ?)`, append(append([]any{}, args...), limit+1)...).Scan(&n)
	return n, err
}

func (r auditQueryRepo) MaxSeq(ctx context.Context) (int64, error) {
	var last int64
	err := r.q.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0) FROM audit_log`).Scan(&last)
	return last, err
}
