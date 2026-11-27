// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"testing"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/store"
)

// fixRaw completes the rows a test wrote with raw SQL: with a codec it seals
// the plaintext columns, without one it fills the blind indexes (both also
// compute the lookup indexes the repositories search by).
func fixRaw(t testing.TB, st *store.Store) {
	t.Helper()
	a := sqlite.New(st.DB)
	ctx := context.Background()
	if c := st.ColumnCodec(); c != nil {
		if _, err := a.EncryptPlaintextColumns(ctx, c); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := a.ReindexBlindIndexes(ctx, nil); err != nil {
		t.Fatal(err)
	}
}

// shareIDByLongID resolves a link id (encrypted columns cannot be searched
// with SQL) to the share's row id.
func shareIDByLongID(t testing.TB, st *store.Store, longID string) int64 {
	t.Helper()
	sh, err := st.Repos().Shares().ByLongID(context.Background(), longID)
	if err != nil {
		t.Fatalf("share %q: %v", longID, err)
	}
	return sh.ID
}

// userIDByName resolves a username to the account's row id.
func userIDByName(t testing.TB, st *store.Store, name string) int64 {
	t.Helper()
	id, err := st.Repos().Users().LocalIDByUsername(context.Background(), name)
	if err != nil {
		t.Fatalf("user %q: %v", name, err)
	}
	return id
}

var (
	rawUserLit   = regexp.MustCompile(`\(SELECT id FROM users WHERE username=('[^']*'|\?)\)|\busername=('[^']*'|\?)`)
	rawShareCond = regexp.MustCompile(`((?:WHERE|AND) (?:\w+\.)?)long_id=\?`)
)

// rewriteByName turns the plaintext lookups of a raw test query (username=...,
// long_id=?) into lookups by row id, resolving them through the repositories
// (the columns are encrypted or blind-indexed, so SQL cannot compare them). It
// returns the original query and arguments when a name does not resolve (rows
// inserted with raw SQL, a guest, a missing row).
func rewriteByName(st *store.Store, query string, args []any) (string, []any) {
	ctx := context.Background()
	out := args
	q := query
	// username: scan matches left to right, tracking the '?' index.
	var b strings.Builder
	last := 0
	qIdx := 0
	var newArgs []any
	copyArgsTo := func(upto int) {
		for qIdx < upto && qIdx < len(args) {
			newArgs = append(newArgs, args[qIdx])
			qIdx++
		}
	}
	changed := false
	for _, m := range rawUserLit.FindAllStringSubmatchIndex(q, -1) {
		b.WriteString(q[last:m[0]])
		qBefore := strings.Count(q[:m[0]], "?")
		copyArgsTo(qBefore)
		lit := ""
		if m[2] >= 0 {
			lit = q[m[2]:m[3]]
		} else {
			lit = q[m[4]:m[5]]
		}
		var name string
		if lit == "?" {
			if qIdx >= len(args) {
				return query, args
			}
			name, _ = args[qIdx].(string)
			qIdx++
		} else {
			name = strings.Trim(lit, "'")
		}
		id, err := st.Repos().Users().LocalIDByUsername(ctx, name)
		if err != nil {
			return query, args
		}
		if m[2] >= 0 {
			b.WriteString("?")
		} else {
			b.WriteString("id=?")
		}
		newArgs = append(newArgs, id)
		last = m[1]
		changed = true
	}
	b.WriteString(q[last:])
	copyArgsTo(len(args))
	if changed {
		q, out = b.String(), newArgs
	}
	// long_id=? conditions: the argument is the link id.
	if ms := rawShareCond.FindAllStringSubmatchIndex(q, -1); len(ms) > 0 {
		out = append([]any(nil), out...)
		var sb strings.Builder
		last := 0
		for _, m := range ms {
			idx := strings.Count(q[:m[0]], "?")
			lid, _ := out[idx].(string)
			sh, err := st.Repos().Shares().ByLongID(ctx, lid)
			if err != nil {
				return query, args
			}
			sb.WriteString(q[last:m[0]])
			sb.WriteString(q[m[2]:m[3]] + "id=?")
			out[idx] = sh.ID
			last = m[1]
		}
		sb.WriteString(q[last:])
		q = sb.String()
	}
	return q, out
}

// qByName is st.DB.QueryRow with the plaintext lookups rewritten by id.
func qByName(st *store.Store, query string, args ...any) *sql.Row {
	q, a := rewriteByName(st, query, args)
	return st.DB.QueryRow(q, a...)
}

// eByName is st.DB.Exec with the plaintext lookups rewritten by id.
func eByName(st *store.Store, query string, args ...any) (sql.Result, error) {
	q, a := rewriteByName(st, query, args)
	return st.DB.Exec(q, a...)
}

// rawExec is st.DB.Exec for statements that write encrypted or indexed lookup
// columns with raw SQL: it completes the rows (fixRaw) afterwards.
func rawExec(t testing.TB, st *store.Store, query string, args ...any) (sql.Result, error) {
	t.Helper()
	res, err := st.DB.Exec(query, args...)
	if err == nil {
		fixRaw(t, st)
	}
	return res, err
}
