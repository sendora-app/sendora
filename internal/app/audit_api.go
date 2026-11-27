// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// csvSafe neutralises spreadsheet formula injection in exported cells. Some
// spreadsheet programs skip leading whitespace or control characters and accept
// full-width operators, so those are looked past before the first character is
// checked.
func csvSafe(v string) string {
	trimmed := strings.TrimLeftFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
	if trimmed == "" {
		return v
	}
	first, _ := utf8.DecodeRuneInString(trimmed)
	if strings.ContainsRune("=+-@|%＝＋－＠", first) || trimmed != v {
		return "'" + v
	}
	return v
}

const auditPageMax = 100

// Variables so tests can shorten them.
var (
	auditExportMax = 500000
	// auditTotalCap bounds the COUNT(*) behind a page's total; above it the
	// total is reported as the cap with total_capped=true.
	auditTotalCap int64 = 10000
	// auditExportPage is how many records one query of an export reads; each
	// page is written to the client before the next is read, so the single
	// database connection is free in between.
	auditExportPage = 2000
)

// parseAuditTime accepts RFC 3339 or a plain date (UTC).
func parseAuditTime(v string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// searchTerms splits a search text into lower-case words; spaces, underscores, dashes
// and the wildcards * and % all separate words.
func searchTerms(v string) []string {
	return strings.FieldsFunc(strings.ToLower(v), func(r rune) bool {
		return unicode.IsSpace(r) || r == '_' || r == '-' || r == '*' || r == '%'
	})
}

// auditFilter builds the filter of a log query. Administrators and auditors
// read the same records, share events included.
func auditFilter(q url.Values) (f ports.AuditFilter, msg string) {
	// Free text: every word (split on spaces, underscores, dashes and * wildcards) must
	// occur somewhere in the action, actor, target, detail or category. So "create_user"
	// finds "user_created" and "create" finds all creations.
	f.Terms = searchTerms(q.Get("q"))
	if v := q.Get("category"); v != "" {
		if !auditCategories[v] {
			return ports.AuditFilter{}, "invalid category"
		}
		f.Category = v
	}
	if v := strings.TrimSpace(q.Get("action")); v != "" {
		f.Action = v
	}
	if v := strings.ToLower(strings.TrimSpace(q.Get("actor"))); v != "" {
		f.Actor = v
	}
	if v := q.Get("outcome"); v != "" {
		if !auditOutcomes[v] {
			return ports.AuditFilter{}, "invalid outcome"
		}
		f.Outcome = v
	}
	if v := q.Get("from"); v != "" {
		t, ok := parseAuditTime(v)
		if !ok {
			return ports.AuditFilter{}, "invalid from time"
		}
		f.From = t.Format(store.AuditTimeLayout)
	}
	if v := q.Get("to"); v != "" {
		t, ok := parseAuditTime(v)
		if !ok {
			return ports.AuditFilter{}, "invalid to time"
		}
		if len(v) == len("2006-01-02") { // a date means the whole day
			t = t.AddDate(0, 0, 1)
		}
		f.To = t.Format(store.AuditTimeLayout)
	}
	return f, ""
}

// parsePaging reads limit, offset and the optional keyset parameter before_seq
// (only records with a smaller seq; offset then counts from there).
func parsePaging(w http.ResponseWriter, r *http.Request) (limit, offset int, beforeSeq int64, ok bool) {
	limit = 50
	for key, dest := range map[string]*int{"limit": &limit, "offset": &offset} {
		if value := r.URL.Query().Get(key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || (key == "limit" && n == 0) {
				jerr(w, 400, "invalid pagination")
				return 0, 0, 0, false
			}
			*dest = n
		}
	}
	if value := r.URL.Query().Get("before_seq"); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n <= 0 {
			jerr(w, 400, "invalid pagination")
			return 0, 0, 0, false
		}
		beforeSeq = n
	}
	if limit > auditPageMax {
		limit = auditPageMax
	}
	return limit, offset, beforeSeq, true
}

// auditRows reads matching records. The rows are buffered so the single pooled
// connection is free again before anything is written to the client.
func (s *Server) auditRows(f ports.AuditFilter, newestFirst bool, limit, offset int) ([]store.AuditRecord, error) {
	return s.St.Repos().AuditQuery().Find(context.Background(), f, newestFirst, limit, offset)
}

// auditCount counts matching records, stopping at limit+1 so a broad filter
// never walks the whole table.
func (s *Server) auditCount(f ports.AuditFilter, limit int) (int64, error) {
	return s.St.Repos().AuditQuery().CountCapped(context.Background(), f, limit)
}

func auditTime(ts string) time.Time {
	t, _ := time.Parse(store.AuditTimeLayout, ts)
	return t
}

// auditPage is one page of the log, newest first.
type auditPage struct {
	recs    []store.AuditRecord
	total   int64 // matching records (without before_seq), at most auditTotalCap
	capped  bool  // more than auditTotalCap records match
	nextSeq int64 // before_seq of the next page; 0 when this is the last page
}

// readAuditPage is the query shared by /api/audit and /api/logs. It writes the
// error response itself and returns false then.
func (s *Server) readAuditPage(w http.ResponseWriter, r *http.Request) (auditPage, bool) {
	var p auditPage
	limit, offset, beforeSeq, ok := parsePaging(w, r)
	if !ok {
		return p, false
	}
	f, msg := auditFilter(r.URL.Query())
	if msg != "" {
		jerr(w, 400, msg)
		return p, false
	}
	total, err := s.auditCount(f, int(auditTotalCap))
	if err != nil {
		jerr(w, 500, "database error")
		return p, false
	}
	p.total, p.capped = min(total, auditTotalCap), total > auditTotalCap
	page := f
	if beforeSeq > 0 {
		page.BeforeSeq = &beforeSeq
	}
	if p.recs, err = s.auditRows(page, true, limit, offset); err != nil {
		jerr(w, 500, "database error")
		return p, false
	}
	if len(p.recs) == limit {
		p.nextSeq = p.recs[len(p.recs)-1].Seq
	}
	if u := s.ctxUser(r); u != nil {
		s.auditViewedOnce(u)
	}
	return p, true
}

// listLogs: GET /api/logs (administrators). The same records as /api/audit,
// with the field names this endpoint has always used.
func (s *Server) listLogs(w http.ResponseWriter, r *http.Request) {
	p, ok := s.readAuditPage(w, r)
	if !ok {
		return
	}
	out := make([]map[string]any, 0, len(p.recs))
	for _, x := range p.recs {
		out = append(out, map[string]any{"id": x.Seq, "created_at": auditTime(x.TS), "actor": x.ActorName, "role": x.ActorRole,
			"category": x.Category, "action": x.Action, "target": x.Target, "outcome": x.Outcome, "detail": x.Detail})
	}
	jout(w, 200, map[string]any{"logs": out, "total": p.total, "total_capped": p.capped, "next_before_seq": p.nextSeq,
		"enabled": true, "retention_days": s.auditRetentionDays()})
}

// logsStatus: GET /api/logs/status (administrators): whether the chain verifies.
func (s *Server) logsStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.auditStatus(r.Context())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	refused, _ := s.auditPurgeState()
	jout(w, 200, map[string]any{"verified": st.OK, "retention_days": s.auditRetentionDays(), "ip_logging": s.St.SettingBool("audit_log_ip"),
		"purge_refused": refused, "forwarding": s.fwd.status(s)})
}

// exportDetail describes an export for the audit trail: format, number of records
// and the filters used, so it is clear which part of the log left the system.
func exportDetail(format string, n int, q url.Values) string {
	parts := []string{format, strconv.Itoa(n) + " records"}
	for _, k := range []string{"q", "category", "action", "actor", "outcome", "from", "to"} {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			parts = append(parts, k+"="+clip(v, 40))
		}
	}
	return strings.Join(parts, " ")
}

// exportLogs: GET /api/logs/export (administrators): the same export as
// /api/audit/export (CSV by default), under the file name sendora-logs.
func (s *Server) exportLogs(w http.ResponseWriter, r *http.Request) {
	s.exportAudit(w, r, "sendora-logs")
}

// ---------- auditor endpoints ----------

func auditJSON(x store.AuditRecord) map[string]any {
	return map[string]any{"seq": x.Seq, "ts": x.TS, "category": x.Category, "actor_id": x.ActorID, "actor": x.ActorName, "actor_role": x.ActorRole,
		"action": x.Action, "target": x.Target, "outcome": x.Outcome, "detail": x.Detail, "ip": x.IP, "prev_hash": x.PrevHash, "hash": x.Hash}
}

// auditList: GET /api/audit (auditors and administrators): every category.
func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	p, ok := s.readAuditPage(w, r)
	if !ok {
		return
	}
	out := make([]map[string]any, 0, len(p.recs))
	for _, x := range p.recs {
		out = append(out, auditJSON(x))
	}
	jout(w, 200, map[string]any{"records": out, "total": p.total, "total_capped": p.capped, "next_before_seq": p.nextSeq,
		"retention_days": s.auditRetentionDays()})
}

// auditExport: GET /api/audit/export?format=csv|jsonl (auditors and administrators).
func (s *Server) auditExport(w http.ResponseWriter, r *http.Request) {
	s.exportAudit(w, r, "sendora-audit")
}

var auditCSVHeader = []string{"seq", "time_utc", "category", "actor_id", "user", "role", "action", "target", "outcome", "details", "ip", "prev_hash", "hash"}

// exportAudit streams the matching records oldest first. The number of records
// is counted (cheaply, capped) and an oversized export refused with 413 before
// anything is loaded; the export is then recorded, and only after that served,
// in pages of auditExportPage records read by seq. The export covers the
// records that existed when it started, so the count in its record is exact.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request, name string) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "jsonl" {
		jerr(w, 400, "format must be csv or jsonl")
		return
	}
	f, msg := auditFilter(r.URL.Query())
	if msg != "" {
		jerr(w, 400, msg)
		return
	}
	last, err := s.St.Repos().AuditQuery().MaxSeq(context.Background())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	f.MaxSeq = &last
	n, err := s.auditCount(f, auditExportMax)
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	if n > int64(auditExportMax) {
		jerr(w, 413, "too many records; narrow the filter")
		return
	}
	if u := s.ctxUser(r); u != nil {
		s.logEvent(u.ID, u.Username, "audit_exported", "audit_log", exportDetail(format, int(n), r.URL.Query()))
	}
	h := w.Header()
	if format == "csv" {
		h.Set("Content-Type", "text/csv; charset=utf-8")
	} else {
		h.Set("Content-Type", "application/x-ndjson; charset=utf-8")
	}
	h.Set("Content-Disposition", `attachment; filename="`+name+`-`+time.Now().UTC().Format("20060102-150405")+`.`+format+`"`)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	var cw *csv.Writer
	enc := json.NewEncoder(w)
	if format == "csv" {
		cw = csv.NewWriter(w)
		cw.Write(auditCSVHeader)
	}
	cursor := int64(0)
	for {
		page := f
		page.AfterSeq = &cursor
		recs, err := s.auditRows(page, false, auditExportPage, 0)
		if err != nil {
			// The response has started; a truncated file must not look complete.
			panic(http.ErrAbortHandler)
		}
		for _, x := range recs {
			if cw != nil {
				cw.Write([]string{strconv.FormatInt(x.Seq, 10), x.TS, x.Category, strconv.FormatInt(x.ActorID, 10), csvSafe(x.ActorName), x.ActorRole,
					csvSafe(x.Action), csvSafe(x.Target), x.Outcome, csvSafe(x.Detail), x.IP, x.PrevHash, x.Hash})
			} else if enc.Encode(x) != nil {
				return // the client went away
			}
		}
		if cw != nil {
			if cw.Flush(); cw.Error() != nil {
				return
			}
		}
		if len(recs) < auditExportPage {
			return
		}
		cursor = recs[len(recs)-1].Seq
	}
}

// auditStatusHandler: GET /api/audit/status (auditors and administrators).
func (s *Server) auditStatusHandler(w http.ResponseWriter, r *http.Request) {
	st, err := s.auditStatus(r.Context())
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	refused, since := s.auditPurgeState()
	out := map[string]any{"verified": st.OK, "count": st.Count, "oldest_ts": st.OldestTS, "last_seq": st.LastSeq,
		"retention_days": s.auditRetentionDays(), "ip_logging": s.St.SettingBool("audit_log_ip"),
		"checkpoint":     map[string]any{"seq": st.CheckpointSeq, "hash": st.CheckpointHash},
		"write_failures": s.audit.fails.Load(),
		"purge_refused":  refused,
		"forwarding":     s.fwd.status(s)}
	if refused {
		out["purge_refused_since"] = since.Format(time.RFC3339)
	}
	if !st.OK {
		out["first_broken_seq"] = st.FirstBroken
		out["reason"] = st.Reason
	}
	jout(w, 200, out)
}
