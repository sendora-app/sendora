// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// ---------- settings ----------

type settingsRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r settingsRepo) ListEditable(ctx context.Context) ([]ports.Setting, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT key,value,grp FROM settings WHERE grp NOT IN ('secret','email_templates') AND key<>'jwt_secret' ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.Setting
	for rows.Next() {
		var x ports.Setting
		if rows.Scan(&x.Key, &x.Value, &x.Group) != nil { // contract: an unreadable row keeps the values read so far
			out = append(out, x)
			continue
		}
		v, err := openColKey(r.codec, "settings", "value", x.Key, x.Value)
		if err != nil {
			return nil, err
		}
		x.Value = v
		out = append(out, x)
	}
	return out, nil
}

func (r settingsRepo) EditableKeys(ctx context.Context) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT key FROM settings WHERE grp NOT IN ('secret','email_templates')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			out = append(out, k)
		}
	}
	return out, nil
}

func (r settingsRepo) UpdateEditable(ctx context.Context, key, value string) error {
	sealed, err := sealColKey(r.codec, "settings", "value", key, value)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=? AND grp NOT IN ('secret','email_templates')`, sealed, key)
	return err
}

func (r settingsRepo) Update(ctx context.Context, key, value string) error {
	_, err := writeSetting(ctx, r.q, r.codec, key, value)
	return err
}

func (r settingsRepo) Clear(ctx context.Context, key string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE settings SET value='' WHERE key=?`, key)
	return err
}

func (r settingsRepo) Get(ctx context.Context, key string) (string, error) {
	return readSetting(ctx, r.q, r.codec, key)
}

func (r settingsRepo) Set(ctx context.Context, key, value string) error {
	return upsertSetting(ctx, r.q, r.codec, key, value, "system")
}

// ---------- themes ----------

type themeRepo struct{ q pq }

func (r themeRepo) list(ctx context.Context, where string) ([]ports.ThemeRecord, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id,name,category,bundled,active,data FROM themes `+where+` ORDER BY bundled DESC,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.ThemeRecord
	for rows.Next() {
		var t ports.ThemeRecord
		rows.Scan(&t.ID, &t.Name, &t.Category, &t.Bundled, &t.Active, &t.Data) // contract: partial rows are kept
		out = append(out, t)
	}
	return out, nil
}

func (r themeRepo) List(ctx context.Context) ([]ports.ThemeRecord, error) { return r.list(ctx, ``) }

func (r themeRepo) ListActive(ctx context.Context) ([]ports.ThemeRecord, error) {
	return r.list(ctx, `WHERE active=1`)
}

func (r themeRepo) Create(ctx context.Context, name, data string) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO themes(name,data) VALUES(?,?)`, name, data)
	return err
}

func (r themeRepo) UpdateCustom(ctx context.Context, id int64, name, data string) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE themes SET name=?, data=? WHERE id=? AND bundled=0`, name, data, id))
}

func (r themeRepo) DeleteCustomInactive(ctx context.Context, id int64) (int64, error) {
	return changed(r.q.ExecContext(ctx, `DELETE FROM themes WHERE id=? AND bundled=0 AND active=0`, id))
}

func (r themeRepo) DeactivateAll(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `UPDATE themes SET active=0`)
	return err
}

func (r themeRepo) Activate(ctx context.Context, id int64) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE themes SET active=1 WHERE id=?`, id))
}

// ---------- stats ----------

type statsRepo struct{ q pq }

func (r statsRepo) n(ctx context.Context, query string, args ...any) (int64, error) {
	var n int64
	err := r.q.scan(ctx, query, args, &n)
	return n, err
}

func (r statsRepo) CountLocalUsers(ctx context.Context) (int64, error) {
	return r.n(ctx, `SELECT COUNT(*) FROM users WHERE is_guest=0`)
}
func (r statsRepo) CountShares(ctx context.Context) (int64, error) {
	return r.n(ctx, `SELECT COUNT(*) FROM shares`)
}
func (r statsRepo) CountActiveShares(ctx context.Context, now time.Time) (int64, error) {
	return r.n(ctx, `SELECT COUNT(*) FROM shares WHERE status='active' AND (expires_at IS NULL OR expires_at>?)`, now)
}
func (r statsRepo) CountFiles(ctx context.Context) (int64, error) {
	return r.n(ctx, `SELECT COUNT(*) FROM files`)
}
func (r statsRepo) SumFileBytes(ctx context.Context) (int64, error) {
	return r.n(ctx, `SELECT COALESCE(SUM(size),0)::bigint FROM files`)
}
func (r statsRepo) CountDownloads(ctx context.Context) (int64, error) {
	return r.n(ctx, `SELECT COUNT(*) FROM downloads`)
}

// DownloadsPerDay groups by the UTC calendar day (SQLite's date() of the
// stored time, which it normalises to UTC).
func (r statsRepo) DownloadsPerDay(ctx context.Context, since time.Time) ([]ports.DayCount, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD'),COUNT(*) FROM downloads WHERE created_at > ? GROUP BY 1 ORDER BY 1`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.DayCount
	for rows.Next() {
		var d ports.DayCount
		rows.Scan(&d.Day, &d.Count) // contract: partial rows are kept
		out = append(out, d)
	}
	return out, nil
}

// ---------- maintenance ----------

type maintenanceRepo struct {
	q     pq
	codec ports.ColumnCodec
}

// utcText is the SQL of a "YYYY-MM-DD HH:MM:SS" UTC text parameter as a
// timestamptz (the maintenance cut-offs the port passes as text).
const utcText = `(?::timestamp AT TIME ZONE 'UTC')`

func (r maintenanceRepo) ExpireShares(ctx context.Context, now time.Time) (int64, error) {
	return changed(r.q.ExecContext(ctx, `UPDATE shares SET status='expired' WHERE status='active' AND ((expires_at IS NOT NULL AND expires_at<?) OR (download_limit IS NOT NULL AND download_count>=download_limit))`, now))
}

func (r maintenanceRepo) SharesToWarn(ctx context.Context, before time.Time) ([]ports.ExpiringShare, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT s.id,s.name,s.long_id,s.expires_at,u.email,u.id FROM shares s JOIN users u ON u.id=s.user_id
			WHERE s.status='active' AND s.expiry_warned=0 AND u.email<>'' AND s.expires_at IS NOT NULL AND s.expires_at<?`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.ExpiringShare
	for rows.Next() {
		var x ports.ExpiringShare
		var ownerID int64
		rows.Scan(&x.ID, &x.Name, &x.LongID, &x.ExpiresAt, &x.OwnerEmail, &ownerID) // contract: partial rows are kept
		if x.LongID, err = openCol(r.codec, "shares", "long_id", x.ID, x.LongID); err != nil {
			return nil, err
		}
		if x.OwnerEmail, err = openCol(r.codec, "users", "email", ownerID, x.OwnerEmail); err != nil {
			return nil, err
		}
		if x.Name, err = openCol(r.codec, "shares", "name", x.ID, x.Name); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, nil
}

func (r maintenanceRepo) MarkExpiryWarned(ctx context.Context, shareID int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE shares SET expiry_warned=1 WHERE id=?`, shareID)
	return err
}

func (r maintenanceRepo) RetiredShareIDs(ctx context.Context, before time.Time) ([]int64, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id FROM shares WHERE status<>'active' AND COALESCE(expires_at,created_at)<?`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		out = append(out, id)
	}
	return out, nil
}

func (r maintenanceRepo) StaleUploadIDs(ctx context.Context, before string) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id FROM upload_sessions WHERE created_at<`+utcText, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		out = append(out, id)
	}
	return out, nil
}

func (r maintenanceRepo) CountStaleUpload(ctx context.Context, id, before string) (int, error) {
	var n int
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM upload_sessions WHERE id=? AND created_at<`+utcText, []any{id, before}, &n)
	return n, err
}

func (r maintenanceRepo) PruneExpiredCredentials(ctx context.Context, now time.Time) {
	r.q.ExecContext(ctx, `DELETE FROM revoked_access_tokens WHERE expires_at<?`, now)
	r.q.ExecContext(ctx, `DELETE FROM verification_attempts WHERE expires_at<?`, now)
	r.q.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at<?`, now)
	r.q.ExecContext(ctx, `DELETE FROM refresh_spent WHERE expires_at<?`, now)
	r.q.ExecContext(ctx, `DELETE FROM password_resets WHERE expires_at<?`, now)
	r.q.ExecContext(ctx, `DELETE FROM email_verifications WHERE expires_at<?`, now)
	r.q.ExecContext(ctx, `DELETE FROM mfa_reset_requests WHERE expires_at<? OR used=1`, now)
}

func (r maintenanceRepo) PruneDownloads(ctx context.Context, before string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM downloads WHERE created_at<`+utcText, before)
	return err
}

func (r maintenanceRepo) removed(ctx context.Context, query string, args ...any) ([]ports.RemovedAccount, error) {
	rows, err := r.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.RemovedAccount
	for rows.Next() {
		var a ports.RemovedAccount
		if rows.Scan(&a.ID, &a.Username) == nil {
			var err error
			if a.Username, err = openCol(r.codec, "users", "username", a.ID, a.Username); err != nil {
				return nil, err
			}
			out = append(out, a)
		}
	}
	return out, classify(rows.Err())
}

func (r maintenanceRepo) RemoveUnverifiedRegistrations(ctx context.Context, before string) ([]ports.RemovedAccount, error) {
	return r.removed(ctx, `DELETE FROM users WHERE pending_registration=1 AND email_verified=0 AND is_guest=0 AND created_at<`+utcText+`
		AND password_hash<>''
		AND NOT EXISTS(SELECT 1 FROM user_auth_providers WHERE user_auth_providers.user_id=users.id)
		AND NOT EXISTS(SELECT 1 FROM shares WHERE shares.user_id=users.id)
		AND NOT EXISTS(SELECT 1 FROM upload_sessions WHERE upload_sessions.user_id=users.id OR upload_sessions.quota_owner_id=users.id)
		RETURNING id,username`, before)
}

func (r maintenanceRepo) RemoveExpiredLinkGuests(ctx context.Context, now time.Time) ([]ports.RemovedAccount, error) {
	return r.removed(ctx, `DELETE FROM users WHERE is_guest=1
		AND id IN (SELECT guest_user_id FROM reverse_invites WHERE parent_id IS NOT NULL AND completed_at IS NULL AND expires_at<?)
		AND NOT EXISTS(SELECT 1 FROM upload_sessions WHERE upload_sessions.user_id=users.id)
		RETURNING id,username`, now)
}

func (r maintenanceRepo) RemoveOrphanedLinkInvites(ctx context.Context, now time.Time) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM reverse_invites WHERE parent_id IS NOT NULL AND completed_at IS NULL AND expires_at<?
		AND guest_user_id NOT IN (SELECT id FROM users)`, now)
	return err
}

// ---------- personal data export and erasure ----------

// exportEncrypted lists, per export section, the table and the encrypted
// columns the section selects (the section's rows carry the row id as "id").
var exportEncrypted = map[ports.ExportSection]struct {
	table   string
	columns []string
}{
	ports.ExportShares:  {"shares", []string{"name", "description"}},
	ports.ExportInvites: {"reverse_invites", []string{"recipient_name", "recipient_email", "message"}},
}

type personalDataRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r personalDataRepo) Terms(ctx context.Context, userID int64) (string, *time.Time, error) {
	var version string
	var at sql.NullTime
	err := r.q.scan(ctx, `SELECT terms_accepted_version, terms_accepted_at FROM users WHERE id=?`, []any{userID}, &version, &at)
	return version, nullTime(at), err
}

func (r personalDataRepo) TOTPCreated(ctx context.Context, userID int64) (*time.Time, error) {
	var created sql.NullTime
	if err := r.q.scan(ctx, `SELECT created_at FROM user_totp WHERE user_id=? AND confirmed=1`, []any{userID}, &created); err != nil {
		return nil, err
	}
	return nullTime(created), nil
}

// Section: every exported column has the database type the SQLite export
// produces (integers for counts and 0/1 flags, text, times), so the JSON is
// the same in every flavour.
func (r personalDataRepo) Section(ctx context.Context, s ports.ExportSection, userID int64, limit int) []map[string]any {
	var query string
	var keys []string
	switch s {
	case ports.ExportLinkedLogins:
		query, keys = `SELECT p.name, p.type, up.provider_user_id FROM user_auth_providers up JOIN auth_providers p ON p.id=up.provider_id WHERE up.user_id=?`,
			[]string{"provider", "type", "provider_user_id"}
	case ports.ExportShares:
		query, keys = `SELECT s.id, s.name, s.description, s.status, s.public, (s.password_hash<>'')::int, s.download_limit, s.download_count, s.expires_at, s.created_at,
		(SELECT COUNT(*) FROM files f WHERE f.share_id=s.id), (SELECT COALESCE(SUM(size),0)::bigint FROM files f WHERE f.share_id=s.id)
		FROM shares s WHERE s.user_id=? ORDER BY s.id`,
			[]string{"id", "name", "description", "status", "public", "password_protected", "download_limit", "download_count", "expires_at", "created_at", "file_count", "total_bytes"}
	case ports.ExportShareFiles:
		query, keys = `SELECT f.share_id, f.full_path, f.size, f.type, f.id FROM files f JOIN shares s ON s.id=f.share_id WHERE s.user_id=? ORDER BY f.share_id, f.id`,
			[]string{"share_id", "path", "size", "type", "file_id"}
	case ports.ExportDownloadHistory:
		query, keys = `SELECT d.share_id, COALESCE(f.name,''), d.created_at, COALESCE(f.id,0) FROM downloads d JOIN shares s ON s.id=d.share_id
		LEFT JOIN files f ON f.id=d.file_id WHERE s.user_id=? ORDER BY d.id`, []string{"share_id", "file", "started_at", "file_id"}
	case ports.ExportInvites:
		query, keys = `SELECT id, recipient_name, recipient_email, message, expires_at, used, completed_at, created_at FROM reverse_invites WHERE user_id=? ORDER BY id`,
			[]string{"id", "recipient_name", "recipient_email", "message", "expires_at", "used", "completed_at", "created_at"}
	case ports.ExportSessions:
		query, keys = `SELECT session_started, issued_at, expires_at FROM refresh_tokens WHERE user_id=? ORDER BY issued_at`,
			[]string{"signed_in_at", "last_refreshed_at", "expires_at"}
	case ports.ExportAuditRecords:
		query, keys = `SELECT seq, ts, category, actor_role, action, target, outcome, detail, ip FROM audit_log WHERE actor_id=? ORDER BY seq LIMIT `+strconv.Itoa(limit),
			[]string{"seq", "time_utc", "category", "role", "action", "target", "outcome", "details", "ip"}
	default:
		return []map[string]any{}
	}
	rows := r.exportRows(ctx, query, keys, userID)
	if s == ports.ExportShareFiles {
		for _, row := range rows {
			// the path is sealed, bound to the files row
			fid, _ := row["file_id"].(int64)
			delete(row, "file_id")
			if d, ok := row["path"].(string); ok && r.codec != nil {
				if v, err := openCol(r.codec, "files", "full_path", fid, d); err == nil {
					row["path"] = v
				} else {
					row["path"] = ""
				}
			}
		}
	}
	if s == ports.ExportDownloadHistory {
		for _, row := range rows {
			// the file name is a column of the files row, not of the download
			fid, _ := row["file_id"].(int64)
			delete(row, "file_id")
			if d, ok := row["file"].(string); ok && r.codec != nil && fid != 0 {
				if v, err := openCol(r.codec, "files", "name", fid, d); err == nil {
					row["file"] = v
				} else {
					row["file"] = ""
				}
			}
		}
	}
	if s == ports.ExportAuditRecords && r.codec != nil {
		// The audit columns are sealed and bound to the record's sequence number.
		for _, row := range rows {
			seq, _ := row["seq"].(int64)
			for _, c := range [][2]string{{"target", "target"}, {"details", "detail"}} {
				d, ok := row[c[0]].(string)
				if !ok {
					continue
				}
				if v, err := openCol(r.codec, "audit_log", c[1], seq, d); err == nil {
					row[c[0]] = v
				} else {
					row[c[0]] = ""
				}
			}
		}
	}
	if cols := exportEncrypted[s]; r.codec != nil && cols.table != "" {
		// The export shows the stored values in the clear: open them.
		for _, row := range rows {
			id, _ := row["id"].(int64)
			for _, col := range cols.columns {
				d, ok := row[col].(string)
				if !ok {
					continue
				}
				if v, err := openCol(r.codec, cols.table, col, id, d); err == nil {
					row[col] = v
				} else {
					row[col] = ""
				}
			}
		}
	}
	return rows
}

// exportRows runs a query and returns its rows as objects with the given keys.
// Byte values become strings; times are RFC 3339 (UTC).
func (r personalDataRepo) exportRows(ctx context.Context, query string, keys []string, args ...any) []map[string]any {
	out := []map[string]any{}
	rows, err := r.q.QueryContext(ctx, query, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		vals := make([]any, len(keys))
		ptrs := make([]any, len(keys))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if rows.Scan(ptrs...) != nil {
			continue
		}
		m := make(map[string]any, len(keys))
		for i, k := range keys {
			switch v := vals[i].(type) {
			case []byte:
				m[k] = string(v)
			case time.Time:
				m[k] = v.UTC().Format(time.RFC3339)
			default:
				m[k] = v
			}
		}
		out = append(out, m)
	}
	return out
}

func (r userRepo) ErasedAt(ctx context.Context, id int64) (*time.Time, error) {
	var erased sql.NullTime
	if err := r.q.scan(ctx, `SELECT erased_at FROM users WHERE id=?`, []any{id}, &erased); err != nil {
		return nil, err
	}
	return nullTime(erased), nil
}

func (r userRepo) IsAdmin(ctx context.Context, id int64) (bool, error) {
	var admin bool
	err := r.q.scan(ctx, `SELECT admin FROM users WHERE id=?`, []any{id}, &admin)
	return admin, err
}

func (r userRepo) CountOtherUnerasedAdmins(ctx context.Context, id int64) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM users WHERE admin=1 AND is_guest=0 AND erased_at IS NULL AND id<>?`, id)
}

func (r userRepo) LockForErasure(ctx context.Context, id int64) (int64, error) {
	return lockRows(ctx, r.q, `SELECT 1 FROM users WHERE id=? AND is_guest=0 AND erased_at IS NULL FOR UPDATE`, id)
}

func (r userRepo) EraseWithOwnedData(ctx context.Context, id int64) error {
	const sharesOf = `SELECT id FROM shares WHERE user_id=? OR user_id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=?) OR invite_id IN (SELECT id FROM reverse_invites WHERE user_id=?)`
	for _, q := range []string{
		`DELETE FROM download_mail_outbox WHERE share_id IN (` + sharesOf + `)`,
		`DELETE FROM upload_sessions WHERE user_id=? OR quota_owner_id=? OR user_id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=?)`,
		`DELETE FROM shares WHERE user_id=? OR user_id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=?) OR invite_id IN (SELECT id FROM reverse_invites WHERE user_id=?)`,
		`DELETE FROM users WHERE is_guest=1 AND id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=?)`,
		`DELETE FROM reverse_invites WHERE user_id=?`,
		`DELETE FROM refresh_tokens WHERE user_id=?`,
		`DELETE FROM refresh_spent WHERE user_id=?`,
		`DELETE FROM password_resets WHERE user_id=?`,
		`DELETE FROM email_verifications WHERE user_id=?`,
		`DELETE FROM verification_attempts WHERE user_id=?`,
		`DELETE FROM mfa_reset_requests WHERE user_id=?`,
		`DELETE FROM user_totp WHERE user_id=?`,
		`DELETE FROM user_recovery_codes WHERE user_id=?`,
		`DELETE FROM user_webauthn WHERE user_id=?`,
		`DELETE FROM user_auth_providers WHERE user_id=?`,
		`DELETE FROM user_signin_seen WHERE user_id=?`,
		`DELETE FROM password_history WHERE user_id=?`,
	} {
		args := make([]any, strings.Count(q, "?"))
		for i := range args {
			args[i] = id
		}
		if _, err := r.q.ExecContext(ctx, q, args...); err != nil {
			return err
		}
	}
	// The account stays as a tombstone: a unique placeholder name, nothing else.
	erased := "erased-" + strconv.FormatInt(id, 10)
	sealed, err := sealCol(r.codec, "users", "username", id, erased)
	if err != nil {
		return err
	}
	bi, err := blindIdx(r.codec, "users", "username", erased)
	if err != nil {
		return err
	}
	_, err = r.q.ExecContext(ctx, `UPDATE users SET username=?, username_bi=?::bytea, name='', email='', email_bi=NULL, password_hash='', email_verified=0, must_change_password=0,
			admin=0, is_auditor=0, pending_registration=0, login_failures=0, login_locked_until=0, mfa_epoch=mfa_epoch+1,
			terms_accepted_version='', terms_accepted_at=NULL, password_changed_at=NULL, password_expiry_warned_at=NULL,
			password_rotation_exempt=0, erased_at=date_trunc('second', now()) WHERE id=?`, sealed, bi, id)
	return err
}

func (r passwordResetRepo) Identity(ctx context.Context, hash string, now time.Time) (string, string, error) {
	var uid int64
	var name, email string
	if err := r.q.scan(ctx, `SELECT u.id, u.username, u.email FROM password_resets p JOIN users u ON u.id=p.user_id WHERE p.hash=? AND p.expires_at>?`, []any{hash, now}, &uid, &name, &email); err != nil {
		return "", "", err
	}
	var err error
	if name, err = openCol(r.codec, "users", "username", uid, name); err != nil {
		return "", "", err
	}
	email, err = openCol(r.codec, "users", "email", uid, email)
	return name, email, err
}

// CopyTo is SQLite-only (unencrypted test fixtures, VACUUM INTO).
func (r systemRepo) CopyTo(ctx context.Context, path string) error {
	return fmt.Errorf("%w: CopyTo (a SQLite fixture copy) on PostgreSQL", ports.ErrUnsupported)
}
