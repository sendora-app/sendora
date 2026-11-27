// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// userCols is the column list behind ports.UserRecord (scanUserRecord).
const userCols = `id,username,name,email,admin,must_change_password,is_guest,is_auditor,email_verified,created_at,password_hash,language,ui_language,quota_bytes,login_failures,login_locked_until,quota_inherits_default,(SELECT value FROM settings WHERE key='default_storage_quota_bytes'),mfa_policy,mfa_epoch,disabled_at IS NOT NULL,disabled_reason,password_changed_at,password_rotation_exempt`

// openUser opens the encrypted columns of a scanned user row (name, username,
// email, password hash), each bound to the row's id.
func openUser(c ports.ColumnCodec, u ports.UserRecord) (ports.UserRecord, error) {
	var err error
	if u.Name, err = openCol(c, "users", "name", u.ID, u.Name); err != nil {
		return u, err
	}
	if u.Username, err = openCol(c, "users", "username", u.ID, u.Username); err != nil {
		return u, err
	}
	if u.Email, err = openCol(c, "users", "email", u.ID, u.Email); err != nil {
		return u, err
	}
	if u.PasswordHash, err = openCol(c, "users", "password_hash", u.ID, u.PasswordHash); err != nil {
		return u, err
	}
	if u.DefaultQuota != nil {
		v, err := openColKey(c, "settings", "value", "default_storage_quota_bytes", *u.DefaultQuota)
		if err != nil {
			return u, err
		}
		u.DefaultQuota = &v
	}
	return u, nil
}

func (r userRepo) scanUser(row interface{ Scan(...any) error }) (ports.UserRecord, error) {
	u, err := scanUserRecord(row)
	if err != nil {
		return u, err
	}
	return openUser(r.codec, u)
}

// userIdent is the identity of an account as an INSERT stores it. With a codec the
// encrypted values are bound to the row id, which only exists after the
// insert: the row starts with the hex of the username's blind index (a unique
// placeholder for the NOT NULL UNIQUE column), an empty email, name and
// password hash, and sealIdent writes the sealed values next. The blind
// indexes are final from the start, so uniqueness holds throughout.
type userIdent struct {
	username, name, email, hash string // as given
	storedUsername, storedName  string // for the INSERT
	storedEmail, storedHash     string
	usernameBI, emailBI         any
}

func (r userRepo) ident(username, name, email, hash string) (userIdent, error) {
	i := userIdent{username: username, name: name, email: email, hash: hash,
		storedUsername: username, storedName: name, storedEmail: email, storedHash: hash}
	var err error
	if i.usernameBI, err = blindIdx(r.codec, "users", "username", username); err != nil {
		return i, err
	}
	if i.emailBI, err = blindIdx(r.codec, "users", "email", email); err != nil {
		return i, err
	}
	if r.codec != nil {
		i.storedName, i.storedEmail, i.storedHash = "", "", ""
		if b, ok := i.usernameBI.([]byte); ok {
			i.storedUsername = hex.EncodeToString(b)
		}
	}
	return i, nil
}

// sealIdent writes the sealed identity of the row an INSERT just created.
func (r userRepo) sealIdent(ctx context.Context, id int64, i userIdent) error {
	if r.codec == nil {
		return nil
	}
	var v [4]string
	for n, c := range []struct{ col, val string }{{"username", i.username}, {"name", i.name}, {"email", i.email}, {"password_hash", i.hash}} {
		var err error
		if v[n], err = sealCol(r.codec, "users", c.col, id, c.val); err != nil {
			return err
		}
	}
	_, err := r.q.ExecContext(ctx, `UPDATE users SET username=?,name=?,email=?,password_hash=? WHERE id=?`, v[0], v[1], v[2], v[3], id)
	return err
}

// creds is the credential state of an account as the guards compare it: the
// plaintext values and the stored (sealed) ones. A compare-and-swap UPDATE
// binds the stored values, so a concurrent change of either column (a fresh
// seal, even of the same value) makes the swap fail instead of overwriting it.
type creds struct {
	hash, email             string
	storedHash, storedEmail string
	mustChange              bool
}

// readCreds reads id's credential columns; found is false for an unknown id.
func readCreds(ctx context.Context, q querier, c ports.ColumnCodec, id int64) (cr creds, found bool, err error) {
	err = q.QueryRowContext(ctx, `SELECT password_hash,email,must_change_password FROM users WHERE id=?`, id).Scan(&cr.storedHash, &cr.storedEmail, &cr.mustChange)
	if errors.Is(err, sql.ErrNoRows) {
		return cr, false, nil
	}
	if err != nil {
		return cr, false, err
	}
	if cr.hash, err = openCol(c, "users", "password_hash", id, cr.storedHash); err != nil {
		return cr, false, err
	}
	if cr.email, err = openCol(c, "users", "email", id, cr.storedEmail); err != nil {
		return cr, false, err
	}
	return cr, true, nil
}

// guard is readCreds checked against g: ok is false when the account is gone or
// its credentials differ from what the caller read.
func (r userRepo) guard(ctx context.Context, id int64, g ports.CredentialGuard) (creds, bool, error) {
	cr, found, err := readCreds(ctx, r.q, r.codec, id)
	if err != nil || !found {
		return cr, false, err
	}
	return cr, cr.hash == g.PasswordHash && cr.email == g.Email && cr.mustChange == g.MustChangePassword, nil
}

// hashGuard is guard for the callers that compare the password hash alone: it
// returns the stored hash to bind, ok false when the current hash is not want.
func (r userRepo) hashGuard(ctx context.Context, id int64, want string) (string, bool, error) {
	cr, found, err := readCreds(ctx, r.q, r.codec, id)
	if err != nil || !found {
		return "", false, err
	}
	return cr.storedHash, cr.hash == want, nil
}

func scanUserRecord(row interface{ Scan(...any) error }) (ports.UserRecord, error) {
	var u ports.UserRecord
	var quota, inheritance, defaultQuota sql.NullString
	var changed sql.NullTime
	err := row.Scan(&u.ID, &u.Username, &u.Name, &u.Email, &u.Admin, &u.MustChangePassword, &u.IsGuest, &u.Auditor, &u.EmailVerified, &u.CreatedAt, &u.PasswordHash, &u.Language, &u.UILanguage, &quota, &u.LoginFailures, &u.LoginLockedUntil, &inheritance, &defaultQuota, &u.MFAPolicy, &u.MFAEpoch, &u.Disabled, &u.DisabledReason, &changed, &u.PasswordRotationExempt)
	if err != nil {
		return ports.UserRecord{}, notFound(err)
	}
	u.QuotaBytes, u.QuotaInheritsDefault, u.DefaultQuota = nullString(quota), nullString(inheritance), nullString(defaultQuota)
	u.PasswordChangedAt = nullTime(changed)
	return u, nil
}

type userRepo struct {
	q     querier
	codec ports.ColumnCodec
}

func (r userRepo) one(ctx context.Context, query string, args ...any) (ports.UserRecord, error) {
	return r.scanUser(r.q.QueryRowContext(ctx, query, args...))
}

func (r userRepo) ByID(ctx context.Context, id int64) (ports.UserRecord, error) {
	return r.one(ctx, `SELECT `+userCols+` FROM users WHERE id=?`, id)
}

func (r userRepo) FindLocalByUsername(ctx context.Context, username string) (ports.UserRecord, error) {
	bi, err := blindKey(r.codec, "users", "username", username)
	if err != nil {
		return ports.UserRecord{}, err
	}
	return r.one(ctx, `SELECT `+userCols+` FROM users WHERE username_bi=? AND is_guest=0`, bi)
}

// byEmail finds the one account whose address is email (the blind index is
// unique, so a match is the only one).
func (r userRepo) byEmail(ctx context.Context, email, where string) (ports.UserRecord, error) {
	bi, err := blindKey(r.codec, "users", "email", email)
	if err != nil {
		return ports.UserRecord{}, err
	}
	return r.one(ctx, `SELECT `+userCols+` FROM users WHERE email_bi=? AND is_guest=0`+where, bi)
}

func (r userRepo) FindLocalByUniqueEmail(ctx context.Context, email string) (ports.UserRecord, error) {
	return r.byEmail(ctx, email, ``)
}

func (r userRepo) FindVerifiedByUniqueEmail(ctx context.Context, email string) (ports.UserRecord, error) {
	return r.byEmail(ctx, email, ` AND email<>'' AND email_verified=1`)
}

func (r userRepo) FindUnverifiedByUniqueEmail(ctx context.Context, email string) (ports.UserRecord, error) {
	return r.byEmail(ctx, email, ` AND email_verified=0`)
}

func (r userRepo) ListLocal(ctx context.Context) ([]ports.UserRecord, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+userCols+` FROM users WHERE is_guest=0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.UserRecord
	for rows.Next() {
		u, err := r.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (r userRepo) ListPasswordExpiryCandidates(ctx context.Context) ([]ports.UserRecord, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+userCols+` FROM users WHERE is_guest=0 AND password_hash<>'' AND password_rotation_exempt=0
		AND must_change_password=0 AND disabled_at IS NULL AND email_verified=1 AND email<>'' AND password_expiry_warned_at IS NULL
		AND password_changed_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.UserRecord
	for rows.Next() {
		if u, err := r.scanUser(rows); err == nil {
			out = append(out, u)
		}
	}
	return out, nil // contract: like the 0.2 loop, an iteration error ends the list without failing it
}

func (r userRepo) count(ctx context.Context, query string, args ...any) (int, error) {
	var n int
	err := r.q.QueryRowContext(ctx, query, args...).Scan(&n)
	return n, err
}

func (r userRepo) Count(ctx context.Context) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM users`)
}

func (r userRepo) CountByUsernameFold(ctx context.Context, username string) (int, error) {
	bi, err := blindKey(r.codec, "users", "username", username)
	if err != nil {
		return 0, err
	}
	return r.count(ctx, `SELECT COUNT(*) FROM users WHERE username_bi=?`, bi)
}

func (r userRepo) CountOtherWithEmail(ctx context.Context, email string, except int64) (int, error) {
	bi, err := blindKey(r.codec, "users", "email", email)
	if err != nil {
		return 0, err
	}
	return r.count(ctx, `SELECT COUNT(*) FROM users WHERE email_bi=? AND id<>?`, bi, except)
}

func (r userRepo) CreateProvisionedAdmin(ctx context.Context, username, email, passwordHash string, passwordChangedAt time.Time) (int64, error) {
	i, err := r.ident(username, username, email, passwordHash)
	if err != nil {
		return 0, err
	}
	res, err := r.q.ExecContext(ctx, `INSERT INTO users(username,name,email,password_hash,username_bi,email_bi,admin,email_verified,language,ui_language,password_changed_at) VALUES(?,?,?,?,?,?,1,0,'en','en',?)`,
		i.storedUsername, i.storedName, i.storedEmail, i.storedHash, i.usernameBI, i.emailBI, passwordChangedAt)
	if err != nil {
		return 0, userInsertErr(err)
	}
	id, _ := res.LastInsertId() // contract of the 0.2 caller: the id error was ignored
	return id, r.sealIdent(ctx, id, i)
}

func (r userRepo) Username(ctx context.Context, id int64) (string, error) {
	var name string
	err := r.q.QueryRowContext(ctx, `SELECT username FROM users WHERE id=?`, id).Scan(&name)
	if err != nil {
		return "", notFound(err)
	}
	return openCol(r.codec, "users", "username", id, name)
}

func (r userRepo) PasswordHash(ctx context.Context, id int64) (string, error) {
	var h string
	err := r.q.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=?`, id).Scan(&h)
	if err != nil {
		return "", notFound(err)
	}
	return openCol(r.codec, "users", "password_hash", id, h)
}

func (r userRepo) IsGuest(ctx context.Context, id int64) (bool, error) {
	var guest bool
	err := r.q.QueryRowContext(ctx, `SELECT is_guest FROM users WHERE id=?`, id).Scan(&guest)
	return guest, notFound(err)
}

func (r userRepo) CreateFirstAdmin(ctx context.Context, u ports.NewUser) (int64, bool, error) {
	i, err := r.ident(u.Username, u.Name, u.Email, u.PasswordHash)
	if err != nil {
		return 0, false, err
	}
	res, err := r.q.ExecContext(ctx, `INSERT INTO users(username,name,email,password_hash,username_bi,email_bi,admin,language,ui_language,password_changed_at)
		SELECT ?,?,?,?,?,?,1,?,?,? WHERE NOT EXISTS (SELECT 1 FROM users)`, i.storedUsername, i.storedName, i.storedEmail, i.storedHash, i.usernameBI, i.emailBI, u.Language, u.UILanguage, u.PasswordChangedAt)
	if err != nil {
		return 0, false, userInsertErr(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, false, nil
	}
	id, _ := res.LastInsertId()
	return id, true, r.sealIdent(ctx, id, i)
}

func (r userRepo) CreateRegistered(ctx context.Context, u ports.NewUser) (int64, error) {
	i, err := r.ident(u.Username, u.Name, u.Email, u.PasswordHash)
	if err != nil {
		return 0, err
	}
	res, err := r.q.ExecContext(ctx, `INSERT INTO users(username,name,email,password_hash,username_bi,email_bi,email_verified,language,ui_language,pending_registration,password_changed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		i.storedUsername, i.storedName, i.storedEmail, i.storedHash, i.usernameBI, i.emailBI, u.EmailVerified, u.Language, u.UILanguage, u.PendingRegistration, u.PasswordChangedAt)
	if err != nil {
		return 0, userInsertErr(err)
	}
	id, _ := res.LastInsertId()
	return id, r.sealIdent(ctx, id, i)
}

func (r userRepo) Create(ctx context.Context, u ports.NewUser) (int64, error) {
	i, err := r.ident(u.Username, u.Name, u.Email, u.PasswordHash)
	if err != nil {
		return 0, err
	}
	q := `INSERT INTO users(username,name,email,password_hash,username_bi,email_bi,admin,must_change_password,language,ui_language,password_changed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`
	args := []any{i.storedUsername, i.storedName, i.storedEmail, i.storedHash, i.usernameBI, i.emailBI, u.Admin, u.MustChangePassword, u.Language, u.UILanguage, u.PasswordChangedAt}
	if u.QuotaBytes != nil {
		q = `INSERT INTO users(username,name,email,password_hash,username_bi,email_bi,admin,must_change_password,language,ui_language,password_changed_at,quota_bytes,quota_inherits_default) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0)`
		args = append(args, *u.QuotaBytes)
	}
	res, err := r.q.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, userInsertErr(err)
	}
	id, _ := res.LastInsertId()
	return id, r.sealIdent(ctx, id, i)
}

func (r userRepo) Delete(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

func (r userRepo) SetAuditorIfNotAdmin(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET is_auditor=1 WHERE id=? AND admin=0`, id)
	return err
}

func (r userRepo) SetAuditor(ctx context.Context, id int64, auditor bool) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET is_auditor=? WHERE id=?`, auditor, id)
	return err
}

func (r userRepo) RecordLoginAttempt(ctx context.Context, id int64, failures, lockedUntil int64, g ports.CredentialGuard) (int64, error) {
	cr, ok, err := r.guard(ctx, id, g)
	if err != nil || !ok {
		return 0, err
	}
	return affected(r.q.ExecContext(ctx, `UPDATE users SET login_failures=?,login_locked_until=? WHERE id=? AND password_hash=? AND email=? AND must_change_password=? AND is_guest=0`, failures, lockedUntil, id, cr.storedHash, cr.storedEmail, g.MustChangePassword))
}

func (r userRepo) ClearLoginLock(ctx context.Context, id int64) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE users SET login_failures=0,login_locked_until=0 WHERE id=? AND is_guest=0`, id))
}

func (r userRepo) RecordLastLogin(ctx context.Context, id int64, at time.Time) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET last_login_at=? WHERE id=?`, at, id)
	return err
}

func (r userRepo) ReplacePasswordHash(ctx context.Context, id int64, newHash, oldHash string) (int64, error) {
	stored, ok, err := r.hashGuard(ctx, id, oldHash)
	if err != nil || !ok {
		return 0, err
	}
	sealed, err := sealCol(r.codec, "users", "password_hash", id, newHash)
	if err != nil {
		return 0, err
	}
	return affected(r.q.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=? AND password_hash=?`, sealed, id, stored))
}

func (r userRepo) SetPasswordAfterReset(ctx context.Context, id int64, hash string, at time.Time) (int64, error) {
	sealed, err := sealCol(r.codec, "users", "password_hash", id, hash)
	if err != nil {
		return 0, err
	}
	return affected(r.q.ExecContext(ctx, `UPDATE users SET password_hash=?, must_change_password=0, login_failures=0, login_locked_until=0, password_changed_at=?, password_expiry_warned_at=NULL WHERE id=? AND is_guest=0`, sealed, at, id))
}

func (r userRepo) MarkEmailVerified(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE users SET email_verified=1,pending_registration=0 WHERE id=? AND is_guest=0 AND email<>''`, id)
	return err
}

func (r userRepo) VerifyEmailWithCode(ctx context.Context, id int64, email, code string, now time.Time) (int64, error) {
	bi, err := blindKey(r.codec, "users", "email", email)
	if err != nil {
		return 0, err
	}
	return affected(r.q.ExecContext(ctx, `UPDATE users SET email_verified=1,pending_registration=0 WHERE id=? AND email_bi=? AND email_verified=0 AND EXISTS(SELECT 1 FROM email_verifications WHERE user_id=? AND code=? AND expires_at>?)`, id, bi, id, code, now))
}

func (r userRepo) UpdateProfile(ctx context.Context, id int64, p ports.ProfileUpdate, g ports.CredentialGuard) (int64, error) {
	cr, ok, err := r.guard(ctx, id, g)
	if err != nil || !ok {
		return 0, err
	}
	name, err := sealCol(r.codec, "users", "name", id, p.Name)
	if err != nil {
		return 0, err
	}
	email, err := sealCol(r.codec, "users", "email", id, p.Email)
	if err != nil {
		return 0, err
	}
	hash, err := sealCol(r.codec, "users", "password_hash", id, p.PasswordHash)
	if err != nil {
		return 0, err
	}
	bi, err := blindIdx(r.codec, "users", "email", p.Email)
	if err != nil {
		return 0, err
	}
	n, err := affected(r.q.ExecContext(ctx, `UPDATE users SET name=?,email=?,email_bi=?,email_verified=?,password_hash=?,must_change_password=?,language=?,ui_language=COALESCE(?,ui_language),login_failures=CASE WHEN ? THEN 0 ELSE login_failures END,login_locked_until=CASE WHEN ? THEN 0 ELSE login_locked_until END,password_changed_at=CASE WHEN ? THEN ? ELSE password_changed_at END,password_expiry_warned_at=CASE WHEN ? THEN NULL ELSE password_expiry_warned_at END WHERE id=? AND password_hash=? AND email=? AND must_change_password=?`,
		name, email, bi, p.EmailVerified, hash, p.MustChangePassword, p.Language, p.UILanguage, p.PasswordChanged, p.PasswordChanged, p.PasswordChanged, p.ChangedAt, p.PasswordChanged, id, cr.storedHash, cr.storedEmail, g.MustChangePassword))
	return n, userInsertErr(err)
}

func (r userRepo) AdminUpdate(ctx context.Context, id int64, a ports.AdminUserUpdate, g ports.CredentialGuard) (int64, error) {
	cr, ok, err := r.guard(ctx, id, g)
	if err != nil || !ok {
		return 0, err
	}
	name, err := sealCol(r.codec, "users", "name", id, a.Name)
	if err != nil {
		return 0, err
	}
	email, err := sealCol(r.codec, "users", "email", id, a.Email)
	if err != nil {
		return 0, err
	}
	hash, err := sealCol(r.codec, "users", "password_hash", id, a.PasswordHash)
	if err != nil {
		return 0, err
	}
	bi, err := blindIdx(r.codec, "users", "email", a.Email)
	if err != nil {
		return 0, err
	}
	n, err := affected(r.q.ExecContext(ctx, `UPDATE users SET name=?,email=?,email_bi=?,admin=?,password_hash=?,quota_bytes=COALESCE(?,quota_bytes),quota_inherits_default=COALESCE(?,quota_inherits_default),mfa_policy=COALESCE(?,mfa_policy),password_rotation_exempt=COALESCE(?,password_rotation_exempt),login_failures=CASE WHEN ? THEN 0 ELSE login_failures END,login_locked_until=CASE WHEN ? THEN 0 ELSE login_locked_until END,email_verified=CASE WHEN ? THEN 0 ELSE email_verified END,password_changed_at=CASE WHEN ? THEN ? ELSE password_changed_at END,password_expiry_warned_at=CASE WHEN ? THEN NULL ELSE password_expiry_warned_at END WHERE id=? AND is_guest=0 AND password_hash=? AND email=? AND must_change_password=?`,
		name, email, bi, a.Admin, hash, a.QuotaBytes, a.QuotaInheritsDefault, a.MFAPolicy, a.RotationExempt, a.PasswordChanged, a.PasswordChanged, a.EmailUnverified, a.PasswordChanged, a.ChangedAt, a.PasswordChanged, id, cr.storedHash, cr.storedEmail, g.MustChangePassword))
	return n, userInsertErr(err)
}

func (r userRepo) ForcePasswordChange(ctx context.Context, id int64) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE users SET must_change_password=1 WHERE id=? AND is_guest=0`, id))
}

func (r userRepo) FlagPasswordExpired(ctx context.Context, id int64, hash string) (int64, error) {
	stored, ok, err := r.hashGuard(ctx, id, hash)
	if err != nil || !ok {
		return 0, err
	}
	return affected(r.q.ExecContext(ctx, `UPDATE users SET must_change_password=1 WHERE id=? AND password_hash=? AND must_change_password=0 AND is_guest=0`, id, stored))
}

func (r userRepo) MarkPasswordExpiryWarned(ctx context.Context, id int64, hash string, at time.Time) (int64, error) {
	stored, ok, err := r.hashGuard(ctx, id, hash)
	if err != nil || !ok {
		return 0, err
	}
	return affected(r.q.ExecContext(ctx, `UPDATE users SET password_expiry_warned_at=? WHERE id=? AND password_hash=? AND password_expiry_warned_at IS NULL`, at, id, stored))
}

func (r userRepo) LockForDelete(ctx context.Context, id int64) (int64, error) {
	return affected(r.q.ExecContext(ctx, `UPDATE users SET id=id WHERE id=? AND is_guest=0`, id))
}

func (r userRepo) strings(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r userRepo) OwnedUploadIDs(ctx context.Context, id int64) ([]string, error) {
	return r.strings(ctx, `SELECT id FROM upload_sessions WHERE user_id=? OR quota_owner_id=? OR user_id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=?)`, id, id, id)
}

func (r userRepo) OwnedShareLongIDs(ctx context.Context, id int64) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id,long_id FROM shares WHERE user_id=? OR user_id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=?) OR invite_id IN (SELECT id FROM reverse_invites WHERE user_id=?)`, id, id, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sid int64
		var lid string
		if err := rows.Scan(&sid, &lid); err != nil {
			return nil, err
		}
		if lid, err = openCol(r.codec, "shares", "long_id", sid, lid); err != nil {
			return nil, err
		}
		out = append(out, lid)
	}
	return out, rows.Err()
}

func (r userRepo) DeleteWithOwnedData(ctx context.Context, id int64) error {
	for _, st := range []struct {
		q    string
		args []any
	}{
		{`DELETE FROM upload_sessions WHERE user_id=? OR quota_owner_id=? OR user_id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=?)`, []any{id, id, id}},
		{`DELETE FROM shares WHERE user_id=? OR user_id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=?) OR invite_id IN (SELECT id FROM reverse_invites WHERE user_id=?)`, []any{id, id, id}},
		{`DELETE FROM users WHERE is_guest=1 AND id IN (SELECT guest_user_id FROM reverse_invites WHERE user_id=?)`, []any{id}},
		{`DELETE FROM users WHERE id=?`, []any{id}},
	} {
		if _, err := r.q.ExecContext(ctx, st.q, st.args...); err != nil {
			return err
		}
	}
	return nil
}

func (r userRepo) CreateGuest(ctx context.Context, username, name string) (int64, error) {
	i, err := r.ident(username, name, "", "")
	if err != nil {
		return 0, err
	}
	res, err := r.q.ExecContext(ctx, `INSERT INTO users(username,name,username_bi,is_guest) VALUES(?,?,?,1)`, i.storedUsername, i.storedName, i.usernameBI)
	if err != nil {
		return 0, userInsertErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, r.sealIdent(ctx, id, i)
}

func (r userRepo) GuestByID(ctx context.Context, id int64) (ports.UserRecord, error) {
	return r.one(ctx, `SELECT `+userCols+` FROM users WHERE id=? AND is_guest=1`, id)
}
