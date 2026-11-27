// SPDX-License-Identifier: AGPL-3.0-or-later

package platform

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// Admin is a platform administrator. Platform administrators are separate
// from every tenant's users: they sign in only on the console host and have no
// access to tenant data.
type Admin struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	TOTPEnabled  bool   `json:"totp_enabled"`
	CreatedAt    string `json:"created_at"`
	PasswordHash string `json:"-"`
	TOTPSecret   string `json:"-"`
	PendingTOTP  string `json:"-"`
	LastCounter  int64  `json:"-"`
	Failures     int    `json:"-"`
	LockedUntil  int64  `json:"-"`
	// MustChangePassword is set by the offline reset (sendora-db
	// platform-admin-reset): the temporary password only allows choosing a new one.
	MustChangePassword bool `json:"must_change_password"`
}

// adminResult maps a repository lookup to the package's result (as in 0.2,
// a read error other than "not found" comes with what was read).
func adminResult(r ports.PlatformAdmin, err error) (*Admin, error) {
	if errors.Is(err, ports.ErrNotFound) {
		return nil, ErrNotFound
	}
	return adminFrom(r), err
}

func adminFrom(r ports.PlatformAdmin) *Admin {
	return &Admin{ID: r.ID, Username: r.Username, Email: r.Email, TOTPEnabled: r.TOTPEnabled, CreatedAt: r.CreatedAt,
		PasswordHash: r.PasswordHash, TOTPSecret: r.TOTPSecret, PendingTOTP: r.PendingTOTP, LastCounter: r.LastCounter,
		Failures: r.Failures, LockedUntil: r.LockedUntil, MustChangePassword: r.MustChangePassword}
}

// AdminCount is the number of platform administrators.
func (p *Platform) AdminCount() int {
	n, _ := p.repo.PlatformAdmins().Count(context.Background())
	return n
}

// AdminByName looks an administrator up by username (case-insensitive).
func (p *Platform) AdminByName(name string) (*Admin, error) {
	return adminResult(p.repo.PlatformAdmins().ByName(context.Background(), strings.TrimSpace(name)))
}

// AdminByID looks an administrator up by ID.
func (p *Platform) AdminByID(id int64) (*Admin, error) {
	return adminResult(p.repo.PlatformAdmins().ByID(context.Background(), id))
}

// Admins lists all administrators.
func (p *Platform) Admins() ([]*Admin, error) {
	list, err := p.repo.PlatformAdmins().List(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]*Admin, 0, len(list))
	for _, a := range list {
		out = append(out, adminFrom(a))
	}
	return out, nil
}

// ErrAdminExists is returned for a duplicate username.
var ErrAdminExists = errors.New("this username is already in use")

// CreateAdmin inserts an administrator with a bcrypt hash computed by the caller.
func (p *Platform) CreateAdmin(username, email, hash string) (*Admin, error) {
	id, err := p.repo.PlatformAdmins().Create(context.Background(), username, email, hash, now())
	if err != nil {
		return nil, ErrAdminExists
	}
	return p.AdminByID(id)
}

// CreateFirstAdmin inserts the first administrator only while there is none
// (atomic, so two concurrent setup requests cannot both succeed).
func (p *Platform) CreateFirstAdmin(username, email, hash string) (*Admin, error) {
	id, created, err := p.repo.PlatformAdmins().CreateFirst(context.Background(), username, email, hash, now())
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, errors.New("already set up")
	}
	return p.AdminByID(id)
}

// DeleteAdmin removes an administrator (and their sessions); the last one
// cannot be removed.
func (p *Platform) DeleteAdmin(id int64) error {
	n, err := p.repo.PlatformAdmins().DeleteUnlessLast(context.Background(), id)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("the last platform administrator cannot be removed")
	}
	return nil
}

// SetPassword replaces an administrator's password hash (clearing a pending
// must-change mark) and ends their sessions.
func (p *Platform) SetPassword(id int64, hash string) error {
	ctx := context.Background()
	if err := p.repo.PlatformAdmins().SetPassword(ctx, id, hash); err != nil {
		return err
	}
	return p.repo.PlatformSessions().DeleteForAdmin(ctx, id)
}

// SetTemporaryPassword stores a temporary password that must be changed at
// the next sign-in, unlocks the account and ends the administrator's sessions
// (offline recovery).
func (p *Platform) SetTemporaryPassword(id int64, hash string) error {
	ctx := context.Background()
	if err := p.repo.PlatformAdmins().SetTemporaryPassword(ctx, id, hash); err != nil {
		return err
	}
	return p.repo.PlatformSessions().DeleteForAdmin(ctx, id)
}

// EndSessionsWithoutMFA ends the sessions of administrators without an
// authenticator (when platform_mfa_required is switched on).
func (p *Platform) EndSessionsWithoutMFA() error {
	return p.repo.PlatformSessions().DeleteWithoutTOTP(context.Background())
}

// NoteLoginFailure counts a failed sign-in and locks the account for a while
// after repeated failures.
func (p *Platform) NoteLoginFailure(id int64, limit int, lock time.Duration) {
	p.repo.PlatformAdmins().NoteLoginFailure(context.Background(), id, limit, time.Now().Add(lock).Unix())
}

// NoteLoginSuccess clears the failure counter.
func (p *Platform) NoteLoginSuccess(id int64) {
	p.repo.PlatformAdmins().ClearLoginFailures(context.Background(), id)
}

// SetPendingTOTP stores a TOTP secret awaiting confirmation.
func (p *Platform) SetPendingTOTP(id int64, secret string) error {
	return p.repo.PlatformAdmins().SetPendingTOTP(context.Background(), id, secret)
}

// EnableTOTP promotes the pending secret after a correct code.
func (p *Platform) EnableTOTP(id int64, counter int64) error {
	return p.repo.PlatformAdmins().EnableTOTP(context.Background(), id, counter)
}

// UseTOTPCounter records a used TOTP time step; it fails for a step that is
// not newer than the last one used (no replay of a code).
func (p *Platform) UseTOTPCounter(id, counter int64) bool {
	n, err := p.repo.PlatformAdmins().UseTOTPCounter(context.Background(), id, counter)
	if err != nil {
		return false
	}
	return n == 1
}

// ResetTOTP removes an administrator's TOTP (another administrator's action);
// they must enroll again at the next sign-in.
func (p *Platform) ResetTOTP(id int64) error {
	ctx := context.Background()
	if err := p.repo.PlatformAdmins().ResetTOTP(ctx, id); err != nil {
		return err
	}
	return p.repo.PlatformSessions().DeleteForAdmin(ctx, id)
}

// ---------- sessions ----------

// Session is a console session (opaque random token in a host-only cookie).
type Session struct {
	AdminID   int64
	Stage     string // mfa (password ok, TOTP due), enroll (must set up TOTP), full
	CreatedAt int64
	MFAAt     int64
}

// CreateSession stores a session by the hash of its token.
func (p *Platform) CreateSession(hash string, adminID int64, stage string, ttl time.Duration) error {
	n := time.Now().Unix()
	return p.repo.PlatformSessions().Create(context.Background(), ports.PlatformSession{Hash: hash, AdminID: adminID, Stage: stage,
		CreatedAt: n, LastSeen: n, ExpiresAt: time.Now().Add(ttl).Unix(), MFAAt: map[bool]int64{true: n, false: 0}[stage == "full"]})
}

// SessionFor returns a live session and slides its idle timeout.
func (p *Platform) SessionFor(hash string, idle time.Duration) (*Session, error) {
	ctx := context.Background()
	row, err := p.repo.PlatformSessions().Get(ctx, hash)
	if err != nil {
		return nil, ErrNotFound
	}
	s := &Session{AdminID: row.AdminID, Stage: row.Stage, CreatedAt: row.CreatedAt, MFAAt: row.MFAAt}
	lastSeen, expires := row.LastSeen, row.ExpiresAt
	n := time.Now()
	if n.Unix() > expires || n.Sub(time.Unix(lastSeen, 0)) > idle {
		p.repo.PlatformSessions().Delete(ctx, hash)
		return nil, ErrNotFound
	}
	if n.Unix()-lastSeen > 30 {
		p.repo.PlatformSessions().Touch(ctx, hash, n.Unix())
	}
	return s, nil
}

// PromoteSession moves a session to the full stage after MFA.
func (p *Platform) PromoteSession(hash string) error {
	return p.repo.PlatformSessions().Promote(context.Background(), hash, time.Now().Unix())
}

// TouchMFA records a fresh second-factor confirmation (step-up).
func (p *Platform) TouchMFA(hash string) {
	p.repo.PlatformSessions().SetMFAAt(context.Background(), hash, time.Now().Unix())
}

// DeleteSession ends one session.
func (p *Platform) DeleteSession(hash string) {
	p.repo.PlatformSessions().Delete(context.Background(), hash)
}

// PruneSessions removes expired sessions.
func (p *Platform) PruneSessions() {
	p.repo.PlatformSessions().PruneExpired(context.Background(), time.Now().Unix())
}

// ---------- audit ----------

// Audit appends one record to the platform audit log (tamper-evident chain,
// same format and verification as a tenant's audit log).
func (p *Platform) Audit(actorID int64, actorName, action, target, outcome, detail, ip string) error {
	if outcome == "" {
		outcome = "ok"
	}
	cat := "platform"
	switch {
	case strings.HasPrefix(action, "login") || strings.HasPrefix(action, "logout") || strings.HasPrefix(action, "mfa_"):
		cat = "auth"
	case strings.HasPrefix(action, "system_"):
		cat = "system"
	}
	role := "platform_admin"
	if actorID == 0 {
		role = "system"
		if actorName == "" {
			actorName = "system"
		}
	}
	_, err := p.St.AuditAppend(store.AuditRecord{Category: cat, ActorID: actorID, ActorName: actorName, ActorRole: role,
		Action: action, Target: target, Outcome: outcome, Detail: detail, IP: ip})
	return err
}

// AuditPage returns platform audit records, newest first.
func (p *Platform) AuditPage(before int64, limit int) ([]store.AuditRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return p.repo.PlatformAudit().Page(context.Background(), before, limit)
}
