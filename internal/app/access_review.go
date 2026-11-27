// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Access-review report (ISO 27001 A.5.18, SOC 2 CC6.2/CC6.3): every account
// except reverse-share guests, with its role, sign-in sources, second factors,
// lifecycle (created, role and email changes, last sign-in, disabled) and the
// number and size of its shares. Share names, links and contents are never
// part of it: administrators and auditors see counts only.

const accessReviewUnknown = "unknown"

type accessReviewRow struct {
	ID             int64  `json:"id"`
	Username       string `json:"username"`
	Name           string `json:"name"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	Source         string `json:"source"`
	MFAEnrolled    bool   `json:"mfa_enrolled"`
	MFAFactors     string `json:"mfa_factors"`
	MFAPolicy      string `json:"mfa_policy"`
	MFARequired    bool   `json:"mfa_required"`
	EmailVerified  bool   `json:"email_verified"`
	CreatedAt      string `json:"created_at"`
	CreatedBy      string `json:"created_by"`
	RoleChangedAt  string `json:"role_changed_at"`
	RoleChangedBy  string `json:"role_changed_by"`
	EmailChangedAt string `json:"email_changed_at"`
	EmailChangedBy string `json:"email_changed_by"`
	LastLoginAt    string `json:"last_login_at"`
	LoginLocked    bool   `json:"login_locked"`
	Disabled       bool   `json:"disabled"`
	DisabledAt     string `json:"disabled_at"`
	DisabledBy     string `json:"disabled_by"`
	DisabledReason string `json:"disabled_reason"`
	ShareCount     int64  `json:"share_count"`
	StorageUsed    int64  `json:"storage_used_bytes"`
	// Password age (local passwords only; empty for accounts without one or when
	// unknown), the per-account rotation exemption and when the password expires
	// under account_password_max_age_days (empty when the maximum age does not apply).
	PasswordAgeDays        string `json:"password_age_days"`
	PasswordRotationExempt bool   `json:"password_rotation_exempt"`
	PasswordExpiresAt      string `json:"password_expires_at"`
}

var accessReviewCSVHeader = []string{"id", "username", "name", "email", "role", "source", "mfa_enrolled", "mfa_factors", "mfa_policy", "mfa_required",
	"email_verified", "created_at", "created_by", "role_changed_at", "role_changed_by", "email_changed_at", "email_changed_by", "last_login_at",
	"login_locked", "disabled", "disabled_at", "disabled_by", "disabled_reason", "share_count", "storage_used_bytes",
	"password_age_days", "password_rotation_exempt", "password_expires_at"}

func (x accessReviewRow) csvRecord() []string {
	b := strconv.FormatBool
	return []string{strconv.FormatInt(x.ID, 10), csvSafe(x.Username), csvSafe(x.Name), csvSafe(x.Email), x.Role, csvSafe(x.Source), b(x.MFAEnrolled), x.MFAFactors, x.MFAPolicy, b(x.MFARequired),
		b(x.EmailVerified), x.CreatedAt, csvSafe(x.CreatedBy), x.RoleChangedAt, csvSafe(x.RoleChangedBy), x.EmailChangedAt, csvSafe(x.EmailChangedBy), x.LastLoginAt,
		b(x.LoginLocked), b(x.Disabled), x.DisabledAt, csvSafe(x.DisabledBy), csvSafe(x.DisabledReason), strconv.FormatInt(x.ShareCount, 10), strconv.FormatInt(x.StorageUsed, 10),
		x.PasswordAgeDays, b(x.PasswordRotationExempt), x.PasswordExpiresAt}
}

func reviewTime(t sql.NullTime, empty string) string {
	if !t.Valid {
		return empty
	}
	return t.Time.UTC().Format(time.RFC3339)
}

func orUnknown(v string) string {
	if strings.TrimSpace(v) == "" {
		return accessReviewUnknown
	}
	return v
}

// accessReviewRows builds the report. Each step reads with its own query so no
// rows stay open on the single database connection while the next one runs.
func (s *Server) accessReviewRows() ([]accessReviewRow, error) {
	type extra struct {
		created, roleAt, emailAt, lastLogin, disabledAt     sql.NullTime
		createdBy, roleBy, emailBy, disabledBy, disabledWhy string
	}
	recs, err := s.St.Repos().Users().ListForAccessReview(context.Background())
	if err != nil {
		return nil, err
	}
	var users []*User
	var extras []extra
	for _, rec := range recs {
		u, err := userFromRecord(rec.UserRecord, nil)
		if err != nil {
			return nil, err
		}
		x := extra{created: nullTimeOf(rec.Created), roleAt: nullTimeOf(rec.RoleChangedAt), emailAt: nullTimeOf(rec.EmailChangedAt), lastLogin: nullTimeOf(rec.LastLoginAt),
			disabledAt: nullTimeOf(rec.DisabledAt), createdBy: rec.CreatedBy, roleBy: rec.RoleChangedBy, emailBy: rec.EmailChangedBy, disabledBy: rec.DisabledBy, disabledWhy: rec.DisabledReason}
		users, extras = append(users, u), append(extras, x)
	}
	sources := map[int64][]string{}
	links, err := s.St.Repos().AuthProviders().ListLinkNames(context.Background())
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		sources[l.UserID] = append(sources[l.UserID], l.Type)
	}
	now := time.Now().Unix()
	out := make([]accessReviewRow, 0, len(users))
	for i, u := range users {
		x := extras[i]
		src := []string{}
		if u.passwordHash != "" {
			src = append(src, "local")
		}
		src = append(src, sources[u.ID]...)
		f := s.loadFactors(u.ID)
		var factors []string
		if f.TOTP {
			factors = append(factors, "totp")
		}
		if f.WebAuthn > 0 {
			factors = append(factors, "webauthn:"+strconv.Itoa(f.WebAuthn))
		}
		if f.Recovery > 0 {
			factors = append(factors, "recovery_codes:"+strconv.Itoa(f.Recovery))
		}
		shares, err := s.St.Repos().Shares().CountOwnedOrReceived(context.Background(), u.ID)
		if err != nil {
			return nil, err
		}
		usage, err := s.St.UserStorageUsage(u.ID)
		if err != nil {
			return nil, err
		}
		s.fillMFA(u)
		policy := u.MFAPolicy
		if policy == "" {
			policy = "inherit"
		}
		row := accessReviewRow{ID: u.ID, Username: u.Username, Name: u.Name, Email: u.Email, Role: roleOfUser(u), Source: strings.Join(src, "; "),
			MFAEnrolled: u.MFAEnabled, MFAFactors: strings.Join(factors, "; "), MFAPolicy: policy, MFARequired: u.MFARequired, EmailVerified: u.EmailVerified,
			CreatedAt: reviewTime(x.created, accessReviewUnknown), CreatedBy: orUnknown(x.createdBy),
			RoleChangedAt: reviewTime(x.roleAt, ""), RoleChangedBy: x.roleBy, EmailChangedAt: reviewTime(x.emailAt, ""), EmailChangedBy: x.emailBy,
			LastLoginAt: reviewTime(x.lastLogin, ""), LoginLocked: u.loginLockedUntil > now,
			Disabled: x.disabledAt.Valid, DisabledAt: reviewTime(x.disabledAt, ""), DisabledBy: x.disabledBy, DisabledReason: x.disabledWhy,
			ShareCount: shares, StorageUsed: usage.StoredBytes, PasswordRotationExempt: u.PasswordRotationExempt}
		if u.passwordHash != "" && u.passwordChangedAt.Valid {
			row.PasswordAgeDays = strconv.Itoa(max(int(time.Since(u.passwordChangedAt.Time).Hours()/24), 0))
		}
		if exp, ok := s.passwordExpiry(u); ok {
			row.PasswordExpiresAt = exp.UTC().Format(time.RFC3339)
		}
		out = append(out, row)
	}
	return out, nil
}

// accessReview: GET /api/access-review (administrators and auditors).
func (s *Server) accessReview(w http.ResponseWriter, r *http.Request) {
	rows, err := s.accessReviewRows()
	if err != nil {
		jerr(w, 500, "access review unavailable")
		return
	}
	jout(w, 200, map[string]any{"generated_at": time.Now().UTC().Format(time.RFC3339), "users": rows,
		"mfa_policy": s.mfaGlobal(), "provider_session_max_hours": s.providerSessionMaxHours()})
}

// accessReviewExport: GET /api/access-review/export?format=csv|jsonl. Like the
// audit export, it is recorded before anything is served; the critical
// middleware refuses it when the record cannot be written.
func (s *Server) accessReviewExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "jsonl" {
		jerr(w, 400, "format must be csv or jsonl")
		return
	}
	rows, err := s.accessReviewRows()
	if err != nil {
		jerr(w, 500, "access review unavailable")
		return
	}
	u := s.ctxUser(r)
	s.logEvent(u.ID, u.Username, "access_review_exported", "access_review", format+" "+strconv.Itoa(len(rows))+" accounts")
	h := w.Header()
	if format == "csv" {
		h.Set("Content-Type", "text/csv; charset=utf-8")
	} else {
		h.Set("Content-Type", "application/x-ndjson; charset=utf-8")
	}
	h.Set("Content-Disposition", `attachment; filename="sendora-access-review-`+time.Now().UTC().Format("20060102-150405")+`.`+format+`"`)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if format == "jsonl" {
		enc := json.NewEncoder(w)
		for _, x := range rows {
			if enc.Encode(x) != nil {
				return
			}
		}
		return
	}
	cw := csv.NewWriter(w)
	cw.Write(accessReviewCSVHeader)
	for _, x := range rows {
		cw.Write(x.csvRecord())
	}
	cw.Flush()
}
