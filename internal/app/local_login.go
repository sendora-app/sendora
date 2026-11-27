// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

// atomicFlag lets tests and main set the env override without racing request handlers.
type atomicFlag = atomic.Bool

const (
	settingLocalLogin      = "local_login_enabled"
	msgLocalLoginDisabled  = "local login is disabled"
	msgLastExternalAdmin   = "local login is disabled: this would remove the last administrator who can sign in with an external provider"
	msgUnlinkLockout       = "local login is disabled: you need another linked, enabled external provider before unlinking this one"
	msgNeedEnabledProvider = "cannot disable local login: enable at least one external login provider first"
	msgNeedLinkedAdmin     = "cannot disable local login: link your own account to an enabled external provider first, so you cannot lock yourself out"
)

// SetForceLocalLogin applies the SENDORA_FORCE_LOCAL_LOGIN recovery override (read once by main).
func (s *Server) SetForceLocalLogin(v bool) { s.forceLocalLogin.Store(v) }

// LogLocalLoginState writes a startup warning when local login is forced or disabled.
func (s *Server) LogLocalLoginState() {
	stored := s.St.SettingBool(settingLocalLogin)
	switch {
	case s.forceLocalLogin.Load() && !stored:
		log.Printf("WARNING: SENDORA_FORCE_LOCAL_LOGIN=true overrides the disabled local_login_enabled setting; local login is active (the stored setting is unchanged)")
	case s.forceLocalLogin.Load():
		log.Printf("WARNING: SENDORA_FORCE_LOCAL_LOGIN=true is set; local login is active")
	case !stored:
		log.Printf("WARNING: local login is disabled; only external providers can sign in (set SENDORA_FORCE_LOCAL_LOGIN=true and restart to recover)")
	}
}

// localLoginEnabled is the effective state: the stored setting or the env override.
func (s *Server) localLoginEnabled() bool {
	return s.forceLocalLogin.Load() || s.St.SettingBool(settingLocalLogin)
}

// requireLocalLogin answers 403 and returns false while local login is disabled.
func (s *Server) requireLocalLogin(w http.ResponseWriter) bool {
	if s.localLoginEnabled() {
		return true
	}
	jerr(w, 403, msgLocalLoginDisabled)
	return false
}

// localLoginStoredOff reports the stored setting only; safety guards ignore the env override.
func (s *Server) localLoginStoredOff() bool {
	return !s.St.SettingBool(settingLocalLogin)
}

// localLoginSafe reports whether disabling local login cannot lock the acting admin out.
func (s *Server) localLoginSafe(adminID int64) (bool, string) {
	if providers, err := s.St.Repos().AuthProviders().CountEnabled(context.Background()); err != nil || providers < 1 {
		return false, msgNeedEnabledProvider
	}
	if linked, err := s.St.Repos().AuthProviders().CountEnabledLinksOfLocal(context.Background(), adminID); err != nil || linked < 1 {
		return false, msgNeedLinkedAdmin
	}
	return true, ""
}

// externalAdminCount counts non-guest admins linked to an enabled provider, ignoring the
// given user, provider or (user, provider) link (0 means no exclusion).
func (s *Server) externalAdminCount(exclUser, exclProvider, exclLinkUser, exclLinkProvider int64) int {
	n, _ := s.St.Repos().AuthProviders().CountExternalAdmins(context.Background(), exclUser, exclProvider, exclLinkUser, exclLinkProvider)
	return n
}

// refuseLastExternalAdmin answers 409 and returns true when local login is stored off and the
// action would take external admin access from >=1 to 0 administrators.
func (s *Server) refuseLastExternalAdmin(w http.ResponseWriter, exclUser, exclProvider int64) bool {
	if !s.localLoginStoredOff() {
		return false
	}
	if s.externalAdminCount(0, 0, 0, 0) > 0 && s.externalAdminCount(exclUser, exclProvider, 0, 0) == 0 {
		jerr(w, 409, msgLastExternalAdmin)
		return true
	}
	return false
}

// normalizeLocalLoginSetting validates the boolean setting value.
func normalizeLocalLoginSetting(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	return v, v == "true" || v == "false"
}
