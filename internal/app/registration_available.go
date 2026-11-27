// SPDX-License-Identifier: AGPL-3.0-or-later

package app

// registrationAvailable reports whether public registration can actually work:
// it is switched on, local sign-in is allowed and outgoing mail (needed for the
// verification code) is configured. The UI only offers "Create account" then.
func (s *Server) registrationAvailable() bool {
	return s.St.SettingBool("allow_self_registration") && s.localLoginEnabled() && s.smtpConfigured() == nil
}
