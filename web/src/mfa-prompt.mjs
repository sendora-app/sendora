// SPDX-License-Identifier: AGPL-3.0-or-later

// When to remind a signed-in user that two-step verification is not set up.
// Only accounts that sign in with a local password are asked (accounts that use an
// external identity provider rely on that provider's own protection), and only when
// there is a method to enrol with and the policy is not "off" (which disables two-step
// verification entirely). Accounts that already have a factor and guests are never asked
// (auditors can enrol their own factor and are asked too), and neither is an account that
// is already being sent to the profile page to enrol because the policy requires it or
// that still has to replace its password first.
export function shouldPromptMFA({ user, hasPassword, boot, dismissed }) {
  if (!user || dismissed) return false
  if (user.is_guest) return false
  if (!hasPassword) return false
  if (user.mfa_enabled || user.mfa_enroll_required || user.must_change_password) return false
  if (!boot || boot.mfa_policy === 'off') return false
  return !!(boot.mfa_totp_enabled || boot.mfa_webauthn_enabled)
}

export const DAY_MS = 86400000

// A dismissed reminder stays away for `days` days (setting mfa_reminder_days, default 1).
// With 0 days it only stays away for the rest of the browser session.
export function reminderSuppressed({ days, dismissedAt, sessionDismissed, now = Date.now() }) {
  if (!(days > 0)) return !!sessionDismissed
  return Number(dismissedAt) > 0 && now - Number(dismissedAt) < days * DAY_MS
}

export const mfaPromptKey = userId => 'sendora.mfaPrompt.' + userId
