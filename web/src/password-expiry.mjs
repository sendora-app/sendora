// SPDX-License-Identifier: AGPL-3.0-or-later

// Password maximum age: when to show the "your password expires soon" banner.
// The server sends password_expires_in_days with /api/users/me only when the
// maximum age applies to the account.

export const EXPIRY_BANNER_DAYS = 14

// Local date as YYYY-MM-DD: a dismissal lasts for the rest of that day.
export function localDay(now = new Date()) {
  const p = n => String(n).padStart(2, '0')
  return `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`
}

export const expiryDismissKey = id => `sendora.pwexpiry.dismissed.${id}`

// days: password_expires_in_days (undefined/null when the policy does not apply).
// A forced change (must_change_password) has its own flow, so no banner then.
export function shouldShowExpiryBanner({ days, mustChange = false, dismissedDay = '', today = localDay() } = {}) {
  if (mustChange || days === undefined || days === null || !Number.isFinite(Number(days))) return false
  if (Number(days) > EXPIRY_BANNER_DAYS) return false
  return dismissedDay !== today
}
