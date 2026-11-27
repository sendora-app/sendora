// SPDX-License-Identifier: AGPL-3.0-or-later

// Live feedback while choosing a password: a character counter and a
// checklist driven by the active policy (never hard-coded). The server stays
// authoritative and additionally screens common, personal and breached
// passwords, which cannot be checked here.
import { tr } from './i18n/mark.mjs'

const isOn = value => value === true || value === 'true'

// Platform administrators (console, conversion wizard): the platform rule as
// sent by the server ({ password_min_length }).
export function platformPolicy(src = {}) {
  const min = Number.parseInt(src?.password_min_length, 10)
  return { required: true, min: Number.isInteger(min) && min >= 1 && min <= 72 ? min : 12, upper: false, lower: false, digit: false, symbol: false, account: true }
}

// passwordChecklist returns the counter and one item per active rule.
// items: [{ key, n?, ok }] with English i18n keys; ok: every item is met.
export function passwordChecklist(password, policy) {
  const value = typeof password === 'string' ? password : ''
  const count = Array.from(value).length
  const bytes = new TextEncoder().encode(value).length
  const p = policy || { min: 8 }
  const items = [{ key: tr('At least {n} characters'), n: p.min, ok: count >= p.min }]
  if (isOn(p.upper)) items.push({ key: tr('An uppercase letter'), ok: /\p{Lu}/u.test(value) })
  if (isOn(p.lower)) items.push({ key: tr('A lowercase letter'), ok: /\p{Ll}/u.test(value) })
  if (isOn(p.digit)) items.push({ key: tr('A digit'), ok: /\p{Nd}/u.test(value) })
  if (isOn(p.symbol)) items.push({ key: tr('A symbol'), ok: /[\p{P}\p{S}\s]/u.test(value) })
  if (bytes > 72) items.push({ key: tr('Password must not exceed 72 bytes'), ok: false })
  return { count, min: p.min, items, ok: items.every(i => i.ok) }
}

// confirmState compares a confirmation field: '' (nothing typed yet),
// 'match' or 'mismatch'.
export function confirmState(password, confirm) {
  if (!confirm) return ''
  return password === confirm ? 'match' : 'mismatch'
}
