// SPDX-License-Identifier: AGPL-3.0-or-later

import { tr } from './i18n/mark.mjs'
// Mirrors the server-side share password policy for immediate feedback only;
// the server remains authoritative.
const isOn = value => value === true || value === 'true'

export function sharePolicy(boot = {}) {
  const min = Number.parseInt(boot?.share_password_min_length, 10)
  return {
    required: isOn(boot?.require_share_password),
    min: Number.isInteger(min) && min >= 1 && min <= 72 ? min : 8,
    upper: isOn(boot?.share_password_require_upper),
    lower: isOn(boot?.share_password_require_lower),
    digit: isOn(boot?.share_password_require_digit),
    symbol: isOn(boot?.share_password_require_symbol),
  }
}

// Account (local login) password policy: same shape, but a password is always required.
export function accountPolicy(boot = {}) {
  const min = Number.parseInt(boot?.account_password_min_length, 10)
  return {
    required: true,
    min: Number.isInteger(min) && min >= 1 && min <= 72 ? min : 8,
    upper: isOn(boot?.account_password_require_upper),
    lower: isOn(boot?.account_password_require_lower),
    digit: isOn(boot?.account_password_require_digit),
    symbol: isOn(boot?.account_password_require_symbol),
    account: true,
  }
}

// Returns [{key, n?}] with English i18n keys; an empty list means acceptable.
export function passwordProblems(password, policy) {
  const value = typeof password === 'string' ? password : ''
  if (value === '') return policy.required ? [{ key: policy.account ? tr('A password is required') : tr('A share password is required') }] : []
  const problems = []
  if (new TextEncoder().encode(value).length > 72) problems.push({ key: tr('Password must not exceed 72 bytes') })
  if (Array.from(value).length < policy.min) problems.push({ key: tr('At least {n} characters'), n: policy.min })
  if (policy.upper && !/\p{Lu}/u.test(value)) problems.push({ key: tr('An uppercase letter') })
  if (policy.lower && !/\p{Ll}/u.test(value)) problems.push({ key: tr('A lowercase letter') })
  if (policy.digit && !/\p{Nd}/u.test(value)) problems.push({ key: tr('A digit') })
  if (policy.symbol && !/[\p{P}\p{S}\s]/u.test(value)) problems.push({ key: tr('A symbol') })
  return problems
}
