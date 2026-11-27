// SPDX-License-Identifier: AGPL-3.0-or-later

import { tr } from './i18n/mark.mjs'
const GB = 1_000_000_000n
const MAX_BYTES = BigInt(Number.MAX_SAFE_INTEGER)
const INVALID = tr('Enter a valid quota in GB (up to 9 decimal places).')

function validBytes(value) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error(INVALID)
  if (!/^[0-9]+$/.test(String(value))) throw new Error(INVALID)
  const bytes = BigInt(value)
  if (bytes > MAX_BYTES) throw new Error(INVALID)
  return bytes
}

// Text input is intentional: numeric v-model would round before conversion.
// Accept a decimal comma as well as a point, but never exponent notation.
export function gbToBytes(value) {
  if (typeof value !== 'string' || value.length > 64) throw new Error(INVALID)
  const match = /^([0-9]+)(?:[.,]([0-9]{1,9}))?$/.exec(value.trim())
  if (!match) throw new Error(INVALID)
  const bytes = BigInt(match[1]) * GB + BigInt((match[2] || '').padEnd(9, '0'))
  if (bytes > MAX_BYTES) throw new Error(INVALID)
  return Number(bytes)
}

export function bytesToGB(value) {
  const bytes = validBytes(value)
  const fraction = (bytes % GB).toString().padStart(9, '0').replace(/0+$/, '')
  return (bytes / GB).toString() + (fraction ? '.' + fraction : '')
}

export function fmtGB(value) { return bytesToGB(value) + ' GB' }

// Never submit an inherited effective limit as a personal override.
export function quotaPayload(inherits, gb) {
  if (inherits === true) return { quota_inherits_default: true }
  if (inherits === false) return { quota_inherits_default: false, quota_bytes: gbToBytes(gb) }
  throw new Error(INVALID)
}

// Display only: decimal GB rounded to at most two decimals, always with a
// decimal point (international notation). Never use for editing or saving;
// editors use bytesToGB (exact).
export function fmtGBShort(value) {
  const bytes = validBytes(value)
  if (bytes === 0n) return '0 GB'
  const hundredths = (bytes + 5_000_000n) / 10_000_000n
  if (hundredths === 0n) return '<0.01 GB'
  const whole = (hundredths / 100n).toString()
  const fraction = (hundredths % 100n).toString().padStart(2, '0').replace(/0+$/, '')
  return whole + (fraction ? '.' + fraction : '') + ' GB'
}
