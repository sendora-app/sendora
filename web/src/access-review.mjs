// SPDX-License-Identifier: AGPL-3.0-or-later

// Pure helpers for the access-review page and the session list.
import { tr } from './i18n/mark.mjs'

// Case-insensitive match on the identifying columns; every word must match.
export function filterReview(users, query) {
  const words = String(query || '').toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return users || []
  return (users || []).filter(u => {
    const hay = [u.username, u.name, u.email, u.role, u.source, u.created_by].join(' ').toLowerCase()
    return words.every(w => hay.includes(w))
  })
}

// "totp; webauthn:2; recovery_codes:8" -> { totp: true, webauthn: 2, recovery: 8 }
export function parseFactors(text) {
  const out = { totp: false, webauthn: 0, recovery: 0 }
  for (const part of String(text || '').split(';').map(s => s.trim()).filter(Boolean)) {
    const [name, n] = part.split(':')
    if (name === 'totp') out.totp = true
    else if (name === 'webauthn') out.webauthn = Number(n) || 0
    else if (name === 'recovery_codes') out.recovery = Number(n) || 0
  }
  return out
}

// Status labels of an account in the review, most important first.
export function accountStatus(u) {
  const s = []
  if (u?.disabled) s.push(tr('Disabled'))
  if (u?.login_locked) s.push(tr('Locked'))
  if (!s.length) s.push(tr('Active'))
  return s
}

// A short description of a browser's user agent, e.g. "Firefox, Windows".
// Unknown agents fall back to the (already trimmed) text itself.
export function describeAgent(ua) {
  const v = String(ua || '')
  if (!v) return ''
  const browser = /Edg\//.test(v) ? 'Edge' : /OPR\/|Opera/.test(v) ? 'Opera' : /Firefox\//.test(v) ? 'Firefox'
    : /Chrome\//.test(v) ? 'Chrome' : /Safari\//.test(v) ? 'Safari' : ''
  const os = /iPhone|iPad|iPod/.test(v) ? 'iOS' : /Android/.test(v) ? 'Android' : /Windows/.test(v) ? 'Windows'
    : /Mac OS X|Macintosh/.test(v) ? 'macOS' : /CrOS/.test(v) ? 'ChromeOS' : /Linux/.test(v) ? 'Linux' : ''
  if (browser && os) return browser + ', ' + os
  return browser || os || (v.length > 60 ? v.slice(0, 60) + '…' : v)
}
