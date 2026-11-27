// SPDX-License-Identifier: AGPL-3.0-or-later

import { tr } from './i18n/mark.mjs'
// Pure helpers for the database import form. The server remains authoritative.
export const HEX_KEY = /^[0-9a-fA-F]{64}$/

// Returns an error key (English i18n text) or '' when acceptable.
export function keyProblem({ mode, hex, file }) {
  if (mode === 'hex') return HEX_KEY.test((hex || '').trim()) ? '' : tr('The key must be 64 hexadecimal characters.')
  if (mode === 'file') return file && file.size === 32 ? '' : tr('The key file must be exactly 32 bytes.')
  return ''
}

// Builds the multipart body; key parts must precede the database file.
export function importForm({ mode, hex, keyFile, file }) {
  const fd = new FormData()
  if (mode === 'hex') fd.append('key_hex', hex.trim())
  else if (mode === 'file') fd.append('key_file', keyFile, 'database.key')
  fd.append('file', file, file.name)
  return fd
}

// After apply the server restarts itself; resolve when it answers /api/health again.
export async function waitForRestart(fetchFn = fetch, sleep = ms => new Promise(r => setTimeout(r, ms)), { timeoutMs = 120000, intervalMs = 1500 } = {}) {
  const started = Date.now()
  let sawDown = false, okAfter = 0
  await sleep(intervalMs)
  while (Date.now() - started < timeoutMs) {
    let ok = false
    try { ok = (await fetchFn('/api/health', { cache: 'no-store' })).ok } catch { ok = false }
    if (!ok) { sawDown = true; okAfter = 0 } else if (sawDown || Date.now() - started > 15000) { if (++okAfter >= 2) return true }
    await sleep(intervalMs)
  }
  return false
}
