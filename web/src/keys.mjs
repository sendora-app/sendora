// SPDX-License-Identifier: AGPL-3.0-or-later

import { tr } from './i18n/mark.mjs'

// Pure logic of the Admin → Keys screen (unit tested): the tenant key (KEK)
// format, which buttons are enabled, and the progress of a running key job.
// Key material only ever passes through these functions as arguments; nothing
// here stores or logs it.

export const KEK_BYTES = 32

// Purposes the tenant cannot rotate (audit records stay MACed under the key
// they were written with). Listed read-only.
export const FIXED_PURPOSES = ['audit-mac']

export const bytesToBase64 = bytes => {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

// generateKek returns 32 random bytes as base64 (44 characters). random is
// crypto.getRandomValues-compatible; the byte buffer is wiped before returning.
// The server refuses degenerate keys (few distinct bytes, a counting
// sequence); a random key hits that with negligible probability, but retry
// anyway so a refused key never reaches the screen.
export function generateKek(random = c => crypto.getRandomValues(c)) {
  for (let i = 0; i < 8; i++) {
    const buf = new Uint8Array(KEK_BYTES)
    random(buf)
    const weak = kekWeak(buf)
    const out = weak ? '' : bytesToBase64(buf)
    buf.fill(0)
    if (out) return out
  }
  throw new Error('no random key could be generated')
}

function decodeBase64(text) {
  const s = String(text).trim()
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return null
  const std = s.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '')
  if (std.length % 4 === 1) return null
  try {
    const bin = atob(std + '='.repeat((4 - (std.length % 4)) % 4))
    return Uint8Array.from(bin, ch => ch.charCodeAt(0))
  } catch { return null }
}

// kekWeak mirrors the server's strength check (store.checkKEKStrength).
export function kekWeak(raw) {
  if (new Set(raw).size < 12) return true
  let asc = true, desc = true
  for (let i = 1; i < raw.length; i++) {
    if (raw[i] !== ((raw[i - 1] + 1) & 255)) asc = false
    if (raw[i] !== ((raw[i - 1] - 1) & 255)) desc = false
  }
  return asc || desc
}

// kekProblem returns the English message key of what is wrong with a typed or
// pasted key, or '' when it is valid (base64 of exactly 32 bytes, not weak).
export function kekProblem(text) {
  if (!String(text || '').trim()) return tr('Enter the key.')
  const raw = decodeBase64(text)
  if (!raw) return tr('The key must be base64 of 32 random bytes.')
  const n = raw.length
  const weak = n === KEK_BYTES && kekWeak(raw)
  raw.fill(0)
  if (n !== KEK_BYTES) return tr('The key must be exactly 32 bytes (44 base64 characters).')
  if (weak) return tr('The key is too weak: use the generated key.')
  return ''
}

// kekFileName is the download name of a generated key.
export const kekFileName = slug => `${String(slug || 'tenant').replace(/[^a-z0-9-]/gi, '') || 'tenant'}-sendora-tenant-key.txt`

// shortFingerprint shortens a hex fingerprint for display (first 8 characters).
export const shortFingerprint = fp => (fp ? String(fp).slice(0, 8) : '')

// jobOpen reports whether a pending/running key job exists for purpose.
export const jobOpen = (jobs, purpose) => (jobs || []).some(j => j.purpose === purpose && (j.status === 'pending' || j.status === 'running'))
export const anyJobOpen = jobs => (jobs || []).some(j => j.status === 'pending' || j.status === 'running')

// rowsOlder counts the values (and files) of a purpose that a job can still
// move to the active version. Audit-log values (audit_rows, purpose audit-enc)
// are never rewritten, so they are not counted: they only block a retirement.
export function rowsOlder(p) {
  let n = 0
  for (const v of p.versions || []) {
    if (v.version === p.active) continue
    n += Math.max(0, v.rows || 0) + Math.max(0, v.files || 0)
  }
  return n
}

// rotateAction says whether the Rotate button of a purpose is enabled; reason
// is an English message key when it is not.
export function rotateAction(p, jobs) {
  if (!p.rotatable) return { enabled: false, reason: tr('This key cannot be rotated.') }
  if (jobOpen(jobs, p.purpose)) return { enabled: false, reason: tr('A key operation for this purpose is still running.') }
  return { enabled: true, reason: '' }
}

// retireAction says whether a version can be retired. Mirrors the server's
// check: only a decrypt-only version, and (data, files) none of its values or
// files left; for audit-enc no audit record may be left (the audit log is
// never rewritten).
export function retireAction(p, v, jobs) {
  if (!p.rotatable) return { show: false, enabled: false, reason: '' }
  if (v.state !== 'decrypt_only') return { show: false, enabled: false, reason: '' }
  if (jobOpen(jobs, p.purpose)) return { show: true, enabled: false, reason: tr('A key operation for this purpose is still running.') }
  if (p.purpose === 'data') {
    if ((v.rows || 0) > 0) return { show: true, enabled: false, reason: tr('Values are still sealed under this version.') }
  }
  if (p.purpose === 'audit-enc' && (v.audit_rows || 0) > 0) return { show: true, enabled: false, reason: tr('The audit log still holds values sealed under this version; it is never rewritten.') }
  if (p.purpose === 'files') {
    if (v.files < 0) return { show: true, enabled: false, reason: tr('The number of files on this version is unknown.') }
    if ((v.files || 0) > 0) return { show: true, enabled: false, reason: tr('Files are still encrypted under this version.') }
  }
  return { show: true, enabled: true, reason: '' }
}

// legacyAction: the Convert legacy files button.
export const legacyAction = (status, jobs) => ({
  show: !!status && status.legacy_files > 0,
  enabled: !jobOpen(jobs, 'files'),
})

// activeVersion picks the active version record of a purpose (or null).
export const activeVersion = p => (p.versions || []).find(v => v.version === p.active) || null

// progress turns what is left now and the most that was left while the job ran
// (peak) into a whole percentage; null when nothing was pending.
export function progress(peak, remaining) {
  if (!(peak > 0)) return null
  const left = Math.min(Math.max(remaining, 0), peak)
  return Math.round(((peak - left) / peak) * 100)
}

// The open job that matters for a purpose (running before pending).
// lastFinished is the newest done or failed job of purpose (by update time),
// or null: the screen says when the last operation ended and how.
export function lastFinished(jobs, purpose) {
  const done = (jobs || []).filter(j => j.purpose === purpose && (j.status === 'done' || j.status === 'failed'))
  done.sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)))
  return done[0] || null
}

export function openJob(jobs, purpose) {
  const open = (jobs || []).filter(j => j.purpose === purpose && (j.status === 'pending' || j.status === 'running'))
  return open.find(j => j.status === 'running') || open[0] || null
}

// kekFormReady says whether the KEK form of mode ('upload' | 'replace' |
// 'release') may be submitted. upload needs the new key (kek), the "I stored
// it" tick and the typed slug; replace needs old and new (different) and the
// tick; release needs the current key (old).
export function kekFormReady(mode, f, slug) {
  const ok = v => !kekProblem(v)
  if (mode === 'upload') return ok(f.kek) && !!f.stored && String(f.confirm || '').trim() === slug && slug !== ''
  if (mode === 'replace') return ok(f.old) && ok(f.kek) && f.old.trim() !== f.kek.trim() && !!f.stored
  return ok(f.old)
}
