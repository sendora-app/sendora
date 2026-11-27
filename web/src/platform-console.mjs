// SPDX-License-Identifier: AGPL-3.0-or-later

// Helpers of the platform console (multi-tenant mode, served only on admin.<base domain>).
// Kept free of Vue so they can be tested with node --test.
import { tr, translateMessage } from './i18n/mark.mjs'

// Same rules as the server (internal/platform.ValidSlug), for early feedback only.
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const RESERVED = new Set(['admin', 'www', 'api', 'app', 'mail', 'smtp', 'imap', 'pop', 'ftp', 'static', 'assets', 'cdn', 'platform', 'console', 'status',
  'root', 'sendora', 'ns1', 'ns2', 'autodiscover', 'autoconfig', 'localhost', 'default', 'system', 'support', 'help', 'docs', 'auth', 'login', 'sso'])

export function slugProblem(slug) {
  const s = String(slug || '').trim()
  if (!s) return tr('Enter a subdomain.')
  if (s.length < 2 || !SLUG.test(s) || s.includes('--')) return tr('Use 2–63 lowercase letters, digits and single hyphens.')
  if (RESERVED.has(s)) return tr('This subdomain is reserved.')
  return ''
}

export class ConsoleError extends Error {
  constructor(status, data) {
    super(translateMessage(data?.error || 'Request failed'))
    this.status = status
    this.data = data
  }
}

// pconsole calls the console API with the session cookie (same origin only).
export async function pconsole(path, { method = 'GET', body, fetchImpl = globalThis.fetch } = {}) {
  const opts = { method, credentials: 'same-origin', headers: {} }
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const r = await fetchImpl('/api/platform' + path, opts)
  const data = (r.headers.get('content-type') || '').includes('json') ? await r.json().catch(() => null) : null
  if (!r.ok) throw new ConsoleError(r.status, data)
  return data
}

// Decimal sizes, as the quota fields (GB = 10^9 bytes); 0 means unlimited.
export function fmtSize(bytes) {
  const n = Number(bytes) || 0
  if (n <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0, v = n
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++ }
  return (i ? v.toFixed(v < 10 ? 2 : 1) : String(v)) + ' ' + units[i]
}

// Share of a quota in percent (0 when unlimited), capped at 100.
export function quotaPercent(used, max) {
  if (!max || max <= 0) return 0
  return Math.min(100, Math.round((Number(used) || 0) * 100 / max))
}

// What the console shows of a tenant's storage: the kind only ("own:azure",
// "platform", "local", "none"), never its configuration.
const BACKENDS = { s3: 'S3', azure: 'Azure', gcs: 'Google Cloud Storage' }
export function storageKindLabel(kind) {
  const k = String(kind || '')
  if (k.startsWith('own:')) return translateMessage(tr('Own storage ({type})')).replace('{type}', BACKENDS[k.slice(4)] || k.slice(4))
  if (k === 'platform') return translateMessage(tr('Platform bucket'))
  if (k === 'local') return translateMessage(tr('Local disk on the server'))
  return translateMessage(tr('Not set up'))
}

// Re-authentication for a destructive action: the server accepts the
// authenticator code, or the password of an administrator without one while
// the platform does not require it, in the same field.
export function reauthBody(value) {
  return { code: String(value || '') }
}
