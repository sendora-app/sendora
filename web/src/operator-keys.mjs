// SPDX-License-Identifier: AGPL-3.0-or-later

import { tr } from './i18n/mark.mjs'

// Pure logic of the platform console's Key management tab (unit tested). The
// operator only ever sees metadata: modes, fingerprints, versions, jobs.

export const PURPOSES = ['data', 'index', 'secrets', 'files']
export const SLOW_MS = 20000 // list refresh while nothing runs
export const FAST_MS = 3000 // ... while a key job runs

// anyRunning: a row with an unfinished key job.
export const anyRunning = rows => (rows || []).some(r => (r.running || []).length > 0)

// nextPoll returns the delay in ms until the next refresh, or 0 for "do not
// poll" (the tab is hidden, or it is not the one in view).
export function nextPoll(rows, { visible = true, active = true } = {}) {
  if (!visible || !active) return 0
  return anyRunning(rows) ? FAST_MS : SLOW_MS
}

// rowStatus labels the state of a tenant's keys; kind picks the badge style.
export function rowStatus(r) {
  if ((r.running || []).length) return { label: tr('Rotating: {purposes}'), kind: 'busy', purposes: r.running.join(', ') }
  if (r.state === 'locked') return { label: tr('Locked'), kind: 'warn' }
  if (r.state === 'unavailable') return { label: tr('Unavailable'), kind: 'warn' }
  if (r.last_error) return { label: tr('Last operation failed'), kind: 'err' }
  return { label: tr('OK'), kind: 'ok' }
}

// canRotate: the per-tenant button. Tenant-managed tenants are allowed only
// while their key is unlocked on the controllers (state ok).
export function canRotate(r) {
  if (r.state === 'locked') return { enabled: false, reason: tr('The organisation\'s own key is not unlocked on every controller.') }
  if (r.state === 'unavailable') return { enabled: false, reason: tr('The organisation is not available.') }
  if ((r.running || []).length) return { enabled: false, reason: tr('A key operation is still running.') }
  return { enabled: true, reason: '' }
}

// bulkTargets: tenants a "rotate all" would queue (platform-managed, usable).
export const bulkTargets = rows => (rows || []).filter(r => r.kek_mode !== 'tenant' && r.state === 'ok' && !(r.running || []).length)

// progress of the rotation that is running: finished/total over the rows that
// were part of it (ids), as shown in the bulk progress line.
export function progress(rows, ids) {
  const set = new Set(ids || [])
  const part = (rows || []).filter(r => set.has(r.id))
  const done = part.filter(r => !(r.running || []).length).length
  return { done, total: part.length, finished: part.length > 0 && done === part.length }
}

// lastFinished: the newest "last operation finished" time over the rows ('' if none).
export function lastFinished(rows) {
  let best = ''
  for (const r of rows || []) if (r.last_finished && r.last_finished > best) best = r.last_finished
  return best
}

// resultLabel: one line per tenant of a bulk answer.
export function resultLabel(res) {
  switch (res) {
    case 'queued': return tr('Queued')
    case 'busy': return tr('Already running')
    case 'locked': return tr('Locked')
    case 'tenant_managed': return tr('Skipped: tenant-managed')
    case 'unavailable': return tr('Unavailable')
    default: return tr('Failed')
  }
}

// reasonProblem mirrors the server rule (3 to 300 characters).
export function reasonProblem(text) {
  const n = String(text || '').trim().length
  return n < 3 || n > 300 ? tr('Enter a reason of 3 to 300 characters.') : ''
}

// ---------- master key (D46) ----------

// masterRows lists the master key versions of the status answer
// (GET /api/platform/master): number, how many tenants use it, its state.
export function masterRows(st) {
  if (!st) return []
  const top = Math.max(st.active || 1, st.target || 0)
  const rows = []
  for (let v = 1; v <= top; v++) {
    const retired = (st.retired || []).includes(v)
    let state = tr('Unused')
    if (retired) state = tr('Retired')
    else if (v === st.target && v > st.active) state = tr('Target')
    else if (v === st.active) state = tr('Active')
    else if ((st.tenants?.[v] || 0) > 0) state = tr('Still in use')
    rows.push({ version: v, tenants: st.tenants?.[v] || 0, state, infra: v === st.infra, retirable: (st.retirable || []).includes(v), retired })
  }
  return rows
}

// canRotateMaster: the next version must be mounted by the operator first; the
// button is enabled when no rotation runs.
export function canRotateMaster(st) {
  if (!st) return { enabled: false, next: 0, reason: '' }
  if (st.in_progress) return { enabled: false, next: st.target, reason: tr('A master key rotation is in progress.') }
  return { enabled: true, next: (st.active || 1) + 1, reason: '' }
}

// masterProgress: tenants already on the active/target version of all tenants.
export function masterProgress(st) {
  if (!st) return { done: 0, total: 0 }
  const target = st.in_progress ? st.target : st.active
  let done = 0, total = 0
  for (const [v, n] of Object.entries(st.tenants || {})) {
    total += n
    if (Number(v) >= target) done += n
  }
  return { done, total }
}
