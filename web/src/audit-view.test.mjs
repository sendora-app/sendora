// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import {
  localDayStart, localNextDayStart, auditParams, pagerInfo, lastPageOffset, needsClamp,
  actionSuggestions, KNOWN_ACTIONS, labelFor, categoryLabels, outcomeLabels, roleLabels, chainReasonLabels,
  AUDIT_CATEGORIES, AUDIT_OUTCOMES, hasAuditFilters, blankAuditFilters,
} from './audit-view.mjs'

// The local-day conversion depends on the time zone of the process; check it against
// the Date constructor (local time) and, when available, against a fixed zone.
test('date filters are local midnight to the next local midnight, in RFC 3339', () => {
  const from = localDayStart('2026-03-29'), to = localNextDayStart('2026-03-29')
  assert.match(from, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
  assert.equal(new Date(from).getTime(), new Date(2026, 2, 29).getTime())
  assert.equal(new Date(to).getTime(), new Date(2026, 2, 30).getTime())
  assert.equal(localNextDayStart('2026-12-31'), new Date(2027, 0, 1).toISOString().replace('.000Z', 'Z'))
  assert.equal(localDayStart('29-03-2026'), null)
  assert.equal(localDayStart(''), null)
})

test('a fixed time zone gives the expected UTC instants (Europe/Amsterdam, DST day)', async () => {
  const { execFileSync } = await import('node:child_process')
  const script = `import('${new URL('./audit-view.mjs', import.meta.url).href}').then(m => console.log(JSON.stringify([m.localDayStart('2026-03-29'), m.localNextDayStart('2026-03-29'), m.localDayStart('2026-07-01')])))`
  const out = JSON.parse(execFileSync(process.execPath, ['-e', script], { env: { ...process.env, TZ: 'Europe/Amsterdam' } }).toString())
  // 29 March 2026 has 23 hours in Amsterdam (CET -> CEST).
  assert.deepEqual(out, ['2026-03-28T23:00:00Z', '2026-03-29T22:00:00Z', '2026-06-30T22:00:00Z'])
})

test('auditParams trims, skips empty fields and converts dates', () => {
  const p = auditParams({ ...blankAuditFilters(), q: '  login ', category: 'auth', from: '2026-01-02', to: '2026-01-02', actor: ' ' }, { limit: 50, offset: 100 })
  assert.equal(p.get('q'), 'login')
  assert.equal(p.get('category'), 'auth')
  assert.equal(p.has('actor'), false)
  assert.equal(p.get('from'), localDayStart('2026-01-02'))
  assert.equal(p.get('to'), localNextDayStart('2026-01-02'))
  assert.equal(p.get('limit'), '50')
  assert.equal(p.get('offset'), '100')
})

test('hasAuditFilters', () => {
  assert.equal(hasAuditFilters(blankAuditFilters()), false)
  assert.equal(hasAuditFilters({ ...blankAuditFilters(), outcome: 'ok' }), true)
})

test('pager text numbers and clamping', () => {
  assert.deepEqual(pagerInfo(0, 50, 120), { from: 1, to: 50, total: 120, capped: false })
  assert.deepEqual(pagerInfo(100, 20, 120, true), { from: 101, to: 120, total: 120, capped: true })
  assert.deepEqual(pagerInfo(0, 0, 0), { from: 0, to: 0, total: 0, capped: false })
  assert.equal(lastPageOffset(120, 50), 100)
  assert.equal(lastPageOffset(100, 50), 50)
  assert.equal(lastPageOffset(0, 50), 0)
  assert.equal(needsClamp(100, 0, 80), true)
  assert.equal(needsClamp(0, 0, 0), false)
  assert.equal(needsClamp(50, 10, 60), false)
})

test('action suggestions merge the known list with actions on the page', () => {
  const list = actionSuggestions([{ action: 'custom_thing' }, { action: 'login_ok' }, {}])
  assert.ok(list.includes('custom_thing'))
  assert.equal(list.filter(a => a === 'login_ok').length, 1)
  assert.deepEqual(list, [...list].sort())
  assert.ok(KNOWN_ACTIONS.includes('audit_exported'))
})

test('every category, outcome, role and chain reason has a label; unknown codes pass through', () => {
  for (const c of AUDIT_CATEGORIES) assert.ok(categoryLabels[c])
  for (const o of AUDIT_OUTCOMES) assert.ok(outcomeLabels[o])
  for (const r of ['admin', 'auditor', 'user', 'guest', 'system', 'anonymous']) assert.ok(roleLabels[r])
  assert.equal(labelFor(chainReasonLabels, 'record missing'), 'record missing')
  assert.equal(labelFor(outcomeLabels, 'ok'), 'Succeeded')
  assert.equal(labelFor(outcomeLabels, 'weird'), 'weird')
  assert.equal(labelFor(outcomeLabels, 'constructor'), 'constructor')
  assert.equal(labelFor(outcomeLabels, undefined), '')
})
