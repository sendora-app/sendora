// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { nextPoll, FAST_MS, SLOW_MS, rowStatus, canRotate, bulkTargets, progress, lastFinished, resultLabel, reasonProblem } from './operator-keys.mjs'

const rows = [
  { id: 'a', kek_mode: 'platform', state: 'ok', running: [], last_finished: '2026-01-02T00:00:00Z' },
  { id: 'b', kek_mode: 'platform', state: 'ok', running: ['data'] },
  { id: 'c', kek_mode: 'tenant', state: 'locked', running: [] },
  { id: 'd', kek_mode: 'tenant', state: 'ok', running: [], last_finished: '2026-03-01T00:00:00Z' },
]

test('polling is faster while a job runs and pauses when hidden', () => {
  assert.equal(nextPoll(rows), FAST_MS)
  assert.equal(nextPoll([rows[0]]), SLOW_MS)
  assert.equal(nextPoll(rows, { visible: false }), 0)
  assert.equal(nextPoll(rows, { active: false }), 0)
})

test('row status and rotate button', () => {
  assert.equal(rowStatus(rows[1]).kind, 'busy')
  assert.equal(rowStatus(rows[2]).kind, 'warn')
  assert.equal(rowStatus({ state: 'ok', running: [], last_error: 'x' }).kind, 'err')
  assert.equal(canRotate(rows[0]).enabled, true)
  assert.equal(canRotate(rows[1]).enabled, false)
  assert.equal(canRotate(rows[2]).enabled, false)
  assert.equal(canRotate(rows[3]).enabled, true)
})

test('bulk targets are the platform-managed, usable, idle tenants', () => {
  assert.deepEqual(bulkTargets(rows).map(r => r.id), ['a'])
})

test('progress and last finished', () => {
  assert.deepEqual(progress(rows, ['a', 'b']), { done: 1, total: 2, finished: false })
  assert.equal(progress(rows, ['a']).finished, true)
  assert.equal(progress(rows, []).finished, false)
  assert.equal(lastFinished(rows), '2026-03-01T00:00:00Z')
  assert.equal(lastFinished([]), '')
})

test('result labels and reason rule', () => {
  assert.equal(resultLabel('tenant_managed'), 'Skipped: tenant-managed')
  assert.equal(resultLabel('whatever'), 'Failed')
  assert.ok(reasonProblem('ab'))
  assert.equal(reasonProblem('incident'), '')
})

import { masterRows, canRotateMaster, masterProgress } from './operator-keys.mjs'

test('master key rows, rotate button and progress', () => {
  const st = { active: 2, target: 3, retired: [], retirable: [], infra: 1, in_progress: true, tenants: { 2: 3, 3: 1 } }
  const rows = masterRows(st)
  assert.deepEqual(rows.map(r => [r.version, r.state, r.tenants]), [[1, 'Unused', 0], [2, 'Active', 3], [3, 'Target', 1]])
  assert.equal(rows[0].infra, true)
  assert.equal(canRotateMaster(st).enabled, false)
  assert.deepEqual(masterProgress(st), { done: 1, total: 4 })
  const idle = { active: 3, target: 0, retired: [2], retirable: [], infra: 1, in_progress: false, tenants: { 3: 4 } }
  assert.equal(canRotateMaster(idle).next, 4)
  assert.equal(masterRows(idle)[1].state, 'Retired')
  assert.deepEqual(masterProgress(idle), { done: 4, total: 4 })
  assert.deepEqual(masterRows(null), [])
})
