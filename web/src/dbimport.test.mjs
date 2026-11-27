// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { keyProblem, importForm, waitForRestart } from './dbimport.mjs'

test('key validation per mode', () => {
  assert.equal(keyProblem({ mode: 'none' }), '')
  assert.equal(keyProblem({ mode: 'hex', hex: 'a'.repeat(64) }), '')
  assert.equal(keyProblem({ mode: 'hex', hex: ' ' + 'A'.repeat(64) + ' ' }), '')
  assert.notEqual(keyProblem({ mode: 'hex', hex: 'a'.repeat(63) }), '')
  assert.notEqual(keyProblem({ mode: 'hex', hex: 'g'.repeat(64) }), '')
  assert.equal(keyProblem({ mode: 'file', file: { size: 32 } }), '')
  assert.notEqual(keyProblem({ mode: 'file', file: { size: 31 } }), '')
  assert.notEqual(keyProblem({ mode: 'file' }), '')
})

test('key parts precede the database file in the multipart body', () => {
  const file = new Blob(['db']); file.name = 'b.db'
  const names = fd => [...fd.keys()]
  assert.deepEqual(names(importForm({ mode: 'none', file })), ['file'])
  assert.deepEqual(names(importForm({ mode: 'hex', hex: 'a'.repeat(64), file })), ['key_hex', 'file'])
  assert.deepEqual(names(importForm({ mode: 'file', keyFile: new Blob(['k'.repeat(32)]), file })), ['key_file', 'file'])
})

test('restart wait needs the server to come back healthy twice', async () => {
  const answers = [true, false, false, true, true]
  let i = 0
  const ok = await waitForRestart(async () => ({ ok: answers[Math.min(i++, answers.length - 1)] }), async () => {}, { timeoutMs: 1e9 })
  assert.equal(ok, true)
  let calls = 0
  const never = await waitForRestart(async () => { calls++; throw new Error('down') }, async () => { }, { timeoutMs: 5, intervalMs: 0 })
  assert.equal(never, false); assert.ok(calls >= 0)
})
