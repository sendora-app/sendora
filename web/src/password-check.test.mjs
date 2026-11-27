// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { passwordChecklist, platformPolicy, confirmState } from './password-check.mjs'
import { accountPolicy } from './sharepolicy.mjs'

test('counter and checklist follow the active policy', () => {
  const policy = accountPolicy({ account_password_min_length: 10, account_password_require_upper: true, account_password_require_digit: 'true' })
  let c = passwordChecklist('abc', policy)
  assert.equal(c.count, 3)
  assert.equal(c.min, 10)
  assert.deepEqual(c.items.map(i => [i.key, i.ok]), [['At least {n} characters', false], ['An uppercase letter', false], ['A digit', false]])
  assert.equal(c.ok, false)
  c = passwordChecklist('Abcdefghi1', policy)
  assert.equal(c.count, 10)
  assert.ok(c.ok)
  // Characters, not bytes, are counted; the 72-byte limit is reported.
  assert.equal(passwordChecklist('ééé', policy).count, 3)
  const long = passwordChecklist('é'.repeat(40), { min: 8 })
  assert.equal(long.ok, false)
  assert.ok(long.items.some(i => i.key.includes('72 bytes') && !i.ok))
})

test('only configured rules appear', () => {
  const c = passwordChecklist('', accountPolicy({ account_password_min_length: 8 }))
  assert.deepEqual(c.items.map(i => i.key), ['At least {n} characters'])
  const all = passwordChecklist('aA1!', accountPolicy({ account_password_require_upper: true, account_password_require_lower: true, account_password_require_digit: true, account_password_require_symbol: true }))
  assert.equal(all.items.length, 5)
  assert.deepEqual(all.items.slice(1).map(i => i.ok), [true, true, true, true])
})

test('platform rule comes from the server', () => {
  assert.equal(platformPolicy({ password_min_length: 12 }).min, 12)
  assert.equal(platformPolicy({ password_min_length: 16 }).min, 16)
  assert.equal(platformPolicy({}).min, 12)
  assert.equal(passwordChecklist('Harbor-Lantern-Quiet-7', platformPolicy({ password_min_length: 12 })).ok, true)
})

test('confirmation feedback', () => {
  assert.equal(confirmState('secret', ''), '')
  assert.equal(confirmState('secret', 'secret'), 'match')
  assert.equal(confirmState('secret', 'secre'), 'mismatch')
})
