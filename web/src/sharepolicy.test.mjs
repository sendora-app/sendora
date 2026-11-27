// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { sharePolicy, accountPolicy, passwordProblems } from './sharepolicy.mjs'

test('policy defaults and string booleans', () => {
  assert.deepEqual(sharePolicy({}), { required: false, min: 8, upper: false, lower: false, digit: false, symbol: false })
  const p = sharePolicy({ require_share_password: 'true', share_password_min_length: '12', share_password_require_digit: true })
  assert.equal(p.required, true); assert.equal(p.min, 12); assert.equal(p.digit, true); assert.equal(p.upper, false)
  assert.equal(sharePolicy({ share_password_min_length: '999' }).min, 8)
})

test('empty password only fails when required', () => {
  assert.deepEqual(passwordProblems('', sharePolicy({})), [])
  assert.equal(passwordProblems('', sharePolicy({ require_share_password: true })).length, 1)
})

test('length counts characters and bytes are capped', () => {
  const p = sharePolicy({ share_password_min_length: 4 })
  assert.deepEqual(passwordProblems('ééé', p), [{ key: 'At least {n} characters', n: 4 }])
  assert.deepEqual(passwordProblems('éééé', p), [])
  assert.ok(passwordProblems('é'.repeat(37), p).some(x => x.key === 'Password must not exceed 72 bytes'))
})

test('character classes', () => {
  const all = sharePolicy({ share_password_min_length: 1, share_password_require_upper: true, share_password_require_lower: true, share_password_require_digit: true, share_password_require_symbol: true })
  assert.equal(passwordProblems('abc', all).length, 3)
  assert.deepEqual(passwordProblems('Abc1!', all), [])
})

test('account policy always requires a password and has its own keys', () => {
  const p = accountPolicy({ account_password_min_length: '10', account_password_require_upper: 'true', share_password_require_digit: true })
  assert.equal(p.min, 10); assert.equal(p.upper, true); assert.equal(p.digit, false)
  assert.deepEqual(passwordProblems('', p), [{ key: 'A password is required' }])
  assert.equal(passwordProblems('abcdefghij', p).length, 1)
  assert.deepEqual(passwordProblems('Abcdefghij', p), [])
  assert.equal(accountPolicy({}).min, 8)
  assert.equal(accountPolicy({ account_password_min_length: '0' }).min, 8)
})
