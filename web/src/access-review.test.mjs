// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { filterReview, parseFactors, accountStatus, describeAgent } from './access-review.mjs'

const users = [
  { username: 'admin', name: 'Ada', email: 'ada@x.io', role: 'admin', source: 'local', created_by: 'setup' },
  { username: 'bob', name: 'Bob Smith', email: 'bob@x.io', role: 'user', source: 'local; Entra', created_by: 'user#1 (admin)' },
]

test('filterReview matches every word, case-insensitively', () => {
  assert.equal(filterReview(users, '').length, 2)
  assert.deepEqual(filterReview(users, 'ENTRA').map(u => u.username), ['bob'])
  assert.deepEqual(filterReview(users, 'bob smith').map(u => u.username), ['bob'])
  assert.deepEqual(filterReview(users, 'bob setup'), [])
  assert.deepEqual(filterReview(null, 'x'), [])
})

test('parseFactors reads the factor summary', () => {
  assert.deepEqual(parseFactors('totp; webauthn:2; recovery_codes:8'), { totp: true, webauthn: 2, recovery: 8 })
  assert.deepEqual(parseFactors(''), { totp: false, webauthn: 0, recovery: 0 })
})

test('accountStatus lists disabled and locked before active', () => {
  assert.deepEqual(accountStatus({ disabled: true, login_locked: true }), ['Disabled', 'Locked'])
  assert.deepEqual(accountStatus({}), ['Active'])
})

test('describeAgent summarises common browsers', () => {
  assert.equal(describeAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0'), 'Firefox, Windows')
  assert.equal(describeAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15'), 'Safari, macOS')
  assert.equal(describeAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 Edg/126.0'), 'Edge, Linux')
  assert.equal(describeAgent('curl/8.0'), 'curl/8.0')
  assert.equal(describeAgent(''), '')
})
