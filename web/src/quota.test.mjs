// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { gbToBytes, bytesToGB, fmtGB, quotaPayload } from './quota.mjs'

test('GB conversion preserves exact bytes and accepts decimal comma', () => {
  for (const bytes of [0, 1, 10, 999999999, 1000000000, 10737418240, Number.MAX_SAFE_INTEGER]) {
    assert.equal(gbToBytes(bytesToGB(bytes)), bytes)
  }
  assert.equal(bytesToGB(10737418240), '10.73741824')
  assert.equal(gbToBytes('0,5'), 500000000)
  assert.equal(gbToBytes(' 10.000000001 '), 10000000001)
  assert.equal(fmtGB(1000000000), '1 GB')
  assert.equal(bytesToGB('10737418240'), '10.73741824')
})

test('GB validation refuses invalid precision, signs, exponent and overflow', () => {
  for (const input of ['', ' ', '-1', '+1', '.5', '1.', '1e3', 'NaN', 'Infinity', '0.0000000001', '9007199.254740992', '1,2.3', '0x10', '9'.repeat(65), null, undefined, 10]) {
    assert.throws(() => gbToBytes(input), undefined, String(input))
  }
  for (const bytes of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, null, undefined, 'invalid']) assert.throws(() => bytesToGB(bytes))
})

test('inheritance payload cannot accidentally save displayed default as override', () => {
  assert.deepEqual(quotaPayload(true, '10.73741824'), { quota_inherits_default: true })
  assert.deepEqual(quotaPayload(true, ''), { quota_inherits_default: true })
  assert.deepEqual(quotaPayload(false, '10.73741824'), { quota_inherits_default: false, quota_bytes: 10737418240 })
  assert.deepEqual(quotaPayload(false, '0'), { quota_inherits_default: false, quota_bytes: 0 })
  assert.throws(() => quotaPayload(undefined, '1'))
})

test('short GB display rounds to two decimals with a decimal point', async () => {
  const { fmtGBShort } = await import('./quota.mjs')
  assert.equal(fmtGBShort(10000000000), '10 GB')
  assert.equal(fmtGBShort(0), '0 GB')
  assert.equal(fmtGBShort(2380), '<0.01 GB')
  assert.equal(fmtGBShort(9999997620), '10 GB')
  assert.equal(fmtGBShort(9900000000), '9.9 GB')
  assert.equal(fmtGBShort(10000000), '0.01 GB')
  assert.equal(fmtGBShort(1234567890), '1.23 GB')
  assert.equal(fmtGBShort(1005000000), '1.01 GB')
  assert.equal(fmtGBShort(Number.MAX_SAFE_INTEGER), '9007199.25 GB')
  assert.throws(() => fmtGBShort(-1))
})
