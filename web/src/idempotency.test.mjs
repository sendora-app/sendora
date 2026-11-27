// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { isMutating, newIdempotencyKey, withIdempotencyKey, retryDelay, sendWithOutcomeRetry, RETRY_DELAYS } from './idempotency.mjs'

const res = (status, headers = {}) => ({ status, headers: new Headers(headers) })

test('only mutating methods get a key', () => {
  for (const m of ['POST', 'put', 'PATCH', 'DELETE']) assert.equal(isMutating(m), true)
  for (const m of ['GET', 'HEAD', undefined]) assert.equal(isMutating(m), false)
  assert.equal(withIdempotencyKey({ method: 'GET' }).headers, undefined)
  const o = withIdempotencyKey({ method: 'POST', headers: { A: '1' } }, () => 'k1')
  assert.deepEqual(o.headers, { A: '1', 'Idempotency-Key': 'k1' })
})

test('a key is kept for the retries of one action', () => {
  const first = withIdempotencyKey({ method: 'DELETE' }, () => 'k1')
  assert.equal(withIdempotencyKey(first, () => 'k2').headers['Idempotency-Key'], 'k1')
  assert.equal(withIdempotencyKey({ method: 'POST', headers: { 'idempotency-key': 'mine' } }, () => 'k2').headers['Idempotency-Key'], undefined)
  assert.equal(withIdempotencyKey({ method: 'POST', idempotencyKey: false }).headers, undefined)
})

test('keys are random UUIDs, also without randomUUID', () => {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
  assert.match(newIdempotencyKey(), uuid)
  const fallback = newIdempotencyKey({ getRandomValues: a => a.fill(0xff) })
  assert.match(fallback, uuid)
  assert.notEqual(newIdempotencyKey(), newIdempotencyKey())
})

test('retries only unknown outcomes and running duplicates', () => {
  assert.equal(retryDelay(res(503, { 'Sendora-Outcome': 'unknown' }), 0), RETRY_DELAYS[0])
  assert.equal(retryDelay(res(409, { 'Sendora-Idempotency': 'in-progress', 'Retry-After': '2' }), 1), RETRY_DELAYS[1])
  assert.equal(retryDelay(res(503, { 'Sendora-Outcome': 'unknown', 'Retry-After': '30' }), 0), 30000)
  assert.equal(retryDelay(res(503), 0), -1)
  assert.equal(retryDelay(res(409), 0), -1)
  assert.equal(retryDelay(res(422), 0), -1)
  assert.equal(retryDelay(res(503, { 'Sendora-Outcome': 'unknown' }), RETRY_DELAYS.length), -1)
  assert.ok(RETRY_DELAYS.reduce((a, b) => a + b) <= 65000, 'about a minute in total')
})

test('repeats with the same request until a clean answer, at most three times', async () => {
  const answers = [res(503, { 'Sendora-Outcome': 'unknown' }), res(409, { 'Sendora-Idempotency': 'in-progress' }), res(201)]
  const slept = []
  let sent = 0
  const r = await sendWithOutcomeRetry(async () => answers[sent++], async ms => { slept.push(ms) })
  assert.equal(r.status, 201)
  assert.equal(sent, 3)
  assert.deepEqual(slept, RETRY_DELAYS.slice(0, 2))
  sent = 0
  const always = await sendWithOutcomeRetry(async () => { sent++; return res(503, { 'Sendora-Outcome': 'unknown' }) }, async () => {})
  assert.equal(always.status, 503)
  assert.equal(sent, 1 + RETRY_DELAYS.length)
})
