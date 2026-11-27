// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { slugProblem, pconsole, ConsoleError, fmtSize, quotaPercent, storageKindLabel, reauthBody } from './platform-console.mjs'

test('slugProblem mirrors the server rules', () => {
  for (const ok of ['klant1', 'ab', 'acme-corp', 'x9']) assert.equal(slugProblem(ok), '', ok)
  for (const bad of ['', 'a', '-x', 'x-', 'a--b', 'UPPER', 'a_b', 'a.b', 'x'.repeat(64)]) assert.notEqual(slugProblem(bad), '', bad)
  assert.match(slugProblem('admin'), /reserved/)
  assert.match(slugProblem('www'), /reserved/)
})

test('pconsole sends JSON to the console API and throws ConsoleError', async () => {
  const calls = []
  const ok = async (url, opts) => { calls.push([url, opts]); return { ok: true, status: 200, headers: { get: () => 'application/json' }, json: async () => ({ stage: 'full' }) } }
  assert.deepEqual(await pconsole('/login', { method: 'POST', body: { username: 'a' }, fetchImpl: ok }), { stage: 'full' })
  assert.equal(calls[0][0], '/api/platform/login')
  assert.equal(calls[0][1].credentials, 'same-origin')
  assert.equal(calls[0][1].headers['Content-Type'], 'application/json')
  assert.equal(calls[0][1].body, '{"username":"a"}')
  const fail = async () => ({ ok: false, status: 403, headers: { get: () => 'application/json' }, json: async () => ({ error: 'invalid code' }) })
  await assert.rejects(pconsole('/x', { fetchImpl: fail }), e => e instanceof ConsoleError && e.status === 403 && e.message === 'invalid code')
})

test('sizes and quota percentages', () => {
  assert.equal(fmtSize(0), '0 B')
  assert.equal(fmtSize(999), '999 B')
  assert.equal(fmtSize(1500), '1.50 KB')
  assert.equal(fmtSize(25e9), '25.0 GB')
  assert.equal(quotaPercent(5, 0), 0)
  assert.equal(quotaPercent(50, 200), 25)
  assert.equal(quotaPercent(500, 200), 100)
})

test('tenant storage kind labels show the type only', () => {
  assert.equal(storageKindLabel('own:azure'), 'Own storage (Azure)')
  assert.equal(storageKindLabel('own:s3'), 'Own storage (S3)')
  assert.equal(storageKindLabel('platform'), 'Platform bucket')
  assert.equal(storageKindLabel('none'), 'Not set up')
  assert.deepEqual(reauthBody('123456'), { code: '123456' })
  assert.deepEqual(reauthBody(undefined), { code: '' })
})
