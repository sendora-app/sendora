// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { generateKek, kekProblem, kekWeak, kekFileName, shortFingerprint, rotateAction, retireAction, legacyAction, progress, rowsOlder, openJob, lastFinished, kekFormReady, anyJobOpen } from './keys.mjs'

const rnd = c => webcrypto.getRandomValues(c)

test('a generated key is 32 bytes of base64 and valid', () => {
  const k = generateKek(rnd)
  assert.equal(k.length, 44)
  assert.equal(Buffer.from(k, 'base64').length, 32)
  assert.equal(kekProblem(k), '')
  assert.notEqual(generateKek(rnd), k)
})

test('generation retries a weak draw and fails when random never gets better', () => {
  let n = 0
  const k = generateKek(c => { if (n++ === 0) c.fill(7); else rnd(c) })
  assert.equal(kekProblem(k), '')
  assert.throws(() => generateKek(c => c.fill(7)))
})

test('kekProblem validates format', () => {
  const good = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString('base64')
  assert.equal(kekProblem(' ' + good + '\n'), '')
  assert.equal(kekProblem(Buffer.from(good, 'base64').toString('base64url')), '')
  assert.match(kekProblem(''), /Enter/)
  assert.match(kekProblem('not base64!!'), /base64/)
  assert.match(kekProblem(Buffer.alloc(31, 1).toString('base64')), /32 bytes/)
  assert.match(kekProblem(Buffer.alloc(33, 1).toString('base64')), /32 bytes/)
  assert.match(kekProblem(Buffer.alloc(32, 9).toString('base64')), /weak/)
  assert.match(kekProblem(Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString('base64')), /weak/)
})

test('kekWeak matches the server rule', () => {
  assert.equal(kekWeak(new Uint8Array(32)), true)
  assert.equal(kekWeak(Uint8Array.from({ length: 32 }, (_, i) => 255 - i)), true)
  assert.equal(kekWeak(Uint8Array.from({ length: 32 }, (_, i) => (i * 37) & 255)), false)
})

test('names and fingerprints', () => {
  assert.equal(kekFileName('acme'), 'acme-sendora-tenant-key.txt')
  assert.equal(kekFileName('../x y'), 'xy-sendora-tenant-key.txt')
  assert.equal(shortFingerprint('0123456789abcdef'), '01234567')
  assert.equal(shortFingerprint(''), '')
})

const data = { purpose: 'data', rotatable: true, active: 2, versions: [
  { version: 1, state: 'decrypt_only', rows: 0, audit_rows: 0, files: 0 },
  { version: 2, state: 'active', rows: 10, audit_rows: 3, files: 0 }] }

test('rotate: only rotatable purposes without an open job', () => {
  assert.equal(rotateAction(data, []).enabled, true)
  assert.equal(rotateAction({ purpose: 'audit-mac', rotatable: false }, []).enabled, false)
  const jobs = [{ purpose: 'data', status: 'running' }]
  assert.equal(rotateAction(data, jobs).enabled, false)
  assert.equal(rotateAction({ ...data, purpose: 'files' }, jobs).enabled, true)
  assert.equal(rotateAction(data, [{ purpose: 'data', status: 'done' }]).enabled, true)
  assert.equal(anyJobOpen([{ status: 'pending' }]), true)
  assert.equal(anyJobOpen([{ status: 'failed' }]), false)
})

test('retire: decrypt-only versions with nothing left', () => {
  assert.deepEqual(retireAction(data, data.versions[1], []), { show: false, enabled: false, reason: '' })
  assert.equal(retireAction(data, data.versions[0], []).enabled, true)
  assert.equal(retireAction(data, { ...data.versions[0], rows: 4 }, []).enabled, false)
  const auditEnc = { purpose: 'audit-enc', rotatable: true, active: 2 }
  const a = retireAction(auditEnc, { version: 1, state: 'decrypt_only', audit_rows: 1 }, [])
  assert.equal(a.show, true); assert.equal(a.enabled, false); assert.match(a.reason, /audit log/)
  assert.equal(retireAction(auditEnc, { version: 1, state: 'decrypt_only', audit_rows: 0 }, []).enabled, true)
  assert.equal(retireAction(data, data.versions[0], [{ purpose: 'data', status: 'pending' }]).enabled, false)
  const files = { purpose: 'files', rotatable: true, active: 2 }
  assert.equal(retireAction(files, { version: 1, state: 'decrypt_only', files: 0 }, []).enabled, true)
  assert.equal(retireAction(files, { version: 1, state: 'decrypt_only', files: 2 }, []).enabled, false)
  assert.equal(retireAction(files, { version: 1, state: 'decrypt_only', files: -1 }, []).enabled, false)
  assert.equal(retireAction({ purpose: 'secrets', rotatable: true }, { version: 1, state: 'decrypt_only', rows: 5 }, []).enabled, true)
  assert.equal(retireAction({ purpose: 'audit-mac', rotatable: false }, { version: 1, state: 'decrypt_only' }, []).show, false)
  assert.equal(retireAction(data, { version: 1, state: 'retired' }, []).show, false)
})

test('legacy files button', () => {
  assert.deepEqual(legacyAction({ legacy_files: 0 }, []), { show: false, enabled: true })
  assert.deepEqual(legacyAction({ legacy_files: 3 }, []), { show: true, enabled: true })
  assert.deepEqual(legacyAction({ legacy_files: 3 }, [{ purpose: 'files', status: 'running' }]), { show: true, enabled: false })
  assert.equal(legacyAction(null, []).show, false)
})

test('progress and rows on older versions', () => {
  assert.equal(rowsOlder(data), 0)
  assert.equal(rowsOlder({ active: 2, versions: [{ version: 1, rows: 5, audit_rows: 2, files: -1 }, { version: 2, rows: 99 }] }), 5)
  assert.equal(progress(0, 0), null)
  assert.equal(progress(200, 200), 0)
  assert.equal(progress(200, 50), 75)
  assert.equal(progress(200, 0), 100)
  assert.equal(progress(10, 40), 0)
  assert.equal(openJob([{ purpose: 'data', status: 'pending', id: 1 }, { purpose: 'data', status: 'running', id: 2 }], 'data').id, 2)
  assert.equal(openJob([], 'data'), null)
})

test('kek form readiness', () => {
  const k1 = generateKek(rnd), k2 = generateKek(rnd)
  assert.equal(kekFormReady('upload', { kek: k1, stored: true, confirm: 'acme' }, 'acme'), true)
  assert.equal(kekFormReady('upload', { kek: k1, stored: false, confirm: 'acme' }, 'acme'), false)
  assert.equal(kekFormReady('upload', { kek: k1, stored: true, confirm: 'acm' }, 'acme'), false)
  assert.equal(kekFormReady('upload', { kek: 'x', stored: true, confirm: 'acme' }, 'acme'), false)
  assert.equal(kekFormReady('replace', { old: k1, kek: k2, stored: true }, 'acme'), true)
  assert.equal(kekFormReady('replace', { old: k1, kek: k1, stored: true }, 'acme'), false)
  assert.equal(kekFormReady('replace', { old: k1, kek: k2, stored: false }, 'acme'), false)
  assert.equal(kekFormReady('release', { old: k1 }, 'acme'), true)
  assert.equal(kekFormReady('release', { old: '' }, 'acme'), false)
})

test('lastFinished returns the newest finished job of the purpose', () => {
  const jobs = [
    { purpose: 'data', status: 'done', updated_at: '2026-11-25T14:00:00Z', version: 2 },
    { purpose: 'data', status: 'failed', updated_at: '2026-11-25T15:00:00Z', version: 3 },
    { purpose: 'data', status: 'running', updated_at: '2026-11-25T16:00:00Z', version: 4 },
    { purpose: 'files', status: 'done', updated_at: '2026-11-25T17:00:00Z', version: 1 },
  ]
  assert.equal(lastFinished(jobs, 'data').version, 3)
  assert.equal(lastFinished(jobs, 'secrets'), null)
  assert.equal(lastFinished(undefined, 'data'), null)
})
