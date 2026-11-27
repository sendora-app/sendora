// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { b64urlEncode, b64urlDecode, creationArgs, requestArgs, registrationJSON, assertionJSON, normalizeTotp, normalizeRecovery, groupRecovery, recoveryFileText, webauthnErrorKey } from './mfa.mjs'

const bytes = (...n) => new Uint8Array(n)

test('base64url round trips without padding and with url-safe characters', () => {
  for (const sample of [[], [0], [251, 255, 254], [1, 2, 3, 4], Array.from({ length: 300 }, (_, i) => i % 256)]) {
    const text = b64urlEncode(bytes(...sample))
    assert.ok(!/[+/=]/.test(text), text)
    assert.deepEqual([...b64urlDecode(text)], sample)
  }
  assert.equal(b64urlEncode(bytes(251, 255, 254)), '-__-')
  assert.deepEqual([...b64urlDecode('-__-=')], [251, 255, 254], 'padding is tolerated')
  assert.equal(b64urlEncode(new Uint8Array(70000).buffer).length, Math.ceil(70000 * 4 / 3))
})

test('base64url decode is strict', () => {
  for (const bad of ['a b', 'a+b/', 'abc$', 'a', '====a', 'ab\ncd']) assert.throws(() => b64urlDecode(bad), bad)
})

test('creation options are decoded for navigator.credentials.create', () => {
  const server = {
    rp: { id: 'example.com', name: 'Sendora' },
    user: { id: b64urlEncode(bytes(7, 8, 9)), name: 'alice', displayName: 'Alice' },
    challenge: b64urlEncode(bytes(1, 2, 3)),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [{ type: 'public-key', id: b64urlEncode(bytes(4, 5)) }],
    authenticatorSelection: { userVerification: 'preferred' }, attestation: 'none', timeout: 300000,
  }
  const arg = creationArgs(server).publicKey
  assert.deepEqual([...arg.challenge], [1, 2, 3])
  assert.deepEqual([...arg.user.id], [7, 8, 9])
  assert.equal(arg.user.name, 'alice')
  assert.deepEqual([...arg.excludeCredentials[0].id], [4, 5])
  assert.equal(arg.excludeCredentials[0].type, 'public-key')
  assert.equal(arg.attestation, 'none'); assert.equal(arg.rp.id, 'example.com')
  assert.equal(creationArgs({ ...server, excludeCredentials: undefined }).publicKey.excludeCredentials.length, 0)
  assert.throws(() => creationArgs({ ...server, challenge: '***' }))
})

test('request options are decoded for navigator.credentials.get', () => {
  const server = { challenge: b64urlEncode(bytes(9)), rpId: 'example.com', timeout: 1, userVerification: 'preferred', allowCredentials: [{ type: 'public-key', id: b64urlEncode(bytes(1, 1)) }, { type: 'public-key', id: b64urlEncode(bytes(2)) }] }
  const arg = requestArgs(server).publicKey
  assert.deepEqual([...arg.challenge], [9])
  assert.deepEqual(arg.allowCredentials.map(d => [...d.id]), [[1, 1], [2]])
  assert.equal(arg.rpId, 'example.com')
  assert.equal(requestArgs({ ...server, allowCredentials: null }).publicKey.allowCredentials.length, 0)
})

test('credentials are serialised to the contract JSON', () => {
  const reg = registrationJSON({ id: 'abc', type: 'public-key', rawId: bytes(1, 2).buffer, response: { clientDataJSON: bytes(3).buffer, attestationObject: bytes(4, 5).buffer } })
  assert.deepEqual(reg, { id: 'abc', rawId: 'AQI', type: 'public-key', response: { clientDataJSON: 'Aw', attestationObject: 'BAU' } })
  const as = assertionJSON({ id: 'abc', type: 'public-key', rawId: bytes(1).buffer, response: { clientDataJSON: bytes(2).buffer, authenticatorData: bytes(3).buffer, signature: bytes(4).buffer, userHandle: null } })
  assert.deepEqual(as.response, { clientDataJSON: 'Ag', authenticatorData: 'Aw', signature: 'BA', userHandle: null })
  assert.equal(assertionJSON({ id: 'x', type: 'public-key', rawId: bytes(1), response: { clientDataJSON: bytes(1), authenticatorData: bytes(1), signature: bytes(1), userHandle: bytes(9).buffer } }).response.userHandle, 'CQ')
  assert.equal(assertionJSON({ id: 'x', type: 'public-key', rawId: bytes(1), response: { clientDataJSON: bytes(1), authenticatorData: bytes(1), signature: bytes(1), userHandle: new ArrayBuffer(0) } }).response.userHandle, null)
})

test('authenticator codes tolerate spaces and dashes but need exactly six digits', () => {
  assert.deepEqual(normalizeTotp('123 456'), { ok: true, code: '123456' })
  assert.deepEqual(normalizeTotp(' 123-456 '), { ok: true, code: '123456' })
  for (const bad of ['12345', '1234567', 'abcdef', '12 34 5a', '', null, undefined, '١٢٣٤٥٦']) assert.equal(normalizeTotp(bad).ok, false, String(bad))
})

test('recovery codes ignore case, dashes and spaces and need 16 characters', () => {
  assert.deepEqual(normalizeRecovery('abcd-efgh-2345-6789'), { ok: true, code: 'ABCDEFGH23456789' })
  assert.equal(normalizeRecovery(' ABCD EFGH 2345 6789 ').ok, true)
  for (const bad of ['ABCD-EFGH', 'ABCDEFGH23456789X', 'ABCD-EFGH-2345-678!', '', null]) assert.equal(normalizeRecovery(bad).ok, false, String(bad))
  assert.equal(groupRecovery('abcdefgh23456789'), 'ABCD-EFGH-2345-6789')
  const file = recoveryFileText(['abcdefgh23456789', 'ZZZZYYYYXXXXWWWW'], 'Sendora')
  assert.match(file, /ABCD-EFGH-2345-6789\nZZZZ-YYYY-XXXX-WWWW\n$/)
})

test('browser errors map to friendly translation keys', () => {
  const key = name => webauthnErrorKey({ name })
  assert.match(key('NotAllowedError'), /cancelled or timed out/)
  assert.match(key('InvalidStateError'), /already registered/)
  assert.match(key('SecurityError'), /https or localhost/)
  assert.match(key('NotSupportedError'), /does not support/)
  assert.match(key('TypeError'), /invalid passkey request/)
  assert.equal(key('Whatever'), 'The passkey request failed.')
  assert.equal(webauthnErrorKey(null), 'The passkey request failed.')
})
