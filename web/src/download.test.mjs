// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { verifiedDownload } from './download.js'
const data = new TextEncoder().encode('verified contents')
const checksum = createHash('sha256').update(data).digest('hex')
function response(body = data, headers = {}) {
  return new Response(body, { headers: { 'Content-Length': String(data.length), 'X-Checksum-SHA256': checksum, 'Repr-Digest': `sha-256=:${Buffer.from(checksum,'hex').toString('base64')}:`, ...headers } })
}
function fixture() {
  const events = []
  globalThis.window = { isSecureContext: true, showSaveFilePicker: async () => ({ createWritable: async () => ({ write: async bytes => events.push(['write',bytes.length]), close: async () => events.push(['close']), abort: async () => events.push(['abort']) }) }) }
  return events
}
test('verified disk download commits only matching full contents', async () => {
  const events = fixture();globalThis.fetch = async () => response()
  await verifiedDownload('/file', { name: 'file' })
  assert.equal(events.at(-1)[0], 'close');assert.ok(!events.some(e=>e[0]==='abort'))
})
test('tampered, truncated, malformed or missing digest aborts disk save', async () => {
  for (const r of [response(new TextEncoder().encode('corrupt contents!')), response(data.slice(0,-1)), response(data, {'X-Checksum-SHA256':''}), response(data, {'Repr-Digest':'sha-256=:bad:'}), response(data, {'Content-Length':'-1'})]) {
    const events = fixture();globalThis.fetch = async () => r
    await assert.rejects(verifiedDownload('/file', { name: 'file' }))
    assert.equal(events.at(-1)[0],'abort');assert.ok(!events.some(e=>e[0]==='close'))
  }
})
test('cancelled disk download aborts save', async () => {
  const events=fixture(); const controller=new AbortController();controller.abort()
  await assert.rejects(verifiedDownload('/file',{name:'file',signal:controller.signal}), {name:'AbortError'})
  assert.equal(events.at(-1)[0],'abort')
})
test('unsupported browser fails large download before buffering body', async () => {
  globalThis.window = { isSecureContext: true }
  globalThis.fetch = async () => response(data, {'Content-Length':String(129*1024*1024)})
  await assert.rejects(verifiedDownload('/file',{name:'file'}), /cannot verify downloads larger/)
})
