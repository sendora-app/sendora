// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { SHA256, checksumBlob } from './checksum.js'
const expected = data => createHash('sha256').update(data).digest('hex')
test('SHA256 standard vectors and fragmented block boundaries', async () => {
  for (const data of [Buffer.alloc(0), Buffer.from('abc'), Buffer.alloc(1000000, 97), ...[55,56,63,64,65,127,128,129,10001].map(n => randomBytes(n))]) {
    for (const step of [1,7,64,511]) {
      const hash = new SHA256()
      for (let i=0;i<data.length;i+=step) hash.update(data.subarray(i,i+step))
      assert.equal(hash.hex(), expected(data))
    }
    assert.equal(await checksumBlob(new Blob([data])), expected(data))
  }
})
test('hashing cancellation fails without result', async () => {
  const controller = new AbortController(); controller.abort()
  await assert.rejects(checksumBlob(new Blob(['abc']), controller.signal), { name: 'AbortError' })
})
