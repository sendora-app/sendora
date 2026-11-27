// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { filenameFromDisposition } from './content-disposition.mjs'

test('reads quoted and unquoted file names', () => {
  assert.equal(filenameFromDisposition('attachment; filename="sendora-audit-20261118-101500.csv"'), 'sendora-audit-20261118-101500.csv')
  assert.equal(filenameFromDisposition('attachment; filename=backup.db'), 'backup.db')
  assert.equal(filenameFromDisposition('attachment; filename="a \\"b\\".txt"'), 'a "b".txt')
})

test('filename* wins and is percent-decoded', () => {
  assert.equal(filenameFromDisposition(`attachment; filename="x.txt"; filename*=UTF-8''r%C3%A9sum%C3%A9.txt`), 'résumé.txt')
})

test('strips paths and rejects empty names', () => {
  assert.equal(filenameFromDisposition('attachment; filename="../../etc/passwd"'), 'passwd')
  assert.equal(filenameFromDisposition('attachment; filename=".."'), '')
  assert.equal(filenameFromDisposition('attachment'), '')
  assert.equal(filenameFromDisposition(null), '')
})
