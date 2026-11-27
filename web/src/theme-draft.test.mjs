// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { swatchHex, previewData, copyName, nameClashes, isHex } from './theme-draft.mjs'
test('swatchHex normalises hex for the colour input', () => {
  assert.equal(swatchHex('#ABC'), '#aabbcc')
  assert.equal(swatchHex('#abcd'), '#aabbcc')
  assert.equal(swatchHex('#12345678'), '#123456')
  assert.equal(swatchHex('red', '#111111'), '#111111')
})
test('previewData keeps valid values and falls back for invalid ones', () => {
  assert.deepEqual(previewData({ primary: '#12', bg: '#fff', surface: 'x' }, { primary: '#111111' }), { primary: '#111111', bg: '#fff' })
  assert.ok(!isHex('#fff; x'))
})
test('copy names avoid clashes', () => {
  assert.equal(copyName('Light', ['Dark']), 'Light (copy)')
  assert.equal(copyName('Light', ['light (copy)']), 'Light (copy 2)')
  assert.ok(nameClashes('dark ', ['Dark']))
  assert.ok(!nameClashes('Mine', ['Mine'], 'mine'))
})
