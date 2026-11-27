// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeHex, contrastRatio, contrastText, themeContrastChecks, formatRatio } from './contrast.mjs'

test('normalizeHex accepts 3, 4, 6 and 8 digit hex and drops alpha', () => {
  assert.equal(normalizeHex('#ABC'), '#aabbcc')
  assert.equal(normalizeHex('#abcd'), '#aabbcc')
  assert.equal(normalizeHex('#112233'), '#112233')
  assert.equal(normalizeHex('#11223344'), '#112233')
  assert.equal(normalizeHex('red'), null)
  assert.equal(normalizeHex('#12'), null)
  assert.equal(normalizeHex(undefined), null)
})

test('contrastRatio follows WCAG', () => {
  assert.equal(contrastRatio('#000', '#fff'), 21)
  assert.equal(contrastRatio('#fff', '#fff'), 1)
  assert.ok(Math.abs(contrastRatio('#777777', '#ffffff') - 4.48) < 0.01)
  assert.equal(contrastRatio('#000', 'nope'), null)
})

test('contrastText handles alpha hex like the theme validator allows', () => {
  assert.equal(contrastText('#ffff00'), '#000000')
  assert.equal(contrastText('#ffff00cc'), '#000000')
  assert.equal(contrastText('#ff0c'), '#000000')
  assert.equal(contrastText('#1e3a8a80'), '#ffffff')
  assert.equal(contrastText('#2563eb'), '#ffffff')
  assert.equal(contrastText('bad'), '#ffffff')
})

test('themeContrastChecks flags pairs below 4.5:1', () => {
  const checks = themeContrastChecks({ primary: '#2563eb', bg: '#f8fafc', surface: '#ffffff', text: '#0f172a', muted: '#aaaaaa' })
  const by = Object.fromEntries(checks.map(c => [c.key, c]))
  assert.deepEqual(Object.keys(by), ['text-bg', 'text-surface', 'primary-text', 'muted-surface'])
  assert.equal(by['text-bg'].ok, true)
  assert.equal(by['primary-text'].ok, true)
  assert.equal(by['muted-surface'].ok, false)
  assert.equal(themeContrastChecks({ text: '#000' })[0].ratio, null)
})

test('formatRatio never rounds a failing ratio up to 4.5', () => {
  assert.equal(formatRatio(4.49), '4.4:1')
  assert.equal(formatRatio(21), '21.0:1')
})
