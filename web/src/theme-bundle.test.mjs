// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { validateThemeBundle, serializeThemeBundle, themeKeys } from './theme-bundle.js'
const good = () => ({ name: 'Custom theme', data: Object.fromEntries(themeKeys.map(key => [key, '#123456'])) })
test('theme export/import round trip strips database identity and flags', () => {
  const exported = JSON.parse(serializeThemeBundle({ ...good(), id: 9, active: true, bundled: true }))
  assert.deepEqual(validateThemeBundle(exported), good())
  assert.deepEqual(Object.keys(exported), ['name', 'data'])
})
test('import rejects malformed structure, missing colors and CSS injection', () => {
  for (const value of [null, [], {}, { ...good(), id: 1 }, { ...good(), name: 4 }, { ...good(), name: ' ' }, { ...good(), name: 'x\n' }, { ...good(), name: 'x'.repeat(81) }, { ...good(), data: null }, { ...good(), data: [] }, { ...good(), data: { ...good().data, extra: '#fff' } }]) assert.throws(() => validateThemeBundle(value))
  for (const color of ['#12345', '#1234567', 'red', '#fff; background:url(x)', null]) assert.throws(() => validateThemeBundle({ ...good(), data: { ...good().data, primary: color } }))
  const missing = good(); delete missing.data.bg; assert.throws(() => validateThemeBundle(missing))
})
test('valid CSS hex lengths round trip unchanged', () => {
  for (const color of ['#abc', '#abcd', '#ABCDEF', '#12345678']) {
    const bundle = good(); bundle.data.primary = color
    assert.equal(validateThemeBundle(JSON.parse(serializeThemeBundle(bundle))).data.primary, color)
  }
})
