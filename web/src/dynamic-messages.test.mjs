// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { dynamicMatcher, translateDynamic } from './i18n/mark.mjs'

const nl = {
  '%s must be a whole number from %d to %d': '%s moet een geheel getal van %d tot %d zijn',
  'invalid address or range: %s': 'ongeldig adres of bereik: %s',
  'reordered %s and %d': 'eerst %d dan %s',
}
const translate = k => nl[k] ?? k
const matchers = dynamicMatcher(Object.keys(nl).concat(['untranslated %s']))

test('a filled-in server message is translated with its values', () => {
  assert.equal(translateDynamic('backup_keep must be a whole number from 1 to 365', matchers, translate), 'backup_keep moet een geheel getal van 1 tot 365 zijn')
  assert.equal(translateDynamic('invalid address or range: 10.0.0.0/33', matchers, translate), 'ongeldig adres of bereik: 10.0.0.0/33')
})

test('values keep their type order when a translation reorders verbs', () => {
  assert.equal(translateDynamic('reordered abc and 42', matchers, translate), 'eerst 42 dan abc')
})

test('unknown or untranslated messages are returned unchanged', () => {
  assert.equal(translateDynamic('something else entirely', matchers, translate), 'something else entirely')
  assert.equal(translateDynamic('untranslated thing', matchers, translate), 'untranslated thing')
})

test('regex special characters in patterns are literal', () => {
  const m = dynamicMatcher(['cost (%d) [x]'])
  assert.equal(translateDynamic('cost (5) [x]', m, k => (k === 'cost (%d) [x]' ? 'prijs (%d) [x]' : k)), 'prijs (5) [x]')
  assert.equal(translateDynamic('cost 5 x', m, k => k), 'cost 5 x')
})
