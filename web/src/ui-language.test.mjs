// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { lookup, interpolate, buildExport, stripRedundant, parseImport, samePlaceholders, placeholderList, LIMITS } from './ui-language.mjs'

const known = ['Save', 'Max {n} MB per share', '%d file(s) in %d share(s)', 'constructor']

test('lookup: override, then bundled, then the English key', () => {
  assert.equal(lookup('Save', { Save: 'Sla op' }, { Save: 'Opslaan' }), 'Sla op')
  assert.equal(lookup('Save', {}, { Save: 'Opslaan' }), 'Opslaan')
  assert.equal(lookup('Save', {}, {}), 'Save')
  assert.equal(lookup('Save', undefined, undefined), 'Save')
  assert.equal(lookup('Save', { Save: '' }, { Save: 'Opslaan' }), 'Opslaan')
  assert.equal(lookup('constructor', {}, {}), 'constructor')
})

test('interpolate replaces every placeholder', () => {
  assert.equal(interpolate('{n} of {n} {x}', { n: 2, x: 'a' }), '2 of 2 a')
})

test('placeholders compare as a multiset', () => {
  assert.deepEqual(placeholderList('%d file(s) in %d share(s) {n}'), ['%d', '%d', '{n}'])
  assert.ok(samePlaceholders('A {n} {m}', '{m} B {n}'))
  assert.ok(!samePlaceholders('A {n}', 'A'))
  assert.ok(!samePlaceholders('%d of %d', '%d of'))
  assert.ok(!samePlaceholders('%s', '%d'))
})

test('buildExport has every key with its current text', () => {
  const out = buildExport({ code: 'nl', name: 'Nederlands', keys: known, override: { Save: 'Sla op' }, bundled: { 'Max {n} MB per share': 'Max {n} MB' } })
  assert.equal(out.translations.Save, 'Sla op')
  assert.equal(out.translations['Max {n} MB per share'], 'Max {n} MB')
  assert.equal(out.translations['%d file(s) in %d share(s)'], '%d file(s) in %d share(s)')
  assert.equal(Object.keys(out.translations).length, known.length)
})

test('stripRedundant drops texts equal to the bundled text or the key', () => {
  assert.deepEqual(stripRedundant({ Save: 'Opslaan', 'Max {n} MB per share': 'Max {n} MB per share', '%d file(s) in %d share(s)': '%d bestand(en) in %d' }, { Save: 'Opslaan' }), { '%d file(s) in %d share(s)': '%d bestand(en) in %d' })
})

const file = o => JSON.stringify(o)
const opts = { knownKeys: new Set(known), builtinNames: { nl: 'Nederlands' }, existingCodes: [] }

test('parseImport accepts a valid file', () => {
  const r = parseImport(file({ code: 'pt-br', name: 'Português', translations: { Save: 'Salvar', 'Max {n} MB per share': 'Máx {n} MB' } }), opts)
  assert.equal(r.ok, true); assert.equal(r.code, 'pt-br'); assert.equal(r.translations.Save, 'Salvar')
})
test('parseImport uses the built-in name and forced code', () => {
  const r = parseImport(file({ code: 'xx', name: 'Whatever', translations: {} }), { ...opts, forceCode: 'nl' })
  assert.equal(r.ok, true); assert.equal(r.code, 'nl'); assert.equal(r.name, 'Nederlands')
})

const bad = (o, extra, msg) => {
  const r = parseImport(typeof o === 'string' ? o : file(o), { ...opts, ...extra })
  assert.equal(r.ok, false); if (msg) assert.match(r.error, msg)
}
test('parseImport rejects bad input', () => {
  bad('{nope', {}, /valid JSON/)
  bad('[]', {}, /JSON object/)
  bad({ code: 'Bad Code', name: 'x', translations: {} }, {}, /language code/)
  bad({ code: 'pt', name: '', translations: {} }, {}, /language name/)
  bad({ code: 'pt', name: 'a\u0007b', translations: {} }, {}, /language name/)
  bad({ code: 'pt', name: 'x'.repeat(81), translations: {} }, {}, /language name/)
  bad({ code: 'pt', name: 'x' }, {}, /translations/)
  bad({ code: 'pt', name: 'x', translations: { Nope: 'x' } }, {}, /Unknown/)
  bad({ code: 'pt', name: 'x', translations: { Save: 'x'.repeat(LIMITS.valueBytes + 1) } }, {}, /Invalid translation/)
  bad({ code: 'pt', name: 'x', translations: { Save: 'a\u0000b' } }, {}, /Invalid translation/)
  bad({ code: 'pt', name: 'x', translations: { 'Max {n} MB per share': 'Max' } }, {}, /placeholders/)
  bad({ code: 'pt', name: 'x', translations: { 'Max {n} MB per share': 'Max {m}' } }, {}, /placeholders/)
  bad({ code: 'pt', name: 'x', translations: {} }, { existingCodes: Array.from({ length: 32 }, (_, i) => 'aa-' + 'b'.repeat(2) + i) }, /Too many languages/)
  bad(' '.repeat(LIMITS.fileBytes + 1), {}, /1 MiB/)
})
test('parseImport allows replacing an existing custom language at the limit', () => {
  const existing = Array.from({ length: 32 }, (_, i) => 'xx-ab' + i)
  assert.equal(parseImport(file({ code: 'xx-ab3', name: 'x', translations: {} }), { ...opts, existingCodes: existing }).ok, true)
})
