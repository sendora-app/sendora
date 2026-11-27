// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'
import { extractKeys, placeholders } from '../scripts/i18n-keys.mjs'

const dir = join(dirname(fileURLToPath(import.meta.url)), 'i18n')
const load = name => JSON.parse(readFileSync(join(dir, name), 'utf8'))
const langs = ['nl', 'de', 'fr', 'es']
const keys = load('keys.json')
const server = load('server-messages.json').static || []
const admin = load('languages-admin.json') // merged over the language files by index.js
const all = [...new Set([...keys, ...server])]

test('keys.json matches the keys found in the sources', () => {
  assert.deepEqual(extractKeys(), keys)
})

// Only English (the keys themselves) and Dutch are shipped complete. German, French
// and Spanish are partial on purpose: missing texts fall back to English, and
// administrators or users can complete or add any language through Admin -> Languages
// (JSON import). Every language that does have a text must keep the placeholders.
test('nl: every key is translated', () => {
  const dict = { ...load('nl.json'), ...(admin.nl || {}) }
  assert.deepEqual(all.filter(k => !(k in dict) || !String(dict[k]).trim()), [])
})

for (const lang of langs) {
  const dict = { ...load(lang + '.json'), ...(admin[lang] || {}) }
  test(`${lang}: placeholders match the English text`, () => {
    for (const [k, v] of Object.entries(dict)) {
      assert.deepEqual(placeholders(v), placeholders(k), k)
    }
  })
}

// Example files in custom-translations/ must stay importable: known keys, same placeholders.
import { existsSync, readdirSync } from 'node:fs'
test('custom-translations examples are valid', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'custom-translations')
  if (!existsSync(root)) return
  const known = new Set([...all, ...(load('server-messages.json').dynamic || [])])
  for (const d of readdirSync(root, { withFileTypes: true }).filter(e => e.isDirectory())) {
    const f = join(root, d.name, `sendora-ui-${d.name}.json`)
    if (!existsSync(f)) continue
    const j = JSON.parse(readFileSync(f, 'utf8'))
    assert.equal(j.code, d.name)
    for (const [k, v] of Object.entries(j.translations)) {
      assert.ok(known.has(k), `unknown key in ${d.name}: ${k}`)
      assert.deepEqual(placeholders(v).sort(), placeholders(k).sort(), `placeholders differ for ${k}`)
    }
  }
})
