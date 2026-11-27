// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { PROJECT_URL, PROJECT_NAME, sourceLink, attributionLabels } from './attribution.mjs'
import { lookup } from './ui-language.mjs'

test('sourceLink uses the server value for the running build', () => {
  assert.equal(sourceLink({ source_url: 'https://github.com/sendora-app/sendora/tree/v0.2.1' }), 'https://github.com/sendora-app/sendora/tree/v0.2.1')
  assert.equal(sourceLink({ source_url: 'https://git.example.com/fork/tree/abc1234' }), 'https://git.example.com/fork/tree/abc1234')
})

test('sourceLink falls back to the project, never to nothing', () => {
  for (const boot of [null, undefined, {}, { source_url: '' }, { source_url: '  ' }, { source_url: 42 },
    { source_url: 'javascript:alert(1)' }, { source_url: 'not a url' }, { source_url: 'https://u:p@example.com/' }]) {
    assert.equal(sourceLink(boot), PROJECT_URL, JSON.stringify(boot))
  }
})

// The footer component is used by the main app (signed-in and public pages,
// including shares) and by the platform console, and has no switch to hide it.
test('every app shell renders the attribution footer unconditionally', () => {
  const footer = readFileSync(new URL('./components/PoweredBy.vue', import.meta.url), 'utf8')
  assert.match(footer, /Powered by/)
  assert.match(footer, /Source code/)
  assert.doesNotMatch(footer, /v-if|v-show/)
  for (const shell of ['./App.vue', './platform/PlatformApp.vue']) {
    const src = readFileSync(new URL(shell, import.meta.url), 'utf8')
    assert.match(src, /<PoweredBy\b[^>]*>/, shell)
    assert.doesNotMatch(src, /<PoweredBy\b[^>]*v-(if|show)/, shell)
  }
})

// An imported or custom translation cannot remove the attribution or the source link.
test('empty or blank translations of the attribution fall back to English', () => {
  const bundled = { 'Powered by': 'Mogelijk gemaakt door', 'Source code': 'Broncode' }
  for (const override of [
    { 'Powered by': '', 'Source code': '' },
    { 'Powered by': '   ', 'Source code': '​​' },
    { 'Powered by': '­', 'Source code': ' · ' },
    { 'Powered by': 42, 'Source code': null },
  ]) {
    const labels = attributionLabels(key => lookup(key, override, {}))
    assert.deepEqual(labels, { poweredBy: 'Powered by', sourceCode: 'Source code' }, JSON.stringify(override))
    // Bundled translation present: an empty imported override falls back to it, still visible.
    const withBundled = attributionLabels(key => lookup(key, override, bundled))
    assert.ok(withBundled.poweredBy.trim() && withBundled.sourceCode.trim(), JSON.stringify(override))
  }
  assert.deepEqual(attributionLabels(key => lookup(key, {}, bundled)), { poweredBy: 'Mogelijk gemaakt door', sourceCode: 'Broncode' })
  assert.deepEqual(attributionLabels(() => { throw new Error('broken') }), { poweredBy: 'Powered by', sourceCode: 'Source code' })
  // An altered (non-empty) translation only changes the surrounding words.
  assert.deepEqual(attributionLabels(key => lookup(key, { 'Powered by': 'Hidden', 'Source code': 'x' }, bundled)), { poweredBy: 'Hidden', sourceCode: 'x' })
})

// "Sendora" and the link targets never pass through translation, the
// application name or a setting; the source link text is always present.
test('the brand name and link targets are fixed, not translated or configurable', () => {
  assert.equal(PROJECT_NAME, 'Sendora')
  const footer = readFileSync(new URL('./components/PoweredBy.vue', import.meta.url), 'utf8')
  const template = footer.slice(footer.indexOf('<template>'))
  assert.match(template, /<a :href="PROJECT_URL"[^>]*>\{\{ PROJECT_NAME \}\}<\/a>/)
  assert.match(template, /<a :href="source"[^>]*>\{\{ labels\.sourceCode \}\}<\/a>/)
  assert.doesNotMatch(template, /t\('Powered by'\)|t\('Source code'\)|application_name|t\('Sendora'\)/)
  assert.match(footer, /attributionLabels\(t\)/)
})
