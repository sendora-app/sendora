// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { safeNext } from './nav.mjs'

test('local paths are kept', () => {
  assert.equal(safeNext('/shares'), '/shares')
  assert.equal(safeNext('/admin/users?x=1#y'), '/admin/users?x=1#y')
})

test('protocol-relative, backslash and absolute targets fall back to the start page', () => {
  for (const v of ['//evil.example', '/\\evil.example', '\\\\evil.example', 'https://evil.example', 'javascript:alert(1)', '/\t/evil.example', '/ok\\evil', '', undefined, null]) {
    assert.equal(safeNext(v), '/', String(v))
  }
})

test('an array query value uses its first entry', () => {
  assert.equal(safeNext(['/shares', '//x']), '/shares')
  assert.equal(safeNext(['//x']), '/')
})
