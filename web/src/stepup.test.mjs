// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { isStepUpResponse, stepUpChoices, stepUpBody } from './stepup.mjs'
import { effectiveIdleMinutes } from './idle.mjs'

test('recognises the step-up answer', () => {
  assert.equal(isStepUpResponse({ error: 're-authentication required', code: 'stepup_required' }), true)
  assert.equal(isStepUpResponse({ error: 'unauthorized' }), false)
  assert.equal(isStepUpResponse(null), false)
})

test('prefers the second factor and hides passkeys where unsupported', () => {
  assert.deepEqual(stepUpChoices({ methods: ['totp', 'webauthn'] }, true), { mode: 'totp', methods: ['totp', 'webauthn'] })
  assert.deepEqual(stepUpChoices({ methods: ['webauthn'] }, false), { mode: 'reauth', methods: [] })
  assert.deepEqual(stepUpChoices({ methods: ['webauthn'] }, true), { mode: 'webauthn', methods: ['webauthn'] })
  assert.deepEqual(stepUpChoices({ methods: ['password'] }), { mode: 'password', methods: ['password'] })
  assert.equal(stepUpChoices({ methods: [], reauth: true }).mode, 'reauth')
  assert.equal(stepUpChoices({ methods: ['password'], reauth: true }).mode, 'reauth')
})

test('builds the confirmation body', () => {
  assert.deepEqual(stepUpBody('totp', ' 123 456 '), { code: '123456' })
  assert.deepEqual(stepUpBody('password', 'pw'), { password: 'pw' })
  assert.deepEqual(stepUpBody('webauthn'), {})
})

test('administrators get the stricter inactivity window', () => {
  assert.equal(effectiveIdleMinutes(60, 15, true), 15)
  assert.equal(effectiveIdleMinutes(60, 15, false), 60)
  assert.equal(effectiveIdleMinutes(0, 15, true), 15)
  assert.equal(effectiveIdleMinutes(10, 15, true), 10)
  assert.equal(effectiveIdleMinutes(60, 0, true), 60)
  assert.equal(effectiveIdleMinutes(undefined, undefined, true), 0)
})
