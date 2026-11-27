// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { shouldPromptMFA, mfaPromptKey, reminderSuppressed, DAY_MS } from './mfa-prompt.mjs'

const boot = { mfa_policy: 'optional', mfa_totp_enabled: true, mfa_webauthn_enabled: false }
const user = { id: 3, mfa_enabled: false }
const base = { user, hasPassword: true, boot, dismissed: false }

test('asks a local account without a second factor', () => {
  assert.equal(shouldPromptMFA(base), true)
})

test('does not ask accounts that sign in through an identity provider only', () => {
  assert.equal(shouldPromptMFA({ ...base, hasPassword: false }), false)
})

test('does not ask when a factor exists, when enrolment is already forced, or after dismissal', () => {
  assert.equal(shouldPromptMFA({ ...base, user: { ...user, mfa_enabled: true } }), false)
  assert.equal(shouldPromptMFA({ ...base, user: { ...user, mfa_enroll_required: true } }), false)
  assert.equal(shouldPromptMFA({ ...base, dismissed: true }), false)
})

test('does not ask while a password change is still required', () => {
  assert.equal(shouldPromptMFA({ ...base, user: { ...user, must_change_password: true } }), false)
  assert.equal(shouldPromptMFA({ ...base, user: { ...user, must_change_password: false } }), true)
})

test('does not ask guests, or when no method can be enrolled; auditors are asked', () => {
  assert.equal(shouldPromptMFA({ ...base, user: { ...user, is_guest: true } }), false)
  assert.equal(shouldPromptMFA({ ...base, user: { ...user, auditor: true } }), true) // auditors can enrol their own factor
  assert.equal(shouldPromptMFA({ ...base, boot: { mfa_totp_enabled: false, mfa_webauthn_enabled: false } }), false)
  assert.equal(shouldPromptMFA({ ...base, user: null }), false)
})

test('dismissal is remembered per user', () => {
  assert.notEqual(mfaPromptKey(1), mfaPromptKey(2))
})

test('a dismissed reminder returns after the configured number of days', () => {
  const now = 1_000_000_000_000
  const at = now - (DAY_MS - 1000) // dismissed just under a day ago
  assert.equal(reminderSuppressed({ days: 1, dismissedAt: at, now }), true)
  assert.equal(reminderSuppressed({ days: 1, dismissedAt: now - DAY_MS - 1000, now }), false)
  assert.equal(reminderSuppressed({ days: 7, dismissedAt: now - 3 * DAY_MS, now }), true)
  assert.equal(reminderSuppressed({ days: 7, dismissedAt: now - 8 * DAY_MS, now }), false)
  assert.equal(reminderSuppressed({ days: 1, dismissedAt: 0, now }), false)
})

test('with 0 days the reminder only stays away for the browser session', () => {
  assert.equal(reminderSuppressed({ days: 0, dismissedAt: Date.now(), sessionDismissed: false }), false)
  assert.equal(reminderSuppressed({ days: 0, dismissedAt: 0, sessionDismissed: true }), true)
})

test('no reminder when two-step verification is switched off by policy', () => {
  assert.equal(shouldPromptMFA({ ...base, boot: { ...boot, mfa_policy: 'off' } }), false)
  assert.equal(shouldPromptMFA({ ...base, boot: { ...boot, mfa_policy: 'admins' } }), true)
})
