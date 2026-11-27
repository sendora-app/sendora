// SPDX-License-Identifier: AGPL-3.0-or-later

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { shouldShowExpiryBanner, localDay, expiryDismissKey, EXPIRY_BANNER_DAYS } from './password-expiry.mjs'

test('banner from 14 days before expiry', () => {
  assert.equal(EXPIRY_BANNER_DAYS, 14)
  assert.equal(shouldShowExpiryBanner({ days: 15, today: '2026-01-01' }), false)
  assert.equal(shouldShowExpiryBanner({ days: 14, today: '2026-01-01' }), true)
  assert.equal(shouldShowExpiryBanner({ days: 0, today: '2026-01-01' }), true)
})

test('no banner when the policy does not apply or a change is already forced', () => {
  assert.equal(shouldShowExpiryBanner({ days: undefined }), false)
  assert.equal(shouldShowExpiryBanner({ days: null }), false)
  assert.equal(shouldShowExpiryBanner({ days: 'x' }), false)
  assert.equal(shouldShowExpiryBanner({ days: 3, mustChange: true }), false)
})

test('dismissed for the rest of the day', () => {
  assert.equal(shouldShowExpiryBanner({ days: 3, dismissedDay: '2026-01-01', today: '2026-01-01' }), false)
  assert.equal(shouldShowExpiryBanner({ days: 3, dismissedDay: '2026-01-01', today: '2026-01-02' }), true)
})

test('local day and key', () => {
  assert.equal(localDay(new Date(2026, 0, 5, 23, 59)), '2026-01-05')
  assert.equal(expiryDismissKey(7), 'sendora.pwexpiry.dismissed.7')
})
