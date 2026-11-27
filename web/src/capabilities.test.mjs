// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { featureAvailable, featureReason, loadCapabilities } from './capabilities.mjs'

const caps = {
  flavour: 'multi',
  features: {
    platform_console: { available: true, maturity: 'stable' },
    multi_tenant_conversion: { available: false, maturity: 'stable', reason: 'only in the single-tenant flavour' }
  }
}

test('the server answer decides', () => {
  assert.equal(featureAvailable(caps, 'platform_console', false), true)
  assert.equal(featureAvailable(caps, 'multi_tenant_conversion', true), false)
  assert.equal(featureReason(caps, 'multi_tenant_conversion'), 'only in the single-tenant flavour')
  assert.equal(featureReason(caps, 'platform_console'), '')
})

test('missing capabilities or features fall back', () => {
  for (const c of [null, undefined, {}, { features: null }, { features: {} }, { features: { x: { available: 'yes' } } }]) {
    assert.equal(featureAvailable(c, 'x', true), true)
    assert.equal(featureAvailable(c, 'x', false), false)
  }
  assert.equal(featureAvailable(caps, 'toString', true), true, 'prototype keys are not features')
})

test('loading never throws', async () => {
  assert.deepEqual(await loadCapabilities(async () => caps), caps)
  assert.equal(await loadCapabilities(async () => { throw new Error('offline') }), null)
  assert.equal(await loadCapabilities(async () => ({ error: 'x' })), null)
  assert.equal(await loadCapabilities(async p => { assert.equal(p, '/capabilities'); return null }), null)
})
