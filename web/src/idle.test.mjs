// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { createIdleMonitor, safeStorage, ACTIVITY_KEY } from './idle.mjs'
import * as transfers from './transfers.mjs'

const MIN = 60 * 1000
function setup(extra = {}) {
  const clock = { t: 1_000_000 }
  const map = new Map()
  const storage = { get: k => (map.has(k) ? map.get(k) : null), set: (k, v) => map.set(k, String(v)) }
  const events = []
  const monitor = createIdleMonitor({
    now: () => clock.t, storage, limitMs: 60 * MIN,
    isBusy: () => false, doRefresh: async () => events.push('refresh'),
    onWarn: s => events.push('warn:' + s), onClear: () => events.push('clear'), onTimeout: () => events.push('timeout'),
    ...extra,
  })
  return { clock, map, storage, events, monitor }
}

test('times out only after the full idle period with no activity', () => {
  const { clock, events, monitor } = setup()
  clock.t += 30 * MIN; monitor.tick()
  assert.deepEqual(events, [])
  clock.t += 30 * MIN; monitor.tick()
  assert.deepEqual(events, ['timeout'])
  assert.equal(monitor.fired, true)
  clock.t += 5 * MIN; monitor.tick()
  assert.deepEqual(events, ['timeout'], 'fires once')
})

test('activity resets the idle clock', () => {
  const { clock, events, monitor } = setup()
  clock.t += 59 * MIN; monitor.activity()
  clock.t += 59 * MIN; monitor.tick()
  assert.deepEqual(events.filter(e => e === 'timeout'), [])
  clock.t += 2 * MIN; monitor.tick()
  assert.ok(events.includes('timeout'))
})

test('no warning before the last minute', () => {
  const { clock, events, monitor } = setup()
  clock.t += 58 * MIN + 59 * 1000; monitor.tick()
  assert.deepEqual(events, [])
  clock.t += 1000; monitor.tick()
  assert.deepEqual(events, ['warn:60'], 'exactly 60 s left warns')
})

test('warning appears at limit minus 60 s', () => {
  const { clock, events, monitor } = setup()
  clock.t += 59 * MIN + 1000; monitor.tick()
  assert.equal(events.at(-1), 'warn:59')
  clock.t += 30 * 1000; monitor.tick()
  assert.equal(events.at(-1), 'warn:29')
  assert.equal(monitor.warning, true)
  monitor.stay()
  assert.equal(events.at(-1), 'clear')
  assert.equal(monitor.warning, false)
  clock.t += 30 * MIN; monitor.tick()
  assert.ok(!events.includes('timeout'))
})

test('passive activity does not dismiss the open warning', () => {
  const { clock, events, monitor } = setup()
  clock.t += 59 * MIN + 10 * 1000; monitor.tick()
  assert.equal(monitor.warning, true)
  monitor.activity()
  clock.t += 55 * 1000; monitor.tick()
  assert.ok(events.includes('timeout'), 'a stray mouse move must not cancel the warning')
})

test('a running transfer prevents sign-out, counts as activity and refreshes the session', async () => {
  let busy = true
  const { clock, events, monitor } = setup({ isBusy: () => busy })
  for (let i = 0; i < 12; i++) { clock.t += 15 * MIN; monitor.tick() }
  assert.ok(!events.includes('timeout'), 'three hours of transfer must not sign out')
  assert.equal(events.filter(e => e === 'refresh').length, 12, 'a refresh whenever 10 minutes have passed during a transfer')
  busy = false
  clock.t += 30 * MIN; monitor.tick()
  assert.ok(!events.includes('timeout'), 'idle time starts only when the transfer ends')
  clock.t += 31 * MIN; monitor.tick()
  assert.ok(events.includes('timeout'))
})

test('a transfer closes an open warning', () => {
  let busy = false
  const { clock, events, monitor } = setup({ isBusy: () => busy })
  clock.t += 59 * MIN + 5000; monitor.tick()
  assert.equal(monitor.warning, true)
  busy = true; monitor.tick()
  assert.equal(events.at(-1), 'clear')
})

test('activity in another tab (shared timestamp) postpones the sign-out here', () => {
  const { clock, map, events, monitor } = setup()
  clock.t += 50 * MIN
  map.set(ACTIVITY_KEY, String(clock.t)) // another tab was active just now
  clock.t += 20 * MIN; monitor.tick()
  assert.ok(!events.includes('timeout'))
  clock.t += 41 * MIN; monitor.tick()
  assert.ok(events.includes('timeout'))
})

test('limit 0 never signs out and clears a warning; changing the limit adapts', () => {
  const { clock, events, monitor } = setup()
  monitor.setLimit(0)
  clock.t += 24 * 60 * MIN; monitor.tick()
  assert.deepEqual(events, [])
  monitor.setLimit(10 * MIN)
  monitor.tick()
  assert.ok(events.includes('timeout'), 'a shorter limit applies to the existing idle time')
})

test('works without localStorage', () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'localStorage')
  Object.defineProperty(globalThis, 'localStorage', { get() { throw new Error('blocked') }, configurable: true })
  try {
    const storage = safeStorage()
    storage.set('k', 'v')
    assert.equal(storage.get('k'), 'v')
    const clock = { t: 5000 }
    const events = []
    const monitor = createIdleMonitor({ now: () => clock.t, storage, limitMs: 10 * MIN, onTimeout: () => events.push('timeout') })
    clock.t += 11 * MIN; monitor.tick()
    assert.deepEqual(events, ['timeout'])
  } finally {
    if (originalDescriptor) Object.defineProperty(globalThis, 'localStorage', originalDescriptor); else delete globalThis.localStorage
  }
})

test('reset after a new login clears the fired state', () => {
  const { clock, events, monitor } = setup()
  clock.t += 61 * MIN; monitor.tick()
  assert.equal(monitor.fired, true)
  monitor.reset()
  assert.equal(monitor.fired, false)
  clock.t += 10 * MIN; monitor.tick()
  assert.equal(events.filter(e => e === 'timeout').length, 1)
})

test('transfers counter is balanced, idempotent and survives errors', async () => {
  transfers.reset()
  assert.equal(transfers.isBusy(), false)
  const end = transfers.begin()
  assert.equal(transfers.isBusy(), true)
  end(); end()
  assert.equal(transfers.activeCount(), 0)
  await assert.rejects(transfers.track(async () => { assert.equal(transfers.isBusy(), true); throw new Error('boom') }), /boom/)
  assert.equal(transfers.activeCount(), 0)
  const results = await Promise.all([transfers.track(async () => { await null; return 1 }), transfers.track(async () => 2)])
  assert.deepEqual(results, [1, 2])
  assert.equal(transfers.activeCount(), 0)
})

test('native download busy estimate: floor 60 s, 2 MB/s, cap 6 h', () => {
  transfers.reset()
  assert.equal(transfers.nativeBusyMs(0), 60 * 1000)
  assert.equal(transfers.nativeBusyMs(10 * 1024 * 1024), 60 * 1000)
  assert.equal(transfers.nativeBusyMs(3 * 1024 ** 3), Math.round(3 * 1024 ** 3 / (2 * 1024 * 1024) * 1000))
  assert.equal(transfers.nativeBusyMs(1024 ** 5), 6 * 60 * 60 * 1000)
  assert.equal(transfers.nativeBusyMs(NaN), 60 * 1000)
  transfers.markNative(3 * 1024 ** 3, 1000)
  assert.equal(transfers.isBusy(1000 + 25 * 60 * 1000), true)
  assert.equal(transfers.isBusy(1000 + 26 * 60 * 1000), false)
  transfers.reset()
})
