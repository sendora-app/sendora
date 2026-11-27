// SPDX-License-Identifier: AGPL-3.0-or-later

// Tracks running uploads/downloads so automatic sign-out never interrupts them.
// Transfers the page cannot observe (a download handed to the browser) are
// estimated from the file size instead.

export const NATIVE_MIN_MS = 60 * 1000
export const NATIVE_MAX_MS = 6 * 60 * 60 * 1000
export const NATIVE_ASSUMED_BYTES_PER_SECOND = 2 * 1024 * 1024

let active = 0
let nativeUntil = 0

// begin() returns an idempotent end() so a transfer is counted exactly once.
export function begin() {
  active++
  let ended = false
  return () => { if (!ended) { ended = true; active = Math.max(0, active - 1) } }
}

// track runs fn while counted as a transfer, balanced even when fn throws.
export async function track(fn) {
  const end = begin()
  try { return await fn() } finally { end() }
}

export function nativeBusyMs(sizeBytes) {
  const size = Number.isFinite(sizeBytes) && sizeBytes > 0 ? sizeBytes : 0
  return Math.min(Math.max(NATIVE_MIN_MS, (size / NATIVE_ASSUMED_BYTES_PER_SECOND) * 1000), NATIVE_MAX_MS)
}

export function markNative(sizeBytes, now = Date.now()) {
  nativeUntil = Math.max(nativeUntil, now + nativeBusyMs(sizeBytes))
}

export function isBusy(now = Date.now()) { return active > 0 || now < nativeUntil }
export function activeCount() { return active }

// For tests.
export function reset() { active = 0; nativeUntil = 0 }
