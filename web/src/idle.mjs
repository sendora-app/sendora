// SPDX-License-Identifier: AGPL-3.0-or-later

// Inactivity monitor with injectable clock/storage so it can be unit tested.
// Activity is shared between tabs through a timestamp in localStorage (when
// available). While a transfer is running the user counts as active and the
// session is refreshed periodically so the server never sees it as abandoned.

export const ACTIVITY_KEY = 'sendora_last_activity'
export const WARN_MS = 60 * 1000
export const REFRESH_EVERY_MS = 10 * 60 * 1000
const WRITE_THROTTLE_MS = 1000

export function safeStorage() {
  const memory = new Map()
  let real = null
  try { real = typeof localStorage !== 'undefined' ? localStorage : null } catch { real = null }
  return {
    get(key) {
      try { if (real) { const v = real.getItem(key); if (v !== null) return v } } catch {}
      return memory.has(key) ? memory.get(key) : null
    },
    set(key, value) {
      memory.set(key, String(value))
      try { real?.setItem(key, String(value)) } catch {}
    },
  }
}

export function createIdleMonitor({
  now = () => Date.now(),
  storage = safeStorage(),
  key = ACTIVITY_KEY,
  limitMs = 0,
  warnMs = WARN_MS,
  refreshEveryMs = REFRESH_EVERY_MS,
  isBusy = () => false,
  doRefresh = async () => {},
  onWarn = () => {},
  onClear = () => {},
  onTimeout = () => {},
} = {}) {
  let last = now()
  let lastWrite = 0
  let lastRefresh = now()
  let warning = false
  let fired = false

  const stored = () => { const n = Number(storage.get(key)); return Number.isFinite(n) && n > 0 ? n : 0 }
  const write = t => { last = t; lastWrite = t; storage.set(key, t) }

  function record() {
    const t = now()
    if (t - lastWrite >= WRITE_THROTTLE_MS) write(t); else last = t
  }

  const api = {
    // Passive activity (mouse, keys, scroll). Ignored while the warning is open:
    // only the explicit "Stay signed in" button, or activity in another tab,
    // dismisses it.
    activity() { if (!warning && !fired) record() },
    // Explicit "Stay signed in".
    stay() { if (fired) return; write(now()); if (warning) { warning = false; onClear() } },
    setLimit(ms) { limitMs = Math.max(0, Number(ms) || 0); if (limitMs === 0 && warning) { warning = false; onClear() } },
    get limitMs() { return limitMs },
    get warning() { return warning },
    get fired() { return fired },
    secondsLeft() { return Math.max(0, Math.ceil((limitMs - (now() - Math.max(last, stored()))) / 1000)) },
    reset() { fired = false; warning = false; write(now()); lastRefresh = now() },
    tick() {
      if (fired) return
      const t = now()
      if (isBusy(t)) {
        // A running upload/download is activity; keep the session alive.
        write(t)
        if (warning) { warning = false; onClear() }
        if (t - lastRefresh >= refreshEveryMs) { lastRefresh = t; Promise.resolve(doRefresh()).catch(() => {}) }
        return
      }
      lastRefresh = t
      if (limitMs <= 0) { if (warning) { warning = false; onClear() } return }
      const seen = Math.max(last, stored())
      last = seen
      const idle = t - seen
      if (idle >= limitMs) { fired = true; warning = false; onTimeout(); return }
      if (idle >= limitMs - warnMs) { warning = true; onWarn(Math.max(1, Math.ceil((limitMs - idle) / 1000))); return }
      if (warning) { warning = false; onClear() }
    },
  }
  write(now())
  return api
}

// The inactivity window in minutes for a session: administrators get the stricter
// of idle_logout_minutes and admin_idle_logout_minutes (0 there = same as everyone).
// Mirrors effectiveIdleMinutes in internal/app/stepup.go.
export function effectiveIdleMinutes(global, admin, isAdmin) {
  const g = Number.isFinite(Number(global)) && Number(global) > 0 ? Number(global) : 0
  const a = Number.isFinite(Number(admin)) && Number(admin) > 0 ? Number(admin) : 0
  if (!isAdmin || a === 0) return g
  return g === 0 || a < g ? a : g
}
