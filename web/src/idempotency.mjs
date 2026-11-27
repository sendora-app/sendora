// SPDX-License-Identifier: AGPL-3.0-or-later

// Idempotency keys for mutating requests (docs/cluster/DESIGN.md 4.1, D29).
// Sendora's own UI sends one key per user action on every POST, PUT, PATCH and
// DELETE, and reuses it for every retry of that action. The server replays the
// stored response for a retry instead of running the action twice.
//
// Retries: when the server cannot tell whether a commit survived (503 with
// Sendora-Outcome: unknown, for example during a database failover) or when
// the first attempt of the same action is still running (409 with
// Sendora-Idempotency: in-progress), the request is repeated with the same key
// up to three times over about a minute.

export const IDEMPOTENCY_HEADER = 'Idempotency-Key'
export const RETRY_DELAYS = [5000, 15000, 40000]

export const isMutating = method => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(String(method || 'GET').toUpperCase())

// A random UUID (version 4).
export function newIdempotencyKey(c = globalThis.crypto) {
  if (typeof c?.randomUUID === 'function') return c.randomUUID()
  const b = c.getRandomValues(new Uint8Array(16))
  b[6] = (b[6] & 0x0f) | 0x40
  b[8] = (b[8] & 0x3f) | 0x80
  const h = [...b].map(x => x.toString(16).padStart(2, '0')).join('')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

// Returns opts with an Idempotency-Key header for a mutating request (one key
// per call: the caller keeps the returned opts for every retry). An existing
// key is kept; opts.idempotencyKey === false opts out.
export function withIdempotencyKey(opts = {}, makeKey = newIdempotencyKey) {
  if (!isMutating(opts.method) || opts.idempotencyKey === false) return opts
  const headers = { ...(opts.headers || {}) }
  if (!Object.keys(headers).some(k => k.toLowerCase() === 'idempotency-key')) headers[IDEMPOTENCY_HEADER] = makeKey()
  return { ...opts, headers }
}

const header = (r, name) => r?.headers?.get?.(name) || ''

// The delay before retry number attempt (0-based) of response r, or -1 when
// r must not be retried.
export function retryDelay(r, attempt) {
  if (attempt >= RETRY_DELAYS.length || !r) return -1
  const unknown = r.status === 503 && header(r, 'sendora-outcome').toLowerCase() === 'unknown'
  const running = r.status === 409 && header(r, 'sendora-idempotency').toLowerCase() === 'in-progress'
  if (!unknown && !running) return -1
  const after = Number.parseInt(header(r, 'retry-after'), 10)
  return Math.max(RETRY_DELAYS[attempt], Number.isFinite(after) ? after * 1000 : 0)
}

const wait = ms => new Promise(resolve => setTimeout(resolve, ms))

// Sends once and repeats while retryDelay allows it. Only for requests that
// carry an Idempotency-Key (the server deduplicates them).
export async function sendWithOutcomeRetry(send, sleep = wait) {
  let r = await send()
  for (let attempt = 0; ; attempt++) {
    const d = retryDelay(r, attempt)
    if (d < 0) return r
    await sleep(d)
    r = await send()
  }
}
