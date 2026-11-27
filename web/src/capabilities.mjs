// SPDX-License-Identifier: AGPL-3.0-or-later

// Feature availability from GET /api/capabilities (docs/CAPABILITIES.md): the
// server says which features its flavour offers, so screens show or hide them
// from one source instead of scattered multi-tenant checks.

// featureAvailable reports whether feature id is available. When the
// capabilities could not be loaded (older server, network error) or do not
// name the feature, fallback decides, so a missing answer never changes what
// the screen showed before.
export function featureAvailable(caps, id, fallback) {
  const f = caps && caps.features && Object.prototype.hasOwnProperty.call(caps.features, id) ? caps.features[id] : null
  if (!f || typeof f.available !== 'boolean') return fallback
  return f.available
}

// featureReason is the server's explanation for an unavailable feature ('' if none).
export function featureReason(caps, id) {
  const f = caps && caps.features && Object.prototype.hasOwnProperty.call(caps.features, id) ? caps.features[id] : null
  return f && !f.available && typeof f.reason === 'string' ? f.reason : ''
}

// loadCapabilities fetches the capabilities with get (the api helper); null on
// any failure, so boot never fails because of them.
export async function loadCapabilities(get) {
  try {
    const c = await get('/capabilities')
    return c && typeof c === 'object' && c.features && typeof c.features === 'object' ? c : null
  } catch {
    return null
  }
}
