// SPDX-License-Identifier: AGPL-3.0-or-later

// Base domain of multi-tenant mode, edited as two fields (host and port) and
// stored as today: "host" or "host:port" (SENDORA_BASE_DOMAIN stays compatible).

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

// splitHostPort accepts what an administrator types or pastes ("https://x.example:8443/path",
// "x.example:8443", "x.example") and returns { host, port }; the port is '' when absent.
export function splitHostPort(input) {
  let s = String(input || '').trim().toLowerCase()
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
  s = s.replace(/[/?#].*$/, '').replace(/^.*@/, '')
  let port = ''
  const m = s.match(/^(.*):(\d*)$/)
  if (m && !m[1].includes(':')) { s = m[1]; port = m[2] }
  return { host: s.replace(/\.$/, ''), port }
}

// validHost mirrors the server (platform.NormalizeDomain on "x.<host>"): DNS
// labels, single-label names such as "localhost" allowed as a base domain.
export function validHost(host, { minLabels = 1 } = {}) {
  const h = String(host || '')
  if (!h || h.length > 253) return false
  const labels = h.split('.')
  return labels.length >= minLabels && labels.every(l => LABEL.test(l))
}

export function validPort(port) {
  if (port === '' || port == null) return true
  return /^\d{1,5}$/.test(String(port)) && Number(port) >= 1 && Number(port) <= 65535
}

// joinHostPort is the stored form; the default ports are left out.
export function joinHostPort(host, port) {
  const p = String(port || '').trim()
  return p && p !== '80' && p !== '443' ? `${host}:${p}` : host
}

// defaultPort prefills the port from the address the administrator uses
// (location.port is '' for 80/443).
export function defaultPort(locationPort) {
  const p = String(locationPort || '')
  return p === '80' || p === '443' ? '' : p
}

const isLocal = host => host === 'localhost' || host.endsWith('.localhost')

// platformURLs are the addresses after the conversion (http only for localhost names).
export function platformURLs(host, port, slug) {
  if (!validHost(host)) return null
  const scheme = isLocal(host) ? 'http' : 'https'
  const base = joinHostPort(host, port)
  return { console: `${scheme}://admin.${base}`, org: slug ? `${scheme}://${slug}.${base}` : '' }
}

// portWarning: the port of the base domain differs from the one this page is
// served on (likely missing ports in every generated link); '' when fine.
export function portWarning(port, locationPort) {
  const want = defaultPort(locationPort)
  const have = defaultPort(port)
  if (want === have) return ''
  return want ? 'missing-port' : 'extra-port'
}
