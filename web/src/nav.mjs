// SPDX-License-Identifier: AGPL-3.0-or-later

// A post-login redirect target must stay inside this app: a single leading "/"
// followed by a path. Protocol-relative ("//host", "/\host") and absolute URLs
// would send the user to another site after signing in.
export function safeNext(raw) {
  if (Array.isArray(raw)) raw = raw[0]
  const v = raw == null ? '' : String(raw)
  if (!v.startsWith('/') || v.startsWith('//') || v.startsWith('/\\') || /[\u0000-\u001f\u007f\\]/.test(v)) return '/'
  return v
}
