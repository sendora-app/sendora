// SPDX-License-Identifier: AGPL-3.0-or-later

// Pure helpers for the admin theme editor: hex handling and the live-preview data.
export const themeColorKeys = ['primary', 'bg', 'surface', 'text', 'muted', 'border', 'danger']
export const isHex = value => typeof value === 'string' && /^#(?:[\da-f]{3}|[\da-f]{4}|[\da-f]{6}|[\da-f]{8})$/i.test(value)

// <input type=color> only accepts #rrggbb; expand short forms and drop alpha for the swatch.
export function swatchHex(value, fallback = '#000000') {
  if (!isHex(value)) return fallback
  let hex = value.slice(1, value.length <= 5 ? 4 : 7)
  if (hex.length === 3) hex = [...hex].map(c => c + c).join('')
  return '#' + hex.toLowerCase()
}

// Theme data for live preview: invalid (half typed) values fall back to the base theme value.
export function previewData(draft, base = {}) {
  const out = {}
  for (const k of themeColorKeys) {
    const v = [draft?.[k], base?.[k]].find(isHex)
    if (v) out[k] = v
  }
  return out
}

const norm = n => String(n).trim().toLowerCase()
// Suggest a name for a copy of a bundled theme that does not clash with existing names.
export function copyName(name, existing) {
  const taken = new Set(existing.map(norm))
  let candidate = `${name} (copy)`, i = 2
  while (taken.has(norm(candidate))) candidate = `${name} (copy ${i++})`
  return candidate
}
export const nameClashes = (name, existing, ownName = null) => norm(name) !== norm(ownName ?? '') && existing.some(e => norm(e) === norm(name))
