// SPDX-License-Identifier: AGPL-3.0-or-later

// Colour contrast helpers (WCAG 2 relative luminance), dependency-free for Node tests.
import { tr } from './i18n/mark.mjs'

// Accepts #rgb, #rgba, #rrggbb and #rrggbbaa; returns #rrggbb (alpha dropped) or null.
export function normalizeHex(color) {
  if (typeof color !== 'string' || !/^#(?:[\da-f]{3}|[\da-f]{4}|[\da-f]{6}|[\da-f]{8})$/i.test(color.trim())) return null
  let hex = color.trim().slice(1)
  if (hex.length <= 4) hex = [...hex.slice(0, 3)].map(c => c + c).join('')
  return '#' + hex.slice(0, 6).toLowerCase()
}

export function luminance(color) {
  const hex = normalizeHex(color)
  if (!hex) return null
  const [r, g, b] = [1, 3, 5].map(i => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  })
  return r * 0.2126 + g * 0.7152 + b * 0.0722
}

// Contrast ratio between two colours (1 to 21), or null when one is not a valid hex colour.
export function contrastRatio(a, b) {
  const la = luminance(a), lb = luminance(b)
  if (la === null || lb === null) return null
  const [hi, lo] = la > lb ? [la, lb] : [lb, la]
  return (hi + 0.05) / (lo + 0.05)
}

// Pick the higher-contrast foreground (black or white) for a background colour.
export function contrastText(color) {
  const l = luminance(color)
  if (l === null) return '#ffffff'
  return (l + 0.05) / 0.05 >= 1.05 / (l + 0.05) ? '#000000' : '#ffffff'
}

export const MIN_TEXT_CONTRAST = 4.5

// The colour pairs the theme editor checks. primary-text is derived, as applyTheme does.
const PAIRS = [
  { key: 'text-bg', label: tr('Text on background'), fg: d => d.text, bg: d => d.bg },
  { key: 'text-surface', label: tr('Text on surface'), fg: d => d.text, bg: d => d.surface },
  { key: 'primary-text', label: tr('Button text on primary colour'), fg: d => contrastText(d.primary), bg: d => d.primary },
  { key: 'muted-surface', label: tr('Muted text on surface'), fg: d => d.muted, bg: d => d.surface },
]
export function themeContrastChecks(data = {}) {
  return PAIRS.map(p => {
    const ratio = contrastRatio(p.fg(data), p.bg(data))
    return { key: p.key, label: p.label, ratio, ok: ratio === null ? null : ratio >= MIN_TEXT_CONTRAST }
  })
}
// "4.5:1" style, rounded down so 4.49 never shows as passing 4.5.
export const formatRatio = r => (Math.floor(r * 10) / 10).toFixed(1) + ':1'
