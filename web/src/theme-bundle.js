// SPDX-License-Identifier: AGPL-3.0-or-later

import { terr } from './i18n/mark.mjs'
export const themeKeys = ['primary', 'bg', 'surface', 'text', 'muted', 'border', 'danger']
const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value)
export function validateThemeBundle(bundle) {
  if (!plainObject(bundle) || Object.keys(bundle).some(key => !['name', 'data'].includes(key))) throw terr('Invalid theme JSON: expected name and data only.')
  if (typeof bundle.name !== 'string' || !bundle.name.trim() || new TextEncoder().encode(bundle.name).length > 80 || /[\u0000-\u001f\u007f-\u009f]/.test(bundle.name)) throw terr('Theme name must contain 1–80 bytes and no control characters.')
  if (!plainObject(bundle.data) || Object.keys(bundle.data).length !== themeKeys.length || themeKeys.some(key => !Object.hasOwn(bundle.data, key))) throw terr('Theme must contain all seven colors and no extra fields.')
  const data = {}
  for (const key of themeKeys) {
    if (typeof bundle.data[key] !== 'string' || !/^#(?:[\da-f]{3}|[\da-f]{4}|[\da-f]{6}|[\da-f]{8})$/i.test(bundle.data[key])) throw terr('Every theme color must be a valid hex color, for example #1a2b3c.')
    data[key] = bundle.data[key]
  }
  return { name: bundle.name.trim(), data }
}
export function serializeThemeBundle(theme) {
  return JSON.stringify(validateThemeBundle({ name: theme.name, data: theme.data }), null, 2) + '\n'
}
