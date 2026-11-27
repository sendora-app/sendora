// SPDX-License-Identifier: AGPL-3.0-or-later

// Dependency-free helpers for runtime UI translations (safe to import from Node tests).
// The English text is the key. A language is a dictionary of overrides that is merged
// over the bundled dictionary: stored/custom text -> bundled text -> the English key.
// The limits and checks mirror the server (internal/app/ui_languages.go).
import { tr } from './i18n/mark.mjs'

export const LIMITS = { languages: 32, keys: 3000, valueBytes: 2000, nameBytes: 80, fileBytes: 1 << 20 }
export const CODE_PATTERN = /^[a-z]{2,3}(-[a-z0-9]{2,8}){0,2}$/
const PLACEHOLDER = /\{[A-Za-z0-9_]+\}|%[sdqvw]/g
const has = (o, k) => o != null && Object.prototype.hasOwnProperty.call(o, k)
const bytes = s => new TextEncoder().encode(s).length

export const placeholderList = s => (String(s).match(PLACEHOLDER) || []).sort()
export function samePlaceholders(a, b) {
  const x = placeholderList(a), y = placeholderList(b)
  return x.length === y.length && x.every((p, i) => p === y[i])
}

// Lookup order: stored/custom override, bundled dictionary, the English key itself.
export function lookup(key, override, bundled) {
  if (has(override, key) && typeof override[key] === 'string' && override[key] !== '') return override[key]
  if (has(bundled, key) && typeof bundled[key] === 'string' && bundled[key] !== '') return bundled[key]
  return key
}

export function interpolate(text, vars) {
  if (vars) for (const k in vars) text = text.replaceAll('{' + k + '}', vars[k])
  return text
}

// Complete export for translators: every known key with its current text.
export function buildExport({ code, name, keys, override, bundled }) {
  const translations = {}
  for (const key of keys) translations[key] = lookup(key, override, bundled)
  return { code, name, translations }
}

// Entries that equal the effective bundled text (or the key) are not worth storing.
export function stripRedundant(translations, bundled) {
  const out = {}
  for (const [key, value] of Object.entries(translations)) {
    if (value !== lookup(key, null, bundled)) out[key] = value
  }
  return out
}

export function validName(name) {
  return typeof name === 'string' && name !== '' && bytes(name) <= LIMITS.nameBytes && name.trim() === name && !/[\p{Cc}\p{Cf}]/u.test(name)
}
export function validValue(value) {
  return typeof value === 'string' && bytes(value) <= LIMITS.valueBytes && !/[\p{Cc}\p{Cf}]/u.test(value.replace(/[\n\t]/g, '').replace(/[‌‍]/g, ''))
}

const clip = s => (s.length > 60 ? s.slice(0, 60) + '…' : s)

// Parse and check an import file. Returns { ok, error, code, name, translations } where
// error is an English message (translated by the caller through t()).
export function parseImport(text, { knownKeys, builtinNames = {}, existingCodes = [], forceCode } = {}) {
  const fail = (error, vars) => ({ ok: false, error, vars })
  if (bytes(text) > LIMITS.fileBytes) return fail(tr('The file is larger than 1 MiB.'))
  let data
  try { data = JSON.parse(text) } catch { return fail(tr('The file is not valid JSON.')) }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return fail(tr('The file must contain a JSON object with code, name and translations.'))
  const code = forceCode || data.code
  if (typeof code !== 'string' || !CODE_PATTERN.test(code)) return fail(tr('Invalid language code (for example nl, pt-br or zh-hant).'))
  const name = has(builtinNames, code) ? builtinNames[code] : data.name
  if (!validName(name)) return fail(tr('Invalid language name (1 to 80 characters, no control characters).'))
  if (!has(builtinNames, code) && !existingCodes.includes(code) && existingCodes.length >= LIMITS.languages) return fail(tr('Too many languages (at most 32).'))
  const dict = data.translations
  if (!dict || typeof dict !== 'object' || Array.isArray(dict)) return fail(tr('The file must contain a "translations" object.'))
  const entries = Object.entries(dict)
  if (entries.length > LIMITS.keys) return fail(tr('Too many translations (at most 3000).'))
  const known = knownKeys instanceof Set ? knownKeys : new Set(knownKeys)
  for (const [key, value] of entries) {
    if (!known.has(key)) return fail(tr('Unknown translation key: {key}'), { key: clip(key) })
    if (!validValue(value)) return fail(tr('Invalid translation (too long or invalid characters) for key {key}'), { key: clip(key) })
    if (!samePlaceholders(key, value)) return fail(tr('The placeholders of the translation for {key} do not match the original'), { key: clip(key) })
  }
  return { ok: true, code, name, translations: Object.fromEntries(entries) }
}
