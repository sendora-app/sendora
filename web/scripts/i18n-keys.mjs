// SPDX-License-Identifier: AGPL-3.0-or-later

// Static i18n key extractor (no dependencies).
//   node scripts/i18n-keys.mjs          rewrite src/i18n/keys.json
//   node scripts/i18n-keys.mjs --check  fail when keys.json is out of date
// Finds t('…'), t("…"), t(`…` without ${}) and the markers tr('…') / terr('…') used for
// strings that are only looked up dynamically. English text is the key.
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
export const srcDir = join(here, '..', 'src')
export const keysFile = join(srcDir, 'i18n', 'keys.json')

function* walk(dir) {
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) { if (name !== 'assets') yield* walk(path) } else yield path
  }
}

function unescapeLiteral(body) {
  return body.replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|n|r|t|.)/g, (_, c) => {
    if (c[0] === 'u' && c.length === 5) return String.fromCharCode(parseInt(c.slice(1), 16))
    if (c[0] === 'x' && c.length === 3) return String.fromCharCode(parseInt(c.slice(1), 16))
    return c === 'n' ? '\n' : c === 'r' ? '\r' : c === 't' ? '\t' : c
  })
}

const CALL = /(?<![\w$.])(?:t|tr|terr)\(\s*(?:'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"|`((?:[^`\\$]|\\.|\$(?!\{))*)`)/g

export function extractKeys(dir = srcDir) {
  const keys = new Set()
  for (const file of walk(dir)) {
    if (!/\.(vue|js|mjs)$/.test(file) || /\.test\.mjs$/.test(file)) continue
    const source = readFileSync(file, 'utf8')
    for (const m of source.matchAll(CALL)) {
      const raw = m[1] ?? m[2] ?? m[3]
      if (raw === undefined) continue
      const key = unescapeLiteral(raw)
      if (key.trim()) keys.add(key)
    }
  }
  return [...keys].sort((a, b) => a.localeCompare(b, 'en') || (a < b ? -1 : 1))
}

export function placeholders(text) {
  return [...String(text).matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort()
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const keys = extractKeys()
  const next = JSON.stringify(keys, null, 1) + '\n'
  if (process.argv.includes('--check')) {
    let current = ''
    try { current = readFileSync(keysFile, 'utf8') } catch {}
    if (current !== next) { console.error('src/i18n/keys.json is out of date; run: node scripts/i18n-keys.mjs'); process.exit(1) }
    console.log(keys.length + ' keys, keys.json up to date')
  } else {
    writeFileSync(keysFile, next)
    console.log('wrote ' + keys.length + ' keys to src/i18n/keys.json')
  }
}
