// SPDX-License-Identifier: AGPL-3.0-or-later

// Dependency-free i18n helpers, safe to import from plain Node tests.
//   tr('English text')   marks a string that is only looked up dynamically (no-op at
//                        runtime; the key extractor finds it).
//   terr('English text') creates an Error whose message is translated at throw time.
// i18n/index.js registers the real translator; until then messages stay English.
let translator = s => s
export const tr = s => s
export const setTranslator = fn => { translator = typeof fn === 'function' ? fn : (s => s) }
export const translateMessage = s => translator(s)
export const terr = s => new Error(translator(s))

// Server messages with values (Go's %s, %d, %q, %v, %w) arrive already filled in,
// e.g. "backup_keep must be a whole number from 1 to 365". dynamicMatcher turns the
// known patterns into matchers; translateDynamic finds the pattern, translates it and
// puts the values back per verb type in their original order (so a translation may
// move a %s before a %d).
const VERB = /%[sdqvw]/g
export function dynamicMatcher(patterns) {
  return (patterns || []).map(p => {
    const verbs = p.match(VERB) || []
    const body = p.split(VERB).map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    let src = '^' + body[0]
    verbs.forEach((v, i) => { src += (v === '%d' ? '(-?\\d+)' : '(.+?)') + body[i + 1] })
    return { pattern: p, verbs, re: new RegExp(src + '$', 's') }
  })
}
export function translateDynamic(msg, matchers, translate) {
  for (const { pattern, verbs, re } of matchers) {
    const m = re.exec(msg)
    if (!m) continue
    const translated = translate(pattern)
    if (translated === pattern) return msg
    const queues = {}
    verbs.forEach((v, i) => { (queues[v] = queues[v] || []).push(m[i + 1]) })
    return translated.replace(VERB, v => (queues[v] && queues[v].length ? queues[v].shift() : v))
  }
  return msg
}
