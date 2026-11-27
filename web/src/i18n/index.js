// SPDX-License-Identifier: AGPL-3.0-or-later

import { ref, reactive, shallowReactive } from 'vue'
import { tr, setTranslator, dynamicMatcher, translateDynamic } from './mark.mjs'
import serverMessages from './server-messages.json'
import { lookup, interpolate, CODE_PATTERN } from '../ui-language.mjs'
import de from './de.json'
import fr from './fr.json'
import es from './es.json'
import nl from './nl.json'
import adminLanguages from './languages-admin.json'

// Bundled dictionaries. The strings of the Languages admin view live in their own file
// and are merged per language here.
const merge = (base, lang) => ({ ...base, ...(adminLanguages[lang] || {}) })
export const bundled = { en: {}, nl: merge(nl, 'nl'), de: merge(de, 'de'), fr: merge(fr, 'fr'), es: merge(es, 'es') }
export const builtinLanguages = { en: 'English', nl: 'Nederlands', de: 'Deutsch', fr: 'Français', es: 'Español' }
// Menu languages: built-in ones plus the custom languages an administrator imported.
export const languages = reactive({ ...builtinLanguages })
// Runtime overrides per language code, loaded from /api/i18n/{code}.
export const overrides = shallowReactive({})
const stored = new Set()

let saved = null
try { saved = localStorage.getItem('lang') } catch {}
const browser = navigator.language?.slice(0, 2)
export const lang = ref(saved && (bundled[saved] || CODE_PATTERN.test(saved)) ? saved : (bundled[browser] ? browser : 'en'))

async function fetchJSON(path, fresh) {
  const r = await fetch('/api/i18n/' + path, { cache: fresh ? 'reload' : 'default', credentials: 'same-origin' })
  if (!r.ok) throw new Error('i18n ' + r.status)
  return r.json()
}

async function loadOverride(code, fresh) {
  if (!stored.has(code)) { delete overrides[code]; return }
  try { overrides[code] = (await fetchJSON(encodeURIComponent(code), fresh)).translations || {} } catch {}
}

// Refreshes the language list and the active language's overrides (best effort: the
// interface keeps working with the bundled texts when the server has none).
export async function loadLanguageList(fresh = false) {
  try {
    const list = await fetchJSON('languages', fresh)
    stored.clear()
    for (const code of Object.keys(languages)) if (!(code in builtinLanguages)) delete languages[code]
    for (const item of list) {
      stored.add(item.code)
      if (!(item.code in builtinLanguages)) languages[item.code] = item.name
    }
  } catch { return }
  if (!(lang.value in languages)) { lang.value = 'en'; try { localStorage.removeItem('lang') } catch {} ; document.documentElement.lang = 'en' }
  await loadOverride(lang.value, fresh)
}

export function setLang(l) {
  if (!(l in languages) && !(bundled[l] || CODE_PATTERN.test(l))) return
  lang.value = l
  try { localStorage.setItem('lang', l) } catch {}
  document.documentElement.lang = l
  if (stored.has(l) && !overrides[l]) loadOverride(l)
}
// English text is the key; the lookup order is override -> bundled -> the key itself.
export function t(key, vars) {
  return interpolate(lookup(key, overrides[lang.value], bundled[lang.value]), vars)
}
export { tr }
// Server and helper-module messages are translated through this when a translation
// exists; messages with filled-in values are matched against the known patterns.
const dynamicMessages = dynamicMatcher(serverMessages.dynamic)
setTranslator(key => {
  const exact = t(key)
  return exact !== key ? exact : translateDynamic(key, dynamicMessages, t)
})

// BCP 47 locale for dates, following the active menu language.
const locales = { en: 'en-GB', nl: 'nl-NL', de: 'de-DE', fr: 'fr-FR', es: 'es-ES' }
export const dateLocale = () => {
  if (locales[lang.value]) return locales[lang.value]
  try { return Intl.getCanonicalLocales(lang.value)[0] } catch { return undefined }
}
