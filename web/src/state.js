// SPDX-License-Identifier: AGPL-3.0-or-later

import { reactive, ref } from 'vue'
import { api } from './api'
import { setLang, languages, loadLanguageList } from './i18n'
import { contrastText } from './contrast.mjs'
import { featureAvailable, loadCapabilities } from './capabilities.mjs'

export const emailLanguages = reactive({ ...languages })

// Optional per-page title prefix (upload progress, share name); App.vue combines it with the application name.
export const pageTitle = ref('')

export const app = reactive({ boot: null, theme: null, backgrounds: [], version: '', capabilities: null })

// can reports whether the server's flavour offers a feature (GET /api/capabilities);
// fallback applies while the capabilities are unknown.
export function can(id, fallback) { return featureAvailable(app.capabilities, id, fallback) }

// Black or white foreground for custom accents; accepts the 3/4/6/8-digit hex the themes allow.
export { contrastText }

export function applyTheme(th) {
  app.theme = th
  const root = document.documentElement.style
  const map = { primary: '--primary', bg: '--bg', surface: '--surface', text: '--text', muted: '--muted', border: '--border', danger: '--danger' }
  for (const k in map) th?.data?.[k] ? root.setProperty(map[k], th.data[k]) : root.removeProperty(map[k])
  for (const k of ['primary', 'danger']) {
    if (th?.data?.[k]) root.setProperty(`--${k}-text`, contrastText(th.data[k]))
    else root.removeProperty(`--${k}-text`)
  }
}

export async function loadBoot() {
  const [boot, theme, bgs, mailLanguages, caps] = await Promise.all([
    api('/bootstrap'), api('/themes/active').catch(() => null), api('/backgrounds').catch(() => []), api('/auth/email-languages'),
    loadCapabilities(api)
  ])
  app.capabilities = caps
  for (const key of Object.keys(emailLanguages)) delete emailLanguages[key]
  for (const item of mailLanguages) emailLanguages[item.code] = item.name
  app.boot = boot
  await loadLanguageList()
  app.backgrounds = bgs || []
  applyTheme(theme)
  document.title = boot.application_name
  // A custom favicon (Branding) replaces the built-in icons from index.html; without
  // one, the built-in Sendora icon stays or comes back.
  const icons = [...document.querySelectorAll('link[rel=icon]')]
  const custom = icons.filter(l => (l.getAttribute('href') || '').startsWith('/api/branding/'))
  const add = href => { const l = document.createElement('link'); l.rel = 'icon'; l.href = href; document.head.appendChild(l) }
  if (boot.has_favicon) {
    icons.forEach(l => l.remove())
    add('/api/branding/favicon?v=' + Date.now())
  } else {
    custom.forEach(l => l.remove())
    if (icons.length === custom.length) add('/favicon.svg')
  }
  let saved = null
  try { saved = localStorage.getItem('lang') } catch {}
  if (!saved && boot.default_language) setLang(boot.default_language)
}
