// SPDX-License-Identifier: AGPL-3.0-or-later

// "Powered by Sendora" and the "Source code" link in every footer.
// AGPL-3.0 section 13 requires offering the source of the running version to
// everyone who uses it over the network; the attribution is an additional term
// under section 7(b) (LICENSE-ADDITIONAL-TERMS.md). There is deliberately no
// setting or theme option to hide either.

export const PROJECT_URL = 'https://github.com/sendora-app/sendora'
export const LICENSE_NAME = 'AGPL-3.0-or-later'
export const LICENSE_URL = 'https://www.gnu.org/licenses/agpl-3.0.html'

// The brand name "Sendora" and both link targets are fixed and never pass
// through translation. Only the words around them ("Powered by", "Source code")
// are translatable; a translation (bundled, imported or custom) that is missing,
// empty, or has no visible letter or digit falls back to English, so the
// attribution and the source link cannot be emptied through a language file.
export const PROJECT_NAME = 'Sendora'
const ATTRIBUTION_KEYS = { poweredBy: 'Powered by', sourceCode: 'Source code' }
const VISIBLE = /[\p{L}\p{N}]/u
const INVISIBLE = /[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]/gu

export function attributionLabels(translate) {
  const out = {}
  for (const [name, english] of Object.entries(ATTRIBUTION_KEYS)) {
    let text = ''
    try { text = translate(english) } catch {}
    text = typeof text === 'string' ? text.replace(INVISIBLE, '').trim() : ''
    out[name] = VISIBLE.test(text) ? text : english
  }
  return out
}

// The server sends the source of the running build (bootstrap.source_url).
// Until it has loaded, or if the value is not an http(s) URL, link to the project.
export function sourceLink(boot) {
  const u = typeof boot?.source_url === 'string' ? boot.source_url.trim() : ''
  if (!u) return PROJECT_URL
  try {
    const p = new URL(u)
    return (p.protocol === 'https:' || p.protocol === 'http:') && p.host && !p.username && !p.password ? p.href : PROJECT_URL
  } catch {
    return PROJECT_URL
  }
}
