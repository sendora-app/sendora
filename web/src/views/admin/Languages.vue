<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../../api'
import { t, bundled, builtinLanguages, loadLanguageList } from '../../i18n'
import { buildExport, stripRedundant, parseImport, validName, CODE_PATTERN, LIMITS } from '../../ui-language.mjs'
import keys from '../../i18n/keys.json'
import serverMessages from '../../i18n/server-messages.json'

// Every translatable text: interface texts plus the server messages shown to users.
const knownKeys = [...new Set([...keys, ...(serverMessages.static || []), ...(serverMessages.dynamic || [])])].sort()
const list = ref([]), limit = ref(LIMITS.languages), busy = ref(false), msg = ref(''), err = ref('')
const pending = ref(null), fileInput = ref(null), importTarget = ref('')
const newLanguage = ref({ code: '', name: '' })
const existingCodes = computed(() => list.value.filter(l => !l.built_in).map(l => l.code))

async function reload() {
  try { const d = await api('/ui-languages'); list.value = d.languages; limit.value = d.limit } catch (e) { err.value = e.message }
}
onMounted(reload)

async function storedOverrides(code) {
  try { return (await api(`/ui-languages/${encodeURIComponent(code)}/export`)).translations || {} } catch (e) { if (e.status === 404) return {}; throw e }
}
function download(data, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2) + '\n'], { type: 'application/json' }))
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click()
  setTimeout(() => URL.revokeObjectURL(url), 10000)
}
// Built-in texts live in the frontend bundle, so the complete file is assembled here:
// every key with its current text (bundled text plus the stored overrides).
async function exportLanguage(l) {
  err.value = msg.value = ''; busy.value = true
  try {
    const override = await storedOverrides(l.code)
    download(buildExport({ code: l.code, name: l.name, keys: knownKeys, override, bundled: bundled[l.code] }), `sendora-ui-${l.code}.json`)
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
function downloadTemplate() {
  err.value = msg.value = ''
  const { code, name } = newLanguage.value
  if (!CODE_PATTERN.test(code)) { err.value = t('Invalid language code (for example nl, pt-br or zh-hant).'); return }
  if (!validName(name)) { err.value = t('Invalid language name (1 to 80 characters, no control characters).'); return }
  download(buildExport({ code, name, keys: knownKeys, override: {}, bundled: {} }), `sendora-ui-${code}.json`)
  msg.value = t('Template downloaded. Translate the values (not the keys), keep placeholders such as {n} unchanged, then import the file.')
}
function chooseFile(target) { importTarget.value = target; fileInput.value.click() }
async function inspect(e) {
  const file = e.target.files?.[0]; e.target.value = ''; pending.value = null; err.value = msg.value = ''
  if (!file) return
  if (file.size > LIMITS.fileBytes) { err.value = t('The file is larger than 1 MiB.'); return }
  const target = importTarget.value
  const fields = newLanguage.value
  const result = parseImport(await file.text(), {
    knownKeys, builtinNames: builtinLanguages, existingCodes: existingCodes.value,
    forceCode: target || (CODE_PATTERN.test(fields.code) ? fields.code : undefined)
  })
  if (!result.ok) { err.value = t(result.error, result.vars); return }
  const name = !target && validName(fields.name) && !(result.code in builtinLanguages) ? fields.name : result.name
  const translations = stripRedundant(result.translations, bundled[result.code])
  pending.value = { code: result.code, name, translations, total: Object.keys(result.translations).length, changed: Object.keys(translations).length, exists: list.value.some(l => l.code === result.code) }
}
async function apply() {
  const p = pending.value
  if (!p || (p.exists && !confirm(t('Import these translations? The stored translations of this language will be replaced.')))) return
  busy.value = true; err.value = msg.value = ''
  try {
    await api('/ui-languages', { method: 'POST', body: { code: p.code, name: p.name, translations: p.translations } })
    pending.value = null; newLanguage.value = { code: '', name: '' }
    await Promise.all([reload(), loadLanguageList(true)])
    msg.value = t('Translations imported')
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
async function remove(l) {
  const question = l.built_in ? t('Reset {name} to the default texts?', { name: l.name }) : t('Delete the language {name}? Users of this language switch to English.', { name: l.name })
  if (!confirm(question)) return
  busy.value = true; err.value = msg.value = ''
  try {
    await api(`/ui-languages/${encodeURIComponent(l.code)}`, { method: 'DELETE' })
    await Promise.all([reload(), loadLanguageList(true)])
    msg.value = l.built_in ? t('Reset to the default texts') : t('Language deleted')
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
</script>
<template>
  <div class="card">
    <h1>{{ t('Languages') }}</h1>
    <p class="muted">{{ t('Translate buttons, labels and messages through JSON without rebuilding. Download a language, translate the values offline (keep placeholders such as {n} unchanged) and import it again. New languages appear in every language menu; missing texts fall back to the built-in text, then to English.') }}</p>
    <table>
      <thead><tr><th>{{ t('Code') }}</th><th>{{ t('Language') }}</th><th>{{ t('Type') }}</th><th>{{ t('Customised texts') }}</th><th></th></tr></thead>
      <tbody>
        <tr v-for="l in list" :key="l.code">
          <td><code>{{ l.code }}</code></td><td>{{ l.name }}</td>
          <td>{{ l.built_in ? t('Built-in') : t('Custom') }}</td>
          <td>{{ l.stored ? l.keys : 0 }}</td>
          <td class="actions">
            <button type="button" class="secondary" :disabled="busy" @click="exportLanguage(l)">{{ t('Download JSON') }}</button>
            <button type="button" class="secondary" :disabled="busy" @click="chooseFile(l.code)">{{ t('Import JSON') }}</button>
            <button v-if="l.stored" type="button" class="secondary" :disabled="busy" @click="remove(l)">{{ l.built_in ? t('Reset to default') : t('Delete') }}</button>
          </td>
        </tr>
      </tbody>
    </table>
    <section class="card">
      <h2>{{ t('Add a language') }}</h2>
      <p class="muted">{{ t('{count} of {max} custom languages in use.', { count: existingCodes.length, max: limit }) }}</p>
      <div class="row">
        <div><label>{{ t('Language code') }}</label><input v-model="newLanguage.code" maxlength="24" placeholder="pt-br" /></div>
        <div><label>{{ t('Language name') }}</label><input v-model="newLanguage.name" maxlength="80" placeholder="Português (Brasil)" /></div>
      </div>
      <div class="actions">
        <button type="button" class="secondary" :disabled="busy || !newLanguage.code || !newLanguage.name" @click="downloadTemplate">{{ t('Download template') }}</button>
        <button type="button" class="secondary" :disabled="busy" @click="chooseFile('')">{{ t('Import JSON') }}</button>
      </div>
    </section>
    <input ref="fileInput" type="file" accept=".json,application/json" hidden @change="inspect" />
    <section v-if="pending" class="card">
      <h2>{{ t('Import preview') }}: {{ pending.name }} ({{ pending.code }})</h2>
      <p>{{ t('{changed} of {total} texts differ from the built-in text and will be stored.', { changed: pending.changed, total: pending.total }) }}</p>
      <p v-if="pending.exists" class="muted">{{ t('The stored translations of this language will be replaced.') }}</p>
      <div class="actions"><button type="button" :disabled="busy" @click="apply">{{ t('Confirm import') }}</button><button type="button" class="secondary" :disabled="busy" @click="pending = null">{{ t('Cancel') }}</button></div>
    </section>
    <p v-if="msg" class="ok">{{ msg }}</p><p v-if="err" class="err">{{ err }}</p>
  </div>
</template>
