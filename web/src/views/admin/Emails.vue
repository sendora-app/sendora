<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../../api'
import { t, tr } from '../../i18n'
import { emailLanguages, loadBoot } from '../../state'
const newLanguage = ref({ code: '', name: '' }), sourceLanguage = ref('en'), importFile = ref(null), importPreview = ref(null)
const templates = ref({}), language = ref('en'), event = ref('share_created'), msg = ref(''), err = ref(''), preview = ref(null), busy = ref(false)
const labels = { share_created: tr('Share created (to recipients)'), share_downloaded: tr('Download started (to owner)'), share_expiring: tr('Share expiring (to owner)'), password_reset: tr('Password reset'), verify_email: tr('Email verification'), reverse_invite: tr('Reverse share invite'), reverse_completed: tr('Reverse share completed'), welcome: tr('Welcome (new account created by an administrator)'), admin_password_reset: tr('Password reset link requested by an administrator'), account_email_changed_notice: tr('Email address changed by an administrator (sent to the old address)'), mfa_reset_requested: tr('Two-step verification reset: confirmation link'), mfa_reset_done: tr('Two-step verification reset: completed'), password_changed: tr('Password changed (to the user)'), mfa_factor_changed: tr('Two-step verification method added or removed (to the user)'), recovery_codes_regenerated: tr('Recovery codes regenerated (to the user)'), new_signin: tr('Sign-in from a new browser or network (to the user)'), password_expiry_warning: tr('Password expires soon (to the user, 7 days before)') }
const variables = 'ApplicationName RecipientName SenderName URL Message Expires ShareName Code DownloadCount FileName FileNames StartedAt Username LoginURL SetPasswordURL ExpiresDays Time Browser'.split(' ')
const bodyKey = computed(() => `tpl_${event.value}_${language.value}`)
const subjectKey = computed(() => `subj_${event.value}_${language.value}`)
const subject = computed({ get: () => templates.value[subjectKey.value] || '', set: value => { templates.value[subjectKey.value] = value; preview.value = null } })
const body = computed({ get: () => templates.value[bodyKey.value] || '', set: value => { templates.value[bodyKey.value] = value; preview.value = null } })
onMounted(async () => { try { templates.value = await api('/email-templates') } catch (e) { err.value = e.message } })
async function save() {
  msg.value = err.value = ''; busy.value = true
  try {
    const canonical = {}
    for (const eventKey of Object.keys(labels)) for (const code of Object.keys(emailLanguages)) for (const prefix of ['tpl', 'subj']) {
      const key = `${prefix}_${eventKey}_${code}`
      if (Object.hasOwn(templates.value, key)) canonical[key] = templates.value[key]
    }
    await api('/email-templates', { method: 'PUT', body: canonical }); msg.value = t('Saved')
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
async function addLanguage() {
  err.value = msg.value = ''; busy.value = true
  try {
    const added = await api('/email-languages', { method: 'POST', body: newLanguage.value })
    emailLanguages[added.code] = added.name
    const fresh = await api('/email-templates')
    for (const [key, value] of Object.entries(fresh)) if (!Object.hasOwn(templates.value, key)) templates.value[key] = value
    language.value = added.code; preview.value = null; newLanguage.value = { code: '', name: '' }
    await loadBoot(); msg.value = t('Language added; translate the templates below.')
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
function copySource() {
  if (!confirm(t('Replace this subject and body with the selected source?'))) return
  subject.value = templates.value[`subj_${event.value}_${sourceLanguage.value}`] || ''
  body.value = templates.value[`tpl_${event.value}_${sourceLanguage.value}`] || ''
}
async function exportJSON() {
  err.value = ''; busy.value = true
  try {
    const bundle = await api('/email-templates/export?language=' + encodeURIComponent(language.value))
    const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2) + '\n'], { type: 'application/json' }))
    const link = document.createElement('a'); link.href = url; link.download = `sendora-email-${language.value}.json`; link.click()
    setTimeout(() => URL.revokeObjectURL(url), 10000)
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
async function inspectJSON(e) {
  const file = e.target.files?.[0]; e.target.value = ''; importPreview.value = null; err.value = ''; msg.value = ''
  if (!file) return
  busy.value = true
  try {
    if (file.size > 768 * 1024) throw new Error(t('Translation JSON must be smaller than 768 KiB.'))
    const bundle = JSON.parse(await file.text())
    importPreview.value = await api('/email-templates/import', { method: 'POST', body: { bundle, apply: false } })
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
async function applyJSON() {
  const pending = importPreview.value
  if (!pending || !confirm(t('Import these templates? Existing translations for this language will be replaced.'))) return
  busy.value = true; err.value = ''
  try {
    await api('/email-templates/import', { method: 'POST', body: { bundle: pending.bundle, apply: true, overwrite: pending.exists } })
    // Merge only this language, preserving other unsaved editor drafts.
    for (const [key, text] of Object.entries(pending.bundle.templates)) {
      templates.value[`subj_${key}_${pending.bundle.language}`] = text.subject
      templates.value[`tpl_${key}_${pending.bundle.language}`] = text.body
    }
    language.value = pending.bundle.language; importPreview.value = null; preview.value = null
    await loadBoot(); msg.value = t('Translation JSON imported')
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
async function showPreview(send = false) {
  msg.value = err.value = ''; busy.value = true
  try {
    await api('/email-templates', { method: 'PUT', body: { [subjectKey.value]: subject.value, [bodyKey.value]: body.value } })
    preview.value = await api('/email-templates/preview', { method: 'POST', body: {
      key: event.value, language: language.value, send,
      data: { RecipientName: 'Alex', SenderName: 'Sam', URL: location.origin + '/share/example', Message: 'Example message', Expires: '2030-01-15', ShareName: 'Example files', Code: '123456', DownloadCount: '3', FileName: 'example.zip', FileNames: 'one.txt, two.txt', StartedAt: '2030-01-15T10:30:00Z', Username: 'alex', LoginURL: location.origin + '/login', SetPasswordURL: location.origin + '/reset-password/example', ExpiresDays: '7', Time: '2030-01-15 10:30 UTC', Browser: 'Firefox (Windows)' }
    } })
    if (preview.value.sent) msg.value = t('Test email sent')
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
</script>
<template>
  <form class="card" @submit.prevent="save">
    <h1>{{ t('Email templates') }}</h1>
    <p class="muted">{{ t('Translate manually. Keep placeholders unchanged. Extra languages apply to email, not menus.') }}</p>
    <section class="card"><h2>{{ t('Add email language') }}</h2><div class="row"><div><label>{{ t('Language code') }}</label><input v-model="newLanguage.code" maxlength="24" placeholder="pt-br" /></div><div><label>{{ t('Language name') }}</label><input v-model="newLanguage.name" maxlength="80" placeholder="Português (Brasil)" /></div></div><button type="button" class="secondary" :disabled="busy || !newLanguage.code || !newLanguage.name" @click="addLanguage">{{ t('Add email language') }}</button></section>
    <div class="row">
      <div><label>{{ t('Language') }}</label><select v-model="language" @change="preview = null"><option v-for="(name, code) in emailLanguages" :key="code" :value="code">{{ name }}</option></select></div>
      <div><label>{{ t('Template') }}</label><select v-model="event" @change="preview = null"><option v-for="(name, key) in labels" :key="key" :value="key">{{ t(name) }}</option></select></div>
    </div>
    <div class="actions"><button type="button" class="secondary" :disabled="busy" @click="exportJSON">{{ t('Download translation JSON') }}</button><button type="button" class="secondary" :disabled="busy" @click="importFile.click()">{{ t('Upload translation JSON') }}</button><input ref="importFile" type="file" accept=".json,application/json" hidden @change="inspectJSON" /></div>
    <p class="muted">{{ t('Export includes saved templates only. Edit language, name, subject and body; keep format, version, event keys and placeholders unchanged.') }}</p>
    <section v-if="importPreview" class="card"><h2>{{ t('Import preview') }}: {{ importPreview.bundle.name }} ({{ importPreview.bundle.language }})</h2><p>{{ importPreview.exists ? t('Existing language: the templates in this file will replace the current ones.') : t('New language: the templates in this file will be added.') }}</p><details v-for="(text, key) in importPreview.bundle.templates" :key="key"><summary>{{ t(labels[key]) }}</summary><strong>{{ text.subject }}</strong><pre style="white-space:pre-wrap;overflow-wrap:anywhere;font:inherit">{{ text.body }}</pre></details><div class="actions"><button type="button" :disabled="busy" @click="applyJSON">{{ t('Confirm import') }}</button><button type="button" class="secondary" :disabled="busy" @click="importPreview = null">{{ t('Cancel') }}</button></div></section>
    <div class="row"><section><h2>{{ t('Source text') }}</h2><label>{{ t('Source language') }}</label><select v-model="sourceLanguage"><option v-for="(name, code) in emailLanguages" :key="code" :value="code">{{ name }}</option></select><label>{{ t('Subject') }}</label><input :value="templates[`subj_${event}_${sourceLanguage}`] || ''" readonly /><label>{{ t('Body') }}</label><textarea :value="templates[`tpl_${event}_${sourceLanguage}`] || ''" rows="12" readonly /><button type="button" class="secondary" :disabled="busy || language === sourceLanguage" @click="copySource">{{ t('Copy source to translation') }}</button></section><section><h2>{{ t('Translation') }}</h2><label>{{ t('Subject') }}</label><input v-model="subject" maxlength="500" /><label>{{ t('Body') }}</label><textarea v-model="body" rows="12" /></section></div>
    <p class="muted"><code v-text="variables.map(v => '{{.' + v + '}}').join(' ')" /></p>
    <p class="muted">{{ t('English fallback is used when a translation is unavailable.') }}</p>
    <p v-if="msg" class="ok">{{ msg }}</p><p v-if="err" class="err">{{ err }}</p>
    <div class="actions"><button :disabled="busy">{{ t('Save') }}</button><button type="button" class="secondary" :disabled="busy" @click="showPreview(false)">{{ t('Save and preview') }}</button><button type="button" class="secondary" :disabled="busy" @click="showPreview(true)">{{ t('Save and send test to my email') }}</button></div>
    <section v-if="preview" style="margin-top:24px"><h2>{{ t('Preview') }}</h2><strong>{{ preview.subject }}</strong><pre style="white-space:pre-wrap;overflow-wrap:anywhere;font:inherit">{{ preview.body }}</pre></section>
  </form>
</template>
