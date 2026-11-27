<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, onMounted } from 'vue'
import { api, session, fmtBytes, fmtDate, downloadBlob } from '../../api'
import { t } from '../../i18n'
import { keyProblem, importForm, waitForRestart } from '../../dbimport.mjs'
import { begin as beginTransfer } from '../../transfers.mjs'
const list = ref([]), err = ref('')
const imp = ref(null) // null = closed
const blankImport = () => ({ step: 'form', file: null, mode: 'none', hex: '', keyFile: null, progress: 0, summary: null, token: '', confirm: '', password: '', busy: false, error: '', backup: '' })
const importProblem = () => (imp.value.file ? t(keyProblem(imp.value) || '') : t('Choose a database file.'))
function pickFile(e) { imp.value.file = e.target.files[0] || null }
function pickKey(e) { imp.value.keyFile = e.target.files[0] || null }
const hasKeyProblem = () => keyProblem({ mode: imp.value.mode, hex: imp.value.hex, file: imp.value.keyFile })
function upload(form, token, onProgress) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest()
    x.open('POST', '/api/backups/import')
    x.setRequestHeader('Authorization', 'Bearer ' + token)
    x.upload.onprogress = ev => ev.lengthComputable && onProgress(Math.round(ev.loaded / ev.total * 100))
    x.onerror = () => reject(new Error(t('Upload failed')))
    x.onload = () => {
      let data = null
      try { data = JSON.parse(x.responseText) } catch {}
      if (x.status >= 200 && x.status < 300) resolve(data)
      else reject(new Error(data?.error || t('Upload failed')))
    }
    x.send(form)
  })
}
async function check() {
  const s = imp.value
  s.error = ''
  const problem = hasKeyProblem()
  if (!s.file || problem) { s.error = problem ? t(problem) : t('Choose a database file.'); return }
  s.busy = true; s.progress = 0
  const endTransfer = beginTransfer() // a large upload must not be cut off by automatic sign-out
  try {
    await api('/users/me') // refresh an expired access token before a long upload
    const data = await upload(importForm({ mode: s.mode, hex: s.hex, keyFile: s.keyFile, file: s.file }), session.token, p => (s.progress = p))
    s.summary = data.summary; s.token = data.token; s.step = 'review'
  } catch (e) { s.error = e.message } finally { endTransfer(); s.busy = false }
}
async function applyImport() {
  const s = imp.value
  s.error = ''; s.busy = true
  try {
    const r = await api('/backups/import/apply', { method: 'POST', body: { token: s.token, confirm: s.confirm, password: s.password } })
    s.backup = r.backup || ''; s.step = 'restarting'
    const back = await waitForRestart()
    session.token = null; session.user = null
    if (back) location.assign('/login'); else { s.step = 'timeout' }
  } catch (e) { s.error = e.message; s.busy = false }
}
const load = async () => (list.value = await api('/backups'))
onMounted(load)
async function create() { err.value = ''; try { await api('/backups', { method: 'POST' }); load() } catch (e) { err.value = e.message } }
async function del(b) { if (confirm(t('Delete backup?'))) { await api('/backups/' + b.name, { method: 'DELETE' }); load() } }
async function dl(b) {
  err.value = ''
  try { await downloadBlob('/backups/' + encodeURIComponent(b.name), b.name) } catch (e) { err.value = e.message || t('Download failed') }
}
</script>
<template>
  <div class="card"><div class="actions" style="margin:0 0 12px"><h1 style="margin:0">{{ t('Backups') }}</h1><button class="small" @click="create">{{ t('Create backup now') }}</button>
      <button class="small secondary" @click="imp = blankImport()">{{ t('Import database') }}</button></div>
    <section v-if="imp" class="card">
      <h2>{{ t('Import database') }}</h2>
      <template v-if="imp.step === 'form'">
        <p class="muted">{{ t('Replaces the entire database with a Sendora backup. Uploaded files are not part of a database backup and are not touched.') }}</p>
        <label>{{ t('Database file (.db)') }}</label><input type="file" accept=".db" @change="pickFile" :disabled="imp.busy" />
        <label>{{ t('Encryption key of this file') }}</label>
        <select v-model="imp.mode" :disabled="imp.busy"><option value="none">{{ t('Same key as this server') }}</option><option value="hex">{{ t('Other key (64 hex characters)') }}</option><option value="file">{{ t('Other key (key file, 32 bytes)') }}</option></select>
        <input v-if="imp.mode === 'hex'" v-model="imp.hex" type="password" autocomplete="off" spellcheck="false" :disabled="imp.busy" style="margin-top:8px" />
        <input v-if="imp.mode === 'file'" type="file" @change="pickKey" :disabled="imp.busy" style="margin-top:8px" />
        <p class="muted">{{ t('The key is only used for this check and is never stored. The data is re-encrypted with this server\'s key.') }}</p>
        <div v-if="imp.busy"><div class="bar"><i :style="{ width: imp.progress + '%' }" /></div><p class="muted">{{ imp.progress }}%</p></div>
        <p v-if="imp.error" class="err">{{ imp.error }}</p>
        <div class="actions"><button :disabled="imp.busy" @click="check">{{ t('Check file') }}</button><button class="secondary" :disabled="imp.busy" @click="imp = null">{{ t('Cancel') }}</button></div>
      </template>
      <template v-else-if="imp.step === 'review'">
        <p><b>{{ t('File checked. Review before importing:') }}</b></p>
        <ul>
          <li>{{ t('Users') }}: {{ imp.summary.users }} ({{ t('administrators') }}: {{ imp.summary.admins }})</li>
          <li>{{ t('Shares') }}: {{ imp.summary.shares }}, {{ t('Files') }}: {{ imp.summary.files }}</li>
          <li :class="{ err: imp.summary.missing_files > 0 }">{{ t('Files missing on this server') }}: {{ imp.summary.missing_files }} ({{ t('shares affected') }}: {{ imp.summary.missing_shares }})</li>
        </ul>
        <p v-for="w in imp.summary.warnings" :key="w" class="muted">• {{ w }}</p>
        <p class="err">{{ t('All current accounts, shares and settings are replaced. Everyone, including you, must sign in again, and only accounts from the imported database exist afterwards. A backup of the current database is made first.') }}</p>
        <label>{{ t('Type IMPORT to confirm') }}</label><input v-model="imp.confirm" autocomplete="off" :disabled="imp.busy" />
        <label>{{ t('Your password') }}</label><input v-model="imp.password" type="password" autocomplete="current-password" :disabled="imp.busy" />
        <p v-if="imp.error" class="err">{{ imp.error }}</p>
        <div class="actions"><button class="danger" :disabled="imp.busy || imp.confirm !== 'IMPORT'" @click="applyImport">{{ t('Import and restart') }}</button><button class="secondary" :disabled="imp.busy" @click="imp = null">{{ t('Cancel') }}</button></div>
      </template>
      <template v-else-if="imp.step === 'restarting'">
        <p>{{ t('Importing and restarting. This page returns to the sign-in screen when the server is back.') }}</p>
        <p v-if="imp.backup" class="muted">{{ t('Backup of the previous database') }}: {{ imp.backup }}</p>
      </template>
      <template v-else>
        <p class="err">{{ t('The server did not come back in time. Check the server and sign in again.') }}</p>
        <div class="actions"><a href="/login">{{ t('Sign in') }}</a></div>
      </template>
    </section>
    <p class="muted">{{ t('Database only. Back up the files volume separately.') }}</p>
    <p v-if="err" class="err">{{ err }}</p>
    <table><tr v-for="b in list" :key="b.name"><td>{{ b.name }}</td><td>{{ fmtBytes(b.size) }}</td><td>{{ fmtDate(b.created_at) }}</td>
      <td class="actions" style="margin:0"><button class="small secondary" @click="dl(b)">{{ t('Download') }}</button><button class="small danger" @click="del(b)">{{ t('Delete') }}</button></td></tr></table>
  </div>
</template>
