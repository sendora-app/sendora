<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, onMounted } from 'vue'
import { api, session, fmtBytes, fmtDate } from '../api'
import { app, emailLanguages } from '../state'
import { t, lang } from '../i18n'
import QrCode from '../components/QrCode.vue'
import { sharePolicy, passwordProblems } from '../sharepolicy.mjs'
import { fromInput, uploadAll } from '../uploader'
import { begin as beginTransfer } from '../transfers.mjs'

const shares = ref([]), err = ref(''), invite = ref({ kind: 'email', max_uploads: 5, name: '', email: '', message: '', days: 7, email_language: session.user?.language || lang.value }), inviteUrl = ref(''), open = ref(false), invites = ref([]), qrShare = ref(null), qrInvite = ref(null), expiryShare = ref(null), expiryValue = ref(''), editShare = ref(null), edit = ref({}), editErr = ref(''), shareFiles = ref([]), addBusy = ref(false), addPct = ref(0)
const load = async () => { shares.value = await api('/shares'); if (app.boot?.allow_reverse_shares) invites.value = await api('/reverse-shares/invites') }
onMounted(load)
const url = s => location.origin + '/share/' + s.long_id
const copy = s => navigator.clipboard.writeText(url(s))
async function act(fn) { err.value = ''; try { await fn(); await load() } catch (e) { err.value = e.message } }
const expire = s => confirm(t('Expire this share now?')) && act(() => api(`/shares/${s.id}/expire`, { method: 'POST' }))
const extend = s => { const d = +prompt(t('Extend by how many days?'), '7'); if (d > 0) act(() => api(`/shares/${s.id}/extend`, { method: 'POST', body: { days: d } })) }
const limit = s => { const v = prompt(t('Download limit (empty = unlimited)'), s.download_limit || ''); if (v !== null) act(() => api(`/shares/${s.id}/download-limit`, { method: 'POST', body: { limit: +v || null } })) }
function editExpiry(s) {
  expiryShare.value = s
  const d = new Date(s.expires_at || Date.now() + 7 * 864e5), pad = n => String(n).padStart(2, '0')
  expiryValue.value = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}
const saveExpiry = body => act(async () => { await api(`/shares/${expiryShare.value.id}/expiry`, { method: 'PUT', body }); expiryShare.value = null })
const saveDate = () => expiryValue.value && saveExpiry({ expires_at: new Date(expiryValue.value).toISOString() })
const revoke = i => confirm(t('Revoke this upload link?')) && act(() => api(`/reverse-shares/invites/${i.id}/revoke`, { method: 'POST' }))
const copyText = text => navigator.clipboard.writeText(text)
const policy = () => sharePolicy(app.boot)
const editProblems = () => (edit.value.password ? passwordProblems(edit.value.password, policy()) : [])
async function loadFiles() {
  try { shareFiles.value = await api(`/shares/${editShare.value.id}/files`) } catch (e) { editErr.value = e.message }
}
async function removeFile(f) {
  if (!confirm(t('Remove this file from the share?'))) return
  editErr.value = ''
  try { await api(`/shares/${editShare.value.id}/files/${f.id}`, { method: 'DELETE' }); await loadFiles(); await load() } catch (e) { editErr.value = e.message }
}
// Refs inside a v-for become arrays, so the picker is created on demand instead.
function pick(directory) {
  const input = document.createElement('input')
  input.type = 'file'; input.multiple = true
  if (directory) input.webkitdirectory = true
  input.onchange = () => addFiles(fromInput(input.files))
  input.click()
}
async function addFiles(list) {
  if (!list.length || addBusy.value) return
  editErr.value = ''; addBusy.value = true; addPct.value = 0
  const endTransfer = beginTransfer()
  try {
    const id = await uploadAll(list, (d, tot) => (addPct.value = tot ? Math.round(d / tot * 100) : 100), undefined, () => {}, { share_id: editShare.value.id })
    await api(`/uploads/${id}/complete`, { method: 'POST', body: {} })
    await loadFiles(); await load()
  } catch (e) { editErr.value = e.message } finally { endTransfer(); addBusy.value = false }
}
function openEdit(s) {
  editErr.value = ''
  editShare.value = s
  shareFiles.value = []
  loadFiles()
  edit.value = { name: s.name, description: s.description || '', password: '', remove_password: false, download_limit: s.download_limit || '' }
}
async function saveEdit() {
  editErr.value = ''
  const f = edit.value, body = { name: f.name, description: f.description, download_limit: +f.download_limit || 0 }
  if (f.remove_password) body.remove_password = true
  else if (f.password) {
    const problems = editProblems()
    if (problems.length) { editErr.value = problems.map(p => t(p.key, { n: p.n })).join(', '); return }
    body.password = f.password
  }
  try { await api('/shares/' + editShare.value.id, { method: 'PUT', body }); editShare.value = null; await load() } catch (e) { editErr.value = e.message }
}
const del = s => confirm(t('Delete this share and its files?')) && act(() => api('/shares/' + s.id, { method: 'DELETE' }))
const prune = () => act(() => api('/shares/prune-expired', { method: 'POST' }))
const historyShare = ref(null), history = ref(null), historyBusy = ref(false)
async function showHistory(share, offset = 0) {
  err.value = ''; historyBusy.value = true
  try {
    history.value = await api(`/shares/${share.id}/downloads?limit=50&offset=${offset}`)
    historyShare.value = share
  } catch (e) { err.value = e.message }
  finally { historyBusy.value = false }
}
async function makeInvite() {
  err.value = ''
  try {
    const f = invite.value
    const body = f.kind === 'open' ? { open: true, max_uploads: +f.max_uploads, days: +f.days, name: f.name, message: f.message } : { name: f.name, email: f.email, message: f.message, days: +f.days, email_language: f.email_language }
    inviteUrl.value = (await api('/reverse-shares/invite', { method: 'POST', body })).url
    await load()
  } catch (e) { err.value = e.message }
}
</script>
<template>
  <div class="card">
    <div class="actions" style="margin:0 0 12px"><h1 style="margin:0">{{ t('My shares') }}</h1>
      <button class="secondary small" @click="prune">{{ t('Remove expired') }}</button>
      <button v-if="app.boot?.allow_reverse_shares" class="secondary small" @click="open = !open">{{ t('Invite someone to upload') }}</button></div>
    <form v-if="open" class="card" @submit.prevent="makeInvite">
      <label>{{ t('Type') }}</label><select v-model="invite.kind"><option value="email">{{ t('Invite by email') }}</option><option value="open">{{ t('Open link (several uploaders)') }}</option></select>
      <div class="row"><div><label>{{ t('Name') }}</label><input v-model="invite.name" /></div>
        <div v-if="invite.kind === 'email'"><label>{{ t('Email') }}</label><input v-model="invite.email" type="email" /></div>
        <div v-else><label>{{ t('Maximum uploads') }}</label><input v-model.number="invite.max_uploads" type="number" min="1" max="100" /></div>
        <div><label>{{ t('Valid for (days)') }}</label><input v-model.number="invite.days" type="number" min="1" max="30" /></div></div>
      <label v-if="invite.kind === 'email'">{{ t('Email language') }}</label><select v-if="invite.kind === 'email'" v-model="invite.email_language"><option v-for="(name, code) in emailLanguages" :key="code" :value="code">{{ name }}</option></select>
      <label>{{ t('Message') }}</label><textarea v-model="invite.message" rows="2" />
      <div class="actions"><button>{{ t('Create invite') }}</button></div>
      <input v-if="inviteUrl" :value="inviteUrl" readonly @focus="$event.target.select()" style="margin-top:8px" />
      <div v-if="inviteUrl" class="actions" style="margin-top:8px"><button type="button" class="secondary small" @click="copyText(inviteUrl)">{{ t('Copy link') }}</button></div>
      <QrCode v-if="inviteUrl" :value="inviteUrl" />
    </form>
    <section v-if="open && invites.length" class="card"><h2>{{ t('Upload invitations') }}</h2>
      <div class="table-wrap"><table>
        <tr><th>{{ t('Name') }}</th><th>{{ t('Type') }}</th><th>{{ t('Uploads') }}</th><th>{{ t('Expires') }}</th><th /></tr>
        <tr v-for="i in invites" :key="i.id"><td>{{ i.name || i.email }}</td><td>{{ i.kind === 'open' ? t('Open link') : t('Email') }}</td>
          <td>{{ i.used }}/{{ i.max_uploads }}<span v-if="i.pending"> (+{{ i.pending }})</span></td>
          <td>{{ new Date(i.expires_at).getFullYear() > 1 ? fmtDate(i.expires_at) : '—' }} <span class="badge" :class="i.active ? 'on' : 'off'">{{ i.active ? t('Active') : t('Expired') }}</span></td>
          <td class="actions" style="margin:0"><template v-if="i.url && i.active"><button class="small secondary" @click="copyText(i.url)">{{ t('Copy link') }}</button>
            <button class="small secondary" @click="qrInvite = qrInvite === i.id ? null : i.id">{{ t('QR code') }}</button></template>
            <button v-if="i.active" class="small secondary" @click="revoke(i)">{{ t('Revoke') }}</button></td></tr>
        <template v-for="i in invites" :key="'q' + i.id"><tr v-if="qrInvite === i.id && i.url"><td colspan="5"><QrCode :value="i.url" /></td></tr></template>
      </table></div></section>
    <p v-if="err" class="err">{{ err }}</p>
    <p v-if="!shares.length" class="muted">—</p>
    <div class="table-wrap"><table v-if="shares.length">
      <tr><th>{{ t('Name') }}</th><th>{{ t('Size') }}</th><th>{{ t('Downloads') }}</th><th>{{ t('Expires') }}</th><th /></tr>
      <template v-for="s in shares" :key="s.id">
      <tr>
        <td><a :href="url(s)" target="_blank">{{ s.name }}</a> <span v-if="s.password_protected">🔒</span><br v-if="s.description" /><span v-if="s.description" class="muted">{{ s.description }}</span>
          <span class="badge" :class="s.expired ? 'off' : 'on'">{{ s.expired ? t('Expired') : t('Active') }}</span></td>
        <td>{{ fmtBytes(s.size) }} ({{ s.file_count }})</td>
        <td>{{ s.download_count }}<span v-if="s.download_limit">/{{ s.download_limit }}</span></td>
        <td>{{ fmtDate(s.expires_at) }}</td>
        <td class="actions" style="margin:0">
          <button class="small secondary" :disabled="historyBusy" @click="showHistory(s)">{{ t('Download history') }}</button>
          <button class="small secondary" @click="copy(s)">{{ t('Copy link') }}</button>
          <button class="small secondary" @click="qrShare = qrShare === s.id ? null : s.id">{{ t('QR code') }}</button>
          <button class="small secondary" @click="extend(s)">{{ t('Extend') }}</button>
          <button class="small secondary" @click="editExpiry(s)">{{ t('Set expiry') }}</button>
          <button class="small secondary" @click="openEdit(s)">{{ t('Edit') }}</button>
          <button class="small secondary" @click="limit(s)">{{ t('Limit') }}</button>
          <button v-if="!s.expired" class="small secondary" @click="expire(s)">{{ t('Expire now') }}</button>
          <button class="small danger" @click="del(s)">{{ t('Delete') }}</button></td>
      </tr>
        <tr v-if="qrShare === s.id"><td colspan="5"><QrCode :value="url(s)" /></td></tr>
        <tr v-if="editShare && editShare.id === s.id"><td colspan="5">
          <form @submit.prevent="saveEdit">
            <div class="row"><div><label>{{ t('Name') }}</label><input v-model="edit.name" maxlength="120" required /></div>
              <div><label>{{ t('Download limit') }}</label><input v-model="edit.download_limit" type="number" min="1" placeholder="∞" /></div></div>
            <label>{{ t('Description') }}</label><textarea v-model="edit.description" rows="2" maxlength="2000" />
            <label>{{ s.password_protected ? t('New password (leave empty to keep)') : t('Set a password') }}</label>
            <input v-model="edit.password" type="password" autocomplete="new-password" :disabled="edit.remove_password" />
            <p v-if="edit.password && editProblems().length" class="err">{{ t('Needs:') }} {{ editProblems().map(p => t(p.key, { n: p.n })).join(', ') }}</p>
            <label v-if="s.password_protected && !policy().required" class="check"><input type="checkbox" v-model="edit.remove_password" /> {{ t('Remove password') }}</label>
            <label>{{ t('Files') }}</label>
            <div class="table-wrap"><table>
              <tr v-for="f in shareFiles" :key="f.id"><td>{{ f.full_path }}</td><td>{{ fmtBytes(f.size) }}</td>
                <td><button type="button" class="link" :disabled="addBusy || shareFiles.length < 2" :title="shareFiles.length < 2 ? t('A share needs at least one file') : ''" @click="removeFile(f)">✕</button></td></tr>
            </table></div>
            <div class="actions"><button type="button" class="secondary small" :disabled="addBusy" @click="pick(false)">{{ t('Add files') }}</button>
              <button type="button" class="secondary small" :disabled="addBusy" @click="pick(true)">{{ t('Add folder') }}</button>
              <span v-if="addBusy" class="muted">{{ addPct }}%</span></div>
            <p v-if="editErr" class="err">{{ editErr }}</p>
            <div class="actions"><button>{{ t('Save') }}</button><button type="button" class="secondary" @click="editShare = null">{{ t('Cancel') }}</button></div>
          </form></td></tr>
        <tr v-if="expiryShare && expiryShare.id === s.id"><td colspan="5" class="actions" style="margin:0">
          <label style="margin:0">{{ t('Expires') }}</label><input v-model="expiryValue" type="datetime-local" style="width:auto" />
          <button class="small" @click="saveDate">{{ t('Save') }}</button>
          <button class="small secondary" @click="saveExpiry({ never: true })">{{ t('Never expires') }}</button>
          <button class="small secondary" @click="expiryShare = null">{{ t('Cancel') }}</button></td></tr>
      </template>
    </table></div>
    <section v-if="historyShare && history" class="card" style="margin-top:20px">
      <div class="actions"><h2>{{ t('Download history') }} — {{ historyShare.name }}</h2><button type="button" class="secondary small" @click="historyShare = null">{{ t('Close') }}</button></div>
      <p class="muted">{{ t('Records show started transfers, not proof that a file was saved or opened.') }}</p>
      <p v-if="!history.downloads.length">{{ t('No downloads yet') }}</p>
      <div v-else class="table-wrap"><table><tr><th>{{ t('Started at') }}</th><th>{{ t('File') }}</th></tr><tr v-for="entry in history.downloads" :key="entry.id"><td>{{ fmtDate(entry.created_at) }}</td><td>{{ entry.file_name }}</td></tr></table></div>
      <div class="actions"><span>{{ history.total }} {{ t('Downloads') }}</span><button :disabled="historyBusy || history.offset === 0" class="secondary small" @click="showHistory(historyShare, Math.max(0, history.offset - history.limit))">{{ t('Previous') }}</button><button :disabled="historyBusy || history.offset + history.limit >= history.total" class="secondary small" @click="showHistory(historyShare, history.offset + history.limit)">{{ t('Next') }}</button></div>
    </section>
  </div>
</template>
