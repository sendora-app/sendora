<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { api, session, fmtBytes } from '../api'
import { app, emailLanguages, pageTitle } from '../state'
import { t, lang, tr } from '../i18n'
import { collect, fromInput, uploadAll } from '../uploader'
import { begin as beginTransfer } from '../transfers.mjs'
import { sharePolicy, passwordProblems } from '../sharepolicy.mjs'
import QrCode from '../components/QrCode.vue'
import FileTree from '../components/FileTree.vue'
import { buildTree, bytesDonePerFile } from '../folder-tree.mjs'

const entries = ref([]), over = ref(false), busy = ref(false), pct = ref(0), err = ref(''), result = ref(null), copied = ref(false)
const form = ref({ name: '', description: '', password: '', expires_in_days: app.boot?.default_expiry_time || 7, download_limit: '', recipients: '', message: '', email_language: session.user?.language || lang.value })
const guest = computed(() => session.user?.is_guest)
const total = computed(() => entries.value.reduce((a, e) => a + e.file.size, 0))
const maxMB = computed(() => app.boot?.max_share_size)
const tree = computed(() => buildTree(entries.value.map(entry => ({ path: entry.path, size: entry.file.size, entry }))))
const doneBytes = ref(0), started = ref(false)
// Uploads run file after file in list order, so the overall byte count gives per-file progress.
const doneByPath = computed(() => {
  const list = entries.value
  const per = bytesDonePerFile(list.map(e => e.file.size), doneBytes.value)
  return Object.fromEntries(list.map((e, i) => [e.path, per[i]]))
})
const doneOf = item => doneByPath.value[item.entry.path] || 0
const available = ref(null)
// Multi-tenant mode: an organisation without storage cannot accept uploads yet.
const storageReady = ref(true)
onMounted(async () => {
  if (guest.value) return
  try {
    const me = await api('/users/me')
    available.value = me.storage_available_bytes ?? null
    storageReady.value = me.storage_ready !== false
  } catch {}
})
const overQuota = computed(() => available.value != null && total.value > available.value)
const overMax = computed(() => !!maxMB.value && total.value > maxMB.value * 1024 * 1024)
const fileIn = ref(), dirIn = ref(), phase = ref(tr('Uploading…'))
let ctrl = null
const completing = ref(false)
watch([busy, pct, phase], () => { pageTitle.value = busy.value ? `${pct.value}% – ${t(phase.value)}` : '' })
onBeforeUnmount(() => { pageTitle.value = '' })
const policy = computed(() => sharePolicy(app.boot))
const problems = computed(() => (guest.value ? [] : passwordProblems(form.value.password, policy.value)))
const hint = p => t(p.key, { n: p.n })

async function onDrop(e) {
  over.value = false
  if (busy.value) return
  try { add(await collect(e.dataTransfer)) } catch (e) { err.value = e.message }
}
function add(list) {
  if (busy.value) return
  for (const entry of list) {
    if (!entries.value.some(existing => existing.path === entry.path)) entries.value.push(entry)
  }
}
function removeFile(node) { entries.value = entries.value.filter(e => e.path !== node.path) }
function removeFolder(node) { entries.value = entries.value.filter(e => !e.path.startsWith(node.path + '/')) }
function cancel() { if (!completing.value) ctrl?.abort() }

async function go() {
  if (problems.value.length) { err.value = t('Password policy: ') + problems.value.map(hint).join(', '); return }
  err.value = ''; busy.value = true; pct.value = 0; doneBytes.value = 0; started.value = true; ctrl = new AbortController()
  const endTransfer = beginTransfer() // covers checksums, upload and completion
  try {
    const f = { ...form.value }
    const id = await uploadAll([...entries.value], (d, tot) => { doneBytes.value = d; pct.value = tot ? Math.round(d / tot * 100) : 100 }, ctrl.signal, value => (phase.value = value))
    if (ctrl.signal.aborted) {
      await api('/uploads/' + id, { method: 'DELETE' })
      throw new DOMException('Cancelled', 'AbortError')
    }
    // Completion commits a share atomically. Once submitted, cancellation cannot
    // reliably undo it; keep waiting for the definitive response instead.
    completing.value = true
    phase.value = tr('Verifying upload…')
    result.value = await api(`/uploads/${id}/complete`, {
      method: 'POST',
      body: { name: f.name, description: f.description, password: f.password, expires_in_days: +f.expires_in_days,
        download_limit: +f.download_limit || 0, message: f.message, email_language: f.email_language,
        recipients: f.recipients.split(/[,;\s]+/).filter(Boolean) }
    })
    entries.value = []
  } catch (e) { err.value = e.name === 'AbortError' || e.message === 'aborted' ? t('Cancelled') : e.message }
  finally { endTransfer(); busy.value = false; started.value = false; completing.value = false; ctrl = null }
}
async function copy() { await navigator.clipboard.writeText(result.value.url); copied.value = true; setTimeout(() => (copied.value = false), 1500) }
function again() { result.value = null; form.value.name = form.value.description = form.value.password = '' }
</script>

<template>
  <div v-if="!storageReady" class="card" role="status">
    <h1>{{ t('Upload') }}</h1>
    <p class="notice">{{ session.user?.admin ? t('Set up storage first under Admin → Storage. Until then, files cannot be uploaded or shared.') : t('Uploading is not available yet: your organisation has not set up storage. Please ask an administrator.') }}</p>
    <div v-if="session.user?.admin" class="actions"><router-link class="button" to="/admin/storage">{{ t('Set up storage') }}</router-link></div>
  </div>
  <div v-else-if="result" class="card">
    <h1>{{ t('Share created') }}</h1>
    <input v-if="!guest" :value="result.url" readonly @focus="$event.target.select()" />
    <QrCode v-if="!guest" :value="result.url" />
    <div class="actions">
      <button v-if="!guest" @click="copy">{{ copied ? t('Copied') : t('Copy link') }}</button>
      <button v-if="!guest" class="secondary" @click="again">{{ t('Upload') }}</button>
    </div>
    <p v-if="guest" class="ok">{{ t('Thank you! Your files were delivered.') }}</p>
  </div>
  <div v-else>
    <div class="card">
      <div class="drop" :class="{ over }" @dragover.prevent="over = true" @dragleave="over = false" @drop.prevent="onDrop" @click="fileIn.click()">
        <p><b>{{ t('Drop files or folders here') }}</b></p><p>{{ t('or click to browse') }}</p>
      </div>
      <input ref="fileIn" type="file" multiple hidden @change="add(fromInput($event.target.files)); $event.target.value = ''" />
      <input ref="dirIn" type="file" webkitdirectory hidden @change="add(fromInput($event.target.files)); $event.target.value = ''" />
      <div class="actions"><button class="secondary small" @click="dirIn.click()">{{ t('Add folder') }}</button>
        <span v-if="maxMB" class="muted">{{ t('Max {n} MB per share', { n: maxMB }) }}</span></div>
      <div v-if="entries.length" class="summary" aria-live="polite">
        <div class="chip"><b>{{ entries.length }}</b><span>{{ entries.length === 1 ? t('1 file') : t('{n} files', { n: entries.length }) }}</span></div>
        <div v-if="tree.folders" class="chip"><b>{{ tree.folders }}</b><span>{{ tree.folders === 1 ? t('1 folder') : t('{n} folders', { n: tree.folders }) }}</span></div>
        <div class="chip" :class="{ bad: overQuota || overMax }"><b>{{ fmtBytes(total) }}<template v-if="available != null"> / {{ fmtBytes(available) }}</template></b><span>{{ t('Size') }}</span></div>
        <div v-if="!guest" class="chip"><b>{{ form.expires_in_days }}</b><span>{{ t('Expires in (days)') }}</span></div>
      </div>
      <FileTree v-if="entries.length" :root="tree" :done-of="started ? doneOf : null" removable :locked="busy" @remove-file="removeFile" @remove-folder="removeFolder" />
    </div>
    <form v-if="entries.length" class="card" @submit.prevent="go">
      <div class="row">
        <div><label>{{ t('Name') }}</label><input v-model="form.name" /></div>
        <div v-if="!guest"><label>{{ policy.required ? t('Password') : t('Optional password') }}</label><input v-model="form.password" type="password" autocomplete="new-password" :required="policy.required" /></div>
      </div>
      <p v-if="!guest && (form.password || policy.required)" class="muted" :class="{ err: problems.length && form.password }">{{ problems.length ? t('Needs:') + ' ' + problems.map(hint).join(', ') : '✓ ' + t('Password meets the requirements') }}</p>
      <label>{{ t('Description') }}</label><textarea v-model="form.description" rows="2" />
      <div v-if="!guest" class="row">
        <div><label>{{ t('Expires in (days)') }}</label><input v-model="form.expires_in_days" type="number" min="1" :max="app.boot?.max_expiry_time || undefined" /></div>
        <div><label>{{ t('Download limit') }}</label><input v-model="form.download_limit" type="number" min="1" placeholder="∞" /></div>
      </div>
      <template v-if="!guest">
        <label>{{ t('Recipients (emails, comma separated)') }}</label><input v-model="form.recipients" />
        <label v-if="form.recipients">{{ t('Email language') }}</label><select v-if="form.recipients" v-model="form.email_language"><option v-for="(name, code) in emailLanguages" :key="code" :value="code">{{ name }}</option></select>
        <label v-if="form.recipients">{{ t('Message') }}</label><textarea v-if="form.recipients" v-model="form.message" rows="2" />
      </template>
      <div v-if="busy"><div class="bar"><i :style="{ width: pct + '%' }" /></div><p class="muted">{{ t(phase) }} {{ pct }}%</p></div>
      <p v-if="err" class="err">{{ err }}</p>
      <div class="actions"><button :disabled="busy">{{ t('Create share') }}</button>
        <button v-if="busy" :disabled="completing" type="button" class="secondary" @click="cancel">{{ t('Cancel') }}</button></div>
    </form>
  </div>
</template>
