<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Encryption keys of this organisation: status per purpose, rotation and retirement
// (API /api/admin/keys) and, in the Cluster flavour, the tenant-supplied key (KEK,
// /api/admin/kek). Only fingerprints are ever shown. A key the administrator
// generates or types lives in component memory only: never in storage, the URL or a
// log, and it is wiped when the dialog closes. Mutations need a step-up; api() asks.
import { ref, computed, reactive, onMounted, onUnmounted } from 'vue'
import { api, fmtDate } from '../../api'
import { t, tr } from '../../i18n'
import { vFocusTrap } from '../../focus-trap.mjs'
import {
  FIXED_PURPOSES, generateKek, kekProblem, kekFileName, shortFingerprint, rotateAction, retireAction, legacyAction,
  activeVersion, rowsOlder, openJob, lastFinished, anyJobOpen, progress, kekFormReady
} from '../../keys.mjs'

const labels = {
  data: tr('Data (personal data, names, settings)'), index: tr('Search index (blind indexes)'), secrets: tr('Secrets (passwords of integrations)'),
  files: tr('Files'), 'audit-enc': tr('Audit log text'), 'audit-mac': tr('Audit log integrity (MAC)')
}
const stateLabels = { active: tr('active'), decrypt_only: tr('decrypt only'), retired: tr('retired'), created: tr('created'), confirmed: tr('confirmed') }
const label = p => (labels[p] ? t(labels[p]) : p)
const stateLabel = s => (stateLabels[s] ? t(stateLabels[s]) : s)

const status = ref(null), notEnabled = ref(false), loadErr = ref('')
const kek = ref(null), msg = ref(''), err = ref(''), busy = ref(false)
const peaks = reactive({})
let timer = null

const jobs = computed(() => status.value?.jobs || [])
const purposes = computed(() => status.value?.purposes || [])
const running = computed(() => anyJobOpen(jobs.value))
const legacy = computed(() => legacyAction(status.value, jobs.value))
// GET /admin/kek is authoritative: it says supported only where the controller key endpoint is attached.
const kekAvailable = computed(() => !!kek.value && kek.value.supported)
const kekReason = computed(() => (kek.value && !kek.value.supported)
  ? t('A tenant-supplied key is only available in the Cluster flavour.') : '')
const slug = computed(() => kek.value?.slug || '')

function trackPeaks() {
  for (const p of purposes.value) {
    const left = rowsOlder(p)
    if (openJob(jobs.value, p.purpose)) peaks[p.purpose] = Math.max(peaks[p.purpose] || 0, left)
    else delete peaks[p.purpose]
  }
}
const percent = p => progress(peaks[p.purpose] || 0, rowsOlder(p))

async function loadStatus() {
  try {
    status.value = await api('/admin/keys'); notEnabled.value = false; loadErr.value = ''
  } catch (e) {
    if (e.status === 404) { notEnabled.value = true; status.value = null } else loadErr.value = e.message
  }
  trackPeaks()
  if (running.value && !timer) timer = setInterval(() => loadStatus(), 2000)
  if (!running.value && timer) { clearInterval(timer); timer = null }
}
async function loadKek() {
  try { kek.value = await api('/admin/kek') } catch (e) { kek.value = { supported: false }; if (e.status !== 501 && e.status !== 404) loadErr.value = e.message }
}
onMounted(() => { loadStatus(); loadKek() })
onUnmounted(() => { clearInterval(timer); timer = null; wipe() })

// ---- confirm dialog for rotate / retire / convert ----
const dlg = ref(null)
function ask(d) { err.value = ''; msg.value = ''; dlg.value = d }
const askRotate = p => ask({ title: t('Rotate the {purpose} key', { purpose: label(p.purpose) }), body: t('A new key version becomes active and the existing values are re-encrypted in the background. Everything keeps working meanwhile. You are asked to confirm with your password or second factor.'), button: t('Rotate'), path: '/admin/keys/rotate', payload: { purpose: p.purpose }, done: t('Rotation requested.') })
const askRetire = (p, v) => ask({ title: t('Retire {purpose} version {version}', { purpose: label(p.purpose), version: v.version }), body: t('The old key version is retired and can no longer decrypt anything. This cannot be undone.'), button: t('Retire'), danger: true, path: '/admin/keys/retire', payload: { purpose: p.purpose, version: v.version }, done: t('Retirement requested.') })
const askLegacy = () => ask({ title: t('Convert legacy files'), body: t('{n} stored files are still under the old key and are not served until they are re-encrypted. They are re-encrypted in the background.', { n: status.value.legacy_files }), button: t('Convert'), path: '/admin/keys/reencrypt-files', payload: undefined, done: t('Conversion requested.') })
async function runDlg() {
  const d = dlg.value
  // Close the confirmation first: the step-up prompt opens in its own dialog and would sit behind this one.
  dlg.value = null
  busy.value = true; err.value = ''
  try {
    await api(d.path, { method: 'POST', body: d.payload })
    msg.value = d.done
    await loadStatus()
  } catch (e) { err.value = e.message } finally { busy.value = false }
}

// ---- tenant key (KEK) dialogs ----
// kform holds key material while a KEK dialog is open; wipe() overwrites and drops it.
const kform = ref(null)
let downloadUrl = ''
function wipe() {
  if (downloadUrl) { URL.revokeObjectURL(downloadUrl); downloadUrl = '' }
  if (kform.value) { for (const k of ['kek', 'old']) kform.value[k] = '' }
  kform.value = null
}
function openK(mode) {
  err.value = ''; msg.value = ''; wipe()
  kform.value = { mode, kek: '', old: '', stored: false, confirm: '', source: mode === 'upload' ? 'generate' : 'paste', copied: false }
  if (mode === 'upload' || mode === 'replace') generateInto()
}
function generateInto() { kform.value.kek = generateKek(); kform.value.source = 'generate'; kform.value.copied = false }
function pasteOwn() { kform.value.kek = ''; kform.value.source = 'paste' }
const kekOk = computed(() => kform.value && kekFormReady(kform.value.mode, kform.value, slug.value))
const problem = v => (v ? t(kekProblem(v)) : '')
async function copyKey() {
  try { await navigator.clipboard.writeText(kform.value.kek); kform.value.copied = true } catch { err.value = t('Copying failed. Select the key and copy it by hand.') }
}
function downloadKey() {
  if (downloadUrl) URL.revokeObjectURL(downloadUrl)
  downloadUrl = URL.createObjectURL(new Blob([kform.value.kek + '\n'], { type: 'text/plain' }))
  const a = document.createElement('a')
  a.href = downloadUrl; a.download = kekFileName(slug.value)
  document.body.appendChild(a); a.click(); a.remove()
}
async function runKek() {
  const f = kform.value
  const calls = {
    upload: ['/admin/kek/upload', { kek: f.kek.trim(), confirm: f.confirm.trim() }, t('Your organisation now uses its own key. Keep it safe.')],
    replace: ['/admin/kek/replace', { old_kek: f.old.trim(), new_kek: f.kek.trim() }, t('The key was replaced. Keep the new key safe.')],
    release: ['/admin/kek/release', { kek: f.old.trim() }, t('Your organisation is platform-managed again.')]
  }
  const [path, body, done] = calls[f.mode]
  busy.value = true; err.value = ''
  try {
    await api(path, { method: 'POST', body })
    wipe(); msg.value = done
    await Promise.all([loadKek(), loadStatus()])
  } catch (e) {
    err.value = e.message
    if (e.data?.code === 'partial_unlock') { wipe(); await loadKek() }
  } finally { busy.value = false }
}
function closeAll() { dlg.value = null; wipe(); err.value = '' }
const kekTitle = { upload: tr('Use my own key'), replace: tr('Replace key'), release: tr('Return to platform-managed') }
</script>

<template>
  <div class="card">
    <h1 style="margin:0 0 12px">{{ t('Encryption keys') }}</h1>
    <p class="muted">{{ t('Everything in this organisation is encrypted with keys of its own. Only fingerprints are shown here, never the keys.') }}</p>
    <p v-if="busy" role="status"><span class="spinner" aria-hidden="true" />{{ t('Working… confirm with your password or second factor if asked.') }}</p>
    <p v-if="msg" class="ok" role="status">{{ msg }}</p>
    <p v-if="err && !dlg && !kform" class="err" role="alert">{{ err }}</p>
    <p v-if="loadErr" class="err" role="alert">{{ loadErr }}</p>
    <p v-if="notEnabled" class="muted">{{ t('Column encryption is not enabled in this installation, so there are no keys to manage.') }}</p>

    <section v-if="status" aria-labelledby="keys-status">
      <div class="actions" style="margin:12px 0">
        <h2 id="keys-status" style="margin:0">{{ t('Key status') }}</h2>
        <button v-if="legacy.show" class="small" :disabled="!legacy.enabled || busy" @click="askLegacy">{{ t('Convert legacy files') }}</button>
      </div>
      <p v-if="legacy.show" class="err" role="alert">{{ t('{n} stored files are still under the old key and are not served until they are re-encrypted.', { n: status.legacy_files }) }}</p>
      <div v-for="p in purposes" :key="p.purpose" class="card" :data-purpose="p.purpose">
        <div class="actions" style="margin:0 0 8px">
          <h3 style="margin:0">{{ label(p.purpose) }}</h3>
          <button v-if="p.rotatable" class="small" :disabled="!rotateAction(p, jobs).enabled || busy" :title="rotateAction(p, jobs).enabled ? '' : t(rotateAction(p, jobs).reason)" @click="askRotate(p)">{{ t('Rotate') }}</button>
        </div>
        <p v-if="!p.rotatable" class="muted">{{ t('Not rotatable: audit records stay sealed with the key they were written with.') }}</p>
        <p v-if="activeVersion(p)">{{ t('Active version') }}: <b>{{ activeVersion(p).version }}</b> ({{ stateLabel(activeVersion(p).state) }}),
          {{ t('fingerprint') }} <code>{{ shortFingerprint(activeVersion(p).fingerprint) }}</code><span v-if="activeVersion(p).created_at">, {{ t('created') }} {{ fmtDate(activeVersion(p).created_at) }}</span></p>
        <p v-if="p.rotatable && rowsOlder(p) > 0 && !openJob(jobs, p.purpose)" class="muted">{{ t('{n} values or files are still on an older version.', { n: rowsOlder(p) }) }}</p>
        <p v-if="!openJob(jobs, p.purpose) && lastFinished(jobs, p.purpose)" role="status" :class="lastFinished(jobs, p.purpose).status === 'failed' ? 'err' : 'muted'">
          {{ lastFinished(jobs, p.purpose).status === 'failed' ? t('Last operation failed') : t('Last operation finished') }}:
          {{ lastFinished(jobs, p.purpose).op === 'retire' ? t('retired version {v}', { v: lastFinished(jobs, p.purpose).version }) : t('rotated to version {v}', { v: lastFinished(jobs, p.purpose).version }) }},
          {{ fmtDate(lastFinished(jobs, p.purpose).updated_at) }}<span v-if="lastFinished(jobs, p.purpose).detail"> — {{ lastFinished(jobs, p.purpose).detail }}</span>
        </p>
        <div v-if="openJob(jobs, p.purpose)" role="status">
          <p><span class="spinner" aria-hidden="true" />{{ openJob(jobs, p.purpose).status === 'pending' ? t('Waiting to start…') : t('Running…') }}
            <span v-if="percent(p) !== null">{{ percent(p) }}% ({{ t('{n} left', { n: rowsOlder(p) }) }})</span></p>
          <div class="bar" role="progressbar" :aria-valuenow="percent(p) ?? 0" aria-valuemin="0" aria-valuemax="100" :aria-label="label(p.purpose)"><i :style="{ width: (percent(p) ?? 0) + '%' }" /></div>
        </div>
        <div class="table-wrap"><table>
          <thead><tr><th>{{ t('Version') }}</th><th>{{ t('State') }}</th><th>{{ t('Fingerprint') }}</th><th>{{ t('Created') }}</th><th>{{ t('Still in use') }}</th><th></th></tr></thead>
          <tbody>
            <tr v-for="v in p.versions" :key="v.version">
              <td>{{ v.version }}</td><td>{{ stateLabel(v.state) }}</td><td><code>{{ shortFingerprint(v.fingerprint) }}</code></td><td>{{ v.created_at ? fmtDate(v.created_at) : '—' }}</td>
              <td>{{ p.purpose === 'files' ? (v.files < 0 ? '?' : v.files) : v.rows + v.audit_rows }}</td>
              <td>
                <template v-if="retireAction(p, v, jobs).show">
                  <button class="small danger" :disabled="!retireAction(p, v, jobs).enabled || busy" :aria-describedby="retireAction(p, v, jobs).enabled ? null : `why-${p.purpose}-${v.version}`" @click="askRetire(p, v)">{{ t('Retire') }}</button>
                  <span v-if="!retireAction(p, v, jobs).enabled" :id="`why-${p.purpose}-${v.version}`" class="muted"> {{ t(retireAction(p, v, jobs).reason) }}</span>
                </template>
              </td>
            </tr>
          </tbody>
        </table></div>
      </div>
      <p v-if="jobs.some(j => j.status === 'failed')" class="err">{{ t('A key operation failed. See the audit log for details.') }}</p>
    </section>

    <section aria-labelledby="keys-kek" style="margin-top:24px">
      <h2 id="keys-kek">{{ t('Tenant key') }}</h2>
      <p v-if="kekReason" class="muted">{{ kekReason }}</p>
      <template v-else-if="kekAvailable">
        <p>{{ t('Mode') }}: <span class="badge" :class="kek.mode === 'tenant' ? 'on' : ''">{{ kek.mode === 'tenant' ? t('Your own key') : t('Platform-managed') }}</span>
          <span v-if="kek.fingerprint">, {{ t('fingerprint') }} <code>{{ kek.fingerprint }}</code></span>
          <span v-if="kek.locked" class="badge off" role="status" style="margin-left:8px">{{ t('Locked') }}</span></p>
        <p v-if="kek.locked" class="err" role="alert">{{ t('This organisation is locked: the controllers do not hold its key. Present the key on the unlock page of this organisation.') }}</p>
        <p v-if="kek.mode === 'tenant' && kek.controllers_total" class="muted">{{ t('{n} of {total} controller replicas hold the key.', { n: kek.controllers_unlocked, total: kek.controllers_total }) }}</p>
        <p class="muted">{{ t('With your own key the platform operator cannot read your data, and nobody can recover it for you: if you lose the key your data is lost for good, backups included. After a controller restart the organisation stays locked until the key is presented again.') }}</p>
        <div class="actions">
          <button v-if="kek.mode !== 'tenant'" :disabled="busy || running" @click="openK('upload')">{{ t('Use my own key') }}</button>
          <template v-else>
            <button class="secondary" :disabled="busy || running" @click="openK('replace')">{{ t('Replace key') }}</button>
            <button class="secondary" :disabled="busy || running" @click="openK('release')">{{ t('Return to platform-managed') }}</button>
          </template>
        </div>
        <p v-if="running" class="muted">{{ t('Wait until the running key operation has finished.') }}</p>
      </template>
    </section>
  </div>

  <div v-if="dlg" v-focus-trap="closeAll" class="idle-modal" role="dialog" aria-modal="true" aria-labelledby="keys-dlg-title">
    <form class="idle-box card" style="text-align:left" @submit.prevent="runDlg">
      <h2 id="keys-dlg-title">{{ dlg.title }}</h2>
      <p>{{ dlg.body }}</p>
      <p v-if="err" class="err" role="alert">{{ err }}</p>
      <div class="actions"><button :class="{ danger: dlg.danger }" :disabled="busy">{{ dlg.button }}</button><button type="button" class="secondary" :disabled="busy" @click="closeAll">{{ t('Cancel') }}</button></div>
    </form>
  </div>

  <div v-if="kform && !busy" v-focus-trap="closeAll" class="idle-modal" role="dialog" aria-modal="true" aria-labelledby="keys-kdlg-title">
    <form class="idle-box card" style="text-align:left;max-width:560px;max-height:90vh;overflow:auto" autocomplete="off" @submit.prevent="runKek">
      <h2 id="keys-kdlg-title">{{ t(kekTitle[kform.mode]) }}</h2>
      <p class="err">{{ t('The platform operator cannot recover your organisation without this key. If you lose it, all data is lost for good, backups included. After a controller restart the organisation is locked until the key is presented again.') }}</p>

      <template v-if="kform.mode === 'release'">
        <label for="k-old">{{ t('Your current key') }}</label>
        <input id="k-old" v-model="kform.old" type="password" autocomplete="off" spellcheck="false" :aria-invalid="!!problem(kform.old)" />
        <p v-if="problem(kform.old)" class="muted">{{ problem(kform.old) }}</p>
      </template>

      <template v-else>
        <template v-if="kform.mode === 'replace'">
          <label for="k-old">{{ t('Your current key') }}</label>
          <input id="k-old" v-model="kform.old" type="password" autocomplete="off" spellcheck="false" :aria-invalid="!!problem(kform.old)" />
          <p v-if="problem(kform.old)" class="muted">{{ problem(kform.old) }}</p>
        </template>
        <div class="tabs" role="group" :aria-label="t('Source of the new key')" style="margin-top:12px">
          <a href="#" :class="{ 'router-link-active': kform.source === 'generate' }" :aria-current="kform.source === 'generate'" @click.prevent="generateInto">{{ t('Generate a key') }}</a>
          <a href="#" :class="{ 'router-link-active': kform.source === 'paste' }" :aria-current="kform.source === 'paste'" @click.prevent="pasteOwn">{{ t('Paste an existing key') }}</a>
        </div>
        <template v-if="kform.source === 'generate'">
          <label for="k-new">{{ t('New key (shown only now)') }}</label>
          <textarea id="k-new" readonly rows="2" spellcheck="false" :value="kform.kek" style="font-family:ui-monospace,Menlo,monospace" @focus="$event.target.select()"></textarea>
          <p class="muted">{{ t('It was generated in your browser and is not sent anywhere until you confirm. Store it in a password manager or safe now; it cannot be shown again.') }}</p>
          <div class="actions"><button type="button" class="small secondary" @click="copyKey">{{ kform.copied ? t('Copied') : t('Copy') }}</button><button type="button" class="small secondary" @click="downloadKey">{{ t('Download as file') }}</button></div>
        </template>
        <template v-else>
          <label for="k-new">{{ t('New key (base64, 32 bytes)') }}</label>
          <input id="k-new" v-model="kform.kek" type="password" autocomplete="off" spellcheck="false" :aria-invalid="!!problem(kform.kek)" />
          <p v-if="problem(kform.kek)" class="muted">{{ problem(kform.kek) }}</p>
        </template>
        <label style="display:flex;gap:8px;align-items:flex-start;margin-top:12px"><input v-model="kform.stored" type="checkbox" style="width:auto;margin-top:4px" /> <span>{{ t('I stored this key; losing it loses all data.') }}</span></label>
        <template v-if="kform.mode === 'upload'">
          <label for="k-confirm">{{ t('Type the organisation name ({slug}) to confirm', { slug }) }}</label>
          <input id="k-confirm" v-model="kform.confirm" autocomplete="off" spellcheck="false" />
        </template>
      </template>

      <p v-if="err" class="err" role="alert">{{ err }}</p>
      <div class="actions"><button :class="{ danger: kform.mode !== 'replace' }" :disabled="busy || !kekOk">{{ t(kekTitle[kform.mode]) }}</button><button type="button" class="secondary" :disabled="busy" @click="closeAll">{{ t('Cancel') }}</button></div>
    </form>
  </div>
</template>
