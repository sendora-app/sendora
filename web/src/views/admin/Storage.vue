<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Object storage: where new share files go (local, S3, Azure Blob, GCS), the
// connection test, where existing files live and moving them to the current
// location. Only the storage keys are sent when saving.
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { api, fmtBytes, fmtDate } from '../../api'
import { t } from '../../i18n'
import StorageForm from '../../components/StorageForm.vue'

const KEYS = ['storage_backend',
  'storage_s3_endpoint', 'storage_s3_region', 'storage_s3_bucket', 'storage_s3_prefix', 'storage_s3_path_style', 'storage_s3_auth', 'storage_s3_access_key', 'storage_s3_secret_key',
  'storage_azure_account', 'storage_azure_container', 'storage_azure_endpoint', 'storage_azure_prefix', 'storage_azure_auth', 'storage_azure_account_key', 'storage_azure_sas_token',
  'storage_gcs_bucket', 'storage_gcs_endpoint', 'storage_gcs_prefix', 'storage_gcs_auth', 'storage_gcs_credentials_json',
  'backup_remote_enabled']
const SECRETS = ['storage_s3_secret_key', 'storage_azure_account_key', 'storage_azure_sas_token', 'storage_gcs_credentials_json']

const s = ref(null), isSet = ref({}), managed = ref([]), status = ref(null)
const msg = ref(''), err = ref(''), busy = ref(false), testResult = ref(null), testing = ref(false), migMsg = ref(''), migErr = ref('')
const m = k => managed.value.includes(k)
const running = computed(() => status.value?.migration?.status === 'running')
// Multi-tenant mode: the platform decides where files go unless it lets this
// organisation configure its own storage.
const tenant = computed(() => status.value?.tenant || null)
const editable = computed(() => !tenant.value || tenant.value.editable)
// The "local" choice of a tenant is what the platform provides (nothing: hidden).
const localLabel = computed(() => {
  const tn = tenant.value
  if (!tn) return null
  if (tn.offer === 'platform') return t('Platform default ({where})', { where: tn.platform_choice })
  if (tn.offer === 'local') return t('Local disk on the server')
  return ''
})
let timer = null

async function loadStatus() {
  status.value = await api('/storage')
  if (running.value && !timer) timer = setInterval(() => loadStatus().catch(() => {}), 2000)
  if (!running.value && timer) { clearInterval(timer); timer = null }
}
async function loadSettings() {
  const settings = await api('/settings')
  managed.value = settings.managed_settings || []
  s.value = Object.fromEntries(KEYS.map(k => [k, settings[k] ?? '']))
  isSet.value = Object.fromEntries(SECRETS.map(k => [k, !!settings[k + '_set']]))
}
async function load() {
  await Promise.all([loadSettings(), loadStatus()])
  // Nothing provided by the platform: start the form on S3 instead of a hidden choice.
  if (tenant.value && tenant.value.offer === 'none' && s.value && s.value.storage_backend === 'local') s.value.storage_backend = 's3'
}
onMounted(async () => { try { await load() } catch (e) { err.value = e.message } })
onUnmounted(() => { if (timer) clearInterval(timer) })

// Configured (read-only) settings and blank secrets (= keep) are not sent.
const body = () => Object.fromEntries(Object.entries(s.value).filter(([k, v]) => !m(k) && !(SECRETS.includes(k) && v === '') && (editable.value || k === 'backup_remote_enabled')))

async function save() {
  msg.value = err.value = ''; testResult.value = null; busy.value = true
  try {
    await api('/settings', { method: 'PUT', body: body() })
    await load(); msg.value = t('Saved')
  } catch (e) {
    err.value = e.message
    try { await loadStatus() } catch {}
  } finally { busy.value = false }
}
async function test() {
  msg.value = err.value = ''; testResult.value = null; testing.value = true
  try { testResult.value = await api('/storage/test', { method: 'POST', body: body() }) } catch (e) { err.value = e.message } finally { testing.value = false }
}
async function migrate() {
  migMsg.value = migErr.value = ''
  if (!confirm(t('Move all files to the current storage location? Each file is copied, verified and only then removed from its old location.'))) return
  try { await api('/storage/migrate', { method: 'POST' }); migMsg.value = t('Migration started.'); await loadStatus() } catch (e) { migErr.value = e.message }
}
async function cancelMigration() {
  migMsg.value = migErr.value = ''
  try { await api('/storage/migrate/cancel', { method: 'POST' }); await loadStatus() } catch (e) { migErr.value = e.message }
}
const flag = k => s.value[k] === 'true'
const setFlag = (k, e) => { s.value[k] = String(e.target.checked) }
const statusLabel = st => ({ running: t('running'), finished: t('finished'), failed: t('failed'), cancelled: t('cancelled') }[st] || st)
</script>
<template>
  <p v-if="!s && err" class="err" role="alert">{{ err }}</p>
  <div v-if="status" class="card">
    <h1>{{ t('Storage') }}</h1>
    <p>{{ t('New files are stored in: {where}', { where: status.description }) }}</p>
    <p v-if="status.error" class="err" role="alert">{{ t('The storage backend is not usable: {error}', { error: status.error }) }}</p>
    <p v-if="tenant && tenant.limit_applies && tenant.limit_bytes > 0" :class="tenant.used_bytes >= tenant.limit_bytes ? 'err' : ''" role="status">{{ t('Storage used: {used} of {limit} (limit set by the platform).', { used: fmtBytes(tenant.used_bytes), limit: fmtBytes(tenant.limit_bytes) }) }}</p>
    <p v-if="status.backend && status.backend !== 'local'" class="notice" role="note">{{ t('Remote storage can make uploads slower: after the transfer, each file is encrypted and copied to the object store before the share is ready, so large files or a distant region take longer. Downloads are read back from the object store and can be slower as well.') }}</p>
    <p class="muted">{{ t('Files are encrypted before they leave the server: an object store only ever receives encrypted data under random names that reveal neither share links nor file names.') }}</p>
    <h2 style="margin-top:20px">{{ t('Where files live') }}</h2>
    <div class="table-wrap"><table>
      <tr><th>{{ t('Location') }}</th><th>{{ t('Files') }}</th><th>{{ t('Size') }}</th><th></th></tr>
      <tr v-for="l in status.locations" :key="l.id"><td>{{ l.description }}</td><td>{{ l.files }}</td><td>{{ fmtBytes(l.bytes) }}</td>
        <td><span v-if="l.current" class="muted">{{ t('current') }}</span></td></tr>
    </table></div>
    <p class="muted">{{ t('Files in an earlier location stay readable from there until they are moved.') }}</p>
    <p v-if="status.pending_deletes > 0" class="muted">{{ t('{n} removed file(s) are still waiting to be deleted from an object store; deletion is retried automatically.', { n: status.pending_deletes }) }}</p>

    <h2 style="margin-top:20px">{{ t('Move files') }}</h2>
    <template v-if="running">
      <p role="status">{{ t('Moving files: {done} of {total} done, {failed} failed ({bytes}).', { done: status.migration.done, total: status.migration.total, failed: status.migration.failed, bytes: fmtBytes(status.migration.bytes) }) }}</p>
      <div class="actions"><button class="secondary" @click="cancelMigration">{{ t('Cancel') }}</button></div>
    </template>
    <template v-else>
      <p v-if="status.remaining > 0">{{ t('{n} file(s) are not in the current location.', { n: status.remaining }) }}</p>
      <p v-else class="muted">{{ t('All files are in the current location.') }}</p>
      <div v-if="status.remaining > 0" class="actions"><button @click="migrate">{{ t('Move files to the current location') }}</button></div>
    </template>
    <p v-if="status.migration && !running" class="muted">{{ t('Last migration: {status} on {date} ({done} of {total} moved, {failed} failed).', { status: statusLabel(status.migration.status), date: fmtDate(status.migration.finished_at || status.migration.started_at), done: status.migration.done, total: status.migration.total, failed: status.migration.failed }) }}</p>
    <p v-if="status.migration && !running && status.migration.error" class="err">{{ status.migration.error }}</p>
    <p v-if="migMsg" class="ok" role="status">{{ migMsg }}</p><p v-if="migErr" class="err" role="alert">{{ migErr }}</p>
  </div>

  <form v-if="s" class="card" @submit.prevent="save">
    <h1>{{ t('Storage settings') }}</h1>
    <template v-if="tenant">
      <p v-if="!tenant.configured" class="notice storage-missing" role="alert"><strong>{{ t('Storage is not set up yet.') }}</strong>
        {{ tenant.editable ? t('Choose S3, Azure Blob Storage or Google Cloud Storage below, test the connection and save. Until then, files cannot be uploaded or shared.') : t('The platform does not provide storage for this organisation and does not allow storage of its own. Contact the platform administrator.') }}</p>
      <p v-else-if="!tenant.editable" class="muted" role="note">{{ t('The platform manages the storage of this organisation: new files are stored in {where}. Contact the platform administrator to change it.', { where: tenant.platform_choice }) }}</p>
      <p v-else-if="tenant.offer !== 'none'" class="muted" role="note">{{ t('The platform lets this organisation use storage of its own. Choose the platform default to use the storage the platform provides ({where}).', { where: tenant.platform_choice }) }}</p>
    </template>
    <p v-if="KEYS.some(m)" class="muted">{{ t('Settings set in the server configuration (environment or Kubernetes ConfigMap) are read-only here: {n}.', { n: KEYS.filter(m).join(', ') }) }}</p>
    <StorageForm v-if="editable" :model-value="s" :managed="managed" :is-set="isSet" id-prefix="st" :show-notice="!status || status.backend === 'local'"
      :local-label="localLabel" :explicit-only="!!tenant" />
    <label class="check"><input :disabled="m('backup_remote_enabled')" type="checkbox" :checked="flag('backup_remote_enabled')" @change="setFlag('backup_remote_enabled', $event)" /> {{ t('Also copy the daily database backups to the object store') }}</label>
    <p class="muted">{{ t('Backups are already encrypted (SQLCipher) and are stored under backups/ next to the files; the number of backups to keep also applies to the remote copies.') }}</p>

    <p v-if="testResult && testResult.ok" class="ok" role="status">{{ t('Connection works: a test object was written, read and deleted in {ms} ms ({where}).', { ms: testResult.ms, where: testResult.description }) }}</p>
    <p v-if="testResult && !testResult.ok" class="err" role="alert">{{ t('Connection test failed: {error}', { error: testResult.error }) }}</p>
    <p v-if="msg" class="ok" role="status">{{ msg }}</p><p v-if="err" class="err" role="alert">{{ err }}</p>
    <div class="actions"><button :disabled="busy">{{ t('Save') }}</button>
      <button v-if="editable && s.storage_backend !== 'local'" type="button" class="secondary" :disabled="testing" @click="test">{{ testing ? t('Testing…') : t('Test connection') }}</button></div>
  </form>
</template>
