<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// The object storage fields (local, S3, Azure Blob, GCS) shared by Admin ->
// Storage and the platform console (platform default and a tenant's own
// bucket). v-model is a map of storage_* settings; secrets are write-only:
// isSet says whether one is stored, an empty field keeps it.
import { computed } from 'vue'
import { t } from '../i18n'

const props = defineProps({
  modelValue: { type: Object, required: true },
  managed: { type: Array, default: () => [] },
  isSet: { type: Object, default: () => ({}) },
  idPrefix: { type: String, default: 'st' },
  // Label of the "local" option ("" hides it: an own bucket must be remote).
  localLabel: { type: String, default: null },
  // Only explicit credentials (a tenant's own storage in multi-tenant mode).
  explicitOnly: { type: Boolean, default: false },
  disabled: { type: Boolean, default: false },
  // Show the notice about slower transfers when a remote backend is selected
  // (off where the page already shows it for the active backend).
  showNotice: { type: Boolean, default: true },
})
const s = computed(() => props.modelValue)
const m = k => props.disabled || props.managed.includes(k)
const ph = k => (props.isSet[k] ? '••••••••' : '')
const id = k => props.idPrefix + '-' + k
const flag = k => s.value[k] === 'true'
const setFlag = (k, e) => { s.value[k] = String(e.target.checked) }
</script>
<template>
  <label :for="id('backend')">{{ t('Storage backend') }}</label>
  <select :id="id('backend')" :disabled="m('storage_backend')" v-model="s.storage_backend">
    <option v-if="localLabel !== ''" value="local">{{ localLabel || t('Local data directory') }}</option>
    <option value="s3">{{ t('S3-compatible (AWS S3, MinIO, Cloudflare R2, Wasabi, Backblaze B2)') }}</option>
    <option value="azure">Azure Blob Storage</option>
    <option value="gcs">Google Cloud Storage</option>
  </select>

  <template v-if="s.storage_backend === 's3'">
    <div class="row">
      <div><label :for="id('s3-endpoint')">{{ t('Endpoint (empty = AWS)') }}</label><input :id="id('s3-endpoint')" :disabled="m('storage_s3_endpoint')" v-model="s.storage_s3_endpoint" placeholder="https://s3.example.com" /></div>
      <div><label :for="id('s3-region')">{{ t('Region') }}</label><input :id="id('s3-region')" :disabled="m('storage_s3_region')" v-model="s.storage_s3_region" placeholder="eu-west-1" /></div>
    </div>
    <div class="row">
      <div><label :for="id('s3-bucket')">{{ t('Bucket') }}</label><input :id="id('s3-bucket')" :disabled="m('storage_s3_bucket')" v-model="s.storage_s3_bucket" /></div>
      <div><label :for="id('s3-prefix')">{{ t('Prefix') }}</label><input :id="id('s3-prefix')" :disabled="m('storage_s3_prefix')" v-model="s.storage_s3_prefix" placeholder="sendora/" /></div>
    </div>
    <label class="check"><input :disabled="m('storage_s3_path_style')" type="checkbox" :checked="flag('storage_s3_path_style')" @change="setFlag('storage_s3_path_style', $event)" /> {{ t('Path-style addressing (MinIO and most self-hosted services)') }}</label>
    <label :for="id('s3-auth')">{{ t('Credentials') }}</label>
    <select :id="id('s3-auth')" :disabled="m('storage_s3_auth')" v-model="s.storage_s3_auth">
      <option value="static">{{ t('Access key and secret key') }}</option>
      <option v-if="!explicitOnly" value="default">{{ t('AWS default credential chain (IRSA, web identity, instance role)') }}</option>
    </select>
    <div v-if="s.storage_s3_auth === 'static'" class="row">
      <div><label :for="id('s3-ak')">{{ t('Access key') }}</label><input :id="id('s3-ak')" :disabled="m('storage_s3_access_key')" v-model="s.storage_s3_access_key" autocomplete="off" /></div>
      <div><label :for="id('s3-sk')">{{ t('Secret key') }}</label><input :id="id('s3-sk')" :disabled="m('storage_s3_secret_key')" v-model="s.storage_s3_secret_key" type="password" autocomplete="new-password" :placeholder="ph('storage_s3_secret_key')" /></div>
    </div>
  </template>

  <template v-if="s.storage_backend === 'azure'">
    <div class="row">
      <div><label :for="id('az-account')">{{ t('Storage account') }}</label><input :id="id('az-account')" :disabled="m('storage_azure_account')" v-model="s.storage_azure_account" /></div>
      <div><label :for="id('az-container')">{{ t('Container') }}</label><input :id="id('az-container')" :disabled="m('storage_azure_container')" v-model="s.storage_azure_container" /></div>
    </div>
    <div class="row">
      <div><label :for="id('az-endpoint')">{{ t('Endpoint (empty = https://<account>.blob.core.windows.net)') }}</label><input :id="id('az-endpoint')" :disabled="m('storage_azure_endpoint')" v-model="s.storage_azure_endpoint" /></div>
      <div><label :for="id('az-prefix')">{{ t('Prefix') }}</label><input :id="id('az-prefix')" :disabled="m('storage_azure_prefix')" v-model="s.storage_azure_prefix" placeholder="sendora/" /></div>
    </div>
    <label :for="id('az-auth')">{{ t('Authentication') }}</label>
    <select :id="id('az-auth')" :disabled="m('storage_azure_auth')" v-model="s.storage_azure_auth">
      <option value="shared_key">{{ t('Account key (shared key)') }}</option>
      <option value="sas">{{ t('SAS token') }}</option>
      <option v-if="!explicitOnly" value="identity">{{ t('Managed or workload identity (DefaultAzureCredential)') }}</option>
    </select>
    <template v-if="s.storage_azure_auth === 'shared_key'"><label :for="id('az-key')">{{ t('Account key') }}</label><input :id="id('az-key')" :disabled="m('storage_azure_account_key')" v-model="s.storage_azure_account_key" type="password" autocomplete="new-password" :placeholder="ph('storage_azure_account_key')" /></template>
    <template v-if="s.storage_azure_auth === 'sas'"><label :for="id('az-sas')">{{ t('SAS token') }}</label><input :id="id('az-sas')" :disabled="m('storage_azure_sas_token')" v-model="s.storage_azure_sas_token" type="password" autocomplete="new-password" :placeholder="ph('storage_azure_sas_token')" /></template>
  </template>

  <template v-if="s.storage_backend === 'gcs'">
    <div class="row">
      <div><label :for="id('gcs-bucket')">{{ t('Bucket') }}</label><input :id="id('gcs-bucket')" :disabled="m('storage_gcs_bucket')" v-model="s.storage_gcs_bucket" /></div>
      <div><label :for="id('gcs-prefix')">{{ t('Prefix') }}</label><input :id="id('gcs-prefix')" :disabled="m('storage_gcs_prefix')" v-model="s.storage_gcs_prefix" placeholder="sendora/" /></div>
    </div>
    <label :for="id('gcs-endpoint')">{{ t('Endpoint (empty = https://storage.googleapis.com)') }}</label><input :id="id('gcs-endpoint')" :disabled="m('storage_gcs_endpoint')" v-model="s.storage_gcs_endpoint" />
    <label :for="id('gcs-auth')">{{ t('Authentication') }}</label>
    <select :id="id('gcs-auth')" :disabled="m('storage_gcs_auth')" v-model="s.storage_gcs_auth">
      <option value="service_account">{{ t('Service account JSON key') }}</option>
      <option v-if="!explicitOnly" value="default">{{ t('Workload identity or application default credentials') }}</option>
      <option v-if="!explicitOnly" value="none">{{ t('None (emulator only)') }}</option>
    </select>
    <template v-if="s.storage_gcs_auth === 'service_account'"><label :for="id('gcs-json')">{{ t('Service account JSON key') }}</label>
      <textarea :id="id('gcs-json')" :disabled="m('storage_gcs_credentials_json')" v-model="s.storage_gcs_credentials_json" rows="4" spellcheck="false" autocomplete="off" :placeholder="ph('storage_gcs_credentials_json')" /></template>
  </template>

  <p v-if="showNotice && s.storage_backend && s.storage_backend !== 'local'" class="notice" role="note">{{ t('Remote storage can make uploads slower: after the transfer, each file is encrypted and copied to the object store before the share is ready, so large files or a distant region take longer. Downloads are read back from the object store and can be slower as well.') }}</p>
  <p v-if="s.storage_backend !== 'local'" class="muted">{{ explicitOnly
    ? t('Endpoints must use https and be reachable on the internet: private, loopback and link-local addresses are refused. Only explicit credentials can be used. Secrets are never shown again; leave them empty to keep the stored value. A changed configuration is tested before it is saved.')
    : t('Endpoints must use https; http is only accepted for localhost and private networks (for example MinIO next to Sendora). Secrets are never shown again; leave them empty to keep the stored value. A changed configuration is tested before it is saved.') }}</p>
</template>
