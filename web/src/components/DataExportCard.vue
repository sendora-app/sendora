<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Personal data: download everything stored about the own account (JSON) and, after
// confirmation, delete the account (shares, files, invites, sessions, second factors).
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, downloadBlob, logout } from '../api'
import { t } from '../i18n'

const props = defineProps({ hasPassword: { type: Boolean, default: true } })
const router = useRouter()
const msg = ref(''), err = ref(''), busy = ref(false), erasing = ref(false), password = ref('')

async function download() {
  msg.value = err.value = ''; busy.value = true
  try { await downloadBlob('/users/me/export', 'sendora-my-data.json'); msg.value = t('Your data was downloaded.') }
  catch (e) { err.value = e.message } finally { busy.value = false }
}
async function erase() {
  msg.value = err.value = ''
  if (!confirm(t('Delete your account permanently? All your shares, files and invites are deleted and you are signed out. This cannot be undone.'))) return
  busy.value = true
  try {
    await api('/users/me/erase', { method: 'POST', body: { password: password.value } })
    await logout()
    router.replace('/login')
  } catch (e) { err.value = e.message } finally { busy.value = false; password.value = '' }
}
</script>

<template>
  <section class="card" style="max-width:520px">
    <h2>{{ t('Your data') }}</h2>
    <p class="muted">{{ t('Download a copy of the data stored about your account: profile, settings, two-step verification methods (without secrets), your shares (without file contents), download history, invites, sessions and your audit log entries.') }}</p>
    <div class="actions"><button type="button" class="secondary" :disabled="busy" @click="download">{{ t('Download my data') }}</button></div>
    <h3 style="margin-top:16px">{{ t('Delete my account') }}</h3>
    <p class="muted">{{ t('Deletes your shares, files, invites, sessions and two-step verification methods and removes your name and email address. Audit log entries keep your former username until the retention period ends.') }}</p>
    <template v-if="erasing">
      <template v-if="props.hasPassword">
        <label for="erase-password">{{ t('Current password') }}</label>
        <input id="erase-password" v-model="password" type="password" autocomplete="current-password" />
      </template>
      <div class="actions">
        <button type="button" class="danger" :disabled="busy || (props.hasPassword && !password)" @click="erase">{{ t('Delete my account permanently') }}</button>
        <button type="button" class="secondary" @click="erasing = false; password = ''">{{ t('Cancel') }}</button>
      </div>
    </template>
    <div v-else class="actions"><button type="button" class="danger" @click="erasing = true">{{ t('Delete my account') }}</button></div>
    <p v-if="msg" class="ok" role="status">{{ msg }}</p><p v-if="err" class="err" role="alert">{{ err }}</p>
  </section>
</template>
