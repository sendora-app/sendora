<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api'
import { t } from '../i18n'
const route = useRoute()
const err = ref(''), done = ref(false), busy = ref(false)
async function go() {
  err.value = ''; busy.value = true
  try { await api('/auth/mfa-reset/confirm', { method: 'POST', body: { token: route.params.token } }); done.value = true }
  catch (e) { err.value = e.message } finally { busy.value = false }
}
</script>
<template>
  <form class="card narrow" @submit.prevent="go">
    <h1>{{ t('Reset two-step verification') }}</h1>
    <template v-if="!done">
      <p>{{ t('An administrator asked to remove the two-step verification from your account. This signs you out everywhere. If you did not expect this, close this page: nothing changes unless you confirm.') }}</p>
      <p v-if="err" class="err" role="alert">{{ err }}</p>
      <div class="actions"><button :disabled="busy">{{ t('Remove two-step verification') }}</button></div>
    </template>
    <template v-else>
      <p class="ok" role="status">{{ t('Two-step verification was removed. Sign in again and set it up again.') }}</p>
      <div class="actions"><router-link to="/login">{{ t('Sign in') }}</router-link></div>
    </template>
  </form>
</template>
