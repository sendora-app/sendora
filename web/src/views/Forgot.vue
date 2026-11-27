<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref } from 'vue'
import { api } from '../api'
import { t } from '../i18n'
const email = ref(''), sent = ref(false)
async function go() { await api('/auth/forgot-password', { method: 'POST', body: { email: email.value } }); sent.value = true }
</script>
<template>
  <form class="card narrow" @submit.prevent="go">
    <h1>{{ t('Forgot password?') }}</h1>
    <p v-if="sent" class="ok">{{ t('If that account exists, a reset link was emailed.') }}</p>
    <template v-else>
      <label>{{ t('Email') }} / {{ t('Username') }}</label><input v-model="email" required autofocus />
      <div class="actions"><button>{{ t('Send reset link') }}</button></div>
    </template>
    <p><router-link to="/login">{{ t('Sign in') }}</router-link></p>
  </form>
</template>
