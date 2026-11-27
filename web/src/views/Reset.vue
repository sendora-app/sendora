<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api'
import { t } from '../i18n'
import { app } from '../state'
import { accountPolicy, passwordProblems } from '../sharepolicy.mjs'
import PasswordHints from '../components/PasswordHints.vue'
const route = useRoute(), router = useRouter()
const password = ref(''), err = ref('')
async function go() {
  const problems = passwordProblems(password.value, accountPolicy(app.boot))
  if (problems.length) { err.value = t('Needs:') + ' ' + problems.map(p => t(p.key, { n: p.n })).join(', '); return }
  try { await api('/auth/reset-password', { method: 'POST', body: { token: route.params.token, password: password.value } }); router.replace('/login') }
  catch (e) { err.value = e.message }
}
</script>
<template>
  <form class="card narrow" @submit.prevent="go">
    <h1>{{ t('Set your password') }}</h1>
    <label>{{ t('New password') }}</label><input v-model="password" type="password" autocomplete="new-password" required autofocus />
    <PasswordHints :password="password" />
    <p v-if="err" class="err">{{ err }}</p>
    <div class="actions"><button>{{ t('Save') }}</button></div>
  </form>
</template>
