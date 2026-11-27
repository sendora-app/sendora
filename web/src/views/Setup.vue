<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, setSession } from '../api'
import { app } from '../state'
import { t } from '../i18n'
import { accountPolicy, passwordProblems } from '../sharepolicy.mjs'
import PasswordHints from '../components/PasswordHints.vue'
const router = useRouter()
const f = ref({ setup_code: '', username: '', name: '', email: '', password: '' }), err = ref('')
async function go() {
  const problems = passwordProblems(f.value.password, accountPolicy(app.boot))
  if (problems.length) { err.value = t('Needs:') + ' ' + problems.map(p => t(p.key, { n: p.n })).join(', '); return }
  try {
    setSession(await api('/setup', { method: 'POST', body: f.value }))
    app.boot.setup_needed = false
    router.replace('/')
  } catch (e) { err.value = t(e.message) }
}
</script>
<template>
  <form class="card narrow" @submit.prevent="go">
    <h1>{{ t('Create admin account') }}</h1>
    <label>{{ t('Setup code') }}</label><input v-model="f.setup_code" required autofocus autocomplete="off" spellcheck="false" placeholder="ABCD-EFGH-JKLM" />
    <p class="muted">{{ t('The one-time setup code is printed in the server log when Sendora starts without accounts (for Docker: docker compose logs sendora).') }}</p>
    <p class="muted">{{ t('Kubernetes: kubectl -n sendora logs deploy/sendora. Without containers: the service output or journal. You can also choose your own code with SENDORA_SETUP_CODE (at least 16 characters).') }}</p>
    <label>{{ t('Username') }}</label><input v-model="f.username" required />
    <label>{{ t('Name') }}</label><input v-model="f.name" />
    <label>{{ t('Email') }}</label><input v-model="f.email" type="email" />
    <label>{{ t('Password') }}</label><input v-model="f.password" type="password" autocomplete="new-password" required />
    <PasswordHints :password="f.password" />
    <p v-if="err" class="err">{{ err }}</p>
    <div class="actions"><button>{{ t('Create admin account') }}</button></div>
  </form>
</template>
