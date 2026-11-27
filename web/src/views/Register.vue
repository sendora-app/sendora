<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, setSession } from '../api'
import { t, lang } from '../i18n'
import { emailLanguages, app } from '../state'
import { accountPolicy, passwordProblems } from '../sharepolicy.mjs'
import PasswordHints from '../components/PasswordHints.vue'
const router = useRouter()
const f = ref({ username: '', name: '', email: '', password: '', language: lang.value }), err = ref(''), pending = ref(false), code = ref('')
async function go() {
  err.value = ''
  const problems = passwordProblems(f.value.password, accountPolicy(app.boot))
  if (problems.length) { err.value = t('Needs:') + ' ' + problems.map(p => t(p.key, { n: p.n })).join(', '); return }
  try {
    const d = await api('/auth/register', { method: 'POST', body: { ...f.value, ui_language: lang.value } })
    if (d.needs_verification) pending.value = true
    else { setSession(d); router.replace('/') }
  } catch (e) { err.value = e.message }
}
async function verify() {
  try {
    const d = await api('/auth/verify-email', { method: 'POST', body: { email: f.value.email, code: code.value } })
    if (d.access_token) { setSession(d); router.replace('/') }
    else router.replace('/login') // verified, but signing in takes the password (or a second step)
  }
  catch (e) { err.value = e.message }
}
async function resend() {
  err.value = ''
  try { await api('/auth/resend-verification', { method: 'POST', body: { email: f.value.email } }) }
  catch (e) { err.value = e.message }
}
</script>
<template>
  <div v-if="app.boot && !app.boot.registration_available && !pending" class="card narrow">
    <h1>{{ t('Create account') }}</h1>
    <p>{{ t('Registration is not available on this server.') }}</p>
    <div class="actions"><router-link to="/login">{{ t('Sign in') }}</router-link></div>
  </div>
  <form v-else-if="!pending" class="card narrow" @submit.prevent="go">
    <h1>{{ t('Create account') }}</h1>
    <label>{{ t('Username') }}</label><input v-model="f.username" required />
    <label>{{ t('Name') }}</label><input v-model="f.name" />
    <label>{{ t('Email') }}</label><input v-model="f.email" type="email" required />
    <p v-if="app.boot?.registration_domain_restricted" class="muted">{{ t('Registration is limited to specific email domains.') }}</p>
    <label>{{ t('Password') }}</label><input v-model="f.password" type="password" autocomplete="new-password" required />
    <PasswordHints :password="f.password" />
    <label>{{ t('Email language') }}</label><select v-model="f.language"><option v-for="(name, code) in emailLanguages" :key="code" :value="code">{{ name }}</option></select>
    <p v-if="err" class="err">{{ err }}</p>
    <div class="actions"><button>{{ t('Create account') }}</button><router-link to="/login">{{ t('Sign in') }}</router-link></div>
  </form>
  <form v-else class="card narrow" @submit.prevent="verify">
    <h1>{{ t('Verify') }}</h1>
    <p>{{ t('We emailed a code to') }} {{ f.email }}</p>
    <label>{{ t('Code') }}</label><input v-model="code" inputmode="numeric" required />
    <p v-if="err" class="err">{{ err }}</p>
    <div class="actions"><button>{{ t('Verify') }}</button><button type="button" class="secondary" @click="resend">{{ t('Resend code') }}</button></div>
  </form>
</template>
