<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, onMounted } from 'vue'
import { api, session, fmtDate } from '../api'
import { fmtGBShort } from '../quota.mjs'
import { t, languages } from '../i18n'
import { emailLanguages, app } from '../state'
import { accountPolicy, passwordProblems } from '../sharepolicy.mjs'
import PasswordHints from '../components/PasswordHints.vue'
import MfaSecurity from '../components/MfaSecurity.vue'
import SessionsCard from '../components/SessionsCard.vue'
import DataExportCard from '../components/DataExportCard.vue'
const f = ref({ name: '', email: '', password: '', currentPassword: '', language: 'en', ui_language: 'en' }), msg = ref(''), err = ref(''), linked = ref([]), hasPw = ref(true)
const storage = ref(null)
async function load() {
  const d = await api('/users/me'); storage.value = d; session.user = d.user; linked.value = d.providers; hasPw.value = d.has_password
  f.value.name = d.user.name; f.value.email = d.user.email; f.value.language = d.user.language || 'en'; f.value.ui_language = d.user.ui_language || 'en'
}
onMounted(load)
async function save() {
  msg.value = err.value = ''
  if (f.value.password) {
    const problems = passwordProblems(f.value.password, accountPolicy(app.boot))
    if (problems.length) { err.value = t('Needs:') + ' ' + problems.map(p => t(p.key, { n: p.n })).join(', '); return }
  }
  try {
    const body = { name: f.value.name, email: f.value.email, password: f.value.password, current_password: f.value.currentPassword, language: f.value.language, ui_language: f.value.ui_language }
    const saved = await api('/users/me', { method: 'PUT', body })
    if (saved.access_token) session.token = saved.access_token
    if (saved.user) session.user = saved.user
    f.value.password = f.value.currentPassword = ''; msg.value = t('Saved'); await load()
  } catch (e) { err.value = e.message }
}
async function unlink(p) { try { await api('/users/me/providers/' + p.id, { method: 'DELETE' }); await load() } catch (e) { err.value = e.message } }
</script>
<template>
  <div>
  <form class="card" @submit.prevent="save" style="max-width:520px">
    <h1>{{ t('Profile') }}</h1>
    <dl v-if="storage">
      <dt>{{ t('Storage quota') }}</dt><dd>{{ fmtGBShort(storage.quota_bytes) }}</dd>
      <dt>{{ t('Stored files') }}</dt><dd>{{ fmtGBShort(storage.storage_used_bytes) }}</dd>
      <dt>{{ t('Reserved uploads') }}</dt><dd>{{ fmtGBShort(storage.storage_reserved_bytes) }}</dd>
      <dt>{{ t('Available storage') }}</dt><dd>{{ fmtGBShort(storage.storage_available_bytes) }}</dd>
    </dl>
    <p v-if="session.user?.must_change_password" class="err">{{ t('You must set a new password.') }}</p>
    <label>{{ t('Name') }}</label><input v-model="f.name" />
    <label>{{ t('Email') }}</label><input v-model="f.email" type="email" />
    <label>{{ t('Menu language') }}</label><select v-model="f.ui_language"><option v-for="(name, code) in languages" :key="code" :value="code">{{ name }}</option></select>
    <label>{{ t('Email language') }}</label><select v-model="f.language"><option v-for="(name, code) in emailLanguages" :key="code" :value="code">{{ name }}</option></select>
    <p class="muted">{{ t('Email preferences apply to messages sent to your account. Other recipients use the sending language.') }}</p>
    <label v-if="hasPw && !session.user?.must_change_password">{{ t('Current password') }}</label>
    <input v-if="hasPw && !session.user?.must_change_password" v-model="f.currentPassword" type="password" autocomplete="current-password" />
    <p v-if="hasPw && session.user?.password_changed_at" class="muted">{{ t('Password last changed {date}', { date: fmtDate(session.user.password_changed_at) }) }}<template v-if="storage?.password_expires_at"> · {{ t('expires {date}', { date: fmtDate(storage.password_expires_at) }) }}</template></p>
    <label>{{ t('New password') }}</label><input v-model="f.password" type="password" autocomplete="new-password" />
    <PasswordHints :password="f.password" optional />
    <p v-if="msg" class="ok">{{ msg }}</p><p v-if="err" class="err">{{ err }}</p>
    <div class="actions"><button>{{ t('Save') }}</button></div>
    <div v-if="linked.length"><h2 style="margin-top:20px">{{ t('Linked logins') }}</h2>
      <div v-for="p in linked" :key="p.id" class="actions" style="margin:4px 0"><span>{{ p.name }}</span>
        <button type="button" class="small secondary" @click="unlink(p)">{{ t('Unlink') }}</button></div></div>
  </form>
  <MfaSecurity />
  <SessionsCard />
  <DataExportCard v-if="!session.user?.is_guest" :has-password="hasPw" />
  </div>
</template>
