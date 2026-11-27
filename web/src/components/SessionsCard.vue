<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// "Your sessions": every browser or device signed in to this account, with the
// option to sign one or all others out. Revoking ends that session at once.
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtDate, logout } from '../api'
import { t, tr } from '../i18n'
import { describeAgent } from '../access-review.mjs'

const router = useRouter()
const list = ref(null), err = ref(''), msg = ref(''), busy = ref(false)
const METHODS = { password: tr('Password'), provider: tr('Sign-in provider'), invite: tr('Invitation') }
const method = m => t(METHODS[m] || METHODS.password)

async function load() {
  try { list.value = (await api('/users/me/sessions')).sessions } catch (e) { err.value = e.message }
}
onMounted(load)

async function revoke(s) {
  const question = s.current ? t('Sign out this browser?') : t('Sign out the session on {d}?', { d: describeAgent(s.user_agent) || t('an unknown device') })
  if (!confirm(question)) return
  err.value = msg.value = ''; busy.value = true
  try {
    await api('/users/me/sessions/' + encodeURIComponent(s.id), { method: 'DELETE' })
    if (s.current) { await logout(); router.push('/login'); return }
    msg.value = t('Session signed out.'); await load()
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
async function revokeOthers() {
  if (!confirm(t('Sign out all other sessions? This browser stays signed in.'))) return
  err.value = msg.value = ''; busy.value = true
  try {
    const r = await api('/users/me/sessions/revoke-others', { method: 'POST' })
    msg.value = t('Other sessions signed out: {n}', { n: r.revoked }); await load()
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
</script>
<template>
  <section v-if="list" class="card" style="max-width:520px" aria-labelledby="sessions-title">
    <h2 id="sessions-title">{{ t('Your sessions') }}</h2>
    <p class="muted">{{ t('Browsers and devices signed in to your account. Signing a session out ends it immediately.') }}</p>
    <div v-for="s in list" :key="s.id" class="session">
      <div><strong>{{ describeAgent(s.user_agent) || t('Unknown device') }}</strong> <span v-if="s.current" class="badge on">{{ t('This browser') }}</span>
        <div class="muted">{{ method(s.method) }} · {{ t('Signed in: {d}', { d: fmtDate(s.created_at) }) }} · {{ t('Last active: {d}', { d: fmtDate(s.last_used_at) }) }}<template v-if="s.ip"> · {{ s.ip }}</template></div></div>
      <button type="button" class="small secondary" :disabled="busy" @click="revoke(s)">{{ s.current ? t('Sign out') : t('Sign out session') }}</button>
    </div>
    <p v-if="!list.length" class="muted">{{ t('No active sessions') }}</p>
    <p v-if="msg" class="ok" role="status">{{ msg }}</p><p v-if="err" class="err" role="alert">{{ err }}</p>
    <div v-if="list.some(s => !s.current)" class="actions"><button type="button" class="secondary" :disabled="busy" @click="revokeOthers">{{ t('Sign out all other sessions') }}</button></div>
  </section>
</template>
<style scoped>
.session{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--border)}
.session:last-of-type{border-bottom:0}
</style>
