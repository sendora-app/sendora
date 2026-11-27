<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import LegalLinks from '../components/LegalLinks.vue'
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { api, setSession, session } from '../api'
import { app } from '../state'
import { t, tr } from '../i18n'
import { safeNext } from '../nav.mjs'
import { normalizeTotp, normalizeRecovery, requestArgs, assertionJSON, webauthnErrorKey, webauthnSupported } from '../mfa.mjs'

const router = useRouter(), route = useRoute()
const f = ref({ username: '', password: '' }), err = ref(''), busy = ref(false), providers = ref([])
const verify = ref(false), code = ref(''), notice = ref('')
const mfa = ref(null), mfaMode = ref('totp'), mfaCode = ref(''), mfaBusy = ref(false)
const canPasskey = () => !!mfa.value?.methods?.includes('webauthn') && webauthnSupported()
const mfaTabs = () => [['totp', tr('Authenticator app')], ['recovery', tr('Recovery code')], ...(canPasskey() ? [['webauthn', tr('Passkey or security key')]] : [])].filter(([m]) => m === 'webauthn' || mfa.value?.methods?.includes(m))
const idleNotice = () => (route.query.idle ? t('You were signed out after {n} minutes of inactivity.', { n: String(route.query.idle).replace(/[^0-9]/g, '') }) : '')
const local = () => app.boot?.local_login_enabled !== false && app.boot?.local_login_enabled !== 'false'
const next = () => safeNext(route.query.next)

onMounted(async () => {
  if (session.user) return router.replace(next())
  // Only known messages from the sign-in callback are shown: arbitrary text in a
  // crafted link must not appear as an official error on this page.
  if (route.query.auth_error) {
    const known = [tr('invalid state'), tr('login failed'), tr('provider not found'), tr('provider unreachable'), tr('session changed; log in again'),
      tr('account unavailable'), tr('could not create account'), tr('could not link account'), tr('email already has an account; use its existing login'),
      tr('invalid provider email'), tr('no account linked to this login'), tr('account disabled')]
    const msg = String(route.query.auth_error)
    err.value = known.includes(msg) ? t(msg) : t('login failed')
  }
  // Why the previous session ended, when the server said so (known texts only).
  const ended = [tr('account disabled'), tr('your sign-in through the identity provider has expired; sign in again')]
  if (ended.includes(session.endReason)) err.value = t(session.endReason)
  session.endReason = ''
  providers.value = await api('/auth/providers').catch(() => [])
})

// A response is either a finished session or an MFA challenge (no session yet).
function finish(d) {
  if (d.mfa_required) {
    mfa.value = d; mfaCode.value = ''; err.value = ''
    mfaMode.value = d.methods?.includes('totp') ? 'totp' : (canPasskey() ? 'webauthn' : 'recovery')
    f.value.password = ''
    return
  }
  setSession(d)
  router.replace(session.user.must_change_password || session.user.mfa_enroll_required ? '/profile' : next())
}
function backToPassword(message) { mfa.value = null; mfaCode.value = ''; err.value = message || '' }
function mfaError(e) {
  if (e.status === 401 && /expired/.test(e.raw || e.message)) return backToPassword(t('Your sign-in step expired. Enter your password again.'))
  err.value = e.name === 'ApiError' || e.status ? t(e.message) : t(webauthnErrorKey(e))
}
async function submitMfa() {
  err.value = ''
  const mode = mfaMode.value
  const parsed = mode === 'totp' ? normalizeTotp(mfaCode.value) : normalizeRecovery(mfaCode.value)
  if (!parsed.ok) { err.value = mode === 'totp' ? t('Enter the 6-digit code from your authenticator app.') : t('Enter a recovery code (16 characters).'); return }
  mfaBusy.value = true
  try { finish(await api('/auth/mfa/' + mode, { method: 'POST', body: { mfa_token: mfa.value.mfa_token, code: parsed.code }, noRetry: true })) }
  catch (e) { mfaError(e) } finally { mfaBusy.value = false }
}
async function usePasskey() {
  err.value = ''; mfaBusy.value = true
  try {
    const { challenge_id, options } = await api('/auth/mfa/webauthn/begin', { method: 'POST', body: { mfa_token: mfa.value.mfa_token }, noRetry: true })
    const cred = await navigator.credentials.get(requestArgs(options))
    finish(await api('/auth/mfa/webauthn/finish', { method: 'POST', body: { mfa_token: mfa.value.mfa_token, challenge_id, credential: assertionJSON(cred) }, noRetry: true }))
  } catch (e) { mfaError(e) } finally { mfaBusy.value = false }
}
async function submit() {
  busy.value = true; err.value = ''
  try {
    finish(await api('/auth/login', { method: 'POST', body: f.value, noRetry: true }))
  } catch (e) {
    if (e.data?.needs_verification) verify.value = true
    err.value = e.message
  } finally { busy.value = false }
}
async function doVerify() {
  try {
    verify.value = false
    const d = await api('/auth/verify-email', { method: 'POST', body: { email: f.value.username, code: code.value } })
    // Only a new registration is signed in by the code; others sign in with their password.
    if (d.access_token || d.mfa_required) finish(d)
    else { code.value = ''; f.value.password = ''; notice.value = t('Email address verified. Sign in to continue.') }
  } catch (e) { verify.value = true; err.value = e.message }
}
</script>
<template>
  <div class="card narrow">
    <h1>{{ app.boot?.application_name }}</h1>
    <p v-if="route.query.idle" class="muted" role="status">{{ idleNotice() }}</p>
    <form v-if="mfa" @submit.prevent="submitMfa">
      <h2>{{ t('Two-step verification') }}</h2>
      <div class="tabs" role="tablist"><a v-for="[m, label] in mfaTabs()" :key="m" href="#" role="tab" :aria-selected="mfaMode === m" :class="{ 'router-link-active': mfaMode === m }" @click.prevent="mfaMode = m; mfaCode = ''; err = ''">{{ t(label) }}</a></div>
      <template v-if="mfaMode === 'totp'">
        <label for="mfa-code">{{ t('Authenticator code') }}</label>
        <input id="mfa-code" v-model="mfaCode" inputmode="numeric" autocomplete="one-time-code" autofocus maxlength="12" :placeholder="t('6-digit code')" />
      </template>
      <template v-else-if="mfaMode === 'recovery'">
        <label for="mfa-recovery">{{ t('Recovery code') }}</label>
        <input id="mfa-recovery" v-model="mfaCode" autocomplete="off" spellcheck="false" autofocus maxlength="32" placeholder="XXXX-XXXX-XXXX-XXXX" />
        <p class="muted">{{ t('Each recovery code works once.') }}</p>
      </template>
      <template v-else>
        <p>{{ t('Use your passkey, security key or this device to continue.') }}</p>
      </template>
      <p v-if="err" class="err" role="alert">{{ err }}</p>
      <div class="actions">
        <button v-if="mfaMode !== 'webauthn'" :disabled="mfaBusy">{{ t('Verify') }}</button>
        <button v-else type="button" :disabled="mfaBusy" @click="usePasskey">{{ t('Use passkey or security key') }}</button>
        <button type="button" class="secondary" :disabled="mfaBusy" @click="backToPassword()">{{ t('Back') }}</button>
      </div>
    </form>
    <form v-else-if="!verify && local()" @submit.prevent="submit">
      <label>{{ t('Username') }}</label><input v-model="f.username" autocomplete="username" autofocus required />
      <label>{{ t('Password') }}</label><input v-model="f.password" type="password" autocomplete="current-password" required />
      <p v-if="notice" class="muted" role="status">{{ notice }}</p>
      <p v-if="err" class="err">{{ err }}</p>
      <div class="actions"><button :disabled="busy">{{ t('Sign in') }}</button>
        <router-link to="/forgot-password">{{ t('Forgot password?') }}</router-link></div>
    </form>
    <form v-else-if="verify" @submit.prevent="doVerify">
      <p>{{ t('Enter the code we emailed you (use your email as username).') }}</p>
      <label>{{ t('Code') }}</label><input v-model="code" inputmode="numeric" required />
      <p v-if="err" class="err">{{ err }}</p>
      <div class="actions"><button>{{ t('Verify') }}</button></div>
    </form>
    <p v-if="!local() && !verify && !mfa && !providers.length" class="err">{{ t('Local login is disabled and no external login provider is available.') }}</p>
    <p v-if="!local() && !verify && !mfa && providers.length" class="muted">{{ t('Sign in with your organisation account.') }}</p>
    <p v-if="err && !local() && !mfa" class="err">{{ err }}</p>
    <div v-if="providers.length && !verify && !mfa" class="sso">
      <a v-for="p in providers" :key="p.uuid" :href="`/api/auth/oidc/${p.uuid}/start`" :class="{ ms: p.type === 'entra' }">
        <template v-if="p.type === 'entra'">
          <svg class="ms-logo" viewBox="0 0 21 21" width="21" height="21" aria-hidden="true"><rect width="10" height="10" fill="#f25022"/><rect x="11" width="10" height="10" fill="#7fba00"/><rect y="11" width="10" height="10" fill="#00a4ef"/><rect x="11" y="11" width="10" height="10" fill="#ffb900"/></svg>
          <span>{{ t('Sign in with Microsoft') }}</span>
        </template>
        <template v-else>{{ p.name }}</template>
      </a>
    </div>
    <p v-if="app.boot?.registration_available && !verify && !mfa && local()" class="muted"><router-link to="/register">{{ t('Create account') }}</router-link></p>
    <LegalLinks />
  </div>
</template>
