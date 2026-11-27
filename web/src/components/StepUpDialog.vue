<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Re-authentication for critical administrator actions. The api() wrapper calls the
// registered handler when a request answers 401 {code: 'stepup_required'}; on success
// the request is retried once (api.js).
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { api, logout, setStepUpHandler } from '../api'
import { t, tr } from '../i18n'
import { stepUpChoices, stepUpBody, isStepUpResponse } from '../stepup.mjs'
import { requestArgs, assertionJSON, webauthnErrorKey, webauthnSupported } from '../mfa.mjs'
import { vFocusTrap } from '../focus-trap.mjs'

const router = useRouter(), route = useRoute()
const open = ref(false), mode = ref('password'), methods = ref([]), value = ref(''), err = ref(''), busy = ref(false), minutes = ref(5)
let resolver = null, pending = null
const labels = { totp: tr('Authenticator app'), webauthn: tr('Passkey or security key'), password: tr('Password') }

// Requests that need a step-up while the dialog is open share its outcome.
function show(data) {
  if (pending) return pending
  const c = stepUpChoices(data, webauthnSupported())
  mode.value = c.mode; methods.value = c.methods; value.value = ''; err.value = ''; minutes.value = data?.minutes || 5
  open.value = true
  pending = new Promise(resolve => { resolver = resolve }).finally(() => { pending = null })
  return pending
}
function finish(ok) {
  open.value = false
  const r = resolver; resolver = null
  r?.(ok)
}
async function confirmCode() {
  err.value = ''; busy.value = true
  try {
    await api('/auth/step-up', { method: 'POST', body: stepUpBody(mode.value, value.value), noRetry: true, noStepUp: true })
    finish(true)
  } catch (e) {
    if (isStepUpResponse(e.data)) { mode.value = 'reauth'; return }
    err.value = e.message
  } finally { busy.value = false }
}
async function confirmPasskey() {
  err.value = ''; busy.value = true
  try {
    const { challenge_id, options } = await api('/auth/step-up/webauthn/begin', { method: 'POST', noRetry: true, noStepUp: true })
    const cred = await navigator.credentials.get(requestArgs(options))
    await api('/auth/step-up', { method: 'POST', body: { challenge_id, credential: assertionJSON(cred) }, noRetry: true, noStepUp: true })
    finish(true)
  } catch (e) {
    err.value = e.name === 'ApiError' || e.status ? e.message : t(webauthnErrorKey(e))
  } finally { busy.value = false }
}
async function signInAgain() {
  const next = route.fullPath
  finish(false)
  await logout()
  router.replace({ path: '/login', query: { next } })
}
onMounted(() => setStepUpHandler(show))
onBeforeUnmount(() => { setStepUpHandler(null); finish(false) })
</script>

<template>
  <div v-if="open" v-focus-trap="() => finish(false)" class="idle-modal" role="dialog" aria-modal="true" aria-labelledby="stepup-title">
    <form class="idle-box card" @submit.prevent="mode === 'webauthn' ? confirmPasskey() : confirmCode()">
      <h2 id="stepup-title">{{ t('Confirm it is you') }}</h2>
      <template v-if="mode === 'reauth'">
        <p>{{ t('This action needs a recent sign-in. Sign in again at your sign-in provider, then repeat the action.') }}</p>
        <div class="actions">
          <button type="button" @click="signInAgain">{{ t('Sign in again') }}</button>
          <button type="button" class="secondary" @click="finish(false)">{{ t('Cancel') }}</button>
        </div>
      </template>
      <template v-else>
        <p>{{ t('This action changes security-relevant settings or data. Confirm your identity; the confirmation stays valid for {n} minutes.', { n: minutes }) }}</p>
        <div v-if="methods.length > 1" class="tabs" role="tablist">
          <a v-for="m in methods" :key="m" href="#" role="tab" :aria-selected="mode === m" :class="{ 'router-link-active': mode === m }" @click.prevent="mode = m; value = ''; err = ''">{{ t(labels[m]) }}</a>
        </div>
        <template v-if="mode === 'totp'">
          <label for="stepup-code">{{ t('Authenticator code') }}</label>
          <input id="stepup-code" v-model="value" inputmode="numeric" autocomplete="one-time-code" maxlength="12" :placeholder="t('6-digit code')" autofocus />
        </template>
        <template v-else-if="mode === 'password'">
          <label for="stepup-password">{{ t('Current password') }}</label>
          <input id="stepup-password" v-model="value" type="password" autocomplete="current-password" autofocus />
        </template>
        <p v-else class="muted">{{ t('Use your passkey or security key to confirm.') }}</p>
        <p v-if="err" class="err" role="alert">{{ err }}</p>
        <div class="actions">
          <button :disabled="busy">{{ mode === 'webauthn' ? t('Use passkey or security key') : t('Confirm') }}</button>
          <button type="button" class="secondary" @click="finish(false)">{{ t('Cancel') }}</button>
        </div>
      </template>
    </form>
  </div>
</template>
