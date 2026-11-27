<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Asks a signed-in account to accept the current terms of use once (Settings:
// terms_acceptance_required). Until then the server only allows the profile, the
// acceptance, the data export and deleting the account.
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, logout, termsState } from '../api'
import { app, loadBoot } from '../state'
import { t } from '../i18n'
import { vFocusTrap } from '../focus-trap.mjs'

const router = useRouter()
const err = ref(''), busy = ref(false)

async function accept() {
  err.value = ''; busy.value = true
  try {
    await api('/users/me/terms', { method: 'POST', body: { version: app.boot?.terms_version } })
    termsState.pending = false
    router.go(0) // reload the page so everything that was refused loads again
  } catch (e) {
    err.value = e.message
    if (e.status === 409) await loadBoot().catch(() => {})
  } finally { busy.value = false }
}
async function decline() { termsState.pending = false; await logout(); router.replace('/login') }
</script>

<template>
  <div v-if="termsState.pending" v-focus-trap class="idle-modal" role="alertdialog" aria-modal="true" aria-labelledby="terms-title" aria-describedby="terms-desc">
    <div class="idle-box card">
      <h2 id="terms-title">{{ t('Terms of use') }}</h2>
      <p id="terms-desc">{{ t('Please read and accept the terms of use (version {v}) to continue.', { v: app.boot?.terms_version || '' }) }}</p>
      <p v-if="app.boot?.terms_url"><a :href="app.boot.terms_url" target="_blank" rel="noopener noreferrer">{{ t('Read the terms of use') }}</a></p>
      <p v-if="err" class="err" role="alert">{{ err }}</p>
      <div class="actions">
        <button type="button" :disabled="busy" @click="accept">{{ t('I accept') }}</button>
        <button type="button" class="secondary" @click="decline">{{ t('Sign out') }}</button>
      </div>
      <p class="muted"><router-link to="/profile" @click="termsState.pending = false">{{ t('Download my data or delete my account instead') }}</router-link></p>
    </div>
  </div>
</template>
