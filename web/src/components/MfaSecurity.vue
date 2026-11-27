<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, computed, onMounted } from 'vue'
import { api, session, fmtDate } from '../api'
import { app } from '../state'
import { t } from '../i18n'
import QrCode from './QrCode.vue'
import { normalizeTotp, creationArgs, registrationJSON, webauthnErrorKey, webauthnSupported, groupRecovery, recoveryFileText } from '../mfa.mjs'

const st = ref(null), err = ref(''), msg = ref(''), busy = ref(false)
const prompt = ref(null) // { label, run } while the password is being asked
const password = ref('')
const setup = ref(null), setupCode = ref('')
const codes = ref(null), saved = ref(false)
const passkeyName = ref(''), renaming = ref(null), renameValue = ref('')

const passkeysUsable = computed(() => !!st.value?.webauthn?.enabled && !!st.value?.webauthn?.available && webauthnSupported())
const factors = computed(() => (st.value?.totp?.enrolled ? 1 : 0) + (st.value?.webauthn?.credentials?.length || 0))

async function load() {
  try { st.value = await api('/users/me/mfa') } catch (e) { err.value = t(e.message) }
}
onMounted(load)

function applySession(d) {
  if (d?.access_token) session.token = d.access_token
  if (d?.user) session.user = d.user
}
function showCodes(d) { if (d?.recovery_codes?.length) { codes.value = d.recovery_codes; saved.value = false } }
function fail(e) { err.value = e?.status ? t(e.message) : t(webauthnErrorKey(e)) }

// Sensitive actions confirm the current password first (skipped when the account has none).
function ask(label, run) {
  err.value = msg.value = ''
  if (st.value && !st.value.has_password) return run('')
  password.value = ''; prompt.value = { label, run }
}
async function confirmPassword() {
  const p = prompt.value
  if (!p) return
  if (!password.value) { err.value = t('Enter your password to continue.'); return }
  busy.value = true; err.value = ''
  const pw = password.value
  try { await p.run(pw); prompt.value = null; password.value = '' } catch (e) { fail(e) } finally { busy.value = false }
}
const cancelPrompt = () => { prompt.value = null; password.value = '' }

// --- authenticator app
const startTotp = () => ask(t('Set up authenticator app'), async pw => { setup.value = await api('/users/me/mfa/totp/begin', { method: 'POST', body: { password: pw } }); setupCode.value = '' })
async function confirmTotp() {
  const parsed = normalizeTotp(setupCode.value)
  if (!parsed.ok) { err.value = t('Enter the 6-digit code from your authenticator app.'); return }
  busy.value = true; err.value = ''
  try {
    const d = await api('/users/me/mfa/totp/confirm', { method: 'POST', body: { code: parsed.code } })
    applySession(d); setup.value = null; showCodes(d); msg.value = t('Authenticator app enabled.'); await load()
  } catch (e) { fail(e) } finally { busy.value = false }
}
const removeTotp = () => confirm(t('Remove the authenticator app?')) && ask(t('Remove authenticator app'), async pw => { const d = await api('/users/me/mfa/totp/remove', { method: 'POST', body: { password: pw } }); applySession(d); msg.value = t('Authenticator app removed.'); await load() })

// --- recovery codes
const regenerate = () => confirm(t('Create new recovery codes? The old ones stop working.')) && ask(t('Create new recovery codes'), async pw => { const d = await api('/users/me/mfa/recovery/regenerate', { method: 'POST', body: { password: pw } }); showCodes(d); await load() })
async function copyCodes() { try { await navigator.clipboard.writeText(codes.value.map(groupRecovery).join('\n')); msg.value = t('Copied') } catch { err.value = t('Copy failed. Select the codes and copy them manually.') } }
function downloadCodes() {
  const blob = new Blob([recoveryFileText(codes.value, app.boot?.application_name || 'Sendora', t)], { type: 'text/plain' })
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'recovery-codes.txt'
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}
const doneCodes = () => { codes.value = null; saved.value = false }

// --- passkeys / security keys
const addPasskey = () => ask(t('Add passkey or security key'), async pw => {
  const begin = await api('/users/me/mfa/webauthn/begin', { method: 'POST', body: { password: pw } })
  const cred = await navigator.credentials.create(creationArgs(begin.options))
  const d = await api('/users/me/mfa/webauthn/finish', { method: 'POST', body: { challenge_id: begin.challenge_id, name: passkeyName.value.trim() || t('Passkey'), credential: registrationJSON(cred) } })
  applySession(d); showCodes(d); passkeyName.value = ''; msg.value = t('Passkey added.'); await load()
})
async function rename(c) {
  err.value = ''
  try { await api('/users/me/mfa/webauthn/' + encodeURIComponent(c.id), { method: 'PUT', body: { name: renameValue.value.trim() } }); renaming.value = null; await load() } catch (e) { fail(e) }
}
const removeKey = c => confirm(t('Remove {n}?', { n: c.name })) && ask(t('Remove passkey'), async pw => { const d = await api(`/users/me/mfa/webauthn/${encodeURIComponent(c.id)}/remove`, { method: 'POST', body: { password: pw } }); applySession(d); msg.value = t('Passkey removed.'); await load() })
</script>
<template>
  <section v-if="app.boot?.mfa_policy !== 'off' && st" class="card" style="max-width:520px" aria-labelledby="mfa-title">
    <h2 id="mfa-title">{{ t('Two-step verification') }}</h2>
    <p v-if="st.enroll_required || session.user?.mfa_enroll_required" class="err" role="alert">{{ t('Your account requires two-step verification. Set up an authenticator app or a passkey to continue.') }}</p>
    <p class="muted">{{ factors ? t('Two-step verification is on for your account.') : t('Two-step verification is off for your account.') }}
      <span v-if="st.required"> {{ t('It is required for your account.') }}</span></p>

    <div v-if="codes" class="card" role="region" :aria-label="t('Recovery codes')">
      <h3>{{ t('Your recovery codes') }}</h3>
      <p class="err">{{ t('Save these codes now. They are shown only once and each works one time.') }}</p>
      <ul class="codes"><li v-for="c in codes" :key="c"><code>{{ groupRecovery(c) }}</code></li></ul>
      <div class="actions"><button type="button" class="small secondary" @click="copyCodes">{{ t('Copy') }}</button><button type="button" class="small secondary" @click="downloadCodes">{{ t('Download') }}</button></div>
      <label class="check"><input type="checkbox" v-model="saved" /> {{ t('I have saved these codes') }}</label>
      <div class="actions"><button type="button" :disabled="!saved" @click="doneCodes">{{ t('Done') }}</button></div>
    </div>

    <form v-if="prompt" class="card" @submit.prevent="confirmPassword">
      <h3>{{ prompt.label }}</h3>
      <label for="mfa-pw">{{ t('Your password') }}</label>
      <input id="mfa-pw" v-model="password" type="password" autocomplete="current-password" autofocus />
      <div class="actions"><button :disabled="busy">{{ t('Continue') }}</button><button type="button" class="secondary" :disabled="busy" @click="cancelPrompt">{{ t('Cancel') }}</button></div>
    </form>

    <div v-if="st.totp.enabled">
      <h3>{{ t('Authenticator app') }}</h3>
      <div v-if="setup" class="card">
        <p>{{ t('Scan this QR code with an authenticator app (for example Google Authenticator, Microsoft Authenticator, 1Password or Aegis), then enter the 6-digit code.') }}</p>
        <QrCode :value="setup.uri" :label="t('QR code for your authenticator app')" filename="authenticator.svg" />
        <p class="muted">{{ t('Cannot scan? Enter this key manually') }}: <code>{{ setup.secret }}</code></p>
        <label for="mfa-setup-code">{{ t('Authenticator code') }}</label>
        <input id="mfa-setup-code" v-model="setupCode" inputmode="numeric" autocomplete="one-time-code" maxlength="12" :placeholder="t('6-digit code')" />
        <div class="actions"><button type="button" :disabled="busy" @click="confirmTotp">{{ t('Verify and enable') }}</button><button type="button" class="secondary" :disabled="busy" @click="setup = null">{{ t('Cancel') }}</button></div>
      </div>
      <div v-else class="actions">
        <span class="badge" :class="st.totp.enrolled ? 'on' : 'off'">{{ st.totp.enrolled ? t('Enabled') : t('Not set up') }}</span>
        <button v-if="!st.totp.enrolled" type="button" class="small" @click="startTotp">{{ t('Set up authenticator app') }}</button>
        <button v-else type="button" class="small secondary" @click="removeTotp">{{ t('Remove') }}</button>
      </div>
    </div>

    <div v-if="st.webauthn.enabled">
      <h3>{{ t('Passkeys and security keys') }}</h3>
      <p v-if="!st.webauthn.available" class="muted">{{ t('Passkeys need https with a fixed application URL, or localhost.') }}</p>
      <p v-else-if="!passkeysUsable" class="muted">{{ t('This browser does not support passkeys.') }}</p>
      <ul class="keys">
        <li v-for="c in st.webauthn.credentials" :key="c.id">
          <template v-if="renaming === c.id">
            <input v-model="renameValue" maxlength="60" :aria-label="t('Passkey name')" />
            <button type="button" class="small" @click="rename(c)">{{ t('Save') }}</button><button type="button" class="small secondary" @click="renaming = null">{{ t('Cancel') }}</button>
          </template>
          <template v-else>
            <span><b>{{ c.name }}</b> <span class="muted">· {{ t('added') }} {{ fmtDate(c.created_at) }}<template v-if="c.last_used_at"> · {{ t('last used') }} {{ fmtDate(c.last_used_at) }}</template></span></span>
            <span class="actions" style="margin:0"><button type="button" class="small secondary" @click="renaming = c.id; renameValue = c.name">{{ t('Rename') }}</button><button type="button" class="small danger" @click="removeKey(c)">{{ t('Remove') }}</button></span>
          </template>
        </li>
      </ul>
      <p v-if="!st.webauthn.credentials.length" class="muted">{{ t('No passkeys yet.') }}</p>
      <div v-if="passkeysUsable" class="actions">
        <input v-model="passkeyName" maxlength="60" :placeholder="t('Name (for example Laptop)')" :aria-label="t('Passkey name')" style="max-width:240px" />
        <button type="button" class="small" @click="addPasskey">{{ t('Add passkey or security key') }}</button>
      </div>
    </div>

    <div v-if="factors">
      <h3>{{ t('Recovery codes') }}</h3>
      <p class="muted">{{ t('Recovery codes left') }}: {{ st.recovery_codes_remaining }}</p>
      <div class="actions"><button type="button" class="small secondary" @click="regenerate">{{ t('Create new recovery codes') }}</button></div>
    </div>

    <p v-if="msg" class="ok" role="status">{{ msg }}</p>
    <p v-if="err" class="err" role="alert">{{ err }}</p>
  </section>
</template>
<style scoped>
.codes { list-style: none; margin: 8px 0; padding: 0; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px }
.codes code { font-size: 14px }
.keys { list-style: none; padding: 0; margin: 8px 0; display: flex; flex-direction: column; gap: 8px }
.keys li { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between }
</style>
