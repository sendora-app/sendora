<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { computed, ref, watch, watchEffect } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { session, logout, api, termsState } from './api'
import { app, pageTitle } from './state'
import { bundledUrl } from './backgrounds'
import { t, lang, languages, setLang } from './i18n'
import { onMounted, onBeforeUnmount } from 'vue'
import { session as sess, refresh as refreshSession } from './api'
import { createIdleMonitor, effectiveIdleMinutes } from './idle.mjs'
import { isBusy } from './transfers.mjs'
import { shouldPromptMFA, mfaPromptKey, reminderSuppressed } from './mfa-prompt.mjs'
import { vFocusTrap } from './focus-trap.mjs'
import { shouldShowExpiryBanner, expiryDismissKey, localDay } from './password-expiry.mjs'
import StepUpDialog from './components/StepUpDialog.vue'
import TermsDialog from './components/TermsDialog.vue'
import LegalLinks from './components/LegalLinks.vue'
import PoweredBy from './components/PoweredBy.vue'

const router = useRouter(), route = useRoute()
const ready = true
// A custom logo uploaded under Branding wins; otherwise the built-in Sendora mark.
const logoUrl = computed(() => app.boot?.has_logo ? "/api/branding/logo" : "/logo.svg")
// An uploaded custom image wins; otherwise the chosen bundled one ('none' = plain theme colour).
const bg = computed(() => app.backgrounds.length ? '/api/backgrounds/' + app.backgrounds[(new Date().getDate()) % app.backgrounds.length] : bundledUrl(app.boot?.background))

watchEffect(() => {
  const name = app.boot?.application_name || 'Sendora'
  document.title = pageTitle.value ? pageTitle.value + ' – ' + name : name
})

// The version label is shown in the footer to signed-in users only. Every page,
// public ones included, links to the source of the running build (PoweredBy, AGPL section 13).
// The same call tells whether the account uses a local password, which decides if we
// remind the user that two-step verification is not set up yet.
const mfaPrompt = ref(false)
// A dismissed reminder returns after mfa_reminder_days days (default 1; 0 = next sign-in).
// The time is kept in this browser; the session flag covers the 0-day case.
function mfaDismissed(id) {
  let dismissedAt = 0, sessionDismissed = false
  try { dismissedAt = Number(localStorage.getItem(mfaPromptKey(id))) || 0 } catch {}
  try { sessionDismissed = sessionStorage.getItem(mfaPromptKey(id)) === '1' } catch {}
  return reminderSuppressed({ days: app.boot?.mfa_reminder_days ?? 1, dismissedAt, sessionDismissed })
}
function dismissMfa() {
  const id = session.user?.id
  mfaPrompt.value = false
  if (!id) return
  try { localStorage.setItem(mfaPromptKey(id), String(Date.now())) } catch {}
  try { sessionStorage.setItem(mfaPromptKey(id), '1') } catch {}
}
function setupMfa() { dismissMfa(); router.push('/profile') }
// Password maximum age: a non-blocking banner from 14 days before expiry,
// dismissible for the rest of the day (kept in this browser).
const pwExpiry = ref(null)
function expiryDismissedDay(id) { try { return localStorage.getItem(expiryDismissKey(id)) || '' } catch { return '' } }
function dismissExpiry() {
  const id = session.user?.id
  pwExpiry.value = null
  if (id) { try { localStorage.setItem(expiryDismissKey(id), localDay()) } catch {} }
}
// Re-checked when a required password change is completed (same account, flag cleared)
// and after any password change (password_changed_at moves on).
// Multi-tenant mode: the organisation has no storage yet (administrators see a banner).
const storageMissing = ref(false)
watch(() => [session.user?.id, !!session.user?.must_change_password, session.user?.password_changed_at], async ([id]) => {
  app.version = ''
  mfaPrompt.value = false
  pwExpiry.value = null
  if (!id) return
  try {
    const d = await api('/users/me')
    if (session.user?.id !== id) return
    app.version = d.version || ''
    storageMissing.value = d.storage_ready === false
    termsState.pending = !!d.terms_pending
    mfaPrompt.value = shouldPromptMFA({ user: d.user, hasPassword: d.has_password, boot: app.boot, dismissed: mfaDismissed(id) })
    if (shouldShowExpiryBanner({ days: d.password_expires_in_days, mustChange: !!d.user?.must_change_password, dismissedDay: expiryDismissedDay(id) })) {
      pwExpiry.value = { days: d.password_expires_in_days, at: d.password_expires_at }
    }
  } catch {}
}, { immediate: true })
const versionLabel = computed(() => !session.user || !app.version ? '' : /^\d/.test(app.version) ? 'v' + app.version : app.version)

const languageBusy = ref(false), languageError = ref('')
watch(() => [session.user?.id, session.user?.ui_language], () => {
  if (session.user?.ui_language) setLang(session.user.ui_language)
}, { immediate: true })
async function chooseLanguage(value) {
  languageError.value = ''
  if (!session.user || session.user.is_guest) { setLang(value); return }
  languageBusy.value = true
  try {
    const saved = await api('/users/me', { method: 'PUT', body: { name: session.user.name, email: session.user.email, ui_language: value } })
    if (saved.access_token) session.token = saved.access_token
    session.user = saved.user
    setLang(saved.user.ui_language)
  } catch (e) { languageError.value = e.message }
  finally { languageBusy.value = false }
}
async function out() { await logout(); router.push('/login') }

// ---- automatic sign-out after inactivity (never while a transfer is running) ----
const idle = ref({ warning: false, seconds: 0 })
// The sign-out warning always wins: the MFA reminder waits while it is open.
const showMfaPrompt = computed(() => mfaPrompt.value && !idle.value.warning)
let monitor = null, timer = null
// Administrators get the stricter window when admin_idle_logout_minutes is set.
const idleMs = () => effectiveIdleMinutes(app.boot?.idle_logout_minutes, app.boot?.admin_idle_logout_minutes, !!sess.user?.admin) * 60 * 1000
function idleApplies() { return !!sess.user && !sess.user.is_guest }
async function idleTimedOut() {
  const minutes = Math.round(idleMs() / 60000)
  const next = route.fullPath
  idle.value = { warning: false, seconds: 0 }
  await logout()
  router.replace({ path: '/login', query: { next, idle: String(minutes) } })
}
function startIdle() {
  stopIdle()
  if (!idleApplies()) return
  monitor = createIdleMonitor({
    limitMs: idleMs(), isBusy, doRefresh: () => refreshSession(),
    onWarn: seconds => { idle.value = { warning: true, seconds } },
    onClear: () => { idle.value = { warning: false, seconds: 0 } },
    onTimeout: idleTimedOut,
  })
  timer = setInterval(() => monitor?.tick(), 5000)
  // The warning countdown needs finer ticks than the 5 s inactivity check.
  countdown = setInterval(() => { if (monitor?.warning) monitor.tick() }, 1000)
}
let countdown = null
function stopIdle() {
  if (timer) clearInterval(timer)
  if (countdown) clearInterval(countdown)
  timer = countdown = monitor = null
  idle.value = { warning: false, seconds: 0 }
}
function stay() { monitor?.stay() }
const activity = () => monitor?.activity()
const ACTIVITY_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'scroll', 'touchstart']
onMounted(() => { for (const e of ACTIVITY_EVENTS) window.addEventListener(e, activity, { passive: true, capture: true }); window.addEventListener('focus', activity) })
onBeforeUnmount(() => { for (const e of ACTIVITY_EVENTS) window.removeEventListener(e, activity, { capture: true }); window.removeEventListener('focus', activity); stopIdle() })
watch(() => [sess.user?.id, sess.user?.is_guest], startIdle, { immediate: true })
watch(() => [app.boot?.idle_logout_minutes, app.boot?.admin_idle_logout_minutes], () => { if (monitor) monitor.setLimit(idleMs()); else startIdle() })
</script>

<template>
  <div v-if="ready" class="shell" :class="{ hasbg: bg }" :style="bg ? { '--shell-bg': `url(${bg})` } : null">
    <header v-if="session.user && !(session.user.is_guest)" class="nav">
      <router-link to="/" class="brand">
        <img :src="logoUrl" alt="" class="logo" />
        <span>{{ app.boot?.application_name }}</span>
      </router-link>
      <nav>
        <router-link v-if="!session.user.auditor" to="/">{{ t('Upload') }}</router-link>
        <router-link v-if="!session.user.auditor" to="/shares">{{ t('My shares') }}</router-link>
        <router-link v-if="session.user.auditor" to="/audit">{{ t('Audit log') }}</router-link>
        <router-link v-if="session.user.auditor" to="/access-review">{{ t('Access review') }}</router-link>
        <router-link v-if="session.user.admin" to="/admin">{{ t('Admin') }}</router-link>
        <router-link to="/profile">{{ session.user.name || session.user.username }}</router-link>
        <select v-if="app.boot?.show_language_selector" :value="lang" @change="chooseLanguage($event.target.value)" :disabled="languageBusy" :aria-label="t('Language')">
          <option v-for="(n, k) in languages" :key="k" :value="k">{{ n }}</option>
        </select>
        <button class="link" @click="out">{{ t('Sign out') }}</button>
      </nav>
    </header>
    <header v-else class="nav">
      <router-link to="/" class="brand"><img :src="logoUrl" alt="" class="logo" /><span>{{ app.boot?.application_name || 'Sendora' }}</span></router-link>
      <nav v-if="!session.user && !app.boot?.setup_needed"><router-link to="/login">{{ t('Sign in') }}</router-link><router-link v-if="app.boot?.registration_available" to="/register">{{ t('Create account') }}</router-link></nav>
    </header>
    <div v-if="idle.warning" v-focus-trap class="idle-modal idle-warning" role="alertdialog" aria-modal="true" aria-labelledby="idle-title" aria-describedby="idle-desc">
      <div class="idle-box card">
        <h2 id="idle-title">{{ t('Still there?') }}</h2>
        <p id="idle-desc" aria-live="assertive">{{ t('You will be signed out in {n} seconds', { n: idle.seconds }) }}</p>
        <div class="actions"><button type="button" @click="stay">{{ t('Stay signed in') }}</button></div>
      </div>
    </div>
    <div v-if="showMfaPrompt" v-focus-trap="dismissMfa" class="idle-modal" role="alertdialog" aria-modal="true" aria-labelledby="mfa-title" aria-describedby="mfa-desc">
      <div class="idle-box card">
        <h2 id="mfa-title">{{ t('Two-step verification is not set up yet') }}</h2>
        <p id="mfa-desc">{{ t('Your account is protected by a password only. Set up an authenticator app or a passkey to protect it better.') }}</p>
        <div class="actions">
          <button type="button" @click="setupMfa">{{ t('Set up now') }}</button>
          <button type="button" class="secondary" @click="dismissMfa">{{ t('Remind me later') }}</button>
        </div>
      </div>
    </div>
    <StepUpDialog />
    <TermsDialog v-if="session.user && !session.user.is_guest" />
    <main><p v-if="languageError" class="err" role="alert">{{ languageError }}</p>
      <div v-if="storageMissing && session.user?.admin" class="card notice storage-missing" role="alert">
        <strong>{{ t('Storage is not set up yet.') }}</strong> {{ t('Set up storage first under Admin → Storage. Until then, files cannot be uploaded or shared.') }}
        <router-link to="/admin/storage">{{ t('Set up storage') }}</router-link>
      </div>
      <div v-if="pwExpiry && session.user" class="card pw-expiry" role="status">
        <span>{{ pwExpiry.days > 0 ? t('Your password expires in {n} days.', { n: pwExpiry.days }) : t('Your password expires today.') }}</span>
        <router-link to="/profile" @click="dismissExpiry">{{ t('Change password') }}</router-link>
        <button type="button" class="link" @click="dismissExpiry">{{ t('Remind me tomorrow') }}</button>
      </div>
      <router-view :key="route.fullPath" /></main>
    <footer class="foot">
      <PoweredBy :boot="app.boot"><template v-if="versionLabel"> · {{ versionLabel }}</template></PoweredBy>
      <LegalLinks />
      <select v-if="app.boot?.show_language_selector && !session.user" :value="lang" @change="chooseLanguage($event.target.value)" :disabled="languageBusy" :aria-label="t('Language')">
        <option v-for="(n, k) in languages" :key="k" :value="k">{{ n }}</option>
      </select>
    </footer>
  </div>
</template>
<style scoped>
.pw-expiry{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;max-width:960px;margin:0 auto 12px}
</style>
