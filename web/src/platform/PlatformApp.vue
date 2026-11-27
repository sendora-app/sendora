<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Platform console (multi-tenant mode): served only on admin.<base domain>.
// Platform administrators manage tenants, never tenant content.
import { ref, reactive, computed, onMounted, onBeforeUnmount, watch } from 'vue'
import QrCode from '../components/QrCode.vue'
import StorageForm from '../components/StorageForm.vue'
import PasswordHints from '../components/PasswordHints.vue'
import PoweredBy from '../components/PoweredBy.vue'
import { platformPolicy } from '../password-check.mjs'
import { splitHostPort, validHost, validPort, joinHostPort, platformURLs } from '../base-domain.mjs'
import { t, tr, lang, setLang, builtinLanguages } from '../i18n'
import { gbToBytes, bytesToGB } from '../quota.mjs'
import { masterRows, canRotateMaster, masterProgress, PURPOSES, nextPoll, rowStatus, canRotate, bulkTargets, progress, lastFinished, resultLabel, reasonProblem } from '../operator-keys.mjs'
import { pconsole, slugProblem, fmtSize, quotaPercent, reauthBody, storageKindLabel } from '../platform-console.mjs'

const boot = ref(null), stage = ref('loading'), me = ref(null), err = ref(''), notice = ref(''), busy = ref(false)
const mfaRequired = ref(true), mustChange = ref(false)
// The platform administrators' password rule, from the server.
const pwRule = computed(() => platformPolicy(boot.value || {}))
const pw = reactive({ current: '', next: '' })
// Destructive actions are confirmed with the authenticator code, or with the
// password by an administrator without one while the platform does not require it.
const byPassword = computed(() => !!me.value && !me.value.totp_enabled && !mfaRequired.value)
const reauthLabel = computed(() => byPassword.value ? t('Your password (required for changes)') : t('Your authenticator code (required for changes)'))
const reauth = v => reauthBody(v)
const tab = ref('tenants')
const f = reactive({ setup_code: '', username: '', email: '', password: '', code: '' })
const enroll = ref(null)

async function load() {
  err.value = ''
  boot.value = await pconsole('/bootstrap').catch(() => null)
  if (boot.value?.setup_needed) { stage.value = 'setup'; return }
  try {
    const d = await pconsole('/me')
    me.value = d.admin; mfaRequired.value = d.mfa_required !== false; mustChange.value = !!d.must_change_password
    stage.value = mustChange.value ? 'password' : d.stage
    if (stage.value === 'full') await loadTenants()
  } catch { stage.value = 'login' }
}
onMounted(load)

async function run(fn) {
  err.value = ''; notice.value = ''; busy.value = true
  try { await fn() } catch (e) { err.value = e.message } finally { busy.value = false }
}
const doSetup = () => run(async () => {
  const d = await pconsole('/setup', { method: 'POST', body: { setup_code: f.setup_code, username: f.username, email: f.email, password: f.password } })
  f.password = ''; f.setup_code = ''; stage.value = d.stage
})
const doLogin = () => run(async () => {
  const d = await pconsole('/login', { method: 'POST', body: { username: f.username, password: f.password } })
  f.password = ''; await load()
})
const changePassword = () => run(async () => {
  await pconsole('/password', { method: 'POST', body: { current: pw.current, password: pw.next } })
  pw.current = ''; pw.next = ''; notice.value = t('Password changed.'); await load()
})
const doTotp = () => run(async () => {
  await pconsole('/login/totp', { method: 'POST', body: { code: f.code } })
  f.code = ''; await load()
})
const beginEnroll = () => run(async () => { enroll.value = await pconsole('/mfa/begin', { method: 'POST' }) })
const confirmEnroll = () => run(async () => {
  await pconsole('/mfa/confirm', { method: 'POST', body: { code: f.code } })
  f.code = ''; enroll.value = null; await load()
  if (stage.value === 'full') notice.value = t('Authenticator set up.')
})
const logout = () => run(async () => { await pconsole('/logout', { method: 'POST' }); me.value = null; stage.value = 'login' })

// ---------- tenants ----------
const tenants = ref([]), q = ref(''), sel = ref(null), created = ref(null)
const nt = reactive({ slug: '', name: '', admin_email: '', admin_username: '', max_users: '0', max_storage_gb: '0', storage_offer: 'none', allow_own_storage: true })
const slugHint = computed(() => nt.slug ? t(slugProblem(nt.slug)) : '')
async function loadTenants() {
  tenants.value = (await pconsole('/tenants?q=' + encodeURIComponent(q.value))).tenants
  // The create form preselects "Storage for new tenants" (platform setting).
  if (!nt.slug) { try { nt.storage_offer = (await pconsole('/settings')).settings.new_tenant_storage_offer || 'none' } catch {} }
}
const search = () => run(loadTenants)
const createTenant = () => run(async () => {
  const d = await pconsole('/tenants', { method: 'POST', body: {
    slug: nt.slug.trim(), name: nt.name, admin_email: nt.admin_email, admin_username: nt.admin_username,
    max_users: Number(nt.max_users) || 0, max_storage_bytes: gbToBytes(String(nt.max_storage_gb || '0')),
    storage_offer: nt.storage_offer, allow_own_storage: nt.allow_own_storage } })
  created.value = d
  Object.assign(nt, { slug: '', name: '', admin_email: '', admin_username: '', max_users: '0', max_storage_gb: '0', allow_own_storage: true })
  await loadTenants()
})
const quota = reactive({ max_users: '0', max_storage_gb: '0' })
const storage = reactive({ offer: 'none', tenant_managed: true, view: null })
const net = reactive({ allow: false, code: '' })
const domainInput = ref(''), del = reactive({ confirm: '', code: '', force: false })
function applyStorage(v) {
  storage.view = v || null
  storage.offer = v?.offer || 'none'
  storage.tenant_managed = v ? !!v.tenant_managed : true
}
async function openTenant(id) {
  await run(async () => {
    const d = await pconsole('/tenants/' + id)
    sel.value = d
    quota.max_users = String(d.tenant.max_users)
    quota.max_storage_gb = bytesToGB(d.tenant.max_storage_bytes)
    applyStorage(d.storage)
    net.allow = !!d.tenant.allow_private_targets; net.code = ''
    del.confirm = ''; del.code = ''; del.force = false; created.value = null
  })
}
const refreshSel = () => openTenant(sel.value.tenant.id)
const tid = () => sel.value.tenant.id
const setStatus = s => run(async () => { await pconsole(`/tenants/${tid()}/${s}`, { method: 'POST' }); await refreshSel(); await loadTenants() })
const saveQuota = () => run(async () => {
  await pconsole(`/tenants/${tid()}/quotas`, { method: 'PUT', body: { max_users: Number(quota.max_users) || 0 } })
  notice.value = t('Saved'); await loadTenants()
})
const addDomain = () => run(async () => { await pconsole(`/tenants/${tid()}/domains`, { method: 'POST', body: { domain: splitHostPort(domainInput.value).host } }); domainInput.value = ''; await refreshSel() })
const verifyDomain = d => run(async () => { await pconsole(`/tenants/${tid()}/domains/${encodeURIComponent(d)}/verify`, { method: 'POST' }); await refreshSel() })
const removeDomain = d => run(async () => { await pconsole(`/tenants/${tid()}/domains/${encodeURIComponent(d)}`, { method: 'DELETE' }); await refreshSel() })
const makePrimary = d => run(async () => { await pconsole(`/tenants/${tid()}/primary-domain`, { method: 'PUT', body: { domain: d } }); await refreshSel() })
// The storage limit (GB) applies to storage the platform provides (platform
// bucket or local disk); one source of truth with the quota max_storage_bytes;
// saved with the Storage card (re-authentication only when it changes).
const limit = reactive({ code: '' })
const limitShown = computed(() => (storage.offer === 'platform' || storage.offer === 'local') && !(storage.view?.kind || '').startsWith('own:'))
const limitChanged = computed(() => limitShown.value && sel.value && gbToBytes(String(quota.max_storage_gb || '0')) !== sel.value.tenant.max_storage_bytes)
const saveStorage = () => run(async () => {
  const body = { offer: storage.offer, tenant_managed: storage.tenant_managed }
  if (limitChanged.value) Object.assign(body, { max_storage_bytes: gbToBytes(String(quota.max_storage_gb || '0')) }, reauth(limit.code))
  applyStorage(await pconsole(`/tenants/${tid()}/storage`, { method: 'PUT', body }))
  limit.code = ''; notice.value = t('Saved'); await refreshSel(); await loadTenants()
})
const saveNetwork = () => run(async () => {
  await pconsole(`/tenants/${tid()}/network`, { method: 'PUT', body: { allow_private_targets: net.allow, ...reauth(net.code) } })
  net.code = ''; notice.value = t('Saved'); await refreshSel()
})
const deleteTenant = () => run(async () => {
  const d = await pconsole(`/tenants/${tid()}/delete`, { method: 'POST', body: { confirm: del.confirm, ...reauth(del.code), force: del.force } })
  sel.value = null; notice.value = t('Tenant deleted.') + (d.objects_removed ? ' ' + t('{n} object(s) removed from object storage.', { n: d.objects_removed }) : ''); await loadTenants()
})

// ---------- settings, audit, administrators ----------
const settings = ref(null), managed = ref([]), smtpPass = ref('')
const settingKeys = [
  ['tenant_idle_minutes', tr('Close idle tenants after (minutes)')], ['max_open_tenants', tr('Maximum open tenants')],
  ['tenant_maintenance_hours', tr('Maintenance of idle tenants every (hours)')], ['default_max_users', tr('Default user limit for new tenants (0 = unlimited)')],
  ['default_max_storage_bytes', tr('Default storage limit for new tenants in bytes (0 = unlimited)')], ['platform_audit_retention_days', tr('Platform audit log retention (days)')],
  ['platform_smtp_host', tr('Default SMTP server')], ['platform_smtp_port', tr('SMTP port')], ['platform_smtp_user', tr('SMTP username')],
  ['platform_smtp_from', tr('Sender address')], ['platform_smtp_tls', tr('SMTP security (none, tls, starttls)')]]
// Layout of the settings card: general limits, then the default mail server ('password' is the SMTP password field).
const settingLabel = Object.fromEntries(settingKeys)
const generalKeys = ['tenant_idle_minutes', 'max_open_tenants', 'tenant_maintenance_hours', 'default_max_users', 'default_max_storage_bytes', 'platform_audit_retention_days']
const smtpKeys = ['platform_smtp_host', 'platform_smtp_port', 'platform_smtp_tls', 'platform_smtp_user', 'password', 'platform_smtp_from']
const mfa = reactive({ required: true, code: '' })
const newOffer = reactive({ value: 'none', code: '' })
const offerProblem = computed(() => newOffer.value === 'platform' && !!pstore.settings && pstore.savedBackend === 'local')
const saveNewOffer = () => run(async () => {
  await pconsole('/settings', { method: 'PUT', body: { new_tenant_storage_offer: newOffer.value, ...reauth(newOffer.code) } })
  notice.value = t('Saved'); await loadSettings()
})
const pstore = reactive({ settings: null, set: {}, managed: [], description: '', test: null, testing: false })
async function loadSettings() {
  const d = await pconsole('/settings'); settings.value = d.settings; managed.value = d.managed; restartAvailable.value = !!d.restart_available
  Object.assign(bd, { host: d.base_host || '', port: d.base_port || '', managed: !!d.base_domain_managed, code: '', saved: joinHostPort(d.base_host || '', d.base_port || '') })
  mfa.required = d.settings.platform_mfa_required !== 'false'; mfa.code = ''
  newOffer.value = d.settings.new_tenant_storage_offer || 'none'; newOffer.code = ''
  const ps = await pconsole('/storage')
  Object.assign(pstore, { settings: { ...ps.settings }, set: ps.set || {}, managed: ps.managed || [], description: ps.description, savedBackend: ps.settings.storage_backend, test: null })
}
const restartCode = ref(''), restarting = ref(false), restartAvailable = ref(false)
// Base domain as host and port (stored as host[:port]; SENDORA_BASE_DOMAIN wins).
const bd = reactive({ host: '', port: '', managed: false, code: '', saved: '' })
const bdOK = computed(() => validHost(bd.host) && validPort(bd.port))
const bdLive = computed(() => (validHost(bd.host) ? platformURLs(bd.host, bd.port, '<slug>') : null))
function onBdHost() { const { host, port } = splitHostPort(bd.host); bd.host = host; if (port) bd.port = port }
const saveBaseDomain = () => run(async () => {
  const d = await pconsole('/base-domain', { method: 'PUT', body: { host: bd.host, port: bd.port, ...reauth(bd.code) } })
  bd.code = ''; bd.saved = d.base_domain
  notice.value = d.restart_needed ? t('Saved. The new base domain applies after a restart of the server.') : t('Saved')
})
const restartServer = () => run(async () => {
  if (!confirm(t('Restart the server now? Requests in progress finish first; everyone stays signed in.'))) return
  await pconsole('/restart', { method: 'POST', body: reauth(restartCode.value) })
  restartCode.value = ''; restarting.value = true
  for (let i = 0; i < 120; i++) {
    await new Promise(r => setTimeout(r, 2000))
    try { const r = await fetch('/api/health', { cache: 'no-store' }); if (r.ok) break } catch {}
  }
  restarting.value = false; notice.value = t('The server was restarted.'); await load()
})
const saveMfa = () => run(async () => {
  if (!mfa.required && !confirm(t('Platform administrators will be able to sign in with only a password. Anyone who learns a password gets full control over all tenants. Continue?'))) return
  await pconsole('/settings', { method: 'PUT', body: { platform_mfa_required: mfa.required, ...reauth(mfa.code) } })
  notice.value = t('Saved'); await load(); if (stage.value === 'full') { tab.value = 'settings'; await loadSettings() }
})
const savePlatformStorage = () => run(async () => {
  const d = await pconsole('/storage', { method: 'PUT', body: { settings: pstore.settings } })
  notice.value = t('Saved') + ': ' + d.description; await loadSettings()
})
const testPlatformStorage = async () => {
  err.value = ''; pstore.test = null; pstore.testing = true
  try { pstore.test = await pconsole('/storage/test', { method: 'POST', body: { settings: pstore.settings } }) } catch (e) { err.value = e.message } finally { pstore.testing = false }
}
const saveSettings = () => run(async () => {
  const body = {}
  for (const [k] of settingKeys) if (!managed.value.includes(k)) body[k] = String(settings.value[k] ?? '')
  if (smtpPass.value && !managed.value.includes('platform_smtp_pass')) body.platform_smtp_pass = smtpPass.value
  await pconsole('/settings', { method: 'PUT', body }); smtpPass.value = ''; notice.value = t('Saved'); await loadSettings()
})
const audit = ref([]), auditStatus = ref(null)
async function loadAudit() { audit.value = (await pconsole('/audit')).records; auditStatus.value = await pconsole('/audit/status') }
const admins = ref([]), na = reactive({ username: '', email: '', password: '', code: '' }), adminCode = ref('')
async function loadAdmins() { admins.value = (await pconsole('/admins')).admins }
const createAdmin = () => run(async () => { await pconsole('/admins', { method: 'POST', body: { username: na.username, email: na.email, password: na.password, ...reauth(na.code) } }); Object.assign(na, { username: '', email: '', password: '', code: '' }); await loadAdmins() })
const deleteAdmin = a => run(async () => { await pconsole(`/admins/${a.id}/delete`, { method: 'POST', body: reauth(adminCode.value) }); adminCode.value = ''; await loadAdmins() })
const resetAdminMfa = a => run(async () => { await pconsole(`/admins/${a.id}/mfa-reset`, { method: 'POST', body: reauth(adminCode.value) }); adminCode.value = ''; notice.value = t('Authenticator removed; they set up a new one at their next sign-in.') })
function show(name) {
  tab.value = name; sel.value = null; err.value = ''; notice.value = ''
  run(name === 'tenants' ? loadTenants : name === 'settings' ? loadSettings : name === 'keys' ? loadKeys : name === 'audit' ? loadAudit : loadAdmins)
}
// Key mode of a tenant: who holds its key encryption key. Only the fingerprint, never a key.
const kekLabel = tn => (tn.kek_mode === 'tenant'
  ? t('Tenant-managed') + (tn.kek_fingerprint ? ' (' + tn.kek_fingerprint.slice(0, 8) + ')' : '')
  : t('Platform-managed'))
const statusLabel = s => (s === 'active' ? t('Active') : s === 'suspended' ? t('Suspended') : s)

// ---------- key management (operator-forced rotation; metadata only) ----------
const keyRows = ref([]), keyBudget = ref(0), keyLoaded = ref(false)
const rot = reactive({ open: false, scope: '', label: '', purposes: [...PURPOSES], reason: '', code: '' })
const tracked = ref([]), bulkResults = ref([]), rotating = ref(false)
const keyProgress = computed(() => progress(keyRows.value, tracked.value))
const keysFinished = computed(() => lastFinished(keyRows.value))
const bulkCount = computed(() => bulkTargets(keyRows.value).length)
const reasonHint = computed(() => (rot.reason ? t(reasonProblem(rot.reason)) : ''))
const master = ref(null)
const mrot = reactive({ open: false, kind: 'rotate', version: 0, reason: '', code: '' })
const masterTable = computed(() => masterRows(master.value))
const masterCan = computed(() => canRotateMaster(master.value))
const masterProg = computed(() => masterProgress(master.value))
const mreasonHint = computed(() => (mrot.reason ? t(reasonProblem(mrot.reason)) : ''))
const askMaster = (kind, version) => Object.assign(mrot, { open: true, kind, version, reason: '', code: '' })
const cancelMaster = () => { mrot.open = false; mrot.code = '' }
const doMaster = () => {
  const { kind, version } = mrot, body = { version, reason: mrot.reason, ...reauth(mrot.code) }
  mrot.open = false; mrot.code = ''
  return run(async () => {
    await pconsole(kind === 'rotate' ? '/master/rotate' : '/master/retire', { method: 'POST', body })
    notice.value = kind === 'rotate' ? t('Master key rotation requested. The controller moves the organisations one at a time.') : t('Master key version retired.')
    await loadKeys()
  })
}
async function loadKeys() {
  master.value = await pconsole('/master').catch(() => master.value)
  const d = await pconsole('/keys')
  keyRows.value = d.tenants; keyBudget.value = d.budget_per_hour; keyLoaded.value = true
  if (!tracked.value.length || (progress(d.tenants, tracked.value).finished && !d.running)) rotating.value = false
}
function askRotate(row) {
  Object.assign(rot, { open: true, scope: row ? row.id : 'all', label: row ? row.slug : t('all platform-managed organisations'), purposes: [...PURPOSES], reason: '', code: '' })
}
const cancelRotate = () => { rot.open = false; rot.code = '' }
const rotateKeys = () => {
  // Close the confirmation first: nothing else may sit between the button and the request.
  const body = { purposes: [...rot.purposes], reason: rot.reason, ...reauth(rot.code) }, scope = rot.scope, label = rot.label
  rot.open = false; rot.code = ''
  return run(async () => {
    rotating.value = true
    try {
      if (scope === 'all') {
        const d = await pconsole('/keys/rotate-all', { method: 'POST', body })
        bulkResults.value = d.results
        tracked.value = d.results.filter(r => r.result === 'queued').map(r => r.id)
      } else {
        const d = await pconsole(`/tenants/${scope}/keys/rotate`, { method: 'POST', body })
        bulkResults.value = [d]; tracked.value = d.result === 'queued' ? [d.id] : []
      }
      notice.value = t('Rotation requested for {name}. It runs in the background.', { name: label })
    } catch (e) { tracked.value = []; rotating.value = false; throw e }
    await loadKeys()
  })
}
const keyBadge = r => { const s = rowStatus(r); return { ...s, text: t(s.label, { purposes: s.purposes || '' }) } }

// Tenant list and key table refresh themselves while the tab is visible:
// every ~20 s, every ~3 s while a key job runs; nothing while hidden.
let pollTimer = null
function schedulePoll() {
  clearTimeout(pollTimer); pollTimer = null
  const onKeys = tab.value === 'keys', onTenants = tab.value === 'tenants' && !sel.value
  const ms = nextPoll(onKeys ? (master.value?.in_progress ? [{ running: ['master'] }, ...keyRows.value] : keyRows.value) : [], { visible: typeof document === 'undefined' || !document.hidden, active: stage.value === 'full' && (onKeys || onTenants) })
  if (!ms) return
  pollTimer = setTimeout(async () => {
    if (!busy.value) { try { await (onKeys ? loadKeys() : refreshTenantList()) } catch {} }
    schedulePoll()
  }, ms)
}
async function refreshTenantList() { tenants.value = (await pconsole('/tenants?q=' + encodeURIComponent(q.value))).tenants }
const onVisible = () => { if (!document.hidden && stage.value === 'full') { (tab.value === 'keys' ? loadKeys() : tab.value === 'tenants' && !sel.value ? refreshTenantList() : Promise.resolve()).catch(() => {}) } schedulePoll() }
onMounted(() => document.addEventListener('visibilitychange', onVisible))
onBeforeUnmount(() => { document.removeEventListener('visibilitychange', onVisible); clearTimeout(pollTimer) })
watch([tab, sel, stage, keyRows], schedulePoll)
const showPassword = () => { tab.value = 'account'; sel.value = null; err.value = ''; notice.value = '' }
const fmtTime = v => (v ? new Date(v).toLocaleString() : '—')
</script>

<template>
  <div class="shell">
    <nav class="nav">
      <span class="brand"><img src="/logo.svg" alt="" class="logo" />{{ t('Sendora platform') }}</span>
      <div class="row" style="flex:0 1 auto;align-items:center">
        <select :value="lang" :aria-label="t('Language')" @change="setLang($event.target.value)">
          <option v-for="(n, c) in builtinLanguages" :key="c" :value="c">{{ n }}</option>
        </select>
        <button v-if="me" class="secondary small" @click="logout">{{ t('Sign out') }}</button>
      </div>
    </nav>
    <main style="width:calc(100% - 32px);max-width:1040px;margin:24px auto">
      <p v-if="stage === 'loading'" class="muted">…</p>

      <form v-else-if="stage === 'setup'" class="card narrow" @submit.prevent="doSetup">
        <h1>{{ t('Set up the platform console') }}</h1>
        <p class="muted">{{ t('Create the first platform administrator. The setup code is printed in the server log.') }}</p>
        <label for="p-code">{{ t('Setup code') }}</label><input id="p-code" v-model="f.setup_code" autocomplete="off" required />
        <label for="p-user">{{ t('Username') }}</label><input id="p-user" v-model="f.username" autocomplete="username" required />
        <label for="p-mail">{{ t('Email') }}</label><input id="p-mail" v-model="f.email" type="email" />
        <label for="p-pass">{{ t('Password') }}</label><input id="p-pass" v-model="f.password" type="password" autocomplete="new-password" minlength="12" required />
        <PasswordHints :password="f.password" :policy="pwRule" />
        <p class="muted">{{ t('An authenticator app is set up next.') }}</p>
        <p v-if="err" class="err" role="alert">{{ err }}</p>
        <div class="actions"><button :disabled="busy">{{ t('Create administrator') }}</button></div>
      </form>

      <form v-else-if="stage === 'login'" class="card narrow" @submit.prevent="doLogin">
        <h1>{{ t('Platform console') }}</h1>
        <label for="l-user">{{ t('Username') }}</label><input id="l-user" v-model="f.username" autocomplete="username" autofocus required />
        <label for="l-pass">{{ t('Password') }}</label><input id="l-pass" v-model="f.password" type="password" autocomplete="current-password" required />
        <p v-if="err" class="err" role="alert">{{ err }}</p>
        <div class="actions"><button :disabled="busy">{{ t('Sign in') }}</button></div>
      </form>

      <form v-else-if="stage === 'password'" class="card narrow" @submit.prevent="changePassword">
        <h1>{{ t('Choose a new password') }}</h1>
        <p class="muted">{{ t('You signed in with a temporary password. Choose a new password to continue.') }}</p>
        <label for="pw-cur">{{ t('Temporary password') }}</label><input id="pw-cur" v-model="pw.current" type="password" autocomplete="current-password" required />
        <label for="pw-new">{{ t('New password') }}</label><input id="pw-new" v-model="pw.next" type="password" autocomplete="new-password" minlength="12" required />
        <PasswordHints :password="pw.next" :policy="pwRule" />
        <p v-if="err" class="err" role="alert">{{ err }}</p>
        <div class="actions"><button :disabled="busy">{{ t('Save') }}</button><button type="button" class="secondary" @click="logout">{{ t('Sign out') }}</button></div>
      </form>

      <form v-else-if="stage === 'mfa'" class="card narrow" @submit.prevent="doTotp">
        <h1>{{ t('Two-step verification') }}</h1>
        <label for="t-code">{{ t('Authenticator code') }}</label>
        <input id="t-code" v-model="f.code" inputmode="numeric" autocomplete="one-time-code" autofocus maxlength="12" :placeholder="t('6-digit code')" required />
        <p v-if="err" class="err" role="alert">{{ err }}</p>
        <div class="actions"><button :disabled="busy">{{ t('Verify') }}</button><button type="button" class="secondary" @click="logout">{{ t('Back') }}</button></div>
      </form>

      <div v-else-if="stage === 'enroll'" class="card narrow">
        <h1>{{ t('Set up two-step verification') }}</h1>
        <p class="muted">{{ t('Platform administrators must use an authenticator app.') }}</p>
        <div v-if="!enroll" class="actions"><button :disabled="busy" @click="beginEnroll">{{ t('Start') }}</button></div>
        <form v-else @submit.prevent="confirmEnroll">
          <QrCode :value="enroll.uri" :label="t('QR code for your authenticator app')" filename="sendora-platform-totp.svg" />
          <p class="muted">{{ t('Or enter this key manually:') }} <code>{{ enroll.secret }}</code></p>
          <label for="e-code">{{ t('Authenticator code') }}</label>
          <input id="e-code" v-model="f.code" inputmode="numeric" autocomplete="one-time-code" maxlength="12" required />
          <div class="actions"><button :disabled="busy">{{ t('Confirm') }}</button></div>
        </form>
        <p v-if="err" class="err" role="alert">{{ err }}</p>
      </div>

      <template v-else-if="stage === 'full'">
        <div class="tabs" role="tablist">
          <a v-for="[k, label] in [['tenants', tr('Tenants')], ['settings', tr('Platform settings')], ['keys', tr('Key management')], ['audit', tr('Platform audit log')], ['admins', tr('Administrators')]]" :key="k"
            href="#" role="tab" :aria-selected="tab === k" :class="{ 'router-link-active': tab === k }" @click.prevent="show(k)">{{ t(label) }}</a>
          <a href="#" role="tab" :aria-selected="tab === 'account'" :class="{ 'router-link-active': tab === 'account' }" @click.prevent="showPassword">{{ t('My account') }}</a>
        </div>
        <p v-if="!mfaRequired" class="err" role="note">{{ t('Platform administrators can sign in without an authenticator app (platform setting).') }}</p>
        <p v-if="err" class="err" role="alert">{{ err }}</p>
        <p v-if="notice" class="ok" role="status">{{ notice }}</p>

        <template v-if="tab === 'tenants' && !sel">
          <div class="card">
            <h2>{{ t('New tenant') }}</h2>
            <form @submit.prevent="createTenant">
              <div class="row">
                <div><label for="n-slug">{{ t('Subdomain') }}</label><input id="n-slug" v-model="nt.slug" required autocomplete="off" />
                  <p class="muted" v-if="nt.slug && !slugHint">{{ nt.slug }}.{{ boot?.base_domain }}</p><p v-if="slugHint" class="err">{{ slugHint }}</p></div>
                <div><label for="n-name">{{ t('Name') }}</label><input id="n-name" v-model="nt.name" /></div>
              </div>
              <div class="row">
                <div><label for="n-mail">{{ t('Email of the first administrator') }}</label><input id="n-mail" v-model="nt.admin_email" type="email" required /></div>
                <div><label for="n-user">{{ t('Username of the first administrator') }}</label><input id="n-user" v-model="nt.admin_username" :placeholder="t('default: the part before @')" /></div>
              </div>
              <div class="row">
                <div><label for="n-mu">{{ t('Maximum users (0 = unlimited)') }}</label><input id="n-mu" v-model="nt.max_users" inputmode="numeric" /></div>
                <div><label for="n-ms">{{ t('Maximum storage in GB (0 = unlimited)') }}</label><input id="n-ms" v-model="nt.max_storage_gb" inputmode="decimal" /></div>
              </div>
              <div class="row">
                <div><label for="n-offer">{{ t('Storage provided by the platform') }}</label>
                  <select id="n-offer" v-model="nt.storage_offer">
                    <option value="none">{{ t('None: the tenant sets up its own storage') }}</option>
                    <option value="platform">{{ t('Platform bucket (own prefix)') }}</option>
                    <option value="local">{{ t('Local disk on the server') }}</option>
                  </select></div>
                <div><label class="check" style="margin-top:38px"><input type="checkbox" v-model="nt.allow_own_storage" /> {{ t('Tenant may configure its own storage') }}</label></div>
              </div>
              <p class="muted">{{ t('Without storage provided by the platform, uploads are refused until the tenant\'s administrator sets up storage under Admin → Storage.') }}</p>
              <div class="actions"><button :disabled="busy || !!slugHint">{{ t('Create tenant') }}</button></div>
            </form>
            <div v-if="created" class="card" role="status" style="margin-top:16px">
              <p class="ok">{{ t('Tenant {name} created.', { name: created.tenant.slug }) }} <a :href="created.tenant.url" rel="noopener">{{ created.tenant.url }}</a></p>
              <p v-if="created.welcome_emailed">{{ t('A welcome email with a link to choose a password was sent to the first administrator.') }}</p>
              <template v-else>
                <p>{{ t('No email could be sent. Give this one-time link to the first administrator (valid for 7 days, shown only now):') }}</p>
                <p><code style="word-break:break-all">{{ created.setup_link }}</code></p>
              </template>
            </div>
          </div>
          <div class="card">
            <form class="row" @submit.prevent="search">
              <div><label for="q">{{ t('Search') }}</label><input id="q" v-model="q" :placeholder="t('Subdomain, name or domain')" /></div>
              <div class="row-end"><button class="secondary">{{ t('Search') }}</button></div>
            </form>
            <div class="table-wrap">
              <table>
                <thead><tr><th>{{ t('Subdomain') }}</th><th>{{ t('Name') }}</th><th>{{ t('Status') }}</th><th>{{ t('Users') }}</th><th>{{ t('Storage') }}</th><th>{{ t('Key') }}</th><th></th></tr></thead>
                <tbody>
                  <tr v-for="tn in tenants" :key="tn.id">
                    <td><a :href="tn.url" rel="noopener">{{ tn.primary_host }}</a></td>
                    <td>{{ tn.name }}</td>
                    <td><span class="badge">{{ statusLabel(tn.status) }}</span></td>
                    <td>{{ tn.user_count }}<span v-if="tn.max_users" class="muted"> / {{ tn.max_users }}</span></td>
                    <td>{{ fmtSize(tn.storage_used_bytes) }}<span v-if="tn.max_storage_bytes" class="muted"> / {{ fmtSize(tn.max_storage_bytes) }} ({{ quotaPercent(tn.storage_used_bytes, tn.max_storage_bytes) }}%)</span></td>
                    <td>{{ kekLabel(tn) }}</td>
                    <td><button class="small secondary" @click="openTenant(tn.id)">{{ t('Manage') }}</button></td>
                  </tr>
                  <tr v-if="!tenants.length"><td colspan="7" class="muted">{{ t('No tenants yet.') }}</td></tr>
                </tbody>
              </table>
            </div>
            <p class="muted">{{ t('Counts are refreshed while a tenant is in use and by the periodic maintenance. The console never shows tenant content.') }}</p>
          </div>
        </template>

        <template v-if="tab === 'tenants' && sel">
          <div class="card">
            <div class="actions" style="margin-top:0"><button class="secondary small" @click="sel = null">{{ t('Back') }}</button></div>
            <h2>{{ sel.tenant.name }} <span class="badge">{{ statusLabel(sel.tenant.status) }}</span></h2>
            <p class="muted">{{ sel.tenant.url }} · {{ t('Created') }} {{ fmtTime(sel.tenant.created_at) }} · ID <code>{{ sel.tenant.id }}</code>
              <span v-if="sel.tenant.key_mode === 'legacy'"> · {{ t('imported from a single-tenant installation') }}</span>
              · {{ t('Key') }}: {{ kekLabel(sel.tenant) }}</p>
            <div class="actions">
              <button v-if="sel.tenant.status === 'active'" class="secondary" @click="setStatus('suspend')">{{ t('Suspend') }}</button>
              <button v-else @click="setStatus('resume')">{{ t('Resume') }}</button>
            </div>
          </div>
          <form class="card" @submit.prevent="saveQuota">
            <h3>{{ t('Quotas') }}</h3>
            <p class="muted">{{ t('In use: {users} users, {storage}.', { users: sel.tenant.user_count, storage: fmtSize(sel.tenant.storage_used_bytes) }) }}</p>
            <div class="row">
              <div class="field-short"><label for="q-mu">{{ t('Maximum users (0 = unlimited)') }}</label><input id="q-mu" v-model="quota.max_users" inputmode="numeric" /></div>
              <div class="row-end"><button :disabled="busy">{{ t('Save') }}</button></div>
            </div>
          </form>
          <div class="card">
            <h3>{{ t('Domains') }}</h3>
            <div class="table-wrap"><table>
              <tbody>
                <tr><td><code>{{ sel.subdomain }}</code></td><td>{{ t('Subdomain') }}</td><td><span v-if="sel.tenant.primary_host === sel.subdomain" class="badge">{{ t('Primary') }}</span>
                  <button v-else class="small secondary" @click="makePrimary(sel.subdomain)">{{ t('Make primary') }}</button></td><td></td></tr>
                <tr v-for="d in sel.domains" :key="d.domain">
                  <td><code>{{ d.domain }}</code></td>
                  <td><template v-if="d.verified">{{ t('Verified') }}</template>
                    <template v-else>{{ t('Add this DNS TXT record, then verify:') }}<br /><code>{{ d.record_name }}</code> → <code style="word-break:break-all">{{ d.record_value }}</code></template></td>
                  <td><span v-if="sel.tenant.primary_host === d.domain" class="badge">{{ t('Primary') }}</span>
                    <button v-else-if="d.verified" class="small secondary" @click="makePrimary(d.domain)">{{ t('Make primary') }}</button>
                    <button v-else class="small" @click="verifyDomain(d.domain)">{{ t('Verify') }}</button></td>
                  <td><button class="small danger" @click="removeDomain(d.domain)">{{ t('Remove') }}</button></td>
                </tr>
              </tbody>
            </table></div>
            <form class="row" @submit.prevent="addDomain">
              <div><label for="d-new">{{ t('Custom domain') }}</label><input id="d-new" v-model="domainInput" placeholder="files.example.com" /></div>
              <div class="row-end"><button class="secondary">{{ t('Add') }}</button></div>
            </form>
            <p class="muted">{{ t('A custom domain needs a DNS record pointing to this platform and a TLS certificate. Other addresses of the tenant redirect to its primary domain.') }}</p>
          </div>
          <form class="card" @submit.prevent="saveStorage">
            <h3>{{ t('Storage') }}</h3>
            <p v-if="storage.view">{{ t('In use') }}: <strong>{{ storageKindLabel(storage.view.kind) }}</strong> · {{ fmtSize(storage.view.usage_bytes) }}</p>
            <p v-if="storage.view && (storage.view.kind || '').startsWith('own:')" class="muted">{{ t('The tenant manages its own storage. Its configuration is not visible to the platform.') }}</p>
            <p v-if="storage.view && (storage.view.kind === 'platform' || (storage.view.kind || '').startsWith('own:'))" class="notice" role="note">{{ t('Remote storage can make uploads slower: after the transfer, each file is encrypted and copied to the object store before the share is ready, so large files or a distant region take longer. Downloads are read back from the object store and can be slower as well.') }}</p>
            <div class="row">
              <div><label for="s-offer">{{ t('Storage provided by the platform') }}</label>
                <select id="s-offer" v-model="storage.offer">
                  <option value="none">{{ t('None: the tenant sets up its own storage') }}</option>
                  <option value="platform">{{ t('Platform bucket (own prefix)') }}</option>
                  <option value="local">{{ t('Local disk on the server') }}</option>
                </select></div>
              <div v-if="limitShown" class="field-short"><label for="q-ms">{{ t('Storage limit in GB (0 = unlimited)') }}</label><input id="q-ms" v-model="quota.max_storage_gb" inputmode="decimal" /></div>
              <div v-if="limitShown && limitChanged" class="field-short"><label for="q-code">{{ reauthLabel }}</label>
                <input id="q-code" v-model="limit.code" :type="byPassword ? 'password' : 'text'" autocomplete="off" /></div>
            </div>
            <p v-if="limitShown" class="muted">{{ t('Applies to the storage the platform provides. Uploads that would exceed it are refused.') }}<template v-if="sel.tenant.max_storage_bytes">&nbsp;{{ t('Used') }}: {{ fmtSize(storage.view?.usage_bytes) }} / {{ fmtSize(sel.tenant.max_storage_bytes) }}</template></p>
            <p v-else-if="(storage.view?.kind || '').startsWith('own:')" class="muted">{{ t('The tenant uses storage of its own, which it pays for and manages itself: no platform storage limit applies.') }}</p>
            <p v-if="storage.offer === 'platform' && storage.view?.platform_backend === 'local'" class="muted">{{ t('The platform default is the local data directory: the tenant\'s files stay in its directory. Configure object storage under Platform settings.') }}</p>
            <label class="check"><input type="checkbox" v-model="storage.tenant_managed" /> {{ t('Tenant may configure its own storage') }}</label>
            <p class="muted">{{ t('Files keep the location they were written to; the tenant\'s administrators can move earlier files to the current location (Admin → Storage).') }}</p>
            <div class="actions"><button :disabled="busy">{{ t('Save') }}</button></div>
          </form>
          <form class="card" @submit.prevent="saveNetwork">
            <h3>{{ t('Network targets') }}</h3>
            <p class="muted">{{ t('By default the tenant\'s SMTP server, sign-in providers, audit log forwarding and own storage must not resolve to loopback, private, link-local, carrier-grade NAT or cloud metadata addresses (checked when saved and on every connection).') }}</p>
            <div class="row">
              <div><label class="check row-check"><input type="checkbox" v-model="net.allow" /> {{ t('Allow private network targets for this tenant') }}</label></div>
              <div class="field-short"><label for="n-code">{{ reauthLabel }}</label>
                <input id="n-code" v-model="net.code" :type="byPassword ? 'password' : 'text'" :inputmode="byPassword ? undefined : 'numeric'" autocomplete="off" /></div>
              <div class="row-end"><button :disabled="busy || net.allow === !!sel.tenant.allow_private_targets">{{ t('Save') }}</button></div>
            </div>
          </form>
          <form class="card" @submit.prevent="deleteTenant">
            <h3>{{ t('Delete tenant') }}</h3>
            <p class="err">{{ t('This permanently removes the tenant\'s database, files and backups. It cannot be undone.') }}</p>
            <div class="row">
              <div><label for="x-c">{{ t('Type the subdomain to confirm') }}</label><input id="x-c" v-model="del.confirm" autocomplete="off" /></div>
              <div><label for="x-t">{{ reauthLabel }}</label><input id="x-t" v-model="del.code" :type="byPassword ? 'password' : 'text'" autocomplete="off" /></div>
            </div>
            <label class="check"><input type="checkbox" v-model="del.force" /> {{ t('Delete even if objects in object storage cannot be removed') }}</label>
            <div class="actions"><button class="danger" :disabled="busy || del.confirm !== sel.tenant.slug">{{ t('Delete tenant') }}</button></div>
          </form>
        </template>

        <form v-if="tab === 'settings' && settings" class="card" @submit.prevent="saveSettings">
          <h2>{{ t('Platform settings') }}</h2>
          <p class="muted">{{ t('Base domain') }}: <code>{{ boot?.base_domain }}</code><template v-if="bd.managed"> ({{ t('set by SENDORA_BASE_DOMAIN') }})</template></p>
          <div class="grid-3">
            <div v-for="k in generalKeys" :key="k">
              <label :for="'s-' + k">{{ t(settingLabel[k]) }}</label>
              <input :id="'s-' + k" v-model="settings[k]" :disabled="managed.includes(k)" />
              <p v-if="managed.includes(k)" class="muted">{{ t('Set by the server configuration.') }}</p>
            </div>
          </div>
          <p class="muted grid-note">{{ t('Tenants without their own SMTP server send email through this default server.') }}</p>
          <div class="grid-3">
            <template v-for="k in smtpKeys" :key="k">
              <div v-if="k === 'password'">
                <label for="s-pass">{{ t('SMTP password') }}</label>
                <input id="s-pass" v-model="smtpPass" type="password" autocomplete="new-password" :disabled="managed.includes('platform_smtp_pass')" :placeholder="settings.platform_smtp_pass_set ? t('unchanged') : ''" />
              </div>
              <div v-else>
                <label :for="'s-' + k">{{ t(settingLabel[k]) }}</label>
                <input :id="'s-' + k" v-model="settings[k]" :disabled="managed.includes(k)" />
                <p v-if="managed.includes(k)" class="muted">{{ t('Set by the server configuration.') }}</p>
              </div>
            </template>
          </div>
          <div class="actions"><button :disabled="busy">{{ t('Save') }}</button></div>
        </form>

        <form v-if="tab === 'settings' && settings" class="card" @submit.prevent="saveMfa">
          <h2>{{ t('Sign-in of platform administrators') }}</h2>
          <label class="check"><input type="checkbox" v-model="mfa.required" :disabled="managed.includes('platform_mfa_required')" /> {{ t('Platform administrators must use an authenticator app') }}</label>
          <p v-if="managed.includes('platform_mfa_required')" class="muted">{{ t('Set by the server configuration.') }}</p>
          <p v-if="!mfa.required" class="err" role="alert">{{ t('Warning: without an authenticator app, a stolen or guessed password gives full control over all tenants. Only switch this off when the console is otherwise protected (for example only reachable on a private network).') }}</p>
          <p class="muted">{{ t('Administrators can always set up an authenticator app under My account. The change is recorded in the platform audit log.') }}</p>
          <div class="row">
            <div class="field-short"><label for="m-code">{{ reauthLabel }}</label>
              <input id="m-code" v-model="mfa.code" :type="byPassword ? 'password' : 'text'" autocomplete="off" /></div>
            <div class="row-end"><button :disabled="busy || managed.includes('platform_mfa_required') || mfa.required === (settings.platform_mfa_required !== 'false')">{{ t('Save') }}</button></div>
          </div>
        </form>

        <form v-if="tab === 'settings' && pstore.settings" class="card" @submit.prevent="savePlatformStorage">
          <h2>{{ t('Default storage') }}</h2>
          <p>{{ t('Current default: {where}', { where: pstore.description }) }}</p>
          <p class="muted">{{ t('Tenants on the platform default store their files under their own prefix tenants/<tenant id>/ inside this location. Changing it only affects new files; earlier files stay readable where they are.') }}</p>
          <p v-if="pstore.managed.length" class="muted">{{ t('Settings set in the server configuration (environment or Kubernetes ConfigMap) are read-only here: {n}.', { n: pstore.managed.join(', ') }) }}</p>
          <StorageForm :model-value="pstore.settings" :managed="pstore.managed" :is-set="pstore.set" id-prefix="ps" />
          <p v-if="pstore.test && pstore.test.ok" class="ok" role="status">{{ t('Connection works: a test object was written, read and deleted in {ms} ms ({where}).', { ms: pstore.test.ms, where: pstore.test.description }) }}</p>
          <p v-if="pstore.test && !pstore.test.ok" class="err" role="alert">{{ t('Connection test failed: {error}', { error: pstore.test.error }) }}</p>
          <div class="actions"><button :disabled="busy">{{ t('Save') }}</button>
            <button v-if="pstore.settings.storage_backend !== 'local'" type="button" class="secondary" :disabled="pstore.testing" @click="testPlatformStorage">{{ pstore.testing ? t('Testing…') : t('Test connection') }}</button></div>
        </form>

        <form v-if="tab === 'settings' && settings" class="card" @submit.prevent="saveNewOffer">
          <h2>{{ t('Storage for new tenants') }}</h2>
          <div class="row row-bottom">
            <div><select id="no-offer" v-model="newOffer.value" :disabled="managed.includes('new_tenant_storage_offer')" :aria-label="t('Storage for new tenants')">
              <option value="none">{{ t('None: the tenant sets up its own storage') }}</option>
              <option value="platform">{{ t('Platform bucket (own prefix)') }}</option>
              <option value="local">{{ t('Local disk on the server') }}</option>
            </select></div>
            <div class="field-short"><label for="no-code">{{ reauthLabel }}</label>
              <input id="no-code" v-model="newOffer.code" :type="byPassword ? 'password' : 'text'" autocomplete="off" /></div>
            <div class="row-end"><button :disabled="busy || offerProblem || managed.includes('new_tenant_storage_offer') || newOffer.value === settings.new_tenant_storage_offer">{{ t('Save') }}</button></div>
          </div>
          <p v-if="managed.includes('new_tenant_storage_offer')" class="muted">{{ t('Set by the server configuration.') }}</p>
          <p v-if="offerProblem" class="err" role="alert">{{ t('No platform default storage backend is configured. Configure Default storage first; until then the platform bucket cannot be offered.') }}</p>
          <p class="muted">{{ t('Preselected when creating a tenant; it can still be changed per tenant. The change is recorded in the platform audit log.') }}</p>
        </form>

        <form v-if="tab === 'settings' && settings" class="card" @submit.prevent="saveBaseDomain">
          <h2>{{ t('Base domain') }}</h2>
          <div class="row">
            <div style="flex:3"><label for="bd-host">{{ t('Base domain') }}</label><input id="bd-host" v-model="bd.host" :disabled="bd.managed" autocomplete="off" @blur="onBdHost" />
              <p v-if="bd.host && !validHost(bd.host)" class="err">{{ t('Enter a host name only, without http:// or a path.') }}</p></div>
            <div style="flex:1"><label for="bd-port">{{ t('Port') }}</label><input id="bd-port" v-model="bd.port" :disabled="bd.managed" inputmode="numeric" placeholder="443" autocomplete="off" />
              <p v-if="!validPort(bd.port)" class="err">{{ t('Enter a port from 1 to 65535, or leave it empty for 80/443.') }}</p></div>
          </div>
          <p v-if="bdLive" class="muted" aria-live="polite">{{ t('Platform console') }}: <code>{{ bdLive.console }}</code> · {{ t('Organisation') }}: <code>{{ bdLive.org }}</code></p>
          <p v-if="bd.managed" class="muted">{{ t('Set by SENDORA_BASE_DOMAIN in the server configuration.') }}</p>
          <template v-else>
            <p class="muted">{{ t('Stored in the data directory; it applies after a restart of the server.') }}</p>
            <label for="bd-code">{{ reauthLabel }}</label>
            <input id="bd-code" v-model="bd.code" :type="byPassword ? 'password' : 'text'" autocomplete="off" />
            <div class="actions"><button :disabled="busy || !bdOK || joinHostPort(bd.host, bd.port) === bd.saved">{{ t('Save') }}</button></div>
          </template>
        </form>

        <form v-if="tab === 'settings' && settings && restartAvailable" class="card" @submit.prevent="restartServer">
          <h2>{{ t('Restart the server') }}</h2>
          <p class="muted">{{ t('Stops the server in an orderly way (requests in progress finish, every tenant is closed) and starts it again with the same configuration.') }}</p>
          <p v-if="restarting" class="notice" role="status" aria-live="polite">{{ t('Restarting…') }}</p>
          <div class="row">
            <div class="field-short"><label for="rs-code">{{ reauthLabel }}</label>
              <input id="rs-code" v-model="restartCode" :type="byPassword ? 'password' : 'text'" autocomplete="off" /></div>
            <div class="row-end"><button class="secondary" :disabled="busy || restarting">{{ t('Restart now') }}</button></div>
          </div>
        </form>

        <div v-if="tab === 'account'" class="card">
          <h2>{{ t('My account') }}</h2>
          <p>{{ me?.username }} · {{ t('Authenticator') }}: {{ me?.totp_enabled ? t('Active') : t('Not set up') }}</p>
          <template v-if="!me?.totp_enabled">
            <div v-if="!enroll" class="actions"><button :disabled="busy" @click="beginEnroll">{{ t('Set up an authenticator app') }}</button></div>
            <form v-else @submit.prevent="confirmEnroll">
              <QrCode :value="enroll.uri" :label="t('QR code for your authenticator app')" filename="sendora-platform-totp.svg" />
              <p class="muted">{{ t('Or enter this key manually:') }} <code>{{ enroll.secret }}</code></p>
              <label for="me-code">{{ t('Authenticator code') }}</label>
              <input id="me-code" v-model="f.code" inputmode="numeric" autocomplete="one-time-code" maxlength="12" required />
              <div class="actions"><button :disabled="busy">{{ t('Confirm') }}</button></div>
            </form>
          </template>
          <h3>{{ t('Change password') }}</h3>
          <form @submit.prevent="changePassword">
            <div class="row">
              <div><label for="ma-cur">{{ t('Current password') }}</label><input id="ma-cur" v-model="pw.current" type="password" autocomplete="current-password" required /></div>
              <div><label for="ma-new">{{ t('New password') }}</label><input id="ma-new" v-model="pw.next" type="password" autocomplete="new-password" minlength="12" required /><PasswordHints :password="pw.next" optional :policy="pwRule" /></div>
            </div>
            <div class="actions"><button :disabled="busy">{{ t('Change password') }}</button></div>
          </form>
        </div>

        <template v-if="tab === 'keys'">
          <div class="card">
            <h2>{{ t('Master key') }}</h2>
            <p class="muted">{{ t('The master key protects the key-encryption key of every organisation. Rotating it moves each organisation to the new version, one at a time, without re-encrypting any data. Mount the new version (master-<n>) in the controllers\' key Secret first. Keep the old version until every backup that needs it has expired.') }}</p>
            <p v-if="master?.in_progress" role="status"><span class="spinner" aria-hidden="true"></span>{{ t('Rotating to version {n}: {done} of {total} organisations moved.', { n: master.target, done: masterProg.done, total: masterProg.total }) }}</p>
            <p v-if="master?.note" class="muted">{{ master.note }}</p>
            <form v-if="mrot.open" class="card" role="dialog" aria-modal="true" :aria-label="t('Confirm master key action')" @submit.prevent="doMaster" @keydown.esc="cancelMaster">
              <h3>{{ mrot.kind === 'rotate' ? t('Rotate the master key to version {n}', { n: mrot.version }) : t('Retire master key version {n}', { n: mrot.version }) }}</h3>
              <label for="mr-reason">{{ t('Reason (recorded in the audit logs)') }}</label>
              <input id="mr-reason" v-model="mrot.reason" maxlength="300" autocomplete="off" required />
              <p v-if="mreasonHint" class="err">{{ mreasonHint }}</p>
              <label for="mr-code">{{ reauthLabel }}</label>
              <input id="mr-code" v-model="mrot.code" :type="byPassword ? 'password' : 'text'" autocomplete="off" required />
              <div class="actions"><button :disabled="busy || !!reasonProblem(mrot.reason) || !mrot.code">{{ mrot.kind === 'rotate' ? t('Rotate master key') : t('Retire version') }}</button><button type="button" class="secondary" @click="cancelMaster">{{ t('Cancel') }}</button></div>
            </form>
            <div class="table-wrap"><table>
              <thead><tr><th>{{ t('Version') }}</th><th>{{ t('Organisations') }}</th><th>{{ t('Status') }}</th><th></th></tr></thead>
              <tbody>
                <tr v-for="r in masterTable" :key="r.version">
                  <td>{{ r.version }}</td><td>{{ r.tenants }}</td>
                  <td><span class="badge">{{ t(r.state) }}</span><span v-if="r.infra" class="muted"> {{ t('Also derives the database passwords and the platform\'s own keys.') }}</span></td>
                  <td><button v-if="r.retirable" class="small secondary" :disabled="busy" @click="askMaster('retire', r.version)">{{ t('Retire') }}</button></td>
                </tr>
              </tbody>
            </table></div>
            <div class="actions"><button :disabled="busy || !masterCan.enabled" :title="masterCan.reason ? t(masterCan.reason) : ''" @click="askMaster('rotate', masterCan.next)">{{ t('Rotate the master key to version {n}', { n: masterCan.next }) }}</button></div>
          </div>
          <div class="card">
            <h2>{{ t('Key management') }}</h2>
            <p class="muted">{{ t('Forces a rotation of the data keys of an organisation, for example after an incident. The new keys are created and old values are re-encrypted by the controllers in the background; you never see key material or content. Organisations that hold their own key can only be rotated while their key is unlocked on the controllers.') }}</p>
            <div class="actions" style="margin-top:0">
              <button :disabled="busy || rotating || !bulkCount" @click="askRotate(null)">{{ t('Rotate keys of all platform-managed organisations') }} ({{ bulkCount }})</button>
              <span v-if="rotating || keyRows.some(r => r.running.length)" class="muted" role="status"><span class="spinner" aria-hidden="true"></span> {{ t('Key rotation in progress…') }}</span>
            </div>
            <p v-if="tracked.length" class="muted" role="status">{{ t('{done} of {total} organisations finished.', { done: keyProgress.done, total: keyProgress.total }) }}</p>
            <p v-if="keysFinished" class="muted">{{ t('Last operation finished at {time}', { time: fmtTime(keysFinished) }) }}</p>
            <form v-if="rot.open" class="card" role="dialog" aria-modal="true" :aria-label="t('Confirm key rotation')" @submit.prevent="rotateKeys" @keydown.esc="cancelRotate">
              <h3>{{ t('Rotate keys: {name}', { name: rot.label }) }}</h3>
              <fieldset><legend>{{ t('Purposes') }}</legend>
                <label v-for="p in PURPOSES" :key="p" class="check"><input type="checkbox" :value="p" v-model="rot.purposes" /> {{ p }}</label></fieldset>
              <label for="rot-reason">{{ t('Reason (recorded in the audit logs)') }}</label>
              <input id="rot-reason" v-model="rot.reason" maxlength="300" autocomplete="off" required />
              <p v-if="reasonHint" class="err">{{ reasonHint }}</p>
              <label for="rot-code">{{ reauthLabel }}</label>
              <input id="rot-code" v-model="rot.code" :type="byPassword ? 'password' : 'text'" autocomplete="off" required />
              <div class="actions"><button :disabled="busy || !rot.purposes.length || !!reasonProblem(rot.reason) || !rot.code">{{ t('Rotate keys') }}</button><button type="button" class="secondary" @click="cancelRotate">{{ t('Cancel') }}</button></div>
            </form>
            <div class="table-wrap">
              <table>
                <thead><tr><th>{{ t('Subdomain') }}</th><th>{{ t('Key') }}</th><th>{{ t('Key fingerprint') }}</th><th>{{ t('Last rotation') }}</th><th>{{ t('Old versions kept') }}</th><th>{{ t('Status') }}</th><th></th></tr></thead>
                <tbody>
                  <tr v-for="r in keyRows" :key="r.id">
                    <td>{{ r.slug }}</td>
                    <td>{{ kekLabel(r) }}</td>
                    <td><code v-if="r.kek_fingerprint">{{ r.kek_fingerprint.slice(0, 16) }}</code><span v-else class="muted">—</span></td>
                    <td>{{ r.last_rotation ? fmtTime(r.last_rotation) : t('Never') }}</td>
                    <td>{{ r.versions_behind }}</td>
                    <td><span class="badge" :class="keyBadge(r).kind">{{ keyBadge(r).text }}</span><span v-if="keyBadge(r).kind === 'busy'" class="spinner" aria-hidden="true"></span>
                      <span v-if="r.last_error" class="err"> {{ r.last_error }}</span></td>
                    <td><button class="small secondary" :disabled="busy || rotating || !canRotate(r).enabled" :title="canRotate(r).reason ? t(canRotate(r).reason) : ''" @click="askRotate(r)">{{ t('Rotate keys') }}</button></td>
                  </tr>
                  <tr v-if="keyLoaded && !keyRows.length"><td colspan="7" class="muted">{{ t('No tenants yet.') }}</td></tr>
                </tbody>
              </table>
            </div>
            <ul v-if="bulkResults.length" class="muted">
              <li v-for="x in bulkResults" :key="x.id">{{ x.slug }}: {{ t(resultLabel(x.result)) }}<span v-if="x.detail"> ({{ x.detail }})</span></li>
            </ul>
            <p class="muted">{{ t('At most {n} key operations per hour; a request for all organisations counts once.', { n: keyBudget }) }}</p>
          </div>
        </template>

        <div v-if="tab === 'audit'" class="card">
          <h2>{{ t('Platform audit log') }}</h2>
          <p v-if="auditStatus" :class="auditStatus.ok ? 'ok' : 'err'">{{ auditStatus.ok ? t('The audit log is intact.') : t('The audit log does not verify.') }}</p>
          <div class="table-wrap"><table>
            <thead><tr><th>#</th><th>{{ t('Time') }}</th><th>{{ t('Who') }}</th><th>{{ t('Action') }}</th><th>{{ t('Target') }}</th><th>{{ t('Details') }}</th></tr></thead>
            <tbody><tr v-for="r in audit" :key="r.seq"><td>{{ r.seq }}</td><td>{{ fmtTime(r.ts) }}</td><td>{{ r.actor_name }}</td><td>{{ r.action }} <span v-if="r.outcome !== 'ok'" class="badge">{{ r.outcome }}</span></td><td>{{ r.target }}</td><td>{{ r.detail }}</td></tr></tbody>
          </table></div>
        </div>

        <div v-if="tab === 'admins'" class="card">
          <h2>{{ t('Administrators') }}</h2>
          <div class="row"><div class="field-short"><label for="a-code">{{ reauthLabel }}</label>
            <input id="a-code" v-model="adminCode" :type="byPassword ? 'password' : 'text'" autocomplete="off" /></div></div>
          <div class="table-wrap"><table>
            <thead><tr><th>{{ t('Username') }}</th><th>{{ t('Email') }}</th><th>{{ t('Authenticator') }}</th><th></th></tr></thead>
            <tbody><tr v-for="a in admins" :key="a.id"><td>{{ a.username }}</td><td>{{ a.email }}</td><td>{{ a.totp_enabled ? t('Active') : t('Not set up') }}</td>
              <td><template v-if="a.id !== me?.id"><button class="small secondary" @click="resetAdminMfa(a)">{{ t('Reset authenticator') }}</button> <button class="small danger" @click="deleteAdmin(a)">{{ t('Remove') }}</button></template></td></tr></tbody>
          </table></div>
          <h3>{{ t('New administrator') }}</h3>
          <form @submit.prevent="createAdmin">
            <div class="row">
              <div><label for="na-u">{{ t('Username') }}</label><input id="na-u" v-model="na.username" required /></div>
              <div><label for="na-e">{{ t('Email') }}</label><input id="na-e" v-model="na.email" type="email" /></div>
            </div>
            <div class="row">
              <div><label for="na-p">{{ t('Password') }}</label><input id="na-p" v-model="na.password" type="password" autocomplete="new-password" minlength="12" required /><PasswordHints :password="na.password" optional :policy="pwRule" /></div>
              <div><label for="na-c">{{ reauthLabel }}</label><input id="na-c" v-model="na.code" :type="byPassword ? 'password' : 'text'" autocomplete="off" required /></div>
            </div>
            <div class="actions"><button :disabled="busy">{{ t('Create administrator') }}</button></div>
          </form>
        </div>
      </template>
    </main>
    <footer class="foot"><PoweredBy :boot="boot" /></footer>
  </div>
</template>
