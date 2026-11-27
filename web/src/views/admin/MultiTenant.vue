<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Converting this single-tenant installation to multi-tenant mode: the
// conversion is scheduled here and runs at the next start of the server
// (internal/app/mt_convert.go, docs/MULTI-TENANT.md section 7).
import { ref, reactive, computed, onMounted } from 'vue'
import { api } from '../../api'
import { t } from '../../i18n'
import PasswordHints from '../../components/PasswordHints.vue'
import { platformPolicy, passwordChecklist } from '../../password-check.mjs'
import { splitHostPort, validHost, validPort, joinHostPort, defaultPort, platformURLs, portWarning } from '../../base-domain.mjs'

const st = ref(null), err = ref(''), msg = ref(''), busy = ref(false), confirmed = ref(false)
const f = reactive({ base_host: '', base_port: '', slug: '', name: '', admin_username: '', admin_email: '', admin_password: '', mfa_required: true, use_custom_domain: true, custom_domain: '' })
async function load() {
  st.value = await api('/multitenant')
  // The port of the address in use (or of the configured public URL).
  if (!f.base_port) f.base_port = defaultPort(location.port) || st.value.public_port || ''
  if (!f.custom_domain) f.custom_domain = st.value.suggested_custom_domain || ''
  f.use_custom_domain = !!f.custom_domain
}
onMounted(async () => { try { await load() } catch (e) { err.value = e.message } })
const slugOK = computed(() => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(f.slug) && !f.slug.includes('--'))
const pwPolicy = computed(() => platformPolicy(st.value || {}))
// The base domain is edited as host and port; a port typed into the host
// field moves to the port field.
function onHost() {
  const { host, port } = splitHostPort(f.base_host)
  if (port || host !== f.base_host) { f.base_host = host; if (port) f.base_port = port }
}
function onCustom() { f.custom_domain = splitHostPort(f.custom_domain).host }
const hostOK = computed(() => validHost(f.base_host))
const portOK = computed(() => validPort(f.base_port))
const baseDomain = computed(() => joinHostPort(f.base_host, f.base_port))
const live = computed(() => (hostOK.value ? platformURLs(f.base_host, f.base_port, f.slug) : null))
const pagePort = typeof location === 'undefined' ? '' : location.port
const portHint = computed(() => portWarning(f.base_port, pagePort))
const ready = computed(() => hostOK.value && portOK.value && slugOK.value && f.admin_username && f.admin_email && passwordChecklist(f.admin_password, pwPolicy.value).ok && confirmed.value)

async function schedule() {
  err.value = msg.value = ''; busy.value = true
  try {
    const res = await api('/multitenant', { method: 'POST', body: { base_domain: baseDomain.value, slug: f.slug, name: f.name, admin_username: f.admin_username, admin_email: f.admin_email,
      admin_password: f.admin_password, mfa_required: f.mfa_required, custom_domain: f.use_custom_domain ? f.custom_domain : '' } })
    f.admin_password = ''; confirmed.value = false
    msg.value = t('The conversion is scheduled. It runs at the next start of the server.') + (res?.warning ? ' ' + t('Note: {warning}', { warning: res.warning }) : '')
    await load()
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
async function cancel() {
  err.value = msg.value = ''
  try { await api('/multitenant', { method: 'DELETE' }); msg.value = t('The scheduled conversion was cancelled.'); await load() } catch (e) { err.value = e.message }
}
// The addresses after the conversion (http for localhost base domains).
const urls = c => {
  if (!c?.base_domain) return null
  const { host, port } = splitHostPort(c.base_domain)
  const u = platformURLs(host, port, c.slug) || { console: '', org: '' }
  return { ...u, custom: c.custom_domain ? `https://${c.custom_domain}` : '' }
}
const preview = computed(() => ({ base_domain: baseDomain.value, slug: f.slug, name: f.name || f.slug, admin_username: f.admin_username, admin_email: f.admin_email,
  mfa_required: f.mfa_required, custom_domain: f.use_custom_domain ? f.custom_domain : '' }))
const fmtLocal = v => { try { return new Date(v).toLocaleString() } catch { return v } }
const restarting = ref(false), restarted = ref(null)
async function restart() {
  err.value = msg.value = ''
  const target = urls(st.value.pending)
  try {
    await api('/multitenant/restart', { method: 'POST' })
    restarting.value = true
    // Poll /api/health (answered on every host, also after the conversion; the
    // page's CSP only allows its own origin): first until the server went
    // down for the restart, then until it answers again.
    let down = false
    for (let i = 0; i < 240; i++) {
      await new Promise(r => setTimeout(r, 1000))
      let up = false
      try { up = (await fetch('/api/health', { cache: 'no-store' })).ok } catch {}
      if (!up) { down = true; continue }
      if (down || i >= 10) { restarted.value = target; break }
    }
    restarting.value = false
    if (!restarted.value) err.value = t('The server did not come back yet. Check the server log, then open the new addresses.')
  } catch (e) { err.value = e.message; restarting.value = false }
}
</script>
<template>
  <p v-if="!st && err" class="err" role="alert">{{ err }}</p>
  <div v-if="st" class="card">
    <h1>{{ t('Multi-tenant mode') }}</h1>
    <p>{{ t('Convert this installation into a platform that serves several organisations. This installation becomes the first organisation (tenant); a platform console on admin.<base domain> manages the organisations.') }}</p>
    <p v-if="st.last_error" class="err" role="alert">{{ t('The last conversion failed ({stage}): {error}. Nothing was changed; the installation runs single-tenant as before.', { stage: st.last_error.stage, error: st.last_error.error }) }}</p>
    <p v-if="msg" class="ok" role="status">{{ msg }}</p>
    <p v-if="err" class="err" role="alert">{{ err }}</p>

    <div v-if="restarting" class="notice" role="status" aria-live="polite">{{ t('Restarting… the conversion runs now; this page waits for the new addresses.') }}</div>
    <div v-else-if="restarted" class="card" role="status" aria-live="polite">
      <p class="ok">{{ t('The conversion is complete.') }}</p>
      <ul>
        <li>{{ t('Platform console') }}: <a :href="restarted.console">{{ restarted.console }}</a></li>
        <li>{{ t('Organisation') }}: <a :href="restarted.org + '/login'">{{ restarted.org }}</a></li>
        <li v-if="restarted.custom">{{ t('Custom domain') }}: {{ restarted.custom }}</li>
      </ul>
    </div>
    <template v-else-if="st.pending">
      <h2>{{ t('Scheduled conversion') }}</h2>
      <dl class="facts">
        <dt>{{ t('Base domain') }}</dt><dd>{{ st.pending.base_domain }}</dd>
        <dt>{{ t('First organisation') }}</dt><dd>{{ st.pending.name }} ({{ st.pending.slug }})</dd>
        <dt>{{ t('Platform administrator') }}</dt><dd>{{ st.pending.admin_username }} &lt;{{ st.pending.admin_email }}&gt;</dd>
        <dt>{{ t('Custom domain kept') }}</dt><dd>{{ st.pending.custom_domain ? t('Yes') + ': ' + st.pending.custom_domain : t('No') }}</dd>
        <dt>{{ t('Authenticator required for platform administrators') }}</dt><dd>{{ st.pending.mfa_required ? t('Yes') : t('No') }}</dd>
        <dt>{{ t('Scheduled by') }}</dt><dd>{{ st.pending.requested_by }}, {{ fmtLocal(st.pending.requested_at) }}</dd>
        <dt>{{ t('Platform console') }}</dt><dd><code>{{ urls(st.pending).console }}</code></dd>
        <dt>{{ t('Organisation') }}</dt><dd><code>{{ urls(st.pending).org }}</code></dd>
      </dl>
      <p class="muted">{{ t('The conversion runs at the next start of the server. Restart now stops the server in an orderly way and starts it again.') }}</p>
      <div class="actions">
        <button v-if="st.restart_available" @click="restart">{{ t('Restart now') }}</button>
        <button class="secondary" @click="cancel">{{ t('Cancel the conversion') }}</button>
      </div>
      <p v-if="!st.restart_available" class="muted">{{ t('Restart the server (for example docker restart or a new pod) to run the conversion.') }}</p>
    </template>

    <form v-else @submit.prevent="schedule">
      <h2>{{ t('Requirements') }}</h2>
      <ul>
        <li>{{ t('A wildcard DNS record *.<base domain> pointing to this server, and a TLS certificate for <base domain> and *.<base domain> (DNS-01).') }}</li>
        <li>{{ t('The reverse proxy or ingress must pass every host name of the base domain (and custom domains) to Sendora.') }}</li>
        <li>{{ t('Set SENDORA_BASE_DOMAIN in the deployment later if you prefer; the mode and base domain are stored in the data directory.') }}</li>
      </ul>
      <h2>{{ t('What happens') }}</h2>
      <ul>
        <li>{{ t('At the next start a full encrypted backup of the database is made, then the installation is converted with the verified tenant import: database, shares, files, backups and the audit log move to the first organisation. Share files are not rewritten.') }}</li>
        <li>{{ t('The original database and backups are kept in pre-tenant-import-<time>/ in the data directory. If anything fails, the conversion is undone and the server starts single-tenant as before.') }}</li>
        <li v-if="st.jwt_secret_set">{{ t('JWT_SECRET is set: everyone has to sign in again after the conversion (each organisation gets its own signing secret).') }}</li>
        <li>{{ t('Users then sign in at <slug>.<base domain>. With the current address as custom domain, existing share links keep working.') }}</li>
      </ul>

      <h2>{{ t('Platform') }}</h2>
      <div class="row">
        <div style="flex:3"><label for="mt-base">{{ t('Base domain') }}</label><input id="mt-base" v-model="f.base_host" placeholder="sendora.example.com" required autocomplete="off" @blur="onHost" @change="onHost" />
          <p v-if="f.base_host && !hostOK" class="err">{{ t('Enter a host name only, without http:// or a path.') }}</p></div>
        <div style="flex:1"><label for="mt-port">{{ t('Port') }}</label><input id="mt-port" v-model="f.base_port" inputmode="numeric" placeholder="443" autocomplete="off" />
          <p v-if="!portOK" class="err">{{ t('Enter a port from 1 to 65535, or leave it empty for 80/443.') }}</p></div>
      </div>
      <p v-if="portHint === 'missing-port'" class="err" role="alert">{{ t('This page is served on port {port}, but the base domain has no port: unless a reverse proxy serves the platform on 80/443, every address would lack the port.', { port: pagePort }) }}</p>
      <p v-else-if="portHint === 'extra-port'" class="notice" role="note">{{ t('The base domain uses a port, but this page is served without one. Check that the platform is reachable on that port.') }}</p>
      <div class="row">
        <div><label for="mt-slug">{{ t('Subdomain of this organisation') }}</label><input id="mt-slug" v-model="f.slug" required autocomplete="off" /></div>
        <div><label for="mt-name">{{ t('Name of this organisation') }}</label><input id="mt-name" v-model="f.name" /></div>
      </div>
      <label class="check"><input type="checkbox" v-model="f.use_custom_domain" /> {{ t('Keep the current address as a custom domain of this organisation (existing links keep working)') }}</label>
      <input v-if="f.use_custom_domain" id="mt-custom" v-model="f.custom_domain" :aria-label="t('Custom domain')" placeholder="files.example.com" @blur="onCustom" />
      <p v-if="f.use_custom_domain" class="muted">{{ t('A host name only: custom domains are served on the standard ports by your reverse proxy.') }}</p>
      <p v-if="live" class="muted" aria-live="polite">{{ t('Platform console') }}: <code>{{ live.console }}</code><template v-if="live.org"> · {{ t('Organisation') }}: <code>{{ live.org }}</code></template></p>
      <h2>{{ t('First platform administrator') }}</h2>
      <div class="row">
        <div><label for="mt-user">{{ t('Username') }}</label><input id="mt-user" v-model="f.admin_username" required autocomplete="off" /></div>
        <div><label for="mt-mail">{{ t('Email') }}</label><input id="mt-mail" v-model="f.admin_email" type="email" required /></div>
      </div>
      <label for="mt-pass">{{ t('Password') }}</label><input id="mt-pass" v-model="f.admin_password" type="password" autocomplete="new-password" minlength="12" required />
      <PasswordHints :password="f.admin_password" :policy="pwPolicy" />
      <label class="check"><input type="checkbox" v-model="f.mfa_required" /> {{ t('Platform administrators must use an authenticator app') }}</label>
      <template v-if="hostOK && f.slug">
        <h2>{{ t('Summary') }}</h2>
        <dl class="facts">
          <dt>{{ t('Base domain') }}</dt><dd>{{ preview.base_domain }}</dd>
          <dt>{{ t('First organisation') }}</dt><dd>{{ preview.name }} ({{ preview.slug }})</dd>
          <dt>{{ t('Platform administrator') }}</dt><dd>{{ preview.admin_username }}<template v-if="preview.admin_email"> &lt;{{ preview.admin_email }}&gt;</template></dd>
          <dt>{{ t('Custom domain kept') }}</dt><dd>{{ preview.custom_domain ? t('Yes') + ': ' + preview.custom_domain : t('No') }}</dd>
          <dt>{{ t('Authenticator required for platform administrators') }}</dt><dd>{{ preview.mfa_required ? t('Yes') : t('No') }}</dd>
          <dt>{{ t('Platform console') }}</dt><dd><code>{{ urls(preview).console }}</code></dd>
          <dt>{{ t('Organisation') }}</dt><dd><code>{{ urls(preview).org }}</code></dd>
        </dl>
      </template>
      <label class="check"><input type="checkbox" v-model="confirmed" /> {{ t('I have read the requirements; schedule the conversion for the next start') }}</label>
      <div class="actions"><button :disabled="busy || !ready">{{ t('Schedule the conversion') }}</button></div>
    </form>
  </div>
</template>
