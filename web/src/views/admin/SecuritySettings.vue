<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Security-related settings (two-step verification, account password policy, audit log),
// shown on the Security tab. Only these keys are sent when saving.
import { ref, onMounted } from 'vue'
import { api } from '../../api'
import { loadBoot } from '../../state'
import { t, tr } from '../../i18n'

const KEYS = ['mfa_policy', 'mfa_reminder_days', 'mfa_totp_enabled', 'mfa_webauthn_enabled',
  'account_password_require_upper', 'account_password_require_lower', 'account_password_require_digit', 'account_password_require_symbol', 'account_password_min_length',
  'account_password_max_age_days', 'account_password_history',
  'audit_retention_days', 'audit_log_ip', 'provider_session_max_hours',
  'audit_forward_stdout', 'audit_forward_syslog', 'audit_forward_syslog_tls', 'audit_forward_webhook_url',
  'notify_new_signin', 'password_breach_check_online', 'admin_stepup_minutes', 'admin_idle_logout_minutes', 'admin_ip_allowlist']
const s = ref(null), managed = ref([]), msg = ref(''), err = ref(''), busy = ref(false)
const m = k => managed.value.includes(k)
const accountFlags = [['account_password_require_upper', tr('Require an uppercase letter')], ['account_password_require_lower', tr('Require a lowercase letter')], ['account_password_require_digit', tr('Require a digit')], ['account_password_require_symbol', tr('Require a symbol')]]

async function load() {
  const settings = await api('/settings')
  managed.value = settings.managed_settings || []
  s.value = Object.fromEntries(KEYS.map(k => [k, settings[k]]))
}
onMounted(async () => { try { await load() } catch (e) { err.value = e.message } })

async function save() {
  msg.value = err.value = ''; busy.value = true
  try {
    // Configured (read-only) settings are not sent, so they never cause an error.
    const body = Object.fromEntries(Object.entries(s.value).filter(([k]) => !m(k)))
    await api('/settings', { method: 'PUT', body })
    await loadBoot(); await load(); msg.value = t('Saved')
  } catch (e) {
    err.value = e.message
    // Show what is actually stored again, so a refused change does not look applied.
    try { await load() } catch {}
  } finally { busy.value = false }
}
</script>
<template>
  <p v-if="!s && err" class="err" role="alert">{{ err }}</p>
  <form v-if="s" class="card" @submit.prevent="save">
    <h1>{{ t('Security settings') }}</h1>
    <p v-if="KEYS.some(m)" class="muted">{{ t('Settings set in the server configuration (environment or Kubernetes ConfigMap) are read-only here: {n}.', { n: KEYS.filter(m).join(', ') }) }}</p>

    <h2 style="margin-top:8px">{{ t('Multi-factor authentication') }}</h2>
    <label for="mfa-policy">{{ t('Two-step verification policy') }}</label>
    <select :disabled="m('mfa_policy')" id="mfa-policy" v-model="s.mfa_policy"><option value="off">{{ t('Off') }}</option><option value="optional">{{ t('Optional (users choose)') }}</option><option value="admins">{{ t('Required for administrators') }}</option><option value="privileged">{{ t('Required for administrators and auditors') }}</option><option value="all">{{ t('Required for everyone') }}</option></select>
    <label for="mfa-reminder">{{ t('Remind users who skipped two-step setup again after (days, 0 = at every sign-in)') }}</label><input id="mfa-reminder" :disabled="m('mfa_reminder_days')" v-model="s.mfa_reminder_days" type="number" min="0" max="365" />
    <p class="muted">{{ t('Accounts with a local password and no second factor see a reminder after signing in. Dismissing it hides it for this many days in that browser.') }}</p>
    <label class="check"><input :disabled="m('mfa_totp_enabled')" type="checkbox" :checked="s.mfa_totp_enabled !== 'false'" @change="s.mfa_totp_enabled = String($event.target.checked)" /> {{ t('Allow authenticator apps (TOTP)') }}</label>
    <label class="check"><input :disabled="m('mfa_webauthn_enabled')" type="checkbox" :checked="s.mfa_webauthn_enabled !== 'false'" @change="s.mfa_webauthn_enabled = String($event.target.checked)" /> {{ t('Allow passkeys and security keys') }}</label>
    <p class="muted">{{ t('Applies to local accounts. Sign-ins through an external provider (Entra, OpenID Connect, Google, GitHub) use that provider\'s own multi-factor checks. Passkeys need https with a fixed application URL, or localhost. To require it for administrators or everyone, first set up two-step verification for your own account (Profile), then choose the policy. Users can be set to required or exempt individually under Users. Turning the policy off disables all two-step prompts.') }}</p>

    <h2 style="margin-top:20px">{{ t('Account password policy') }}</h2>
    <label v-for="[k, l] in accountFlags" :key="k" class="check"><input :disabled="m(k)" type="checkbox" :checked="s[k] === 'true'" @change="s[k] = String($event.target.checked)" /> {{ t(l) }}</label>
    <label for="acct-min">{{ t('Minimum password length (8-72)') }}</label><input id="acct-min" :disabled="m('account_password_min_length')" v-model="s.account_password_min_length" type="number" min="8" max="72" />
    <p class="muted">{{ t('Applies to local accounts when a password is set or changed (setup, registration, reset, profile, administrators). Existing passwords keep working until they are next changed.') }}</p>
    <label for="acct-max-age">{{ t('Require a new password every (days, 0 = never, max 365)') }}</label><input id="acct-max-age" :disabled="m('account_password_max_age_days')" v-model="s.account_password_max_age_days" type="number" min="0" max="365" />
    <p class="muted">{{ t('0 never asks for a new password, which is less secure. Modern guidance (NIST SP 800-63B) prefers screening passwords and two-step verification over frequent rotation. Users are reminded 14 days before (by email 7 days before); accounts that sign in only through a provider, and users exempted under Users, are not affected.') }}</p>
    <label for="acct-history">{{ t('Remember previous passwords (0-24)') }}</label><input id="acct-history" :disabled="m('account_password_history')" v-model="s.account_password_history" type="number" min="0" max="24" />
    <p class="muted">{{ t('A new password must differ from the current one and from this many earlier passwords (0 = no check). Earlier passwords are kept only as one-way hashes.') }}</p>
    <p class="muted">{{ t('Common passwords, passwords containing the username, the email address or the application name, and simple repetitions or sequences are always refused.') }}</p>
    <label class="check"><input :disabled="m('password_breach_check_online')" type="checkbox" :checked="s.password_breach_check_online === 'true'" @change="s.password_breach_check_online = String($event.target.checked)" /> {{ t('Also check new passwords against known data breaches (Have I Been Pwned)') }}</label>
    <p class="muted">{{ t('Only the first 5 characters of the password\'s SHA-1 hash are sent (k-anonymity); the password itself never leaves the server. If the service cannot be reached, the password is accepted.') }}</p>

    <h2 style="margin-top:20px">{{ t('Notifications') }}</h2>
    <label class="check"><input :disabled="m('notify_new_signin')" type="checkbox" :checked="s.notify_new_signin !== 'false'" @change="s.notify_new_signin = String($event.target.checked)" /> {{ t('Email users about a sign-in from a new browser or network') }}</label>
    <p class="muted">{{ t('Users with a verified email address are always told when their password, two-step verification or recovery codes change. The new sign-in check compares the browser family and the network with the sign-ins of the last 30 days; no IP addresses are stored for it.') }}</p>

    <h2 style="margin-top:20px">{{ t('Administrators') }}</h2>
    <label for="stepup-min">{{ t('Ask administrators to confirm critical actions again after (minutes, 1-60)') }}</label><input id="stepup-min" :disabled="m('admin_stepup_minutes')" v-model="s.admin_stepup_minutes" type="number" min="1" max="60" />
    <p class="muted">{{ t('Deleting or erasing users, changing roles, sign-in providers, these security settings, backups and MFA resets need a password or second-factor confirmation that is at most this old.') }}</p>
    <label for="admin-idle">{{ t('Sign administrators out after inactivity (minutes, 0 = same as everyone)') }}</label><input id="admin-idle" :disabled="m('admin_idle_logout_minutes')" v-model="s.admin_idle_logout_minutes" type="number" min="0" max="10080" />
    <label for="admin-ips">{{ t('Allow administration only from these addresses (IP addresses or ranges, one per line; empty = anywhere)') }}</label>
    <textarea id="admin-ips" :disabled="m('admin_ip_allowlist')" v-model="s.admin_ip_allowlist" rows="3" spellcheck="false" placeholder="203.0.113.0/24" />
    <p class="muted">{{ t('Applies to the administration and audit log pages. The list must include your current address. If you lock yourself out, restart the server with SENDORA_DISABLE_ADMIN_IP_ALLOWLIST=true.') }}</p>

    <h2 style="margin-top:20px">{{ t('Sessions') }}</h2>
    <label for="provider-session-hours">{{ t('Sign in at the provider again after (hours, 1-720)') }}</label><input id="provider-session-hours" :disabled="m('provider_session_max_hours')" v-model="s.provider_session_max_hours" type="number" min="1" max="720" />
    <p class="muted">{{ t('Sessions started through a sign-in provider (Entra, OpenID Connect, Google, GitHub), and all sessions of accounts without a local password, end after this many hours. The user then signs in at the provider again, so an account disabled or removed there loses access here too.') }}</p>

    <h2 style="margin-top:20px">{{ t('Logging') }}</h2>
    <label for="audit-retention">{{ t('Audit log retention (days, 90-365)') }}</label><input id="audit-retention" :disabled="m('audit_retention_days')" v-model="s.audit_retention_days" type="number" min="90" max="365" />
    <label class="check"><input :disabled="m('audit_log_ip')" type="checkbox" :checked="s.audit_log_ip === 'true'" @change="s.audit_log_ip = String($event.target.checked)" /> {{ t('Store the IP address of each audit log entry') }}</label>
    <p class="muted">{{ t('The audit log is always on and tamper-evident; it cannot be switched off or edited. Entries older than the retention period are deleted automatically. Every change to these settings is itself recorded.') }}</p>
    <h3 style="margin-top:12px">{{ t('Forward the audit log to another system') }}</h3>
    <label class="check"><input :disabled="m('audit_forward_stdout')" type="checkbox" :checked="s.audit_forward_stdout === 'true'" @change="s.audit_forward_stdout = String($event.target.checked)" /> {{ t('Write each audit log entry to standard output as one JSON line') }}</label>
    <label for="audit-syslog">{{ t('Syslog server (host:port, empty = off)') }}</label><input id="audit-syslog" :disabled="m('audit_forward_syslog')" v-model="s.audit_forward_syslog" placeholder="logs.example.com:6514" />
    <label class="check"><input :disabled="m('audit_forward_syslog_tls')" type="checkbox" :checked="s.audit_forward_syslog_tls !== 'false'" @change="s.audit_forward_syslog_tls = String($event.target.checked)" /> {{ t('Use TLS for syslog (certificate is verified)') }}</label>
    <label for="audit-webhook">{{ t('Webhook URL (https, empty = off)') }}</label><input id="audit-webhook" :disabled="m('audit_forward_webhook_url')" v-model="s.audit_forward_webhook_url" placeholder="https://collector.example.com/sendora" />
    <p class="muted">{{ t('Each entry is sent with its sequence number and hashes, so the receiving system can check that nothing was removed or changed; every five minutes the latest position of the log is sent as well. Do not put credentials in the webhook URL: the bearer token is read from the file named by SENDORA_AUDIT_FORWARD_WEBHOOK_TOKEN_FILE. Delivery problems never block Sendora; they are counted in the audit log status.') }}</p>

    <p v-if="msg" class="ok" role="status">{{ msg }}</p><p v-if="err" class="err" role="alert">{{ err }}</p>
    <div class="actions"><button :disabled="busy">{{ t('Save') }}</button></div>
  </form>
</template>
