<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Access-review report (administrators and auditors, read-only): who has which
// access, how they sign in, and the lifecycle of each account. Counts only: share
// names, links and contents are never part of it.
import { ref, computed, onMounted } from 'vue'
import { api, fmtDate, fmtBytes, downloadBlob } from '../../api'
import { t } from '../../i18n'
import { labelFor, roleLabels } from '../../audit-view.mjs'
import { filterReview, parseFactors, accountStatus } from '../../access-review.mjs'

const data = ref(null), err = ref(''), busy = ref(false), exporting = ref(false), q = ref('')
const rows = computed(() => filterReview(data.value?.users, q.value))
const role = r => t(labelFor(roleLabels, r))
const yes = v => (v ? t('Yes') : t('No'))
const unknown = v => (!v || v === 'unknown' ? t('unknown') : v)
const dateOr = (d, empty) => (d && d !== 'unknown' ? fmtDate(d) : empty)
function factors(u) {
  const f = parseFactors(u.mfa_factors), out = []
  if (f.totp) out.push(t('Authenticator app'))
  if (f.webauthn) out.push(t('Passkeys: {n}', { n: f.webauthn }))
  if (f.recovery) out.push(t('Recovery codes: {n}', { n: f.recovery }))
  return out.join(', ') || t('None')
}
async function load() {
  busy.value = true; err.value = ''
  try { data.value = await api('/access-review') } catch (e) { err.value = e.message } finally { busy.value = false }
}
async function download(format) {
  if (exporting.value) return
  exporting.value = true; err.value = ''
  try { await downloadBlob('/access-review/export?format=' + format, 'sendora-access-review.' + format) }
  catch (e) { err.value = e.message || t('Download failed') } finally { exporting.value = false }
}
onMounted(load)
</script>
<template>
  <div class="card">
    <div class="actions" style="margin:0 0 12px"><h1 style="margin:0">{{ t('Access review') }}</h1>
      <button class="small secondary" :disabled="busy" @click="load">{{ t('Refresh') }}</button>
      <button class="small secondary" :disabled="!data || busy || exporting" @click="download('csv')">{{ t('Download CSV') }}</button>
      <button class="small secondary" :disabled="!data || busy || exporting" @click="download('jsonl')">{{ t('Download JSONL') }}</button></div>
    <p class="muted">{{ t('Every account with its role, sign-in methods, two-step verification and history, for periodic access reviews. Guests of upload invitations are not accounts and are not listed. Shares are only counted; their names and contents are never shown. Downloads are recorded in the audit log.') }}</p>
    <p v-if="data" class="muted">{{ t('Generated: {d}', { d: fmtDate(data.generated_at) }) }} · {{ t('Accounts: {n}', { n: data.users.length }) }}</p>
    <input v-model="q" :placeholder="t('Filter (user, name, email, role, source)')" :aria-label="t('Filter (user, name, email, role, source)')" style="max-width:360px" />
    <p v-if="err" class="err" role="alert">{{ err }}</p>
    <p v-if="data && !rows.length" class="muted">{{ t('No accounts match this filter') }}</p>
    <div v-if="data && rows.length" class="table-wrap"><table>
      <thead><tr>
        <th scope="col">{{ t('Username') }}</th><th scope="col">{{ t('Role') }}</th><th scope="col">{{ t('Source') }}</th>
        <th scope="col">{{ t('Two-step verification') }}</th><th scope="col">{{ t('Email verified') }}</th><th scope="col">{{ t('Password') }}</th><th scope="col">{{ t('Created') }}</th>
        <th scope="col">{{ t('Last role change') }}</th><th scope="col">{{ t('Last email change') }}</th><th scope="col">{{ t('Last sign-in') }}</th>
        <th scope="col">{{ t('Status') }}</th><th scope="col">{{ t('Shares') }}</th><th scope="col">{{ t('Stored files') }}</th>
      </tr></thead>
      <tbody><tr v-for="u in rows" :key="u.id">
        <td><strong>{{ u.username }}</strong><br /><span class="muted">{{ u.name }}<br />{{ u.email }}</span></td>
        <td>{{ role(u.role) }}</td>
        <td>{{ u.source || '—' }}</td>
        <td>{{ u.mfa_enrolled ? t('On') : t('Off') }}<br /><span class="muted">{{ factors(u) }}<br />{{ t('Policy: {p}', { p: u.mfa_policy }) }}<template v-if="u.mfa_required"> · {{ t('required') }}</template></span></td>
        <td>{{ yes(u.email_verified) }}</td>
        <td><template v-if="u.password_age_days !== ''">{{ t('{n} days old', { n: u.password_age_days }) }}</template><template v-else>—</template>
          <span v-if="u.password_expires_at" class="muted"><br />{{ t('expires {date}', { date: dateOr(u.password_expires_at, '') }) }}</span>
          <span v-if="u.password_rotation_exempt" class="muted"><br />{{ t('Exempt from password rotation') }}</span></td>
        <td>{{ dateOr(u.created_at, t('unknown')) }}<br /><span class="muted">{{ t('by {who}', { who: unknown(u.created_by) }) }}</span></td>
        <td>{{ dateOr(u.role_changed_at, '—') }}<br v-if="u.role_changed_by" /><span v-if="u.role_changed_by" class="muted">{{ t('by {who}', { who: u.role_changed_by }) }}</span></td>
        <td>{{ dateOr(u.email_changed_at, '—') }}<br v-if="u.email_changed_by" /><span v-if="u.email_changed_by" class="muted">{{ t('by {who}', { who: u.email_changed_by }) }}</span></td>
        <td>{{ dateOr(u.last_login_at, t('Never')) }}</td>
        <td><span v-for="s in accountStatus(u)" :key="s" class="badge" :class="s === 'Active' ? 'on' : 'off'">{{ t(s) }}</span>
          <span v-if="u.disabled" class="muted"><br />{{ dateOr(u.disabled_at, '') }} {{ t('by {who}', { who: unknown(u.disabled_by) }) }}<template v-if="u.disabled_reason"><br />{{ u.disabled_reason }}</template></span></td>
        <td>{{ u.share_count }}</td>
        <td>{{ fmtBytes(u.storage_used_bytes) }}</td>
      </tr></tbody>
    </table></div>
  </div>
</template>
