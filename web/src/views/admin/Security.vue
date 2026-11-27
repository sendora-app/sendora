<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, onMounted } from 'vue'
import { api, fmtDate } from '../../api'
import { t } from '../../i18n'
import SecuritySettings from './SecuritySettings.vue'
const info = ref(null), enabled = ref(true), allowlist = ref(''), err = ref(''), msg = ref(''), busy = ref(false)
async function load() {
  err.value = ''
  try {
    info.value = await api('/ip-bans')
    const s = await api('/settings')
    enabled.value = s.ip_ban_enabled !== 'false'
    allowlist.value = s.ip_ban_allowlist || ''
  } catch (e) { err.value = e.message }
}
async function save() {
  err.value = msg.value = ''; busy.value = true
  try {
    await api('/settings', { method: 'PUT', body: { ip_ban_enabled: enabled.value ? 'true' : 'false', ip_ban_allowlist: allowlist.value } })
    msg.value = t('Settings saved.')
    await load()
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
async function unblock(ip) {
  err.value = msg.value = ''
  try { await api('/ip-bans?ip=' + encodeURIComponent(ip), { method: 'DELETE' }); await load() } catch (e) { err.value = e.message }
}
onMounted(load)
</script>
<template>
  <SecuritySettings />
  <div class="card">
    <div class="actions" style="margin:0 0 12px"><h1 style="margin:0">{{ t('Blocked addresses') }}</h1>
      <button class="small secondary" @click="load">{{ t('Refresh') }}</button></div>
    <p v-if="info" class="muted">{{ t('After {n} failed sign-in attempts within {w} minutes an address is blocked for {b} minutes (doubling for repeat offenders, at most {h} hours). Public downloads and existing sessions are not affected.', { n: info.threshold, w: info.window_minutes, b: info.ban_minutes, h: info.max_hours }) }}</p>
    <p v-if="info && info.env_disabled" class="err">{{ t('Blocking is switched off by the SENDORA_DISABLE_IP_BANS environment variable.') }}</p>
    <p class="err" v-if="err">{{ err }}</p>
    <p v-if="msg" class="ok">{{ msg }}</p>
    <form @submit.prevent="save">
      <label class="check"><input type="checkbox" v-model="enabled" /> {{ t('Block addresses after repeated failed sign-ins') }}</label>
      <label>{{ t('Never block these addresses') }}</label>
      <textarea v-model="allowlist" rows="4" spellcheck="false" placeholder="192.0.2.10&#10;10.0.0.0/8"></textarea>
      <p class="muted">{{ t('One address or range (for example 192.0.2.10 or 10.0.0.0/8) per line.') }}<span v-if="info">&nbsp;{{ t('Your current address is {ip}.', { ip: info.your_ip }) }}</span></p>
      <p class="muted">{{ t('Behind a reverse proxy, set SENDORA_TRUSTED_PROXIES; otherwise all visitors share one address.') }}</p>
      <div class="actions"><button :disabled="busy">{{ t('Save') }}</button></div>
    </form>
    <h2 style="margin-top:24px">{{ t('Currently blocked') }}</h2>
    <p v-if="info && !info.bans.length" class="muted">{{ t('No addresses are blocked.') }}</p>
    <div v-if="info && info.bans.length" class="table-wrap"><table>
      <tr><th>{{ t('Address') }}</th><th>{{ t('Blocked until') }}</th><th>{{ t('Times blocked') }}</th><th></th></tr>
      <tr v-for="b in info.bans" :key="b.ip"><td>{{ b.ip }}</td><td>{{ fmtDate(b.until) }}</td><td>{{ b.strikes }}</td>
        <td><button class="small secondary" @click="unblock(b.ip)">{{ t('Unblock') }}</button></td></tr>
    </table></div>
  </div>
</template>
