<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, onMounted, computed } from 'vue'
import { api, fmtBytes } from '../../api'
import { t } from '../../i18n'
const s = ref(null)
onMounted(async () => (s.value = await api('/stats')))
// Every one of the last 14 days, also those without downloads (the server lists only days that had some).
const days = computed(() => {
  const counts = Object.fromEntries((s.value?.downloads_per_day || []).map(d => [d.day, d.count]))
  const out = []
  for (let i = 13; i >= 0; i--) {
    const day = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10)
    out.push({ day, count: counts[day] || 0 })
  }
  return out
})
const max = computed(() => Math.max(1, ...days.value.map(d => d.count)))
const up = n => { const d = Math.floor(n / 86400), h = Math.floor(n % 86400 / 3600), m = Math.floor(n % 3600 / 60); return `${d}d ${h}h ${m}m` }
</script>
<template>
  <div v-if="s">
    <div class="stats">
      <div class="card stat"><b>{{ s.users }}</b>{{ t('Users') }}</div>
      <div class="card stat"><b>{{ s.active_shares }}/{{ s.shares }}</b>{{ t('Active') }} / {{ t('All shares') }}</div>
      <div class="card stat"><b>{{ s.files }}</b>{{ t('Files') }}</div>
      <div class="card stat"><b>{{ fmtBytes(s.storage_bytes) }}</b>{{ t('Storage') }}</div>
      <div class="card stat"><b>{{ s.downloads }}</b>{{ t('Downloads') }}</div>
    </div>
    <div class="card"><h2>{{ t('Downloads, last 14 days') }}</h2>
      <div class="chart"><i v-for="d in days" :key="d.day" :style="{ height: d.count / max * 100 + '%' }" :title="d.day + ': ' + d.count" /></div></div>
    <div class="card"><h2>{{ t('System') }}</h2>
      <p class="muted">v{{ s.system.version }} · {{ s.system.go }} · {{ s.system.os }} · {{ t('uptime') }} {{ up(s.system.uptime_seconds) }} · {{ fmtBytes(s.system.mem_bytes) }}</p></div>
  </div>
</template>
