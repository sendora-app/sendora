<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, computed, onMounted } from 'vue'
import { api, fmtDate, downloadBlob } from '../api'
import { t } from '../i18n'
import {
  AUDIT_PAGE_SIZE as limit, AUDIT_CATEGORIES as categories, AUDIT_OUTCOMES as outcomes, blankAuditFilters, hasAuditFilters,
  auditParams, pagerInfo, lastPageOffset, needsClamp, actionSuggestions, labelFor, categoryLabels, outcomeLabels, roleLabels, chainReasonLabels,
} from '../audit-view.mjs'
const data = ref(null), status = ref(null), err = ref(''), offset = ref(0), busy = ref(false), exporting = ref(false)
// f is what is typed; applied is the last submitted search. Paging, Refresh and the
// downloads only ever use applied, so half-typed filters never leak into them.
const f = ref(blankAuditFilters()), applied = ref(blankAuditFilters())
const label = (map, code) => t(labelFor(map, code))
const actions = computed(() => actionSuggestions(data.value?.records || []))
const showIP = computed(() => !!status.value?.ip_logging || !!data.value?.records?.some(r => r.ip))
const pager = computed(() => data.value && pagerInfo(offset.value, data.value.records.length, data.value.total, data.value.total_capped === true))
const filtered = computed(() => hasAuditFilters(applied.value))

// Only the newest request may update the page: an older, slower response is dropped.
let seq = 0
async function load(o = offset.value, clamped = false) {
  const mine = ++seq
  busy.value = true; err.value = ''
  try {
    const result = await api('/audit?' + auditParams(applied.value, { limit, offset: o }))
    if (mine !== seq) return
    if (!clamped && needsClamp(o, result.records.length, result.total)) {
      // The page we were on no longer exists (records purged or the filter matches fewer): go to the last one.
      busy.value = false
      return load(lastPageOffset(result.total, limit), true)
    }
    data.value = result
    offset.value = o
  } catch (e) { if (mine === seq) err.value = e.message } finally { if (mine === seq) busy.value = false }
}
let statusSeq = 0
async function loadStatus() {
  const mine = ++statusSeq
  try { const s = await api('/audit/status'); if (mine === statusSeq) status.value = s } catch (e) { if (mine === statusSeq) { status.value = null; err.value = e.message } }
}
function search() { applied.value = { ...f.value }; load(0) }
function clearFilters() { f.value = blankAuditFilters(); search() }
function refresh() { load(); loadStatus() }
async function download(format) {
  if (exporting.value) return
  exporting.value = true; err.value = ''
  try { await downloadBlob('/audit/export?' + auditParams(applied.value, { format }), 'sendora-audit.' + format) }
  catch (e) { err.value = e.message || t('Download failed') } finally { exporting.value = false }
}
onMounted(() => { load(0); loadStatus() })
</script>
<template>
  <div class="card">
    <div class="actions" style="margin:0 0 12px"><h1 style="margin:0">{{ t('Audit log') }}</h1>
      <button class="small secondary" :disabled="busy" @click="refresh">{{ t('Refresh') }}</button>
      <button class="small secondary" :disabled="!data || busy || exporting" @click="download('csv')">{{ t('Download CSV') }}</button>
      <button class="small secondary" :disabled="!data || busy || exporting" @click="download('jsonl')">{{ t('Download JSONL') }}</button></div>
    <div v-if="status" :class="status.verified ? 'ok' : 'err'" :role="status.verified ? 'status' : 'alert'">
      <strong v-if="status.verified">{{ t('Chain verified: no record has been changed, removed or added.') }}</strong>
      <strong v-else>{{ t('Chain BROKEN at record {n}: {reason}', { n: status.first_broken_seq, reason: label(chainReasonLabels, status.reason) }) }}</strong>
      <div class="muted">{{ t('Records: {n}', { n: status.count }) }} · {{ t('Oldest: {d}', { d: fmtDate(status.oldest_ts) }) }} · {{ t('Retention: {n} day(s)', { n: status.retention_days }) }} · {{ t('Checkpoint: {n}', { n: status.checkpoint.seq }) }} · {{ t('Write failures: {n}', { n: status.write_failures }) }}</div>
    </div>
    <form class="audit-filters" @submit.prevent="search">
      <input v-model="f.q" :placeholder="t('Filter (action, user, target)')" :aria-label="t('Filter (action, user, target)')" />
      <select v-model="f.category" :aria-label="t('Category')"><option value="">{{ t('All categories') }}</option><option v-for="c in categories" :key="c" :value="c">{{ label(categoryLabels, c) }}</option></select>
      <input v-model="f.action" list="audit-actions" autocomplete="off" spellcheck="false" :placeholder="t('Action')" :aria-label="t('Action (exact name)')" />
      <datalist id="audit-actions"><option v-for="a in actions" :key="a" :value="a" /></datalist>
      <input v-model="f.actor" :placeholder="t('User')" :aria-label="t('User')" />
      <select v-model="f.outcome" :aria-label="t('Outcome')"><option value="">{{ t('All outcomes') }}</option><option v-for="o in outcomes" :key="o" :value="o">{{ label(outcomeLabels, o) }}</option></select>
      <input v-model="f.from" type="date" :aria-label="t('From')" :title="t('From')" /><input v-model="f.to" type="date" :aria-label="t('To')" :title="t('To')" />
      <button class="small secondary" :disabled="busy">{{ t('Search') }}</button></form>
    <p v-if="err" class="err" role="alert">{{ err }}</p>
    <div v-if="data && !data.records.length" class="actions">
      <span class="muted">{{ filtered ? t('No records match these filters') : t('No records') }}</span>
      <button v-if="filtered" type="button" class="small secondary" :disabled="busy" @click="clearFilters">{{ t('Clear filters') }}</button>
    </div>
    <div v-if="data && data.records.length" class="table-wrap"><table>
      <thead><tr><th scope="col">#</th><th scope="col">{{ t('Time') }}</th><th scope="col">{{ t('Category') }}</th><th scope="col">{{ t('User') }}</th><th scope="col">{{ t('Action') }}</th><th scope="col">{{ t('Target') }}</th><th scope="col">{{ t('Outcome') }}</th><th scope="col">{{ t('Details') }}</th><th v-if="showIP" scope="col">IP</th></tr></thead>
      <tbody><tr v-for="l in data.records" :key="l.seq"><td>{{ l.seq }}</td><td>{{ fmtDate(l.ts) }}</td><td :title="l.category">{{ label(categoryLabels, l.category) }}</td><td>{{ l.actor }} <span class="muted" :title="l.actor_role">({{ label(roleLabels, l.actor_role) }})</span></td><td>{{ l.action }}</td><td>{{ l.target }}</td><td :title="l.outcome">{{ label(outcomeLabels, l.outcome) }}</td><td>{{ l.detail }}</td><td v-if="showIP">{{ l.ip }}</td></tr></tbody>
    </table></div>
    <div v-if="data && data.records.length" class="actions"><span>{{ pager.capped ? t('{from}-{to} of {total}+', pager) : t('{from}-{to} of {total}', pager) }}</span>
      <button class="small secondary" :disabled="busy || offset === 0" @click="load(Math.max(0, offset - limit))">{{ t('Previous') }}</button>
      <button class="small secondary" :disabled="busy || (offset + limit >= data.total && !pager.capped)" @click="load(offset + limit)">{{ t('Next') }}</button></div>
  </div>
</template>
<style scoped>
.audit-filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:12px 0;align-items:center}
.audit-filters button{justify-self:start}
</style>
