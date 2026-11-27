<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../../api'
import { app, loadBoot } from '../../state'
import { t } from '../../i18n'
import { bundledBackgrounds } from '../../backgrounds'
const err = ref(''), v = ref(Date.now()), bgs = ref([])
const loadBgs = async () => (bgs.value = await api('/backgrounds'))
onMounted(loadBgs)
async function up(path, e) {
  err.value = ''
  const fd = new FormData(); fd.append('file', e.target.files[0])
  try { await api(path, { method: 'POST', body: fd }); await loadBoot(); await loadBgs(); v.value = Date.now() } catch (x) { err.value = x.message }
  e.target.value = ''
}
async function del(path) {
  err.value = ''
  if (!confirm(t('Delete this image?'))) return
  try { await api(path, { method: 'DELETE' }); await loadBoot(); await loadBgs(); v.value = Date.now() } catch (x) { err.value = x.message }
}
const current = computed(() => bundledBackgrounds.find(b => b.id === app.boot?.background))
async function setBackground(id) {
  err.value = ''
  try { await api('/settings', { method: 'PUT', body: { ui_builtin_background: id } }); await loadBoot() } catch (x) { err.value = x.message }
}
</script>
<template>
  <div>
    <p v-if="err" class="err">{{ err }}</p>
    <div class="card"><h2>{{ t('Logo') }}</h2>
      <img v-if="app.boot?.has_logo" :src="'/api/branding/logo?v=' + v" style="max-height:60px;display:block;margin-bottom:8px" />
      <input type="file" accept="image/*" @change="up('/settings/branding/logo', $event)" />
      <div class="actions"><button v-if="app.boot?.has_logo" class="small danger" @click="del('/settings/branding/logo')">{{ t('Delete') }}</button></div></div>
    <div class="card"><h2>{{ t('Favicon') }}</h2>
      <img v-if="app.boot?.has_favicon" :src="'/api/branding/favicon?v=' + v" style="height:32px;display:block;margin-bottom:8px" />
      <input type="file" accept="image/*" @change="up('/settings/branding/favicon', $event)" />
      <div class="actions"><button v-if="app.boot?.has_favicon" class="small danger" @click="del('/settings/branding/favicon')">{{ t('Delete') }}</button></div></div>
    <div class="card"><h2>{{ t('Background images') }}</h2>
      <p class="muted">{{ t('Choose a built-in background or none (plain theme colour). Images you upload below always replace the built-in one on all pages; delete them to return to the built-in choice.') }}</p>
      <div class="row" role="radiogroup" :aria-label="t('Built-in background')">
        <button v-for="b in bundledBackgrounds" :key="b.id" type="button" class="bgchoice" :class="{ on: app.boot?.background === b.id }" role="radio" :aria-checked="app.boot?.background === b.id" @click="setBackground(b.id)">
          <img :src="b.url" :alt="t(b.name)" loading="lazy" /><span>{{ t(b.name) }}</span></button>
        <button type="button" class="bgchoice none" :class="{ on: app.boot?.background === 'none' }" role="radio" :aria-checked="app.boot?.background === 'none'" @click="setBackground('none')"><span class="nonebox">{{ t('None') }}</span></button>
      </div>
      <p v-if="current" class="muted">{{ t('Photo credit') }}: {{ current.credit }}</p>
      <h3 style="margin-top:20px">{{ t('Your own images') }}</h3>
      <div class="row"><div v-for="b in bgs" :key="b" style="max-width:180px">
        <img :src="'/api/backgrounds/' + b" style="width:100%;height:100px;object-fit:cover;border-radius:8px" />
        <button class="small danger" @click="del('/backgrounds/' + b)">{{ t('Delete') }}</button></div></div>
      <p v-if="!bgs.length" class="muted">{{ t('No uploaded images.') }}</p>
      <input type="file" accept="image/png,image/jpeg,image/webp" @change="up('/backgrounds', $event)" style="margin-top:12px" /></div>
  </div>
</template>
<style scoped>
.bgchoice { display: flex; flex-direction: column; gap: 4px; flex: 0 0 150px; width: 150px; min-width: 0; padding: 6px; background: var(--surface); color: var(--text); border: 2px solid var(--border); border-radius: 10px; cursor: pointer; font-size: 13px }
.bgchoice img { width: 100%; height: 84px; object-fit: cover; border-radius: 6px; display: block }
.bgchoice.on { border-color: var(--primary) }
.bgchoice .nonebox { width: 100%; box-sizing: border-box; display: flex; align-items: center; justify-content: center; height: 84px; border-radius: 6px; background: var(--bg); color: var(--muted) }
</style>
