<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import LegalLinks from '../components/LegalLinks.vue'
import { ref, onMounted, onBeforeUnmount, computed, watch, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { api, fmtBytes, fmtDate } from '../api'
import { t, tr } from '../i18n'
import { app, pageTitle } from '../state'
import QrCode from '../components/QrCode.vue'
import FileTree from '../components/FileTree.vue'
import { buildTree } from '../folder-tree.mjs'
import { verifiedDownload, nativeDownload, canStreamToDisk, BLOB_LIMIT } from '../download'

const route = useRoute()
const id = route.params.id
const share = ref(null), state = ref('loading'), pw = ref(''), err = ref(''), token = ref('')
const hdr = () => (token.value ? { 'X-Share-Token': token.value } : {})
const tree = computed(() => [...(share.value?.files || [])])
const folderTree = computed(() => buildTree(tree.value.map(f => ({ path: f.full_path || f.name, size: f.size, file: f }))))

async function load() {
  try {
    const d = await api('/shares/' + id, { headers: hdr(), noRetry: true })
    if (d.password_protected && !d.files) { share.value = d; state.value = 'locked' } else { share.value = d; state.value = 'ready' }
  } catch (e) { state.value = e.status === 410 ? 'expired' : 'missing' }
}
async function unlock() {
  err.value = ''
  try { token.value = (await api(`/shares/${id}/unlock`, { method: 'POST', body: { password: pw.value }, noRetry: true })).token; await load() }
  catch (e) { err.value = e.message }
}
const q = () => (token.value ? '?token=' + encodeURIComponent(token.value) : '')
const downloading = ref(false), progress = ref(0), notice = ref(''), fallback = ref(null)
let downloadController
async function go(url, name, size) {
  err.value = ''; notice.value = ''; fallback.value = null
  if (!canStreamToDisk() && size > BLOB_LIMIT) { fallback.value = { url, size }; return }
  downloading.value = true; progress.value = 0; downloadController = new AbortController()
  try {
    await verifiedDownload(url, { name, headers: hdr(), signal: downloadController.signal, onProgress: (n, total) => (progress.value = total ? Math.round(n / total * 100) : 100) })
    notice.value = tr('Download checksum verified')
  } catch (e) { err.value = e.name === 'AbortError' ? t('Cancelled') : t(e.message) }
  finally { downloading.value = false; await load() }
}
const all = () => go(`/api/shares/${id}/download`, share.value.files.length === 1 ? share.value.files[0].name : (share.value.name || 'share') + '.zip', share.value.size + (share.value.files.length > 1 ? share.value.files.reduce((n, f) => n + new TextEncoder().encode(f.full_path).length * 2 + 1024, 1024) : 0))
const one = f => go(`/api/shares/${id}/download/` + f.full_path.split('/').map(encodeURIComponent).join('/'), f.name, f.size)
function unverified() { nativeDownload(fallback.value.url + q(), fallback.value.size); fallback.value = null; notice.value = tr('Native download started; browser checksum not verified'); setTimeout(load, 1500) }
const PREVIEW = { png: 'image', jpg: 'image', jpeg: 'image', webp: 'image', gif: 'image', mp4: 'video', webm: 'video', mp3: 'audio', ogg: 'audio', wav: 'audio' }
const kind = f => PREVIEW[(f.name.split('.').pop() || '').toLowerCase()]
const canPreview = f => app.boot?.allow_preview !== false && app.boot?.allow_preview !== 'false' && !share.value?.download_limit && !!kind(f)
const preview = ref(null), showQr = ref(false), closeBtn = ref(null)
const previewable = computed(() => tree.value.filter(canPreview))
const previewIndex = computed(() => Math.max(0, previewable.value.findIndex(f => f.id === preview.value?.id)))
function step(delta) {
  const list = previewable.value
  if (list.length < 2) return
  preview.value = list[(previewIndex.value + delta + list.length) % list.length]
}
function onKey(e) {
  if (!preview.value) return
  if (e.key === 'Escape') preview.value = null
  else if (e.key === 'ArrowLeft') step(-1)
  else if (e.key === 'ArrowRight') step(1)
}
watch(preview, async value => {
  document.body.style.overflow = value ? 'hidden' : ''
  if (value) { await nextTick(); closeBtn.value?.focus() }
})
let savedView = 'list'
try { savedView = localStorage.getItem('shareView') === 'grid' ? 'grid' : 'list' } catch {}
const view = ref(savedView)
function setView(v) { view.value = v; try { localStorage.setItem('shareView', v) } catch {} }
const icon = f => ({ image: '🖼️', video: '🎬', audio: '🎵' }[kind(f)] || '📄')
const shareUrl = () => location.origin + '/share/' + encodeURIComponent(id)
const previewSrc = f => `/api/shares/${id}/preview/` + f.full_path.split('/').map(encodeURIComponent).join('/') + q()
onMounted(() => { load(); window.addEventListener('keydown', onKey) })
watch(() => [state.value, share.value?.name], () => { pageTitle.value = share.value?.name && (state.value === 'ready' || state.value === 'locked') ? share.value.name : '' })
onBeforeUnmount(() => { pageTitle.value = ''; document.body.style.overflow = ''; window.removeEventListener('keydown', onKey) })
</script>

<template>
  <div class="card narrow wide">
    <p v-if="state === 'loading'" class="muted">…</p>
    <template v-else-if="state === 'missing'"><h1>{{ t('Share not found') }}</h1></template>
    <template v-else-if="state === 'expired'"><h1>{{ t('This share has expired') }}</h1><p v-if="notice" class="ok">{{ t(notice) }}</p><p v-if="err" class="err">{{ err }}</p></template>
    <form v-else-if="state === 'locked'" @submit.prevent="unlock">
      <h1>{{ t('Password protected share') }}</h1><p class="muted">{{ t('Enter the password you received to open this share.') }}</p>
      <label>{{ t('Password') }}</label><input v-model="pw" type="password" autofocus required />
      <p v-if="err" class="err">{{ err }}</p>
      <div class="actions"><button>{{ t('Unlock') }}</button></div>
    </form>
    <template v-else>
      <h1>{{ share.name }}</h1>
      <p v-if="share.description">{{ share.description }}</p>
      <p class="muted">{{ share.owner }} · {{ fmtBytes(share.size) }} · {{ t('Expires') }}: {{ fmtDate(share.expires_at) }}
        <span v-if="share.download_limit"> · {{ share.download_count }}/{{ share.download_limit }}</span></p>
      <div class="actions"><button class="small" :class="{ secondary: view !== 'list' }" @click="setView('list')">{{ t('List') }}</button><button class="small" :class="{ secondary: view !== 'grid' }" @click="setView('grid')">{{ t('Grid') }}</button></div>
      <div v-if="view === 'grid'" class="gallery">
        <figure v-for="f in tree" :key="f.id" class="tile">
          <div class="thumb" :title="f.full_path">
            <img v-if="canPreview(f) && kind(f) === 'image'" :src="previewSrc(f)" :alt="f.name" loading="lazy" decoding="async" @click="preview = f" />
            <span v-else class="ico" aria-hidden="true">{{ icon(f) }}</span>
          </div>
          <figcaption><b class="name">{{ f.name }}</b><span class="muted">{{ fmtBytes(f.size) }}</span></figcaption>
          <div class="actions tile-actions"><button v-if="canPreview(f)" class="small secondary" @click="preview = f">{{ t('Preview') }}</button>
            <button class="small secondary" :disabled="downloading" @click="one(f)">{{ t('Download') }}</button></div>
        </figure>
      </div>
      <FileTree v-else :root="folderTree">
        <template #file-actions="{ file: item }">
          <button v-if="canPreview(item.file)" class="small secondary" @click="preview = item.file">{{ t('Preview') }}</button>
          <button class="small secondary" :disabled="downloading" @click="one(item.file)">{{ t('Download') }}</button>
        </template>
      </FileTree>
      <Teleport to="body"><div v-if="preview" class="lightbox" role="dialog" aria-modal="true" :aria-label="preview.name" @click.self="preview = null">
        <div class="lb-bar">
          <span class="lb-title">{{ preview.name }} <span class="muted">({{ previewIndex + 1 }}/{{ previewable.length }})</span></span>
          <span class="lb-actions">
            <button type="button" class="small secondary" :disabled="previewable.length < 2" :title="t('Previous')" @click="step(-1)">‹</button>
            <button type="button" class="small secondary" :disabled="previewable.length < 2" :title="t('Next')" @click="step(1)">›</button>
            <button type="button" class="small secondary" :disabled="downloading" @click="one(preview)">{{ t('Download') }}</button>
            <button ref="closeBtn" type="button" class="small" @click="preview = null">{{ t('Close') }}</button>
          </span>
        </div>
        <div class="lb-stage" @click.self="preview = null">
          <img v-if="kind(preview) === 'image'" :key="preview.id" :src="previewSrc(preview)" :alt="preview.name" class="lb-media" />
          <video v-else-if="kind(preview) === 'video'" :key="preview.id" :src="previewSrc(preview)" controls autoplay preload="metadata" class="lb-media" />
          <audio v-else :key="preview.id" :src="previewSrc(preview)" controls autoplay preload="metadata" class="lb-audio" />
        </div>
        <p class="lb-note muted">{{ t('Preview is not checksum-verified. Use Download for a verified copy.') }}</p>
      </div></Teleport>
      <p v-if="err" class="err">{{ err }}</p>
      <p v-if="notice" class="ok">{{ t(notice) }}</p>
      <p v-if="!canStreamToDisk()" class="muted">{{ t('Automatic verification in this browser is limited to 128 MiB. Larger downloads require a supported browser.') }}</p>
      <div v-if="fallback"><p class="err">{{ t('This browser cannot verify downloads larger than 128 MiB. Use a supported browser or choose an unverified download.') }}</p><button class="secondary" @click="unverified">{{ t('Download without browser verification') }}</button></div>
      <p v-if="downloading" class="muted">{{ t('Downloading and verifying…') }} {{ progress }}% <button class="link" @click="downloadController.abort()">{{ t('Cancel') }}</button></p>
      <section v-if="showQr" class="card"><QrCode :value="shareUrl()" /></section>
      <div class="actions"><button class="secondary" @click="showQr = !showQr">{{ t('QR code') }}</button><button :disabled="downloading" @click="all">{{ share.files.length > 1 ? t('Download all') : t('Download') }}</button></div>
    </template>
    <LegalLinks />
  </div>
</template>
<style scoped>
.wide { max-width: 760px }
.gallery { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 14px; margin: 16px 0 }
.tile { margin: 0; display: flex; flex-direction: column; gap: 8px; min-width: 0; padding: 10px; border-radius: 18px; background: var(--glass-soft); border: 1px solid var(--glass-border) }
.tile-actions { margin: 0; gap: 6px }
.thumb { aspect-ratio: 1 / 1; border-radius: 12px; overflow: hidden; display: flex; align-items: center; justify-content: center; background: color-mix(in srgb, var(--text) 6%, var(--surface)) }
.thumb img { width: 100%; height: 100%; object-fit: contain; cursor: zoom-in }
.ico { font-size: 40px }
figcaption { display: flex; flex-direction: column; min-width: 0 }
.name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px }
.lightbox { position: fixed; inset: 0; z-index: 100; display: flex; flex-direction: column; background: rgba(0, 0, 0, .88); color: #fff }
@supports (backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px)) { .lightbox { background: rgba(8, 10, 16, .72); -webkit-backdrop-filter: blur(18px); backdrop-filter: blur(18px) } }
.lb-bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 20px; flex-wrap: wrap }
.lb-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 60vw; font-weight: 600 }
.lb-title .muted { color: #cbd5e1 }
.lb-actions { display: flex; gap: 8px }
.lb-stage { flex: 1; min-height: 0; display: flex; align-items: center; justify-content: center; padding: 0 16px }
.lb-media { max-width: 96vw; max-height: calc(100vh - 130px); object-fit: contain; border-radius: 16px; background: #000; box-shadow: 0 20px 60px rgba(0, 0, 0, .5) }
.lb-audio { width: min(640px, 92vw) }
.lb-note { margin: 0; padding: 8px 16px 12px; text-align: center; color: #cbd5e1; font-size: 12px }
</style>
