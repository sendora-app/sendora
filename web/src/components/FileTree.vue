<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { computed, ref } from 'vue'
import { fmtBytes } from '../api'
import { t } from '../i18n'
import { visibleRows, folderPaths, folderDone, extensionOf, fileKind, defaultOpen } from '../folder-tree.mjs'

const props = defineProps({
  root: { type: Object, required: true },
  // (item) => bytes already transferred; omit to hide progress bars.
  doneOf: { type: Function, default: null },
  removable: { type: Boolean, default: false },
  locked: { type: Boolean, default: false },
})
const emit = defineEmits(['remove-file', 'remove-folder'])

const open = ref({})
const rows = computed(() => visibleRows(props.root, open.value))
const hasFolders = computed(() => props.root.folders > 0)
const isOpen = node => (node.path in open.value ? open.value[node.path] : defaultOpen(node, props.root.files))
const toggle = node => { open.value = { ...open.value, [node.path]: !isOpen(node) } }
function setAll(value) { open.value = Object.fromEntries(folderPaths(props.root).map(p => [p, value])) }
const pct = (done, size) => (size > 0 ? Math.min(100, Math.round(done / size * 100)) : 0)
const folderPct = node => pct(folderDone(node, props.doneOf), node.bytes)
const filePct = node => pct(props.doneOf(node.item) || 0, node.size)
const count = n => (n === 1 ? t('1 file') : t('{n} files', { n }))
const subfolders = n => (n === 1 ? t('1 folder') : t('{n} folders', { n }))
const pad = node => ({ '--depth': node.depth })
</script>

<template>
  <div class="tree">
    <div v-if="hasFolders" class="tree-tools">
      <button type="button" class="link" @click="setAll(true)">{{ t('Expand all') }}</button>
      <button type="button" class="link" @click="setAll(false)">{{ t('Collapse all') }}</button>
    </div>
    <ul class="tree-list">
      <li v-for="node in rows" :key="node.type + ':' + node.path" class="trow" :class="node.type" :style="pad(node)">
        <template v-if="node.type === 'folder'">
          <button type="button" class="tmain" :aria-expanded="isOpen(node)" @click="toggle(node)">
            <svg class="chev" :class="{ on: isOpen(node) }" viewBox="0 0 20 20" aria-hidden="true"><path d="M7 4l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" /></svg>
            <svg class="ico folder" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" fill="currentColor" /></svg>
            <span class="tname" :title="node.path">{{ node.name }}</span>
            <span class="tmeta">{{ count(node.files) }}<template v-if="node.folders"> · {{ subfolders(node.folders) }}</template> · {{ fmtBytes(node.bytes) }}</span>
          </button>
          <button v-if="removable" type="button" class="tremove" :disabled="locked" :title="t('Remove folder')" :aria-label="t('Remove folder') + ': ' + node.name" @click="emit('remove-folder', node)">✕</button>
          <div v-if="doneOf" class="bar tbar" role="progressbar" :aria-valuenow="folderPct(node)" aria-valuemin="0" aria-valuemax="100" :aria-label="node.name"><i :style="{ width: folderPct(node) + '%' }" /></div>
        </template>
        <template v-else>
          <div class="tmain static">
            <svg class="ico" :class="fileKind(node.name)" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h8l5 5v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5a2 2 0 012-2z" fill="currentColor" opacity=".9" /><path d="M14 3v5h5" fill="none" stroke="var(--surface)" stroke-width="1.5" opacity=".7" /></svg>
            <span class="tname wrap" :title="node.path">{{ node.name }}</span>
            <span v-if="extensionOf(node.name)" class="badge ext">{{ extensionOf(node.name) }}</span>
            <span class="tmeta size">{{ fmtBytes(node.size) }}</span>
          </div>
          <div class="tacts"><slot name="file-actions" :file="node.item" :node="node" />
            <button v-if="removable" type="button" class="tremove" :disabled="locked" :title="t('Remove file')" :aria-label="t('Remove file') + ': ' + node.name" @click="emit('remove-file', node)">✕</button></div>
          <div v-if="doneOf && node.size > 0" class="bar tbar thin" role="progressbar" :aria-valuenow="filePct(node)" aria-valuemin="0" aria-valuemax="100" :aria-label="node.name"><i :style="{ width: filePct(node) + '%' }" /></div>
        </template>
      </li>
    </ul>
  </div>
</template>

<style scoped>
.tree-tools { display: flex; gap: 16px; justify-content: flex-end; margin: 0 4px 6px; font-size: 13px }
.tree-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px }
.trow { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; column-gap: 6px; row-gap: 0;
  margin-left: calc(var(--depth, 0) * 18px); padding: 6px 8px; border-radius: 14px; background: var(--glass-soft); border: 1px solid var(--glass-border) }
.trow.folder { background: var(--glass-strong) }
.tmain { display: flex; align-items: center; gap: 10px; min-width: 0; padding: 4px 4px; border: 0; background: none; color: var(--text); font: inherit; font-weight: 500; text-align: left; border-radius: 10px; cursor: pointer; box-shadow: none }
.tmain.static { cursor: default }
button.tmain:hover { background: color-mix(in srgb, var(--primary) 8%, transparent) }
.chev { width: 16px; height: 16px; flex: none; color: var(--muted); transition: transform .15s }
.chev.on { transform: rotate(90deg) }
.ico { width: 22px; height: 22px; flex: none; color: var(--muted) }
.ico.folder { color: var(--primary) }
.ico.image { color: #0d9488 } .ico.video { color: #7c3aed } .ico.audio { color: #db2777 } .ico.archive { color: #b45309 } .ico.doc { color: #2563eb } .ico.code { color: #475569 }
.tname { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
.tname.wrap { white-space: normal; overflow-wrap: anywhere; text-overflow: clip; line-height: 1.3 }
.tmeta { flex: none; color: var(--muted); font-size: 13px; font-weight: 400; white-space: nowrap }
.badge.ext { flex: none; text-transform: uppercase; letter-spacing: .04em; font-size: 11px }
.tacts { display: flex; align-items: center; gap: 6px }
.tremove { width: 30px; height: 30px; padding: 0; border-radius: 99px; background: transparent; color: var(--muted); box-shadow: none; line-height: 1; flex: none }
.tremove:hover:not(:disabled) { background: color-mix(in srgb, var(--danger) 14%, transparent); color: var(--danger) }
.tbar { grid-column: 1 / -1; margin: 4px 4px 2px }
.tbar.thin { height: 5px }
@media (max-width: 600px) {
  .trow { margin-left: calc(var(--depth, 0) * 10px); padding: 6px }
  .tmain { flex-wrap: wrap; row-gap: 0 }
  .tmeta { font-size: 12px }
  .tmain .tname { flex-basis: calc(100% - 60px) }
  .trow.file { grid-template-columns: minmax(0, 1fr) auto }
}
</style>
