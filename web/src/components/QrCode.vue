<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { computed } from 'vue'
import { t } from '../i18n'
import { qrSvg } from '../qr.mjs'

const props = defineProps({ value: { type: String, default: '' }, label: { type: String, default: '' }, filename: { type: String, default: 'qr-code.svg' } })
const result = computed(() => {
  try { return { svg: qrSvg(props.value, { scale: 4, margin: 4 }) } } catch (e) { return { error: e.message } }
})
const label = computed(() => props.label || t('QR code for this link'))
function download() {
  const blob = new Blob([qrSvg(props.value, { scale: 8, margin: 4 })], { type: 'image/svg+xml' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = props.filename
  document.body.appendChild(a); a.click(); a.remove()
  setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}
</script>
<template>
  <div v-if="result.svg" class="qr">
    <div class="qr-img" role="img" :aria-label="label" :title="label" v-html="result.svg"></div>
    <div class="actions"><button type="button" class="small secondary" @click="download">{{ t('Download QR code') }}</button></div>
  </div>
</template>
<style scoped>
.qr-img { display: inline-block; line-height: 0; border: 1px solid var(--border, #ccc); border-radius: 6px; overflow: hidden; }
.qr-img :deep(svg) { width: 176px; height: 176px; }
</style>
