<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Live feedback while choosing a password: a character counter and a
// checklist of the active policy (account policy from the boot data, or the
// platform rule passed as `policy`), plus confirmation feedback. The server
// stays authoritative and also screens common, personal and breached passwords.
import { computed } from 'vue'
import { t } from '../i18n'
import { accountPolicy } from '../sharepolicy.mjs'
import { passwordChecklist, confirmState } from '../password-check.mjs'
import { app } from '../state'

const props = defineProps({
  password: { type: String, default: '' },
  optional: { type: Boolean, default: false },
  policy: { type: Object, default: null },
  confirm: { type: String, default: null },
})
const active = computed(() => props.policy || accountPolicy(app.boot))
const check = computed(() => passwordChecklist(props.password, active.value))
const problems = computed(() => (props.optional && !props.password ? [] : check.value.items.filter(i => !i.ok)))
const confirmed = computed(() => (props.confirm == null ? '' : confirmState(props.password, props.confirm)))
defineExpose({ problems })
</script>
<template>
  <div v-if="password || !optional" class="pw-hints" aria-live="polite">
    <p class="pw-count" :class="{ ok: check.count >= check.min }">
      {{ t('{n} / {min} characters', { n: check.count, min: check.min }) }} <span aria-hidden="true">{{ check.count >= check.min ? '✓' : '' }}</span>
    </p>
    <ul class="pw-list">
      <li v-for="i in check.items" :key="i.key" :class="i.ok ? 'ok' : 'todo'">
        <span aria-hidden="true">{{ i.ok ? '✓' : '○' }}</span>
        {{ t(i.key, { n: i.n }) }}<span class="sr-only"> — {{ i.ok ? t('met') : t('not met yet') }}</span>
      </li>
    </ul>
    <p v-if="confirmed" :class="confirmed === 'match' ? 'ok' : 'err'">{{ confirmed === 'match' ? '✓ ' + t('The passwords match') : '✗ ' + t('The passwords do not match') }}</p>
    <p class="muted">{{ t('The server also refuses common passwords, passwords containing your name and, where enabled, passwords known from data breaches.') }}</p>
  </div>
</template>
