<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Row actions in Admin -> Users: disable / enable an account and sign a user out
// everywhere. Emits 'changed' after a state change and 'note' (kind, text) with
// the result to show next to the row.
import { ref } from 'vue'
import { api, session } from '../api'
import { t } from '../i18n'

const props = defineProps({ user: { type: Object, required: true } })
const emit = defineEmits(['changed', 'note'])
const busy = ref(false)
const self = () => props.user.id === session.user?.id

async function run(fn) {
  busy.value = true
  try { await fn() } catch (e) { emit('note', 'err', e.message) } finally { busy.value = false }
}
function disable() {
  const u = props.user
  if (!confirm(t('Disable {n}? They are signed out everywhere and cannot sign in, their share links stop working and their pending uploads and invitations are cancelled. Nothing is deleted; you can enable the account again.', { n: u.username }))) return
  const reason = prompt(t('Reason (optional, recorded in the audit log):'), '')
  if (reason === null) return
  run(async () => {
    await api(`/users/${u.id}/disable`, { method: 'POST', body: { reason } })
    emit('changed'); emit('note', 'ok', t('{n} is disabled.', { n: u.username }))
  })
}
function enable() {
  const u = props.user
  if (!confirm(t('Enable {n} again? They can sign in again and their share links work again (unless expired).', { n: u.username }))) return
  run(async () => {
    await api(`/users/${u.id}/enable`, { method: 'POST' })
    emit('changed'); emit('note', 'ok', t('{n} is enabled again.', { n: u.username }))
  })
}
function signOut() {
  const u = props.user
  if (!confirm(t('Sign {n} out on every device now?', { n: u.username }))) return
  run(async () => {
    const r = await api(`/users/${u.id}/sessions/revoke`, { method: 'POST' })
    emit('note', 'ok', t('{n} is signed out everywhere (sessions ended: {c}).', { n: u.username, c: r.revoked }))
  })
}
</script>
<template>
  <button v-if="!user.disabled" class="small secondary" :disabled="busy || self()" @click="signOut">{{ t('Sign out everywhere') }}</button>
  <button v-if="user.disabled" class="small secondary" :disabled="busy" @click="enable">{{ t('Enable') }}</button>
  <button v-else class="small danger" :disabled="busy || self()" @click="disable">{{ t('Disable') }}</button>
</template>
