<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, setSession } from '../api'
import { t } from '../i18n'
const route = useRoute(), router = useRouter()
const err = ref(''), info = ref(null)
onMounted(async () => {
  try {
    const d = await api('/reverse-shares/accept', { method: 'POST', body: { token: route.params.token }, noRetry: true })
    setSession(d); info.value = d
    router.replace('/')
  } catch (e) { err.value = e.message }
})
</script>
<template>
  <div class="card narrow"><h1>{{ t('Invitation') }}</h1>
    <p v-if="err" class="err">{{ err }}</p><p v-else class="muted">…</p></div>
</template>
