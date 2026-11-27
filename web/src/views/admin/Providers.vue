<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../../api'
import { t } from '../../i18n'
const list = ref([]), edit = ref(null), err = ref('')
const load = async () => (list.value = await api('/auth-providers'))
onMounted(load)
const blank = () => ({ id: 0, name: '', type: 'oidc', enabled: true, client_id: '', client_secret: '', issuer_url: '', tenant_id: '', trust_email: false, allow_registration: true })
async function save() {
  err.value = ''
  const p = edit.value
  try {
    if (p.id) await api('/auth-providers/' + p.id, { method: 'PUT', body: p })
    else await api('/auth-providers', { method: 'POST', body: p })
    edit.value = null; await load()
  } catch (e) { err.value = e.message }
}
async function del(p) { if (confirm(t('Delete provider?'))) { await api('/auth-providers/' + p.id, { method: 'DELETE' }); load() } }
</script>
<template>
  <div class="card"><div class="actions" style="margin:0 0 12px"><h1 style="margin:0">{{ t('Login providers') }}</h1><button class="small" @click="edit = blank()">+ {{ t('Add provider') }}</button></div>
    <p v-if="err" class="err">{{ err }}</p>
    <form v-if="edit" class="card" @submit.prevent="save">
      <div class="row"><div><label>{{ t('Name') }}</label><input v-model="edit.name" required /></div>
        <div><label>{{ t('Type') }}</label><select v-model="edit.type"><option value="oidc">OpenID Connect</option><option value="google">Google</option><option value="github">GitHub</option><option value="entra">Microsoft Entra ID</option></select></div></div>
      <label v-if="edit.type === 'oidc'">{{ t('Issuer URL') }}</label><input v-if="edit.type === 'oidc'" v-model="edit.issuer_url" placeholder="https://auth.example.com/realms/main" />
      <template v-if="edit.type === 'entra'"><label>{{ t('Directory (tenant) ID') }}</label><input v-model="edit.tenant_id" required placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" /><p class="muted">{{ t('Single organization tenant only. Microsoft email claims are not treated as verified; accounts are never linked by email.') }}</p></template>
      <div class="row"><div><label>{{ t('Client ID') }}</label><input v-model="edit.client_id" required /></div>
        <div><label>{{ t('Client secret') }}</label><input v-model="edit.client_secret" type="password" autocomplete="new-password" :placeholder="edit.client_secret_set ? '••••••••' : ''" /></div></div>
      <label class="check"><input type="checkbox" v-model="edit.enabled" /> {{ t('Enabled') }}</label>
      <label class="check"><input type="checkbox" v-model="edit.allow_registration" /> {{ t('Create accounts on first login') }}</label>
      <label v-if="edit.type !== 'entra'" class="check"><input type="checkbox" v-model="edit.trust_email" /> {{ t('Use verified provider email for new accounts (never auto-link)') }}</label>
      <p v-if="edit.callback_url" class="muted">{{ t('Callback URL') }}: <code>{{ edit.callback_url }}</code></p>
      <div class="actions"><button>{{ t('Save') }}</button><button type="button" class="secondary" @click="edit = null">{{ t('Cancel') }}</button></div>
    </form>
    <table><tr v-for="p in list" :key="p.id"><td>{{ p.name }} <span class="badge">{{ p.type }}</span> <span class="badge" :class="p.enabled ? 'on' : 'off'">{{ p.enabled ? t('Enabled') : t('Disabled') }}</span> <span v-if="p.managed" class="badge" :title="t('Set in the server configuration (environment or Kubernetes ConfigMap); change it there.')">{{ t('Managed by configuration') }}</span>
      <div class="muted">{{ t('Callback URL') }}: <code>{{ p.callback_url }}</code></div></td>
      <td class="actions" style="margin:0"><template v-if="!p.managed"><button class="small secondary" @click="edit = { ...p, client_secret: '' }">{{ t('Edit') }}</button><button class="small danger" @click="del(p)">{{ t('Delete') }}</button></template></td></tr></table>
  </div>
</template>
