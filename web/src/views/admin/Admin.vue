<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
import { t } from '../../i18n'
import { app, can } from '../../state'
</script>
<template>
  <div>
    <div class="tabs">
      <router-link to="/admin/stats">{{ t('Statistics') }}</router-link>
      <router-link to="/admin/users">{{ t('Users') }}</router-link>
      <router-link to="/admin/access-review">{{ t('Access review') }}</router-link>
      <router-link to="/admin/settings">{{ t('Settings') }}</router-link>
      <router-link to="/admin/branding">{{ t('Branding') }}</router-link>
      <router-link to="/admin/themes">{{ t('Themes') }}</router-link>
      <router-link to="/admin/providers">{{ t('Login providers') }}</router-link>
      <router-link to="/admin/emails">{{ t('Email templates') }}</router-link>
      <router-link to="/admin/security">{{ t('Security') }}</router-link>
      <router-link to="/admin/languages">{{ t('Languages') }}</router-link>
      <router-link to="/admin/backups">{{ t('Backups') }}</router-link>
      <router-link to="/admin/storage">{{ t('Storage') }}</router-link>
      <router-link v-if="can('key_management_ui', true)" to="/admin/keys">{{ t('Keys') }}</router-link>
      <router-link v-if="app.boot && can('multi_tenant_conversion', !app.boot.multi_tenant)" to="/admin/multitenant">{{ t('Multi-tenant') }}</router-link>
      <router-link to="/admin/logs">{{ t('Audit log') }}</router-link>
    </div>
    <router-view />
  </div>
</template>
