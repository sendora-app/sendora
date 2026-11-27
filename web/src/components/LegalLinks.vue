<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// Links to the privacy statement and the terms of use (Settings), when configured.
import { app } from '../state'
import { t } from '../i18n'
</script>

<template>
  <p v-if="app.boot?.privacy_url || app.boot?.terms_url" class="legal-links muted">
    <a v-if="app.boot?.privacy_url" :href="app.boot.privacy_url" target="_blank" rel="noopener noreferrer">{{ t('Privacy statement') }}</a>
    <template v-if="app.boot?.privacy_url && app.boot?.terms_url"> · </template>
    <a v-if="app.boot?.terms_url" :href="app.boot.terms_url" target="_blank" rel="noopener noreferrer">{{ t('Terms of use') }}</a>
  </p>
</template>

<style scoped>
.legal-links{margin:8px 0 0;font-size:13px}
</style>
