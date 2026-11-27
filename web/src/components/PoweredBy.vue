<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script setup>
// "Powered by Sendora" and the link to the source of the running build, shown
// in the footer of every page (AGPL-3.0 section 13 and the section 7(b)
// attribution term in LICENSE-ADDITIONAL-TERMS.md). Intentionally not
// configurable: there is no setting or branding option that hides it. The
// brand name and the link targets are fixed (not translations, not the
// application name); empty translations of the surrounding words fall back to
// English (attributionLabels).
import { computed } from 'vue'
import { t, lang } from '../i18n'
import { PROJECT_NAME, PROJECT_URL, LICENSE_NAME, LICENSE_URL, sourceLink, attributionLabels } from '../attribution.mjs'

const props = defineProps({ boot: { type: Object, default: null } })
const source = computed(() => sourceLink(props.boot))
// lang is read so the labels follow a language switch. The keys are listed for
// the i18n extractor: t('Powered by') t('Source code')
const labels = computed(() => (lang.value, attributionLabels(t)))
const year = new Date().getFullYear()
</script>

<template>
  <p class="powered-by">{{ t('© {year} Sendora contributors', { year }) }} · {{ labels.poweredBy }} <a :href="PROJECT_URL" target="_blank" rel="noopener noreferrer">{{ PROJECT_NAME }}</a> · <a :href="source" target="_blank" rel="noopener noreferrer">{{ labels.sourceCode }}</a> · <a :href="LICENSE_URL" target="_blank" rel="noopener noreferrer">{{ LICENSE_NAME }}</a><slot /></p>
</template>
