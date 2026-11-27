// SPDX-License-Identifier: AGPL-3.0-or-later

import { createApp } from 'vue'
import PlatformApp from './PlatformApp.vue'
import { setLang, lang } from '../i18n'
import '../style.css'

// Platform console entry (multi-tenant mode, admin.<base domain> only).
setLang(lang.value)
createApp(PlatformApp).mount('#app')
