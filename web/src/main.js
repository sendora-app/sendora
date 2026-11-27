// SPDX-License-Identifier: AGPL-3.0-or-later

import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import { refresh, setLocaleGetter } from './api'
import { dateLocale } from './i18n'
import { loadBoot } from './state'
import './style.css'

setLocaleGetter(dateLocale)

Promise.all([loadBoot().catch(() => {}), refresh()]).then(() => createApp(App).use(router).mount('#app'))
