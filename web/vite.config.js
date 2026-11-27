// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// Publishes the list of translatable texts next to the build, so the server can
// validate imported translation files without keeping its own copy of the keys.
const i18nKeys = () => ({
  name: 'sendora-i18n-keys',
  generateBundle() {
    for (const [file, out] of [['keys.json', 'keys.json'], ['server-messages.json', 'server-messages.json']]) {
      this.emitFile({ type: 'asset', fileName: 'i18n-keys/' + out, source: readFileSync(new URL('./src/i18n/' + file, import.meta.url), 'utf8') })
    }
  }
})

export default defineConfig({
  plugins: [vue(), i18nKeys()],
  server: { proxy: { '/api': 'http://localhost:8080' } },
  build: {
    outDir: 'dist', emptyOutDir: true,
    // platform.html is the platform console of multi-tenant mode; the server
    // serves it only on admin.<base domain>.
    rollupOptions: { input: { main: fileURLToPath(new URL('./index.html', import.meta.url)), platform: fileURLToPath(new URL('./platform.html', import.meta.url)) } }
  }
})
