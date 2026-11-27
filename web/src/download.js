// SPDX-License-Identifier: AGPL-3.0-or-later

import { SHA256 } from './checksum.js'
import { begin as beginTransfer, markNative } from './transfers.mjs'
import { tr, terr } from './i18n/mark.mjs'

export const BLOB_LIMIT = 128 * 1024 * 1024
export const canStreamToDisk = () => typeof window.showSaveFilePicker === 'function' && window.isSecureContext
// The browser takes over this download and the page cannot observe it, so the
// session is kept alive for an estimate based on the size (see transfers.mjs).
export function nativeDownload(url, size = 0) {
  markNative(size)
  const link = document.createElement('a'); link.href = url; link.click()
}

// Save only after a full response has matched its server representation digest.
// FSAPI writes stay uncommitted until close; abort discards a partial/mismatched file.
export async function verifiedDownload(url, { name, headers = {}, signal, onProgress = () => {} }) {
  let writable, reader, response
  const endTransfer = beginTransfer() // running transfer: no automatic sign-out
  try {
    // Must happen in the original click's user activation, before any fetch awaits.
    if (canStreamToDisk()) {
      const handle = await window.showSaveFilePicker({ suggestedName: name })
      writable = await handle.createWritable()
    }
    if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
    response = await fetch(url, { headers, signal, cache: 'no-store' })
    if (!response.ok) {
      const data = await response.json().catch(() => null)
      throw terr(data?.error || tr('Download failed'))
    }
    const expected = response.headers.get('X-Checksum-SHA256')
    const digest = response.headers.get('Repr-Digest')
    const encoded = /^[a-f0-9]{64}$/.test(expected || '')
      ? btoa(String.fromCharCode(...expected.match(/../g).map(x => parseInt(x, 16)))) : ''
    if (!encoded || digest !== `sha-256=:${encoded}:` || response.status !== 200) throw terr('Missing or invalid download checksum')
    const length = response.headers.get('Content-Length')
    if (!/^\d+$/.test(length || '') || !Number.isSafeInteger(Number(length))) throw terr('Missing or invalid download size')
    const total = Number(length)
    if (!writable && total > BLOB_LIMIT) throw terr('This browser cannot verify downloads larger than 128 MiB. Use a supported browser or choose an unverified download.')
    if (!response.body) throw terr('Streaming downloads are not supported in this browser')
    reader = response.body.getReader()
    const hash = new SHA256(), parts = []
    let received = 0
    while (true) {
      if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
      const { done, value } = await reader.read()
      if (done) break
      received += value.byteLength
      if (received > total || (!writable && received > BLOB_LIMIT)) throw terr('Download size mismatch')
      hash.update(value)
      if (writable) await writable.write(value)
      else parts.push(value)
      onProgress(received, total)
    }
    if (received !== total || hash.hex() !== expected) throw terr('Download checksum mismatch; file was not saved')
    if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
    if (writable) { await writable.close(); writable = null }
    else {
      const objectURL = URL.createObjectURL(new Blob(parts, { type: 'application/octet-stream' }))
      const link = document.createElement('a'); link.href = objectURL; link.download = name; link.click()
      setTimeout(() => URL.revokeObjectURL(objectURL), 60000)
    }
  } catch (error) {
    if (reader) await reader.cancel().catch(() => {})
    else if (response?.body) await response.body.cancel().catch(() => {})
    if (writable) await writable.abort().catch(() => {})
    throw error
  } finally { reader?.releaseLock(); endTransfer() }
}
