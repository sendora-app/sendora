// SPDX-License-Identifier: AGPL-3.0-or-later

import { api, session, ApiError } from './api'
import { checksumBlob } from './checksum'
import { begin as beginTransfer } from './transfers.mjs'
import { tr, terr } from './i18n/mark.mjs'

const CHUNK = 8 * 1024 * 1024

export { collect, fromInput } from './upload-selection'

// Upload all entries in a resumable session; onProgress(bytesDone, total).
// opts.share_id appends the files to an existing share of the caller.
export async function uploadAll(entries, onProgress, signal, onPhase = () => {}, opts = {}) {
  // Counted as a running transfer for the whole upload, including checksums, so
  // automatic sign-out never interrupts it (callers also cover the completion step).
  const endTransfer = beginTransfer()
  try { return await uploadAllInner(entries, onProgress, signal, onPhase, opts) } finally { endTransfer() }
}

async function uploadAllInner(entries, onProgress, signal, onPhase, opts) {
  onPhase(tr('Calculating checksums…'))
  const files = []
  for (const entry of entries) files.push({ name: entry.file.name, full_path: entry.path, size: entry.file.size, type: entry.file.type, sha256: await checksumBlob(entry.file, signal) })
  if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
  onPhase(tr('Uploading…'))
  // Creation deliberately completes even after cancellation so its returned ID
  // can release the reservation with a non-aborted request.
  const { id } = await api('/uploads', { method: 'POST', body: opts.share_id ? { files, share_id: opts.share_id } : { files } })
  try {
    if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
    const total = entries.reduce((a, e) => a + e.file.size, 0)
    let done = 0
    for (let i = 0; i < entries.length; i++) {
      const f = entries[i].file
      let offset = 0
      while (offset < f.size) {
        if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
        const end = Math.min(offset + CHUNK, f.size)
        try {
          const r = await fetch(`/api/uploads/${id}/files/${i}`, {
            method: 'PATCH', signal,
            headers: { Authorization: 'Bearer ' + session.token, 'Upload-Offset': String(offset) },
            body: f.slice(offset, end)
          })
          if (r.status === 401) { await api('/uploads/' + id); continue }
          if (r.status === 409) { const d = await r.json(); offset = d.received; if (d.busy) await new Promise(res => setTimeout(res, 1000)); continue }
          if (!r.ok) throw new ApiError(r.status, await r.json().catch(() => null))
          const d = await r.json()
          offset = d.received
        } catch (e) {
          if (e.name === 'AbortError') throw e
          if (e instanceof ApiError) throw e
          await new Promise(r => setTimeout(r, 1500))
          if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
          const st = await api('/uploads/' + id)
          offset = st.files[i].received
        }
        onProgress(done + offset, total)
      }
      done += f.size
      onProgress(done, total)
    }
    if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
    return id
  } catch (error) {
    if (signal?.aborted || error.name === 'AbortError') {
      try { await api('/uploads/' + id, { method: 'DELETE' }) }
      catch (cleanup) { throw terr('Upload cancelled, but reservation cleanup failed.') }
      throw new DOMException('Cancelled', 'AbortError')
    }
    // Retryable failures retain resumable sessions; only explicit cancellation
    // releases their reservations automatically.
    throw error
  }
}
