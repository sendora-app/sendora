// SPDX-License-Identifier: AGPL-3.0-or-later

// File name from a Content-Disposition header (RFC 6266): filename* (UTF-8) wins over
// filename. Path parts are stripped; returns '' when there is no usable name.
export function filenameFromDisposition(header) {
  if (!header) return ''
  let name = ''
  const star = /filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i.exec(header)
  if (star) {
    try { name = decodeURIComponent(star[2].trim().replace(/^"|"$/g, '')) } catch { name = '' }
  }
  if (!name) {
    const plain = /filename\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;]+))/i.exec(header)
    if (plain) name = plain[1] !== undefined ? plain[1].replace(/\\(.)/g, '$1') : plain[2].trim()
  }
  name = name.split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f]/g, '').trim()
  return name === '.' || name === '..' ? '' : name
}
