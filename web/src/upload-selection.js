// SPDX-License-Identifier: AGPL-3.0-or-later

// Dot-prefixed files/directories are excluded from folder uploads.
// Explicitly selected standalone files remain allowed. Browser APIs do not
// expose Windows hidden attributes or macOS Finder visibility flags.
export const hiddenPath = path => path.split('/').some(part => part.startsWith('.'))
// Conservative filename rules: do not exclude real backups (.bak) or every
// .lock file. These rules apply to folder uploads, not explicit file choices.
export const temporaryFile = name => name.startsWith('~') || /\.(tmp|temp)$/i.test(name) || /^(thumbs\.db|desktop\.ini)$/i.test(name)
export const skipFolderFile = path => hiddenPath(path) || temporaryFile(path.split('/').pop())

export function fromInput(fileList) {
  return [...fileList]
    .filter(file => !file.webkitRelativePath || !skipFolderFile(file.webkitRelativePath))
    .map(file => ({ file, path: file.webkitRelativePath || file.name }))
}

export async function collect(dt) {
  const out = []
  const walk = async (entry, prefix, inFolder = false) => {
    if ((inFolder || entry.isDirectory) && entry.name.startsWith('.')) return
    if (inFolder && entry.isFile && temporaryFile(entry.name)) return
    if (entry.isFile) {
      const file = await new Promise((res, rej) => entry.file(res, rej))
      out.push({ file, path: prefix + file.name })
    } else if (entry.isDirectory) {
      const reader = entry.createReader()
      let batch
      do {
        batch = await new Promise((res, rej) => reader.readEntries(res, rej))
        for (const child of batch) await walk(child, prefix + entry.name + '/', true)
      } while (batch.length)
    }
  }
  const items = [...(dt.items || [])].map(item => item.webkitGetAsEntry?.()).filter(Boolean)
  if (items.length) for (const entry of items) await walk(entry, '')
  else out.push(...fromInput(dt.files || []))
  return out
}
