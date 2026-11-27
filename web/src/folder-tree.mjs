// SPDX-License-Identifier: AGPL-3.0-or-later

// Pure helpers for the folder tree shown in the upload and share views.
// Items are { path, size, ...anything }; paths use "/" separators. Folders carry
// totals (files, folders, bytes) so rows can show "12 files · 3.4 MB" without walking again.

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' })

export function buildTree(items) {
  const root = { type: 'folder', name: '', path: '', depth: -1, children: [], files: 0, folders: 0, bytes: 0 }
  const index = new Map([['', root]])
  const folder = (parent, name) => {
    const path = parent.path ? parent.path + '/' + name : name
    let node = index.get(path)
    if (!node) {
      node = { type: 'folder', name, path, depth: parent.depth + 1, children: [], files: 0, folders: 0, bytes: 0 }
      index.set(path, node)
      parent.children.push(node)
    }
    return node
  }
  for (const item of items) {
    const parts = String(item.path).split('/').filter(Boolean)
    if (!parts.length) continue
    let parent = root
    const trail = [root]
    for (const name of parts.slice(0, -1)) { parent = folder(parent, name); trail.push(parent) }
    const name = parts[parts.length - 1]
    parent.children.push({ type: 'file', name, path: parts.join('/'), depth: parent.depth + 1, size: item.size || 0, item })
    for (const f of trail) { f.files++; f.bytes += item.size || 0 }
  }
  const finish = node => {
    node.children.sort((a, b) => (a.type === b.type ? collator.compare(a.name, b.name) : a.type === 'folder' ? -1 : 1))
    for (const child of node.children) if (child.type === 'folder') { finish(child); node.folders += 1 + child.folders }
  }
  finish(root)
  return root
}

// Folders open by default near the top, or when the whole tree is small.
export function defaultOpen(node, total) {
  return node.depth < 1 || total <= 40 || node.files <= 8
}

// Flattens the tree into the visible rows. `open` maps folder path -> boolean overrides.
export function visibleRows(root, open = {}) {
  const rows = []
  const walk = node => {
    for (const child of node.children) {
      rows.push(child)
      if (child.type === 'folder' && (child.path in open ? open[child.path] : defaultOpen(child, root.files))) walk(child)
    }
  }
  walk(root)
  return rows
}

export function folderPaths(root) {
  const out = []
  const walk = node => { for (const c of node.children) if (c.type === 'folder') { out.push(c.path); walk(c) } }
  walk(root)
  return out
}

// Files are uploaded sequentially in list order, so overall bytes done map onto each file.
// Returns bytes done per file, same order as `sizes`.
export function bytesDonePerFile(sizes, done) {
  let before = 0
  return sizes.map(size => {
    const mine = size > 0 ? Math.min(size, Math.max(0, done - before)) : 0
    before += size
    return mine
  })
}

// Sum of bytes done below a folder, given a Map(item -> bytes done).
export function folderDone(node, doneOf) {
  let sum = 0
  const walk = n => { for (const c of n.children) c.type === 'folder' ? walk(c) : (sum += doneOf(c.item) || 0) }
  walk(node)
  return sum
}

export const extensionOf = name => {
  const i = name.lastIndexOf('.')
  return i > 0 && i < name.length - 1 ? name.slice(i + 1).toLowerCase().slice(0, 6) : ''
}

const KINDS = {
  image: ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'avif', 'bmp', 'heic'],
  video: ['mp4', 'webm', 'mov', 'mkv', 'avi', 'm4v'],
  audio: ['mp3', 'ogg', 'wav', 'flac', 'm4a', 'aac'],
  archive: ['zip', 'tar', 'gz', 'tgz', '7z', 'rar', 'bz2', 'xz'],
  doc: ['pdf', 'doc', 'docx', 'odt', 'txt', 'md', 'rtf', 'xls', 'xlsx', 'ods', 'csv', 'ppt', 'pptx'],
  code: ['js', 'ts', 'json', 'html', 'css', 'go', 'py', 'sh', 'yml', 'yaml', 'xml', 'vue'],
}
export function fileKind(name) {
  const ext = extensionOf(name)
  for (const [kind, list] of Object.entries(KINDS)) if (list.includes(ext)) return kind
  return 'file'
}
