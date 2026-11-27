// SPDX-License-Identifier: AGPL-3.0-or-later

// Dependency-free QR Code (Model 2) encoder: byte mode (UTF-8), error correction M,
// versions 1-10 chosen automatically.

// Per version (index = version): [ecCodewordsPerBlock, [[blockCount, dataCodewordsPerBlock], ...]]
const EC_M = [null,
  [10, [[1, 16]]], [16, [[1, 28]]], [26, [[1, 44]]], [18, [[2, 32]]], [24, [[2, 43]]],
  [16, [[4, 27]]], [18, [[4, 31]]], [22, [[2, 38], [2, 39]]], [22, [[3, 36], [2, 37]]], [26, [[4, 43], [1, 44]]],
]
const ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]]
export const MAX_VERSION = 10

const dataCodewords = v => EC_M[v][1].reduce((s, [n, d]) => s + n * d, 0)
const sizeOf = v => 17 + 4 * v
// Max payload bytes: 4 mode bits + count bits + 8*n <= 8*dataCodewords
const countBits = v => (v < 10 ? 8 : 16)
export const capacity = v => Math.floor((dataCodewords(v) * 8 - 4 - countBits(v)) / 8)
export const MAX_BYTES = capacity(MAX_VERSION)

// ---- GF(256), primitive polynomial 0x11D ----
const EXP = new Uint8Array(512), LOG = new Uint8Array(256)
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = x; LOG[x] = i
  x <<= 1
  if (x & 0x100) x ^= 0x11d
}
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]
const gmul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0)

// Generator polynomial of given degree, coefficients high->low without leading 1.
export function rsGenerator(degree) {
  let g = [1]
  for (let i = 0; i < degree; i++) {
    const next = new Array(g.length + 1).fill(0)
    for (let j = 0; j < g.length; j++) {
      next[j] ^= g[j]
      next[j + 1] ^= gmul(g[j], EXP[i])
    }
    g = next
  }
  return g.slice(1)
}

export function rsRemainder(data, degree) {
  const gen = rsGenerator(degree)
  const rem = new Array(degree).fill(0)
  for (const b of data) {
    const factor = b ^ rem.shift()
    rem.push(0)
    for (let i = 0; i < degree; i++) rem[i] ^= gmul(gen[i], factor)
  }
  return rem
}

// ---- data encoding ----
function utf8(text) { return Array.from(new TextEncoder().encode(String(text))) }

function pickVersion(n) {
  for (let v = 1; v <= MAX_VERSION; v++) if (n <= capacity(v)) return v
  throw new RangeError(`QR code: text too long (${n} bytes, max ${MAX_BYTES})`)
}

export function dataBytes(bytes, version) {
  const bits = []
  const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1) }
  put(0b0100, 4)
  put(bytes.length, countBits(version))
  for (const b of bytes) put(b, 8)
  const cap = dataCodewords(version) * 8
  put(0, Math.min(4, cap - bits.length))
  while (bits.length % 8) bits.push(0)
  const out = []
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j]
    out.push(b)
  }
  for (let pad = 0xec; out.length < dataCodewords(version); pad ^= 0xec ^ 0x11) out.push(pad)
  return out
}

// Split into blocks, compute EC, interleave. Returns the final codeword sequence.
export function buildCodewords(data, version) {
  const [ecLen, groups] = EC_M[version]
  const blocks = []
  let pos = 0
  for (const [count, len] of groups) {
    for (let i = 0; i < count; i++) {
      const d = data.slice(pos, pos + len); pos += len
      blocks.push({ d, ec: rsRemainder(d, ecLen) })
    }
  }
  const out = []
  const maxData = Math.max(...blocks.map(b => b.d.length))
  for (let i = 0; i < maxData; i++) for (const b of blocks) if (i < b.d.length) out.push(b.d[i])
  for (let i = 0; i < ecLen; i++) for (const b of blocks) out.push(b.ec[i])
  return out
}

// ---- BCH info words ----
export function formatBits(mask) {
  const data = (0b00 << 3) | mask // EC level M = 00
  let rem = data
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537)
  return ((data << 10) | rem) ^ 0x5412
}
export function versionBits(version) {
  let rem = version
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
  return (version << 12) | rem
}

// ---- matrix construction ----
function newGrid(size) { return Array.from({ length: size }, () => new Array(size).fill(false)) }

function buildBase(version) {
  const size = sizeOf(version)
  const m = newGrid(size), fn = newGrid(size)
  const set = (x, y, dark) => { m[y][x] = dark; fn[y][x] = true }
  // timing
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0) }
  // finders with separators
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy
      if (x < 0 || y < 0 || x >= size || y >= size) continue
      const d = Math.max(Math.abs(dx), Math.abs(dy))
      set(x, y, d !== 2 && d !== 4)
    }
  }
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4)
  // alignment
  const ap = ALIGN[version]
  for (const cy of ap) for (const cx of ap) {
    const last = ap.length - 1
    if ((cx === ap[0] && cy === ap[0]) || (cx === ap[0] && cy === ap[last]) || (cx === ap[last] && cy === ap[0])) continue
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) {
      set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
    }
  }
  // reserve format areas (drawn later) and version info
  drawFormat(m, fn, 0, size)
  if (version >= 7) {
    const vb = versionBits(version)
    for (let i = 0; i < 18; i++) {
      const bit = ((vb >>> i) & 1) === 1, a = size - 11 + (i % 3), b = Math.floor(i / 3)
      set(a, b, bit); set(b, a, bit)
    }
  }
  return { m, fn, size }
}

function drawFormat(m, fn, mask, size) {
  const bits = formatBits(mask)
  const bit = i => ((bits >>> i) & 1) === 1
  const set = (x, y, d) => { m[y][x] = d; fn[y][x] = true }
  for (let i = 0; i <= 5; i++) set(8, i, bit(i))
  set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8))
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i))
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i))
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i))
  set(8, size - 8, true) // dark module
}

function placeData(m, fn, size, codewords) {
  let i = 0
  const total = codewords.length * 8
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j
        const upward = ((right + 1) & 2) === 0
        const y = upward ? size - 1 - vert : vert
        if (!fn[y][x] && i < total) {
          m[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1
          i++
        }
      }
    }
  }
  if (i !== total) throw new Error('QR code: internal error placing data')
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x, y) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
]

function applyMask(m, fn, size, mask) {
  const f = MASKS[mask]
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && f(x, y)) m[y][x] = !m[y][x]
}

export function penalty(m) {
  const size = m.length
  let score = 0
  const line = get => {
    // rule 1 and rule 3 on a single line
    let run = 1
    for (let i = 1; i <= size; i++) {
      if (i < size && get(i) === get(i - 1)) run++
      else { if (run >= 5) score += 3 + (run - 5); run = 1 }
    }
    const P = [true, false, true, true, true, false, true]
    for (let i = 0; i + 7 <= size; i++) {
      if (!P.every((v, k) => get(i + k) === v)) continue
      const light = (a, b) => { for (let k = a; k < b; k++) if (k >= 0 && k < size && get(k)) return false; return true }
      // 4 light modules before or after (modules outside the symbol count as light)
      if (light(i - 4, i)) score += 40
      if (light(i + 7, i + 11)) score += 40
    }
  }
  for (let y = 0; y < size; y++) line(i => m[y][i])
  for (let x = 0; x < size; x++) line(i => m[i][x])
  for (let y = 0; y < size - 1; y++) for (let x = 0; x < size - 1; x++) {
    const c = m[y][x]
    if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) score += 3
  }
  let dark = 0
  for (const r of m) for (const c of r) if (c) dark++
  const total = size * size
  score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10
  return score
}

// Encode text; returns { version, mask, size, modules } (modules[y][x] === true is dark).
export function qrEncode(text) {
  const bytes = utf8(text)
  const version = pickVersion(bytes.length)
  const codewords = buildCodewords(dataBytes(bytes, version), version)
  const base = buildBase(version)
  const { size } = base
  placeData(base.m, base.fn, size, codewords)
  let best = null
  for (let mask = 0; mask < 8; mask++) {
    const m = base.m.map(r => r.slice())
    applyMask(m, base.fn, size, mask)
    drawFormat(m, base.fn.map(r => r.slice()), mask, size)
    const p = penalty(m)
    if (!best || p < best.p) best = { p, mask, m }
  }
  return { version, mask: best.mask, size, modules: best.m }
}

export const qrMatrix = text => qrEncode(text).modules

// SVG string. scale = pixels per module (width/height attrs), margin = quiet zone in modules (spec: 4).
export function qrSvg(text, { scale = 4, margin = 4 } = {}) {
  const m = qrMatrix(text)
  const n = m.length + margin * 2
  let d = ''
  for (let y = 0; y < m.length; y++) {
    for (let x = 0; x < m.length; x++) {
      if (!m[y][x]) continue
      let run = 1
      while (x + run < m.length && m[y][x + run]) run++
      d += `M${x + margin} ${y + margin}h${run}v1h-${run}z`
      x += run - 1
    }
  }
  const px = n * scale
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n} ${n}" width="${px}" height="${px}" shape-rendering="crispEdges"><rect width="${n}" height="${n}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`
}
