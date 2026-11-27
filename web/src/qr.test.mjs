// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { qrEncode, qrMatrix, qrSvg, capacity, MAX_BYTES, rsRemainder, rsGenerator, buildCodewords, dataBytes, formatBits, versionBits } from './qr.mjs'

const url60 = 'http://localhost:9090/share/tiger-bike-chest-3485217-river-2765290-cloud'

test('known answer: RS EC codewords for the classic HELLO WORLD 1-M example', () => {
  const data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]
  assert.deepEqual(rsRemainder(data, 10), [196, 35, 39, 119, 235, 215, 231, 226, 93, 23])
})

test('known answer: generator polynomial degree 7', () => {
  // alpha exponents 0 87 229 146 149 238 102 21 -> values
  assert.equal(rsGenerator(7).length, 7)
  assert.deepEqual(rsGenerator(7), [127, 122, 154, 164, 11, 68, 117])
})

test('known answer: format and version info words', () => {
  assert.equal(formatBits(0), 0b101010000010010)
  assert.equal(versionBits(7), 0b000111110010010100)
  assert.equal(versionBits(10), 0b001010010011010011)
})

test('format info is a valid BCH codeword for all masks', () => {
  for (let m = 0; m < 8; m++) {
    let v = formatBits(m) ^ 0x5412, rem = v
    for (let i = 14; i >= 10; i--) if ((rem >>> i) & 1) rem ^= 0x537 << (i - 10)
    assert.equal(rem, 0)
    assert.equal(v >>> 10, m) // EC level M = 00, then mask
  }
})

function readFormat(mod) {
  const n = mod.length
  const a = [], b = []
  for (let i = 0; i <= 5; i++) a.push(mod[i][8])
  a.push(mod[7][8], mod[8][8], mod[8][7])
  for (let i = 9; i < 15; i++) a.push(mod[8][14 - i])
  for (let i = 0; i < 8; i++) b.push(mod[8][n - 1 - i])
  for (let i = 8; i < 15; i++) b.push(mod[n - 15 + i][8])
  const num = bits => bits.reduce((s, v, i) => s | (v ? 1 << i : 0), 0)
  return [num(a), num(b)]
}

const samples = ['a', 'hello', url60, url60 + url60.slice(0, 60), 'x'.repeat(200), 'x'.repeat(MAX_BYTES), 'héllo wörld ✓ 日本語 😀']

test('structure: finders, timing, dark module, format info, size', () => {
  for (const s of samples) {
    const { version, mask, size, modules: m } = qrEncode(s)
    assert.equal(size, 17 + 4 * version)
    assert.equal(m.length, size)
    for (const [ox, oy] of [[0, 0], [size - 7, 0], [0, size - 7]]) {
      for (let y = 0; y < 7; y++) for (let x = 0; x < 7; x++) {
        const d = Math.max(Math.abs(x - 3), Math.abs(y - 3))
        assert.equal(m[oy + y][ox + x], d !== 2, `finder ${s.length}`)
      }
    }
    // separators
    for (let i = 0; i < 8; i++) {
      assert.equal(m[7][i], false); assert.equal(m[i][7], false)
      assert.equal(m[7][size - 1 - i], false); assert.equal(m[i][size - 8], false)
      assert.equal(m[size - 8][i], false); assert.equal(m[size - 1 - i][7], false)
    }
    for (let i = 8; i < size - 8; i++) { assert.equal(m[6][i], i % 2 === 0); assert.equal(m[i][6], i % 2 === 0) }
    assert.equal(m[size - 8][8], true)
    const [f1, f2] = readFormat(m)
    assert.equal(f1, formatBits(mask)); assert.equal(f2, formatBits(mask))
    if (version >= 7) {
      const vb = versionBits(version)
      for (let i = 0; i < 18; i++) {
        const bit = ((vb >>> i) & 1) === 1
        assert.equal(m[Math.floor(i / 3)][size - 11 + (i % 3)], bit)
        assert.equal(m[size - 11 + (i % 3)][Math.floor(i / 3)], bit)
      }
    }
  }
})

test('alignment patterns present (v2+)', () => {
  const { version, modules: m } = qrEncode(url60)
  assert.ok(version >= 2)
  const centre = [0, 0, 18, 22, 26, 30, 34][version]
  for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++)
    assert.equal(m[centre + dy][centre + dx], Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
})

test('RS validation: every block of the real codeword stream re-divides to zero remainder', () => {
  for (const s of samples) {
    const bytes = Array.from(new TextEncoder().encode(s))
    const { version } = qrEncode(s)
    const data = dataBytes(bytes, version)
    const cw = buildCodewords(data, version)
    // data stream begins with mode 0100 and the length
    assert.equal(data[0] >>> 4, 0b0100)
    // rebuild: remainder of (data + ec) should be zero, per block, via de-interleave
    const ecLen = cw.length - data.length
    assert.ok(ecLen > 0)
    // Verify via recomputation: EC for each block equals remainder; and appending EC yields zero remainder
    const tables = { 8: [[2, 38], [2, 39]], 9: [[3, 36], [2, 37]], 10: [[4, 43], [1, 44]] }
    const simple = { 1: [[1, 16]], 2: [[1, 28]], 3: [[1, 44]], 4: [[2, 32]], 5: [[2, 43]], 6: [[4, 27]], 7: [[4, 31]] }
    const groups = tables[version] || simple[version]
    const nb = groups.reduce((a, [n]) => a + n, 0), per = ecLen / nb
    const lens = groups.flatMap(([n, l]) => Array(n).fill(l))
    const blocks = lens.map(() => ({ d: [], e: [] }))
    let p = 0
    const maxD = Math.max(...lens)
    for (let i = 0; i < maxD; i++) blocks.forEach((b, k) => { if (i < lens[k]) b.d.push(cw[p++]) })
    for (let i = 0; i < per; i++) blocks.forEach(b => b.e.push(cw[p++]))
    assert.equal(p, cw.length)
    for (const b of blocks) assert.deepEqual(rsRemainder([...b.d, ...b.e], per), new Array(per).fill(0))
  }
})

test('decoded data region round-trips: unmask and read the byte payload back', () => {
  for (const s of samples) {
    const { version, mask, size, modules } = qrEncode(s)
    // independent re-read: rebuild function-pattern map by encoding is internal, so
    // compare by reading all codeword bits in zigzag skipping the known function areas.
    const isFn = (x, y) => {
      if (x === 6 || y === 6) return true
      if ((x < 9 && y < 9) || (x >= size - 8 && y < 9) || (x < 9 && y >= size - 8)) return true
      if (version >= 7 && ((x >= size - 11 && y < 6) || (y >= size - 11 && x < 6))) return true
      const ap = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]][version]
      for (const cy of ap) for (const cx of ap) {
        if ((cx === 6 && cy === 6) || (cx === 6 && cy === ap.at(-1)) || (cx === ap.at(-1) && cy === 6)) continue
        if (Math.abs(x - cx) <= 2 && Math.abs(y - cy) <= 2) return true
      }
      return false
    }
    const f = [(x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x, y) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
      (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0, (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
      (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0][mask]
    const bits = []
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5
      for (let v = 0; v < size; v++) for (let j = 0; j < 2; j++) {
        const x = right - j, y = ((right + 1) & 2) === 0 ? size - 1 - v : v
        if (!isFn(x, y)) bits.push(modules[y][x] !== f(x, y))
      }
    }
    const bytes = Array.from(new TextEncoder().encode(s))
    const expected = buildCodewords(dataBytes(bytes, version), version)
    const got = []
    for (let i = 0; i + 8 <= bits.length; i += 8) got.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0))
    assert.deepEqual(got.slice(0, expected.length), expected)
    // remainder bits are zero
    assert.ok(bits.slice(expected.length * 8).every(b => !b))
  }
})

test('capacity limits and automatic version choice', () => {
  assert.equal(capacity(1), 14); assert.equal(capacity(2), 26); assert.equal(capacity(3), 42)
  assert.equal(capacity(4), 62); assert.equal(capacity(5), 84); assert.equal(capacity(6), 106)
  assert.equal(capacity(7), 122); assert.equal(capacity(8), 152); assert.equal(capacity(9), 180)
  assert.equal(capacity(10), 213); assert.equal(MAX_BYTES, 213)
  assert.equal(qrEncode('x'.repeat(14)).version, 1)
  assert.equal(qrEncode('x'.repeat(15)).version, 2)
  assert.equal(qrEncode('x'.repeat(213)).version, 10)
  assert.throws(() => qrEncode('x'.repeat(214)), RangeError)
  assert.throws(() => qrSvg('x'.repeat(300)), /too long/)
  // multi-byte counts bytes, not characters
  assert.throws(() => qrEncode('€'.repeat(72)), RangeError)
  assert.equal(qrEncode('€'.repeat(71)).version, 10)
})

test('deterministic, and UTF-8 differs from ASCII', () => {
  assert.deepEqual(qrMatrix(url60), qrMatrix(url60))
  assert.equal(qrSvg('héllo'), qrSvg('héllo'))
  assert.notDeepEqual(qrMatrix('é'), qrMatrix('e'))
})

test('svg output: quiet zone and scale', () => {
  const m = qrMatrix('hi')
  const svg = qrSvg('hi', { scale: 5, margin: 4 })
  const n = m.length + 8
  assert.ok(svg.startsWith('<svg'))
  assert.ok(svg.includes(`viewBox="0 0 ${n} ${n}"`))
  assert.ok(svg.includes(`width="${n * 5}"`))
  // top-left finder corner is offset by the margin
  assert.ok(svg.includes('M4 4h7v1h-7z'))
  assert.ok(qrSvg('hi', { margin: 0 }).includes('M0 0h7v1h-7z'))
})
