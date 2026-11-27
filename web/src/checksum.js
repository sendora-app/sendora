// SPDX-License-Identifier: AGPL-3.0-or-later

// Incremental SHA-256, bounded to one caller-provided chunk plus a 64-byte block.
// FIPS 180-4; works without WebCrypto's whole-message memory requirement.
const K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
])
const rotr = (x,n) => (x >>> n) | (x << (32-n))
export class SHA256 {
  constructor() {
    this.h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19])
    this.block = new Uint8Array(64); this.w = new Uint32Array(64); this.used = 0; this.bytes = 0; this.finished = false
  }
  compress(data, offset) {
    // Hot loop: locals only, no destructuring or per-block allocations.
    const w = this.w, hh = this.h
    for (let i = 0, j = offset; i < 16; i++, j += 4) w[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3]
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15], b = w[i - 2]
      w[i] = (w[i - 16] + (((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3)) + w[i - 7] + (((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10))) | 0
    }
    let a = hh[0] | 0, b = hh[1] | 0, c = hh[2] | 0, d = hh[3] | 0, e = hh[4] | 0, f = hh[5] | 0, g = hh[6] | 0, h = hh[7] | 0
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0
      const t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c))) | 0
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0
    }
    hh[0] += a; hh[1] += b; hh[2] += c; hh[3] += d; hh[4] += e; hh[5] += f; hh[6] += g; hh[7] += h
  }
  update(data) {
    if (this.finished) throw new Error('Hash already finalized')
    this.bytes += data.length
    let offset=0
    if (this.used) {
      const n=Math.min(64-this.used,data.length); this.block.set(data.subarray(0,n),this.used); this.used+=n; offset=n
      if(this.used===64) { this.compress(this.block,0); this.used=0 }
    }
    while(offset+64<=data.length) { this.compress(data,offset); offset+=64 }
    if(offset<data.length) { this.block.set(data.subarray(offset),0); this.used=data.length-offset }
    return this
  }
  hex() {
    if(this.finished) throw new Error('Hash already finalized')
    this.finished=true
    const n=this.used; this.block[n]=0x80; this.block.fill(0,n+1)
    if(n>=56) { this.compress(this.block,0); this.block.fill(0) }
    const view=new DataView(this.block.buffer)
    view.setUint32(56,Math.floor(this.bytes/0x20000000)); view.setUint32(60,(this.bytes*8)>>>0)
    this.compress(this.block,0)
    return [...this.h].map(x=>x.toString(16).padStart(8,'0')).join('')
  }
}
export async function checksumBlob(blob, signal, progress = () => {}) {
  const hash = new SHA256(), chunk = 8 * 1024 * 1024
  for(let offset=0;offset<blob.size;offset+=chunk) {
    if(signal?.aborted) throw new DOMException('Cancelled','AbortError')
    hash.update(new Uint8Array(await blob.slice(offset,offset+chunk).arrayBuffer()))
    progress(Math.min(offset+chunk,blob.size))
    // Yield for painting and cancellation rather than freezing large-file uploads.
    await new Promise(resolve=>setTimeout(resolve,0))
  }
  if(signal?.aborted) throw new DOMException('Cancelled','AbortError')
  return hash.hex()
}
