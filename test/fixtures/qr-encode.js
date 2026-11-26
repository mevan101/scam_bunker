// Tiny zero-dependency QR code encoder for test fixtures (byte mode, error correction level L, versions 1-6, mask 0),
// plus a PNG writer. Used to generate invented QR images for the intake-media tests; not part of the app.
const zlib = require('zlib');

const VERSIONS = { 1: [19, 7, 1, []], 2: [34, 10, 1, [6, 18]], 3: [55, 15, 1, [6, 22]], 4: [80, 20, 1, [6, 26]], 5: [108, 26, 1, [6, 30]], 6: [136, 18, 2, [6, 34]] }; // data bytes, EC bytes per block, blocks, alignment
const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 256) x ^= 0x11d; }
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
function rs(data, n) {
  let gen = [1];
  for (let i = 0; i < n; i++) { const g = new Array(gen.length + 1).fill(0); gen.forEach((c, j) => { g[j] ^= c; g[j + 1] ^= mul(c, EXP[i]); }); gen = g; }
  const msg = [...data, ...new Array(n).fill(0)];
  for (let i = 0; i < data.length; i++) { const c = msg[i]; if (c) for (let j = 0; j < gen.length; j++) msg[i + j] ^= mul(gen[j], c); }
  return msg.slice(data.length);
}

function encode(text) {
  const bytes = [...Buffer.from(text, 'utf8')];
  const v = +Object.keys(VERSIONS).find(k => VERSIONS[k][0] * 8 >= 12 + bytes.length * 8);
  if (!v) throw new Error('Text too long for this test encoder');
  const [total, ecLen, blocks, align] = VERSIONS[v];
  const bits = [];
  const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  put(4, 4); put(bytes.length, 8); bytes.forEach(b => put(b, 8));
  put(0, Math.min(4, total * 8 - bits.length));
  while (bits.length % 8) bits.push(0);
  const data = []; for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  for (let p = 0; data.length < total; p++) data.push(p % 2 ? 0x11 : 0xEC);
  const per = total / blocks, dBlocks = [], eBlocks = [];
  for (let b = 0; b < blocks; b++) { const d = data.slice(b * per, (b + 1) * per); dBlocks.push(d); eBlocks.push(rs(d, ecLen)); }
  const cw = [];
  for (let i = 0; i < per; i++) dBlocks.forEach(d => cw.push(d[i]));
  for (let i = 0; i < ecLen; i++) eBlocks.forEach(e => cw.push(e[i]));

  const size = 17 + 4 * v;
  const m = Array.from({ length: size }, () => new Array(size).fill(false)), fn = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => { m[y][x] = dark; fn[y][x] = true; };
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  const finder = (cx, cy) => { for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) { const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy)); if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4); } };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  for (const ax of align) for (const ay of align) {
    if ((ax === 6 && ay === 6) || (ax === 6 && ay === align[align.length - 1]) || (ay === 6 && ax === align[align.length - 1])) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  // Format bits: level L (01), mask 0
  const fd = 1 << 3 | 0; let rem = fd; for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const f = ((fd << 10) | rem) ^ 0x5412, fb = i => ((f >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) set(8, i, fb(i));
  set(8, 7, fb(6)); set(8, 8, fb(7)); set(7, 8, fb(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, fb(i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, fb(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, fb(i));
  set(8, size - 8, true);
  // Data, zig-zag from the bottom right, mask 0: (x + y) % 2 === 0
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j, up = ((right + 1) & 2) === 0, y = up ? size - 1 - vert : vert;
      if (fn[y][x]) continue;
      let dark = i < cw.length * 8 ? ((cw[i >>> 3] >>> (7 - (i & 7))) & 1) === 1 : false; i++;
      if ((x + y) % 2 === 0) dark = !dark;
      m[y][x] = dark;
    }
  }
  return m;
}

function crc32(buf) { let c, crc = 0xffffffff; for (const b of buf) { c = (crc ^ b) & 0xff; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crc = (crc >>> 8) ^ c; } return (crc ^ 0xffffffff) >>> 0; }
function chunk(type, data) { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type, 'latin1'), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td)); return Buffer.concat([len, td, crc]); }
// Greyscale PNG of a QR matrix with a 4-module quiet zone.
function qrPng(text, scale = 8) {
  const mat = encode(text), n = mat.length + 8, w = n * scale;
  const raw = Buffer.alloc((w + 1) * w, 255);
  for (let y = 0; y < w; y++) { raw[y * (w + 1)] = 0; for (let x = 0; x < w; x++) { const mx = Math.floor(x / scale) - 4, my = Math.floor(y / scale) - 4; if (mat[my] && mat[my][mx]) raw[y * (w + 1) + 1 + x] = 0; } }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(w, 4); ihdr[8] = 8; ihdr[9] = 0;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

module.exports = { encode, qrPng };
