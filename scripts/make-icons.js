// Renders the Scam Bunker mark (the favicon: ink tile, magnifier ring, square-capped handle) to the PWA icons
// in public/icons/. Zero dependencies: a 4x4-supersampled rasteriser and a minimal PNG encoder (node:zlib).
// Usage: node scripts/make-icons.js   (outputs are committed; rerun only if the mark changes)
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const INK = [0x16, 0x18, 0x1d], WHITE = [0xff, 0xff, 0xff];

// Shapes in the mark's 32x32 design space (see the inline SVG in public/index.html).
const inRoundRect = (x, y, r) => {
  if (x < 0 || y < 0 || x > 32 || y > 32) return false;
  const cx = Math.min(Math.max(x, r), 32 - r), cy = Math.min(Math.max(y, r), 32 - r);
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
};
const inRing = (x, y) => { const d = Math.hypot(x - 14, y - 14); return d >= 6.5 - 1.3 && d <= 6.5 + 1.3; };
const inHandle = (x, y) => { // segment (19,19)-(25,25), width 2.8, square caps extend 1.4 past each end
  const u = ((x - 19) + (y - 19)) / Math.SQRT2, v = ((x - 19) - (y - 19)) / Math.SQRT2, len = 6 * Math.SQRT2;
  return u >= -1.4 && u <= len + 1.4 && Math.abs(v) <= 1.4;
};

// maskable: full-bleed tile with the glyph shrunk into the 80% safe zone.
function render(size, { maskable = false } = {}) {
  const px = Buffer.alloc(size * size * 4), S = 4;
  for (let j = 0; j < size; j++) for (let i = 0; i < size; i++) {
    let tile = 0, glyph = 0;
    for (let sy = 0; sy < S; sy++) for (let sx = 0; sx < S; sx++) {
      let x = (i + (sx + 0.5) / S) * 32 / size, y = (j + (sy + 0.5) / S) * 32 / size;
      if (maskable) { tile++; x = 16 + (x - 16) / 0.72; y = 16 + (y - 16) / 0.72; }
      else if (inRoundRect(x, y, 6)) tile++; else continue;
      if (inRing(x, y) || inHandle(x, y)) glyph++;
    }
    const n = S * S, a = tile / n, g = tile ? glyph / tile : 0, o = (j * size + i) * 4;
    for (let c = 0; c < 3; c++) px[o + c] = Math.round(INK[c] * (1 - g) + WHITE[c] * g);
    px[o + 3] = Math.round(a * 255);
  }
  return png(size, size, px);
}

const CRC = new Uint32Array(256).map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (buf) => { let c = 0xffffffff; for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const chunk = (type, data) => {
  const len = Buffer.alloc(4), crc = Buffer.alloc(4), td = Buffer.concat([Buffer.from(type), data]);
  len.writeUInt32BE(data.length); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
};
function png(w, h, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) rgba.copy(raw, y * (w * 4 + 1) + 1, y * w * 4, (y + 1) * w * 4);
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

const ICONS = [
  ['icon-192.png', 192], ['icon-512.png', 512],
  ['icon-maskable-192.png', 192, { maskable: true }], ['icon-maskable-512.png', 512, { maskable: true }],
];
module.exports = { render, ICONS };

if (require.main === module) {
  const dir = path.join(__dirname, '..', 'public', 'icons');
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, size, opts] of ICONS) fs.writeFileSync(path.join(dir, name), render(size, opts));
  console.log(`Wrote ${ICONS.length} icons to public/icons/`);
}
