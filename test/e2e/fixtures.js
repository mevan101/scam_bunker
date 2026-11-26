// Shared fixtures for the e2e suite. Everything here is invented: no real people, wallets or places.
const { test: base, expect } = require('@playwright/test');
const zlib = require('zlib');

// ---------- Invented test data ----------
// A Tron address built from the payload 0x41 e0 e1 … f3 with a valid Base58Check checksum. It belongs to nobody.
const INVENTED_WALLET = 'TWUGxtCdXappHp3EUbtXik8woeG2V2grWC';

const SAMPLE_VERDICTS = {
  crypto: ['Scam', 'Likely scam'],
  job: ['Scam', 'Likely scam'],
  phish: ['Scam', 'Likely scam'],
  viral: ['Misleading / manipulated'],
  bots: ['Coordinated / inauthentic'],
};

// ---------- PNG with a tEXt "parameters" chunk (Stable Diffusion style) ----------
function crc32(buf) {
  if (zlib.crc32) return zlib.crc32(buf);
  let c, crc = 0xffffffff;
  for (const b of buf) { c = (crc ^ b) & 0xff; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crc = (crc >>> 8) ^ c; }
  return (crc ^ 0xffffffff) >>> 0;
}
function pngChunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function aiPng({ width = 80, height = 60, parameters } = {}) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = 2; // 8-bit RGB
  const raw = Buffer.alloc((width * 3 + 1) * height);
  for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
    const o = y * (width * 3 + 1) + 1 + x * 3; raw[o] = (x * 3) & 255; raw[o + 1] = (y * 4) & 255; raw[o + 2] = ((x ^ y) * 5) & 255;
  }
  const params = parameters || 'a lighthouse on an invented island at dusk, oil painting\nNegative prompt: blurry\nSteps: 28, Sampler: DPM++ 2M Karras, CFG scale: 7, Seed: 1234567, Size: 80x60, Model: invented-model-v1';
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('tEXt', Buffer.concat([Buffer.from('parameters\0', 'latin1'), Buffer.from(params, 'latin1')])),
    pngChunk('IDAT', zlib.deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

// ---------- JPEG with EXIF GPS + DateTimeOriginal ----------
// Big-endian TIFF: IFD0 (Make, Model, ExifIFD, GPS IFD) → Exif IFD (DateTimeOriginal) → GPS IFD.
function exifApp1({ make, model, dateTimeOriginal, lat, lon, gpsDate }) {
  const ifds = []; // built as [{ entries: [{tag,type,count,value:Buffer}] }]
  const ascii = s => Buffer.from(s + '\0', 'latin1');
  const rationals = arr => { const b = Buffer.alloc(arr.length * 8); arr.forEach(([n, d], i) => { b.writeUInt32BE(n, i * 8); b.writeUInt32BE(d, i * 8 + 4); }); return b; };
  const dms = v => { const a = Math.abs(v), d = Math.floor(a), m = Math.floor((a - d) * 60), s = Math.round(((a - d) * 60 - m) * 60 * 100); return [[d, 1], [m, 1], [s, 100]]; };
  const ifd0 = [
    { tag: 0x010f, type: 2, value: ascii(make) },
    { tag: 0x0110, type: 2, value: ascii(model) },
    { tag: 0x8769, type: 4, ptr: 1 },
    { tag: 0x8825, type: 4, ptr: 2 },
  ];
  const exifIfd = [{ tag: 0x9003, type: 2, value: ascii(dateTimeOriginal) }];
  const gpsIfd = [
    { tag: 1, type: 2, value: ascii(lat >= 0 ? 'N' : 'S') },
    { tag: 2, type: 5, value: rationals(dms(lat)) },
    { tag: 3, type: 2, value: ascii(lon >= 0 ? 'E' : 'W') },
    { tag: 4, type: 5, value: rationals(dms(lon)) },
    { tag: 29, type: 2, value: ascii(gpsDate) },
  ];
  ifds.push(ifd0, exifIfd, gpsIfd);
  const ifdSize = es => 2 + es.length * 12 + 4;
  const extSize = es => es.reduce((n, e) => n + (e.value && e.value.length > 4 ? e.value.length + (e.value.length & 1) : 0), 0);
  const offsets = []; let off = 8;
  for (const es of ifds) { offsets.push(off); off += ifdSize(es) + extSize(es); }
  const tiff = Buffer.alloc(off);
  tiff.write('MM', 0, 'latin1'); tiff.writeUInt16BE(42, 2); tiff.writeUInt32BE(8, 4);
  ifds.forEach((es, k) => {
    let p = offsets[k], ext = p + ifdSize(es);
    tiff.writeUInt16BE(es.length, p); p += 2;
    for (const e of es) {
      const unit = { 2: 1, 4: 4, 5: 8 }[e.type];
      tiff.writeUInt16BE(e.tag, p); tiff.writeUInt16BE(e.type, p + 2);
      if (e.ptr) { tiff.writeUInt32BE(1, p + 4); tiff.writeUInt32BE(offsets[e.ptr], p + 8); }
      else {
        tiff.writeUInt32BE(e.value.length / unit, p + 4);
        if (e.value.length <= 4) e.value.copy(tiff, p + 8);
        else { tiff.writeUInt32BE(ext, p + 8); e.value.copy(tiff, ext); ext += e.value.length + (e.value.length & 1); }
      }
      p += 12;
    }
    tiff.writeUInt32BE(0, p);
  });
  const body = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]);
  const head = Buffer.alloc(4); head[0] = 0xff; head[1] = 0xe1; head.writeUInt16BE(body.length + 2, 2);
  return Buffer.concat([head, body]);
}
// The pixels come from the browser's own JPEG encoder (canvas), so the file always decodes; the EXIF is spliced in after SOI.
async function gpsJpeg(page, exif) {
  const b64 = await page.evaluate(() => {
    const c = document.createElement('canvas'); c.width = 96; c.height = 64;
    const g = c.getContext('2d');
    const grd = g.createLinearGradient(0, 0, 96, 64); grd.addColorStop(0, '#2a6f97'); grd.addColorStop(1, '#f4a261');
    g.fillStyle = grd; g.fillRect(0, 0, 96, 64); g.fillStyle = '#fff'; g.fillRect(30, 20, 36, 24);
    return c.toDataURL('image/jpeg', 0.9).split(',')[1];
  });
  const jpg = Buffer.from(b64, 'base64');
  return Buffer.concat([jpg.subarray(0, 2), exifApp1(exif), jpg.subarray(2)]);
}
const INVENTED_PHOTO = { make: 'InventedCam', model: 'IC-1', dateTimeOriginal: '2021:06:14 09:30:12', lat: 12.5, lon: -30.25, gpsDate: '2021:06:14' }; // open Atlantic

// ---------- Page fixture: hermetic network + error capture ----------
const LOCAL = /^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?\//;
const test = base.extend({
  errors: async ({}, use) => { await use([]); },
  page: async ({ page, errors }, use) => {
    page.on('pageerror', e => errors.push(`pageerror: ${e.message}`));
    page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) errors.push(`console.error: ${m.text()}`); });
    // Only the app under test is reachable. claude.ai gets a stub page; fonts, maps and explorers are cut off.
    await page.context().route('**/*', route => {
      const u = route.request().url();
      if (LOCAL.test(u) || u.startsWith('data:') || u.startsWith('blob:')) return route.continue();
      if (u.startsWith('https://claude.ai/')) return route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>Claude (stub)</title><p>stub</p>' });
      return route.abort();
    });
    await page.addInitScript(() => {
      window.__sbComplete = 0;
      document.addEventListener('sb:case-complete', () => { window.__sbComplete++; });
    });
    await use(page);
    expect(errors, 'no page errors or console errors').toEqual([]);
  },
});

async function openApp(page, { mode = 'investigator' } = {}) {
  await page.goto('./');
  await page.waitForFunction(() => window.ScamBunker && document.querySelector('#pill-local.on'));
  await page.waitForFunction(() => document.documentElement.hasAttribute('data-static') || document.querySelector('#pill-web.on'));
  // Guard against a reused local server that has a paid provider configured.
  if (!(await page.evaluate(() => window.ScamBunker.isStatic()))) expect(await page.evaluate(() => window.ScamBunker.server().ai), 'test server must run without an AI provider').toBe(false);
  await setMode(page, mode);
}

// Simple/Investigator modes (docs/PRODUCT.md) land in a parallel PR, so everything here is defensive:
// before ScamBunker.mode exists the app has only the full report, which is what investigator tests need.
const hasModes = page => page.evaluate(() => typeof window.ScamBunker?.mode === 'function');
async function setMode(page, mode) {
  if (!(await hasModes(page)) || (await page.evaluate(() => window.ScamBunker.mode())) === mode) return;
  const viaApi = await page.evaluate(m => { const f = window.ScamBunker.setMode; if (typeof f !== 'function') return false; f(m); return true; }, mode);
  if (!viaApi) {
    const label = mode === 'investigator' ? /investigator/i : /simple/i;
    const toggle = page.locator(`[data-mode-set="${mode}"], [data-mode="${mode}"]`).or(page.getByRole('button', { name: label })).or(page.getByRole('switch', { name: /investigator|mode/i })).first();
    await toggle.click();
  }
  await page.waitForFunction(m => window.ScamBunker.mode() === m, mode, { timeout: 5000 });
}

// Runs `start` (a click that opens a case) and waits until the case has fully completed.
async function completeCase(page, start) {
  const before = await page.evaluate(() => window.__sbComplete);
  await start();
  await page.waitForFunction(n => window.__sbComplete > n, before, { timeout: 45_000 });
  // Simple mode shows the plain answer card; Investigator mode shows the full report.
  const simple = await page.evaluate(() => typeof window.ScamBunker?.mode === 'function' && window.ScamBunker.mode() === 'simple');
  if (simple) await expect(page.locator('[data-tour=verdict]')).toBeVisible();
  else { await expect(page.locator('#report')).toBeVisible(); await expect(page.locator('#go')).toBeEnabled(); }
}
// Simple mode has its own example chips with the same data-sample keys; click whichever is visible in the current mode.
const runSample = (page, key) => completeCase(page, () => page.click(`[data-sample="${key}"]:visible`));
async function runText(page, text) {
  await page.fill('#text', text); await page.fill('#url', '');
  await completeCase(page, () => page.click('#go'));
}
async function runImage(page, file, text = '') {
  await page.setInputFiles('#file', file);
  await expect(page.locator('#drop-full')).toBeVisible();
  await page.fill('#text', text); await page.fill('#url', '');
  await completeCase(page, () => page.click('#go'));
}
const visibleTabs = page => page.locator('#tabs [role=tab]:not([hidden])');

module.exports = { test, expect, hasModes, setMode, INVENTED_WALLET, INVENTED_PHOTO, SAMPLE_VERDICTS, aiPng, gpsJpeg, exifApp1, openApp, completeCase, runSample, runText, runImage, visibleTabs };
