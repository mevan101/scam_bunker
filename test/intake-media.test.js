// Zero-dependency tests for public/intake-media.js: screenshot heuristic, EXIF probe, QR payload analysis and quishing.
// All data is invented. Run: node test/intake-media.test.js (also part of npm test)
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const ctx = { window: {}, URL, URLSearchParams, console }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/scam.js'), 'utf8'), ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/intake-media.js'), 'utf8'), ctx);
const M = ctx.window.ScamBunkerIntakeMedia, H = ctx.window.DeduceHeuristics;
const { encode, qrPng } = require('./fixtures/qr-encode');
let n = 0; const ok = (name, fn) => { fn(); n++; console.log('✓ ' + name); };

// ---------- synthetic pixels ----------
function img(w, h, paint) { const data = new Uint8ClampedArray(w * h * 4); for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) { const [r, g, b] = paint(x, y); const o = (y * w + x) * 4; data[o] = r; data[o + 1] = g; data[o + 2] = b; data[o + 3] = 255; } return { data, width: w, height: h }; }
// An app screen: white background, grey status bar, rows of black "text" strokes.
const ui = img(180, 390, (x, y) => y < 14 ? [240, 240, 240] : (y % 22 > 8 && y % 22 < 16 && x > 12 && x < 160 && (x % 7 < 3)) ? [20, 20, 20] : [255, 255, 255]);
// A camera-like photo: smooth gradient plus noise everywhere.
let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
const photo = img(240, 180, (x, y) => { const v = 80 + x * 0.4 + y * 0.3 + rnd() * 40; return [v, v * 0.9, v * 0.7]; });

ok('pixel features separate a UI screen from a photo', () => {
  const a = M.pixelFeatures(ui), b = M.pixelFeatures(photo);
  assert(a.flatRatio > 0.55, 'UI flat ratio ' + a.flatRatio);
  assert(a.textRowRatio > 0.2, 'UI text rows ' + a.textRowRatio);
  assert(b.flatRatio < 0.3, 'photo flat ratio ' + b.flatRatio);
  assert(a.paletteSize < b.paletteSize, 'UI palette is smaller');
});
ok('phone screenshot PNG is a screenshot', () => {
  const r = M.screenshotScore({ width: 1080, height: 2340, format: 'PNG', name: 'Screenshot_20250101-101010.png', hasExif: false, hasCamera: false, pixels: M.pixelFeatures(ui) });
  assert(r.isScreenshot && r.score >= 0.9, JSON.stringify(r));
  assert(r.reasons.some(x => /file name/.test(x)));
});
ok('screenshot with a neutral name is still detected from shape and pixels', () => {
  const r = M.screenshotScore({ width: 1170, height: 2532, format: 'JPEG', name: 'IMG-20250101-WA0003.jpg', hasExif: false, hasCamera: false, pixels: M.pixelFeatures(ui) });
  assert(r.isScreenshot, JSON.stringify(r));
});
ok('camera photo with EXIF is not a screenshot', () => {
  const r = M.screenshotScore({ width: 4032, height: 3024, format: 'JPEG', name: 'IMG_1234.JPG', hasExif: true, hasCamera: true, pixels: M.pixelFeatures(photo) });
  assert(!r.isScreenshot && r.score === 0, JSON.stringify(r));
});
ok('stripped photo from a chat app is not a screenshot', () => {
  const r = M.screenshotScore({ width: 1600, height: 1200, format: 'JPEG', name: 'photo.jpg', hasExif: false, hasCamera: false, pixels: M.pixelFeatures(photo) });
  assert(!r.isScreenshot, JSON.stringify(r));
});

// ---------- EXIF probe ----------
function exifJpeg(withCamera) {
  // JPEG SOI + APP1 Exif with a little-endian TIFF, IFD0 holding Make (0x010F) or only Orientation (0x0112).
  const tag = withCamera ? 0x010F : 0x0112;
  const tiff = Buffer.from([0x49, 0x49, 0x2A, 0, 8, 0, 0, 0, 1, 0, tag & 255, tag >> 8, 3, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
  const body = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]);
  const len = Buffer.alloc(2); len.writeUInt16BE(body.length + 2);
  return new Uint8Array(Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE1]), len, body, Buffer.from([0xFF, 0xD9])]));
}
ok('EXIF probe finds camera make', () => { const r = M.exifCamera(exifJpeg(true)); assert(r.hasExif && r.hasCamera); assert.strictEqual(M.formatOf(exifJpeg(true)), 'JPEG'); });
ok('EXIF probe: EXIF without camera fields', () => { const r = M.exifCamera(exifJpeg(false)); assert(r.hasExif && !r.hasCamera); });
ok('EXIF probe: none in a PNG', () => { const png = new Uint8Array(qrPng('hello')); const r = M.exifCamera(png); assert(!r.hasExif); assert.strictEqual(M.formatOf(png), 'PNG'); });

// ---------- OCR clean-up ----------
ok('OCR clean-up drops noise lines and keeps Bangla', () => {
  const t = M.cleanOcr('  ~ |\nআপনার বিকাশ  অ্যাকাউন্ট   বন্ধ\n\n\n\n.\nCall now  ');
  assert.strictEqual(t, 'আপনার বিকাশ অ্যাকাউন্ট বন্ধ\n\nCall now');
});

// ---------- QR payloads ----------
const az = (raw, context = '', domainAge = null) => M.analyzeQr(raw, { context, analyzeUrl: H.analyzeUrl, domainAge });
ok('plain URL QR: "This QR code opens <domain>"', () => {
  const a = az('https://example.org/menu');
  assert.strictEqual(a.kind, 'url'); assert.strictEqual(a.domain, 'example.org');
  assert(/^This QR code opens example\.org\.$/.test(a.reasons[0].text), a.reasons[0].text);
  assert.strictEqual(a.quishing, null); assert.strictEqual(a.reasons[0].weight, 'weak');
});
ok('parking QR to a lookalike domain is strong quishing', () => {
  const a = az('https://paypa1-parking.top/pay?zone=42', 'PAY PARKING HERE\nScan to pay with PayPal');
  assert.strictEqual(a.quishing, 'strong', JSON.stringify(a.reasons));
  assert(/pay for parking/.test(a.reasons[0].text) && /quishing/.test(a.reasons[0].text), a.reasons[0].text);
  assert(a.actions.some(x => /bank/.test(x.text)) && a.actions.some(x => /sticker/.test(x.text)));
});
ok('login QR on a newly registered domain is strong quishing', () => {
  const a = az('https://mail-verify-portal.example/', 'Your password expires today. Scan to verify your account', { ageDays: 3 });
  assert.strictEqual(a.quishing, 'strong');
  assert(a.reasons.some(r => /registered only 3 days ago/.test(r.text)));
});
ok('brand named in the image but QR opens another domain', () => {
  const a = az('https://bkash-reward-bd.example/login', 'bKash: verify your account to claim the reward');
  assert.strictEqual(a.quishing, 'strong');
  assert(a.reasons.some(r => /that is not bKash's real one/.test(r.text)), JSON.stringify(a.reasons));
});
ok('brand QR that opens the real domain is not flagged', () => {
  const a = az('https://www.bkash.com/en/help', 'bKash help: scan to log in to the app');
  assert.strictEqual(a.quishing, null, JSON.stringify(a.reasons));
});
ok('payment poster to a shortener is suspicious, not proof', () => {
  const a = az('https://bit.ly/3xYzAbc', 'Scan to pay your bill');
  assert.strictEqual(a.quishing, 'suspicious'); assert(/shortener/.test(a.reasons[0].text));
});
ok('domain 3-6 months old adds a moderate reason', () => {
  const a = az('https://example-shop.example/', '', { ageDays: 75 });
  assert(a.reasons.some(r => r.weight === 'moderate' && /75 days/.test(r.text)));
});
ok('EMVCo payment QR shows the merchant; "receive money" story is strong', () => {
  const emv = '000201010211' + '5204000053030505802BD' + '5913INVENTED SHOP' + '6005Dhaka' + '6304ABCD';
  const p = M.parseEmv(emv); assert.strictEqual(p.merchant, 'INVENTED SHOP'); assert.strictEqual(p.city, 'Dhaka');
  const a = az(emv, 'অভিনন্দন! টাকা পেতে এই QR কোড স্ক্যান করুন');
  assert.strictEqual(a.quishing, 'strong'); assert(/never puts money/.test(a.reasons[0].text));
  assert(az(emv, 'Thanks for shopping').quishing === null);
});
ok('UPI request to "get a refund" is strong', () => {
  const a = az('upi://pay?pa=invented@upi&pn=Invented%20Refunds&am=4999', 'Scan this QR code to receive your refund');
  assert.strictEqual(a.kind, 'upi'); assert.strictEqual(a.quishing, 'strong'); assert(/Invented Refunds/.test(a.reasons[a.reasons.length - 1].text));
});
ok('other payload kinds', () => {
  assert.strictEqual(M.classifyPayload('WIFI:T:nopass;S:Free Airport WiFi;;').ssid, 'Free Airport WiFi');
  assert.strictEqual(M.classifyPayload('bitcoin:bc1qinventedaddressxxxxxxxxxxxxxxxxxxxx?amount=0.1').kind, 'crypto');
  assert.strictEqual(M.classifyPayload('SMSTO:+15550100:STOP').body, 'STOP');
  assert.strictEqual(M.classifyPayload('SMSTO:+15550100:Save 20% today').body, 'Save 20% today');
  assert.strictEqual(M.classifyPayload('otpauth://totp/Invented?secret=ABC').kind, 'otp');
  assert.strictEqual(M.classifyPayload('Hello there').kind, 'text');
  assert(/Wi-Fi network called "Free Airport WiFi", which has no password/.test(az('WIFI:T:nopass;S:Free Airport WiFi;;').reasons[0].text));
});
ok('registrable domain and RDAP age', () => {
  assert.strictEqual(M.registrable('login.secure.example.com.bd'), 'example.com.bd');
  assert.strictEqual(M.registrable('a.b.example.top'), 'example.top');
  const r = M.rdapAge({ events: [{ eventAction: 'registration', eventDate: '2026-01-01T00:00:00Z' }] }, Date.parse('2026-01-11T00:00:00Z'));
  assert.strictEqual(r.ageDays, 10); assert.strictEqual(M.rdapAge({ events: [] }), null);
});
ok('QR case text feeds the normal engines (link is analysed like a pasted one)', () => {
  const a = az('http://paypa1.com.secure-verify.top/login');
  const h = H.analyze({ text: a.caseText });
  assert(h.links.some(l => l.host === 'paypa1.com.secure-verify.top' && l.risk >= 30));
});
ok('fixture encoder produces a valid-size matrix', () => {
  assert.strictEqual(encode('hi').length, 21); assert.strictEqual(encode('https://paypa1-parking.top/pay?zone=42').length, 29);
});
ok('every pinned CDN asset is an exact version on jsDelivr', () => {
  const urls = [M.CDN.tesseract.src, M.CDN.tesseractWorker, M.CDN.tesseractCore, M.CDN.lang.eng, M.CDN.lang.ben, M.CDN.jsqr.src];
  urls.forEach(u => assert(/^https:\/\/cdn\.jsdelivr\.net\/npm\/(@[\w.-]+\/)?[\w.-]+@\d+\.\d+\.\d+(\/|$)/.test(u), u));
  assert(/^sha384-/.test(M.CDN.tesseract.integrity) && /^sha384-/.test(M.CDN.jsqr.integrity));
});
console.log(`✓ ${n} intake-media tests passed`);
