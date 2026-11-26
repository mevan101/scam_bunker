// Scam Bunker — screenshot and QR-code intake (PRODUCT.md "Inputs to support" 3 and 4).
// Two intake adapters for ScamBunker.registerIntake: on-device OCR of screenshots (English + Bangla, tesseract.js)
// and on-device QR decoding (BarcodeDetector, else jsQR). Both libraries are lazy-loaded from jsDelivr at exact,
// pinned versions, only when an image needs them, so the app itself keeps zero npm dependencies. The image never
// leaves the device: only the OCR engine and its language data are downloaded (once, then cached).
// Without registerIntake (older shell) the module fills the text and link fields from the dropped image instead.
// Pure helpers are exported as window.ScamBunkerIntakeMedia and unit-tested in test/intake-media.test.js.
(function () {
  'use strict';
  const root = typeof window !== 'undefined' ? window : globalThis;

  // ---------- Pinned CDN assets (exact versions; update together, after the release is at least two weeks old) ----------
  const JSD = 'https://cdn.jsdelivr.net/npm/';
  const CDN = {
    tesseract: { src: JSD + 'tesseract.js@7.0.0/dist/tesseract.min.js', integrity: 'sha384-2BQ3U3OdKOb0Uczxqr41I9UvZkzr4V9Hv8uSzMMZAlmhsFClvdZX5wi5fDCzG+tM' },
    tesseractWorker: JSD + 'tesseract.js@7.0.0/dist/worker.min.js',
    tesseractCore: JSD + 'tesseract.js-core@7.0.0',
    lang: { eng: JSD + '@tesseract.js-data/eng@1.0.0/4.0.0_best_int/eng.traineddata.gz', ben: JSD + '@tesseract.js-data/ben@1.0.0/4.0.0_best_int/ben.traineddata.gz' },
    jsqr: { src: JSD + 'jsqr@1.4.0/dist/jsQR.js', integrity: 'sha384-b5Ya4Bq3qCyz39m2ISh+4DxjAIljdeFwK/BsXLuj9gugaNwAcj/ia15fxNZL9Nlx' },
  };
  const LANG_CACHE = 'scambunker-ocr-v1';
  const LANG_PATH = 'https://lang.scambunker.invalid';

  // ---------- Screenshot heuristic (pure) ----------
  // Common screen widths in device pixels (phones and desktops). A match is a hint, never proof.
  const SCREEN_WIDTHS = [640, 720, 750, 828, 1080, 1125, 1170, 1179, 1206, 1242, 1284, 1290, 1320, 1440, 1280, 1366, 1536, 1600, 1920, 2560, 2880, 3024, 3840];
  const SCREENSHOT_NAME = /screen ?shot|screen[_-]?capture|scrnli|^scr[_-]|^ss[_-]\d|snip|স্ক্রিনশট/i;

  // Pixel features from a downscaled RGBA buffer ({ data, width, height }).
  function pixelFeatures(img) {
    const { data, width: w, height: h } = img;
    if (!w || !h) return null;
    const g = new Float32Array(w * h);
    for (let i = 0, p = 0; p < g.length; i += 4, p++) g[p] = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
    let flat = 0, cells = 0, textRows = 0;
    const palette = new Map();
    for (let y = 1; y < h; y++) {
      let trans = 0;
      for (let x = 1; x < w; x++) {
        const p = y * w + x, dx = Math.abs(g[p] - g[p - 1]), dy = Math.abs(g[p] - g[p - w]);
        cells++; if (dx < 4 && dy < 4) flat++;
        if (dx > 48) trans++;
      }
      const t = trans / w; if (t > 0.02 && t < 0.5) textRows++;
    }
    for (let i = 0; i < data.length; i += 4) { const k = (data[i] >> 4) << 8 | (data[i + 1] >> 4) << 4 | data[i + 2] >> 4; palette.set(k, (palette.get(k) || 0) + 1); }
    const minCount = Math.max(1, (w * h) / 1000);
    const paletteSize = [...palette.values()].filter(n => n >= minCount).length;
    // Top band (status bar / app bar): share of pixels close to the band's most common grey.
    const band = Math.max(2, Math.round(h * 0.04)), hist = new Uint32Array(32);
    for (let p = 0; p < band * w; p++) hist[g[p] >> 3]++;
    const mode = hist.indexOf(Math.max(...hist));
    let near = 0; for (let p = 0; p < band * w; p++) if (Math.abs((g[p] >> 3) - mode) <= 1) near++;
    let sum = 0; for (let p = 0; p < g.length; p++) sum += g[p];
    return { flatRatio: +(flat / cells).toFixed(3), textRowRatio: +(textRows / (h - 1)).toFixed(3), topBandUniform: +(near / (band * w)).toFixed(3), paletteSize, meanLuma: Math.round(sum / g.length) };
  }

  // f: { width, height, format, name, hasCamera, hasExif, pixels: pixelFeatures() }. Returns a score 0..1 and plain reasons.
  function screenshotScore(f) {
    let s = 0; const why = [];
    const w = f.width || 0, h = f.height || 0, px = f.pixels || {};
    if (f.hasCamera) { s -= 0.6; why.push('the file has camera details (make, model or exposure), like a photo'); }
    if (SCREENSHOT_NAME.test(f.name || '')) { s += 0.45; why.push('the file name says it is a screenshot'); }
    if (f.format === 'PNG') { s += 0.15; why.push('it is a PNG, the format phones and computers save screenshots in'); }
    if (!f.hasExif) s += 0.05;
    if (w && h) {
      const portrait = h / w, landscape = w / h;
      if (portrait >= 1.7 && portrait <= 2.4) { s += 0.15; why.push('it has the tall shape of a phone screen'); }
      else if (landscape >= 1.55 && landscape <= 1.8) { s += 0.1; why.push('it has the shape of a computer screen'); }
      if (SCREEN_WIDTHS.includes(w) || SCREEN_WIDTHS.includes(h)) s += 0.1;
    }
    if (px.flatRatio > 0.55) { s += 0.25; why.push('large flat areas of colour, like an app or web page'); } else if (px.flatRatio > 0.4) s += 0.12;
    if (px.textRowRatio > 0.2) { s += 0.2; why.push('many lines that look like text'); } else if (px.textRowRatio > 0.1) s += 0.1;
    if (px.topBandUniform > 0.85) s += 0.05;
    if (px.paletteSize && px.paletteSize < 60) s += 0.1;
    const score = Math.max(0, Math.min(1, +s.toFixed(2)));
    return { score, isScreenshot: score >= 0.5, reasons: why };
  }

  // Minimal EXIF probe: does the file carry camera details? (Make/Model in IFD0, ExposureTime/FNumber/ISO in the Exif IFD.)
  function exifCamera(u8) {
    const out = { hasExif: false, hasCamera: false, hasGps: false };
    const n = Math.min(u8.length, 1 << 20);
    let at = -1;
    for (let i = 0; i < n - 6; i++) if (u8[i] === 0x45 && u8[i + 1] === 0x78 && u8[i + 2] === 0x69 && u8[i + 3] === 0x66 && u8[i + 4] === 0 && u8[i + 5] === 0) { at = i + 6; break; }
    if (at < 0) return out;
    out.hasExif = true;
    try {
      const le = u8[at] === 0x49, r16 = o => le ? u8[o] | u8[o + 1] << 8 : u8[o] << 8 | u8[o + 1], r32 = o => (le ? (u8[o] | u8[o + 1] << 8 | u8[o + 2] << 16 | u8[o + 3] << 24) : (u8[o] << 24 | u8[o + 1] << 16 | u8[o + 2] << 8 | u8[o + 3])) >>> 0;
      const tags = off => { const s = new Set(), base = at + off, cnt = r16(base); for (let k = 0; k < cnt && k < 300; k++) { const e = base + 2 + k * 12; s.add(r16(e)); if (r16(e) === 0x8769) s.exifPtr = r32(e + 8); } return s; };
      const ifd0 = tags(r32(at + 4));
      out.hasGps = ifd0.has(0x8825);
      let cam = ifd0.has(0x010F) || ifd0.has(0x0110);
      if (!cam && ifd0.exifPtr) { const ex = tags(ifd0.exifPtr); cam = ex.has(0x829A) || ex.has(0x829D) || ex.has(0x8827); }
      out.hasCamera = cam;
    } catch { }
    return out;
  }
  const formatOf = u8 => u8[0] === 0x89 && u8[1] === 0x50 ? 'PNG' : u8[0] === 0xFF && u8[1] === 0xD8 ? 'JPEG' : u8[8] === 0x57 && u8[9] === 0x45 && u8[10] === 0x42 && u8[11] === 0x50 ? 'WEBP' : u8[0] === 0x47 && u8[1] === 0x49 ? 'GIF' : 'other';

  // ---------- OCR text clean-up (pure) ----------
  function cleanOcr(t) {
    return String(t || '').split(/\r?\n/).map(l => l.replace(/[ \t\u00a0]+/g, ' ').trim())
      .filter(l => !l || (l.match(/[\p{L}\p{N}]/gu) || []).length >= 2)
      .join('\n').replace(/\n{3,}/g, '\n\n').trim();
  }

  // ---------- QR payload analysis (pure) ----------
  const PURPOSES = [
    ['parking', /\b(parking|park ?(and|&) ?pay|pay ?(and|&) ?display|parking meter|meter|penalty charge|parking fine)\b|পার্কিং/i, 'pay for parking'],
    ['payment', /\b(pay|payment|bill|invoice|fine|toll|fee|donat(e|ion)|checkout|bkash|nagad|rocket|upi|scan to pay|cash ?back|refund|unpaid|overdue)\b|পেমেন্ট|পরিশোধ|বিল|টাকা|বিকাশ|নগদ/i, 'make a payment'],
    ['login', /\b(log ?in|sign ?in|verify|verification|password|account|2fa|mfa|multi-?factor|authenticat\w*|re-?activate|security update|voicemail|shared (a )?document|docusign|payroll|benefits)\b|লগইন|যাচাই|অ্যাকাউন্ট|পাসওয়ার্ড/i, 'log in or verify your account'],
    ['delivery', /\b(parcel|package|delivery|redeliver\w*|courier|customs fee|shipment|tracking)\b|পার্সেল|ডেলিভারি/i, 'sort out a delivery'],
  ];
  const RECEIVE = /\b(receive|get|claim|collect)\b[^.!?\n]{0,30}\b(money|payment|refund|prize|reward|cash|funds)\b|\b(you (have )?won|cash ?back|refund)\b|টাকা পাবেন|টাকা পেতে|ফেরত|পুরস্কার/i;
  // Brands with their real domains. A login or payment QR that names one but opens another domain is a strong quishing sign.
  const OFFICIAL = {
    bkash: ['bkash.com'], nagad: ['nagad.com.bd'], 'rocket': ['dutchbanglabank.com'], paypal: ['paypal.com', 'paypal.me'], microsoft: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'sharepoint.com'],
    'office 365': ['office.com', 'microsoft.com', 'microsoftonline.com'], outlook: ['outlook.com', 'live.com', 'office.com'], google: ['google.com', 'goo.gl', 'g.co'], docusign: ['docusign.com', 'docusign.net'],
    amazon: ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amzn.to'], netflix: ['netflix.com'], apple: ['apple.com'], dhl: ['dhl.com'], fedex: ['fedex.com'], usps: ['usps.com'], 'royal mail': ['royalmail.com'],
    whatsapp: ['whatsapp.com', 'wa.me'], facebook: ['facebook.com', 'fb.com', 'fb.me'], instagram: ['instagram.com'], binance: ['binance.com'], coinbase: ['coinbase.com'],
  };
  const MULTI_SUFFIX = /^(com|net|org|gov|edu|ac|co|or|ne|go|mil|info|biz|ltd|plc|nic|gob)\.[a-z]{2}$/;
  function registrable(host) {
    const p = String(host || '').toLowerCase().replace(/\.$/, '').split('.');
    if (p.length <= 2 || /^\d+$/.test(p[p.length - 1])) return p.join('.');
    return MULTI_SUFFIX.test(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.');
  }
  const SHORT = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly|rebrand\.ly|shorturl\.at|tiny\.cc|rb\.gy|t\.ly|s\.id|qrco\.de|qr\.page|bl\.ink|lnkd\.in)$/i;

  // EMVCo merchant-presented QR (used by bKash, Nagad, UPI, PayNow and most bank QR codes): top-level TLV fields.
  function parseEmv(s) {
    if (!/^000201/.test(s)) return null;
    const f = {}; let i = 0;
    while (i + 4 <= s.length) { const id = s.slice(i, i + 2), len = parseInt(s.slice(i + 2, i + 4), 10); if (!(len >= 0)) break; f[id] = s.slice(i + 4, i + 4 + len); i += 4 + len; }
    return { merchant: f['59'] || '', city: f['60'] || '', amount: f['54'] || '', currency: f['53'] || '', country: f['58'] || '' };
  }

  function classifyPayload(raw) {
    const s = String(raw || '').trim();
    if (/^https?:\/\//i.test(s)) return { kind: 'url', url: s };
    if (/^www\.[^\s]+\.[a-z]{2,}/i.test(s)) return { kind: 'url', url: 'https://' + s };
    if (/^upi:\/\/pay/i.test(s)) { let q; try { q = new URL(s).searchParams; } catch { q = new URLSearchParams(s.split('?')[1] || ''); } return { kind: 'upi', payee: q.get('pa') || '', name: q.get('pn') || '', amount: q.get('am') || '' }; }
    const emv = parseEmv(s); if (emv) return { kind: 'emv', ...emv };
    let m;
    if ((m = /^(bitcoin|ethereum|litecoin|tron|usdt|dogecoin):([^?\s]+)/i.exec(s))) return { kind: 'crypto', chain: m[1].toLowerCase(), address: m[2] };
    if (/^(bc1[0-9a-z]{20,80}|[13][1-9A-HJ-NP-Za-km-z]{25,34}|0x[0-9a-fA-F]{40}|T[1-9A-HJ-NP-Za-km-z]{33})$/.test(s)) return { kind: 'crypto', chain: '', address: s };
    if ((m = /^WIFI:(.*)$/i.exec(s))) { const g = k => (new RegExp('(?:^|;)' + k + ':((?:\\\\.|[^;])*)').exec(m[1]) || [])[1] || ''; return { kind: 'wifi', ssid: g('S').replace(/\\(.)/g, '$1'), security: g('T') || 'nopass' }; }
    if ((m = /^tel:(.+)$/i.exec(s))) return { kind: 'tel', number: m[1] };
    if ((m = /^(?:sms|smsto):([^:?]+)(?:[:?](?:body=)?(.*))?$/i.exec(s))) return { kind: 'sms', number: m[1], body: safeDecode((m[2] || '').replace(/\+/g, ' ')) };
    if ((m = /^mailto:([^?]+)/i.exec(s))) return { kind: 'email', address: m[1] };
    if (/^otpauth:\/\//i.test(s)) return { kind: 'otp' };
    if (/^(whatsapp|tg|viber|intent|market|itms-apps?):/i.test(s)) return { kind: 'app', scheme: s.split(':')[0].toLowerCase() };
    return { kind: 'text', text: s };
  }

  const purposesIn = t => PURPOSES.filter(([, re]) => re.test(t)).map(([id, , words]) => ({ id, words }));
  const short = (s, n = 80) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

  // Analyse one decoded QR payload. ctx: { context: text around the QR (OCR text, the message), analyzeUrl, domainAge: { ageDays } | null }.
  // Returns { kind, host, domain, reasons: [{ text, weight }], actions: [{ text, href? }], quishing: 'strong' | 'suspicious' | null, caseText }.
  function analyzeQr(raw, ctx = {}) {
    const p = classifyPayload(raw), context = String(ctx.context || ''), reasons = [], actions = [];
    const purposes = purposesIn(context);
    const out = { kind: p.kind, payload: String(raw || ''), reasons, actions, quishing: null, caseText: `QR code: ${String(raw || '').trim()}` };
    const purposeWords = purposes.length ? purposes[0].words : '';
    if (p.kind === 'url') {
      let u; try { u = new URL(p.url); } catch { }
      const host = u ? u.hostname.toLowerCase().replace(/^www\./, '') : '';
      const domain = registrable(host); out.host = host; out.domain = domain; out.url = p.url;
      const a = ctx.analyzeUrl ? ctx.analyzeUrl(p.url) : { flags: [], risk: 0 };
      out.risk = a.risk || 0;
      const urlPurposes = purposesIn(u ? (u.hostname + ' ' + u.pathname) : '');
      const all = purposes.length ? purposes : urlPurposes;
      const why = [];
      if (a.risk >= 30) why.push(plainFlag(a.flags.find(f => !/^Not encrypted|^Credential/.test(f)) || a.flags[0]));
      if (SHORT.test(host)) why.push('a link shortener that hides where it really goes');
      const age = ctx.domainAge && ctx.domainAge.ageDays;
      if (age != null && age < 30) why.push(`a website registered only ${age === 1 ? '1 day' : age + ' days'} ago`);
      const named = Object.keys(OFFICIAL).filter(b => new RegExp('\\b' + b + '\\b', 'i').test(context));
      // Only a mismatch when the code opens none of the brands the image names (a checkout may list several).
      const isOfficial = b => OFFICIAL[b].some(d => domain === d || host.endsWith('.' + d) || host === d);
      const mismatch = named.length && !named.some(isOfficial) ? named[0] : null;
      if (mismatch && all.length) why.push(`a website that is not ${titleCase(mismatch)}'s real one`);
      if (u && u.protocol === 'http:' && all.some(x => x.id !== 'delivery')) why.push('an unencrypted (http) page');
      reasons.push({ text: `This QR code opens ${host || p.url}.${why.length ? ` Warning signs: ${why.join('; ')}.` : ''}`, weight: why.length ? (a.risk >= 30 || mismatch || (age != null && age < 30) ? 'strong' : 'moderate') : 'weak', source: 'qr' });
      if (age != null && age >= 30 && age < 180) reasons.push({ text: `The website in the QR code (${domain}) was registered ${age} days ago. Real parking, bank and payment sites are usually years old.`, weight: 'moderate', source: 'qr' });
      if (all.length && why.length) {
        const strong = a.risk >= 30 || !!mismatch || (age != null && age < 30);
        out.quishing = strong ? 'strong' : 'suspicious';
        reasons[0] = { text: `This QR code opens ${host || p.url}. The image asks you to scan it to ${all[0].words}, but it leads to ${why.join('; ')}. This is a common QR code scam ("quishing").`, weight: strong ? 'strong' : 'moderate', source: 'qr' };
        actions.push({ text: `Do not scan it or enter anything. To ${all[0].words}, open the official app, or type the official website address yourself.` });
        if (all.some(x => x.id === 'parking')) actions.push({ text: 'Check the parking sign or meter for a sticker placed over the real code, and tell the parking operator.' });
        if (all.some(x => x.id === 'payment' || x.id === 'parking')) actions.push({ text: 'If you already paid or typed card details, call your bank using the number on the back of your card.' });
        if (all.some(x => x.id === 'login')) actions.push({ text: 'If you already typed a password, change it now from the real website and turn on two-step login.' });
      } else if (all.length) {
        actions.push({ text: `Before you ${all[0].words}, check that ${domain || host} is the official website. If you are not sure, type the address you know yourself.` });
      }
    } else if (p.kind === 'upi' || p.kind === 'emv') {
      const who = p.kind === 'upi' ? [p.name, p.payee && `(${p.payee})`].filter(Boolean).join(' ') : [p.merchant, p.city && `in ${p.city}`].filter(Boolean).join(' ');
      reasons.push({ text: `This is a payment QR code${who ? ` that pays ${who}` : ''}${p.amount ? `, amount ${p.amount}` : ''}. Scanning it sends money from you.`, weight: 'weak', source: 'qr' });
      if (RECEIVE.test(context)) {
        out.quishing = 'strong';
        reasons.unshift({ text: 'The message says you will receive money by scanning, but this QR code makes you pay. Scanning a QR code never puts money into your account.', weight: 'strong', source: 'qr' });
        actions.push({ text: 'Do not scan it or enter your PIN. Nobody needs your PIN or a QR scan to send you money.' });
      } else actions.push({ text: 'Before you pay, check that the name your payment app shows is exactly who you meant to pay.' });
      out.caseText = `QR code: payment QR${who ? ' to ' + who : ''}${p.amount ? ' amount ' + p.amount : ''}`;
    } else if (p.kind === 'crypto') {
      reasons.push({ text: `This QR code holds a ${p.chain ? p.chain + ' ' : ''}crypto wallet address. Crypto payments cannot be reversed if this is a scam.`, weight: 'moderate', source: 'qr' });
      actions.push({ text: 'Do not send crypto to an address from a QR code someone sent you, unless you already know and trust them through another channel.' });
      out.caseText = `QR code: ${p.chain ? p.chain + ' ' : ''}wallet ${p.address}`;
    } else if (p.kind === 'wifi') {
      reasons.push({ text: `This QR code joins a Wi-Fi network called "${short(p.ssid, 40)}"${/nopass/i.test(p.security) ? ', which has no password' : ''}. Avoid typing passwords or card details on networks you do not know.`, weight: 'weak', source: 'qr' });
    } else if (p.kind === 'tel' || p.kind === 'sms') {
      reasons.push({ text: `This QR code ${p.kind === 'tel' ? 'calls' : 'sends a text to'} ${p.number}${p.body ? ` saying "${short(p.body, 60)}"` : ''}. Paid "premium" numbers and fake support lines use this trick.`, weight: 'weak', source: 'qr' });
      out.caseText = `QR code: ${p.kind === 'tel' ? 'phone' : 'SMS to'} ${p.number}${p.body ? ' ' + p.body : ''}`;
    } else if (p.kind === 'email') {
      reasons.push({ text: `This QR code writes an email to ${p.address}.`, weight: 'weak', source: 'qr' });
    } else if (p.kind === 'otp') {
      out.quishing = 'suspicious';
      reasons.push({ text: 'This QR code adds a login code to an authenticator app. Only scan one that appears on a website you opened yourself; otherwise someone may be taking over an account.', weight: 'moderate', source: 'qr' });
    } else if (p.kind === 'app') {
      reasons.push({ text: `This QR code opens an app (${p.scheme}) instead of a website.`, weight: 'weak', source: 'qr' });
    } else {
      reasons.push({ text: `This QR code contains text: "${short(p.text, 100)}".`, weight: 'weak', source: 'qr' });
    }
    return out;
  }
  // URL-heuristic flags (scam.js) in plain words, as a phrase that fits "the code leads to …".
  function plainFlag(f) {
    f = String(f || '');
    let m;
    if ((m = f.match(/top-level domain \(([^)]+)\)/i))) return `an address ending in ${m[1]}, which is cheap and often used by scam sites`;
    if (/Punycode/i.test(f)) return 'an address that uses look-alike letters from other alphabets';
    if (/Raw IP/i.test(f)) return 'a bare number instead of a website name';
    if ((m = f.match(/brand name "([^"]+)"/i))) return `an address that uses the name "${m[1]}" but is not its real website`;
    if ((m = f.match(/(?:Look-alike spelling of|away from) "([^"]+)"/i))) return `an address spelled to look like "${m[1]}"`;
    if (/@/.test(f)) return 'an address that hides the real website after an "@"';
    if (/subdomain/i.test(f)) return 'a long address built to hide the real website at the end';
    if (/hyphens/i.test(f)) return 'a throwaway-looking address with several hyphens';
    if (/shortener/i.test(f)) return 'a link shortener that hides where it really goes';
    return f ? lower(f) : 'an address built to look like another website';
  }
  function safeDecode(s) { try { return decodeURIComponent(s); } catch { return s; } }
  function lower(s) { s = String(s).replace(/\s+—\s+/g, ', '); return s.charAt(0).toLowerCase() + s.slice(1); }
  function titleCase(s) { return s.replace(/\b\w/g, c => c.toUpperCase()).replace(/^Bkash$/, 'bKash'); }

  // RDAP JSON → { registeredAt, ageDays } (registration event).
  function rdapAge(j, now = Date.now()) {
    const ev = (j && j.events || []).find(e => String(e.eventAction).toLowerCase() === 'registration');
    const t = ev && Date.parse(ev.eventDate);
    return t ? { registeredAt: new Date(t).toISOString(), ageDays: Math.max(0, Math.floor((now - t) / 864e5)) } : null;
  }

  const API = { CDN, pixelFeatures, screenshotScore, exifCamera, formatOf, cleanOcr, classifyPayload, parseEmv, analyzeQr, registrable, rdapAge };
  root.ScamBunkerIntakeMedia = API;
  if (typeof document === 'undefined' || !document.createElement) return;

  // =====================================================================================================
  // Browser side
  // =====================================================================================================
  const SB = () => window.ScamBunker || {};
  const esc = s => (SB().esc ? SB().esc(s) : String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));
  const $ = s => document.querySelector(s);

  const scripts = {};
  function loadScript({ src, integrity }) {
    return scripts[src] = scripts[src] || new Promise((res, rej) => {
      const s = document.createElement('script');
      s.src = src; s.async = true; s.crossOrigin = 'anonymous'; if (integrity) s.integrity = integrity;
      s.onload = res; s.onerror = () => { delete scripts[src]; rej(new Error('Could not download ' + src.replace(JSD, '') + '. Check your connection.')); };
      document.head.appendChild(s);
    });
  }

  async function bitmapOf(file) {
    try { return await createImageBitmap(file); }
    catch {
      const url = URL.createObjectURL(file);
      try { const img = new Image(); img.src = url; await img.decode(); return img; } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
    }
  }
  function canvasOf(src, maxSide) {
    const sw = src.width || src.naturalWidth, sh = src.height || src.naturalHeight;
    const k = Math.min(1, maxSide / Math.max(sw, sh));
    const c = document.createElement('canvas'); c.width = Math.max(1, Math.round(sw * k)); c.height = Math.max(1, Math.round(sh * k));
    const x = c.getContext('2d', { willReadFrequently: true }); x.imageSmoothingQuality = 'high'; x.drawImage(src, 0, 0, c.width, c.height);
    return c;
  }

  // ---------- QR decoding ----------
  let detector;
  async function nativeDetector() {
    if (detector !== undefined) return detector;
    detector = null;
    try { if ('BarcodeDetector' in window && (await BarcodeDetector.getSupportedFormats()).includes('qr_code')) detector = new BarcodeDetector({ formats: ['qr_code'] }); } catch { }
    return detector;
  }
  // Returns the decoded payloads and where the codes sit (source pixels), so OCR can skip the QR pattern.
  async function decodeQr(bmp) {
    const found = new Set(), boxes = [];
    const d = await nativeDetector();
    if (d) { try { (await d.detect(bmp)).forEach(b => { if (!b.rawValue) return; found.add(b.rawValue); const r = b.boundingBox; if (r) boxes.push({ x: r.x, y: r.y, w: r.width, h: r.height }); }); } catch { } }
    if (!found.size) {
      await loadScript(CDN.jsqr);
      const sw = bmp.width || bmp.naturalWidth;
      for (const side of [1200, 640, 2000]) {
        const c = canvasOf(bmp, side), img = c.getContext('2d').getImageData(0, 0, c.width, c.height);
        const r = window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
        if (r && r.data) {
          found.add(r.data);
          const k = sw / c.width, L = r.location, xs = [L.topLeftCorner, L.topRightCorner, L.bottomLeftCorner, L.bottomRightCorner];
          const x0 = Math.min(...xs.map(p => p.x)), y0 = Math.min(...xs.map(p => p.y));
          boxes.push({ x: x0 * k, y: y0 * k, w: (Math.max(...xs.map(p => p.x)) - x0) * k, h: (Math.max(...xs.map(p => p.y)) - y0) * k });
          break;
        }
      }
    }
    return { values: [...found], boxes };
  }

  // ---------- OCR (tesseract.js, lazy) ----------
  async function langData(code, onBytes, signal) {
    const url = CDN.lang[code];
    let cache = null; try { cache = await caches.open(LANG_CACHE); } catch { }
    let res = cache && await cache.match(url);
    const cached = !!res;
    if (!res) {
      res = await fetch(url, { signal, mode: 'cors' });
      if (!res.ok) throw new Error(`Could not download the ${code === 'ben' ? 'Bangla' : 'English'} language data (HTTP ${res.status})`);
      if (cache) { try { await cache.put(url, res.clone()); } catch { } }
    }
    const total = +res.headers.get('content-length') || 0;
    if (!res.body || !total || cached) { const b = new Uint8Array(await res.arrayBuffer()); onBytes(b.length, b.length); return { code, data: b, cached }; }
    const reader = res.body.getReader(), parts = []; let got = 0;
    for (;;) { const { done, value } = await reader.read(); if (done) break; parts.push(value); got += value.length; onBytes(got, total); }
    const b = new Uint8Array(got); let o = 0; parts.forEach(p => { b.set(p, o); o += p.length; });
    return { code, data: b, cached };
  }

  async function runOcr(bmp, ui, signal, boxes) {
    ui.step('Downloading the text reader…', 0.02);
    await loadScript(CDN.tesseract);
    if (signal.aborted) throw abortErr();
    const bytes = { eng: [0, 1], ben: [0, 1] };
    const langs = await Promise.all(['eng', 'ben'].map(code => langData(code, (g, t) => { bytes[code] = [g, t]; const G = bytes.eng[0] + bytes.ben[0], T = bytes.eng[1] + bytes.ben[1]; ui.step('Downloading English and Bangla language data (once only)…', 0.05 + 0.45 * G / T); }, signal)));
    if (signal.aborted) throw abortErr();
    ui.step('Starting the text reader…', 0.5);
    // tesseract.js takes one langPath for all languages, but each language is its own pinned package. The worker
    // is started from a tiny boot script that answers its language requests with the bytes downloaded (and cached)
    // above, so nothing is fetched twice and the versions stay exact.
    const map = {}, blobs = [];
    langs.forEach(l => { const u = URL.createObjectURL(new Blob([l.data])); blobs.push(u); map[`${LANG_PATH}/${l.code}.traineddata.gz`] = u; });
    const boot = `const M=${JSON.stringify(map)},F=self.fetch.bind(self);self.fetch=(u,o)=>F(M[u]||u,o);importScripts(${JSON.stringify(CDN.tesseractWorker)});`;
    const bootUrl = URL.createObjectURL(new Blob([boot], { type: 'text/javascript' })); blobs.push(bootUrl);
    let worker;
    try {
      worker = await withAbort(window.Tesseract.createWorker(langs.map(l => l.code).join('+'), 1, {
        workerPath: bootUrl, workerBlobURL: false, corePath: CDN.tesseractCore, langPath: LANG_PATH, gzip: true, cacheMethod: 'none',
        logger: m => { if (m && m.status === 'recognizing text') ui.step('Reading the text in your screenshot…', 0.6 + 0.4 * (m.progress || 0)); },
        errorHandler: () => { },
      }), signal, 120000, 'The text reader did not start');
    } finally { blobs.forEach(u => URL.revokeObjectURL(u)); }
    if (signal.aborted) { try { worker.terminate(); } catch { } throw abortErr(); }
    const kill = () => { try { worker.terminate(); } catch { } };
    signal.addEventListener('abort', kill, { once: true });
    try {
      if (signal.aborted) throw abortErr();
      ui.step('Reading the text in your screenshot…', 0.6);
      const c = ocrCanvas(bmp, boxes);
      const { data } = await withAbort(worker.recognize(c), signal, 180000, 'Reading the text took too long');
      return { text: cleanOcr(data.text), confidence: Math.round(data.confidence || 0) };
    } finally { signal.removeEventListener('abort', kill); kill(); }
  }
  // Upscale small screenshots, cap huge ones, and invert dark-mode screenshots (light text on dark) for the OCR engine.
  function ocrCanvas(bmp, boxes = []) {
    const sw = bmp.width || bmp.naturalWidth;
    const target = sw < 900 ? Math.min(2, 1200 / sw) : Math.min(1, 2400 / sw);
    const c = canvasOf(bmp, Math.max(bmp.width || bmp.naturalWidth, bmp.height || bmp.naturalHeight) * target);
    const x = c.getContext('2d', { willReadFrequently: true }), img = x.getImageData(0, 0, c.width, c.height), d = img.data;
    let sum = 0; for (let i = 0; i < d.length; i += 16) sum += 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
    if (sum / (d.length / 16) < 110) { for (let i = 0; i < d.length; i += 4) { d[i] = 255 - d[i]; d[i + 1] = 255 - d[i + 1]; d[i + 2] = 255 - d[i + 2]; } x.putImageData(img, 0, 0); }
    // QR modules read as junk characters, so paint over each code (plus its quiet zone) before reading text.
    const k = c.width / sw; x.fillStyle = '#fff';
    boxes.forEach(b => { const pad = Math.max(b.w, b.h) * 0.12; x.fillRect((b.x - pad) * k, (b.y - pad) * k, (b.w + 2 * pad) * k, (b.h + 2 * pad) * k); });
    return c;
  }
  const abortErr = () => Object.assign(new Error('cancelled'), { name: 'AbortError' });
  // Never leave the user waiting: settle on cancel or after a time limit even if the library never answers.
  function withAbort(p, signal, ms, msg) {
    let off = () => { };
    const stop = new Promise((_, rej) => {
      const t = setTimeout(() => rej(new Error(msg)), ms), on = () => rej(abortErr());
      signal.addEventListener('abort', on, { once: true });
      off = () => { clearTimeout(t); signal.removeEventListener('abort', on); };
    });
    return Promise.race([p, stop]).finally(off);
  }

  // ---------- Status UI (progress, cancel, privacy note) ----------
  let box = null;
  function statusBox() {
    if (box && box.isConnected) return box;
    box = document.createElement('div');
    box.className = 'im-status'; box.id = 'im-status'; box.hidden = true;
    box.innerHTML = `<div class="im-row"><span class="im-msg" id="im-msg" role="status" aria-live="polite"></span><button type="button" class="link im-cancel" id="im-cancel" hidden>Cancel</button></div>
      <progress id="im-progress" max="100" value="0" aria-labelledby="im-msg" hidden></progress>
      <p class="im-note" id="im-note" hidden>Your image never leaves this device. The text reader and its English and Bangla language data (about 8 MB) are downloaded once from cdn.jsdelivr.net, then kept in this browser.</p>
      <div class="im-found" id="im-found"></div>`;
    placeBox();
    return box;
  }
  // Show the status next to whichever intake the person is using: the Simple box or the Investigator drop zone.
  function placeBox() {
    const simple = document.documentElement.dataset.mode === 'simple' && $('#s-form');
    const anchor = simple || $('#drop');
    if (anchor && anchor.parentNode) { if (anchor.nextElementSibling !== box) anchor.after(box); }
    else if (!box.isConnected) (document.querySelector('main') || document.body).prepend(box);
    box.classList.toggle('im-simple', !!simple);
  }
  function makeUi(onCancel) {
    const b = statusBox(); placeBox(); const msg = b.querySelector('#im-msg'), bar = b.querySelector('#im-progress'), cancel = b.querySelector('#im-cancel'), note = b.querySelector('#im-note');
    b.hidden = false; b.querySelector('#im-found').innerHTML = ''; b.dataset.state = 'busy';
    cancel.onclick = onCancel;
    return {
      step(text, frac) { msg.textContent = text; bar.hidden = false; note.hidden = false; cancel.hidden = false; bar.value = Math.round(100 * Math.max(0, Math.min(1, frac))); },
      info(text) { msg.textContent = text; },
      done(text, found) {
        b.dataset.state = 'done'; msg.textContent = text; bar.hidden = true; cancel.hidden = true;
        b.querySelector('#im-found').innerHTML = found || '';
        if (!found && !text) b.hidden = true;
      },
      hide() { b.hidden = true; },
    };
  }

  // ---------- The shared pipeline (QR first, then OCR if the image looks like a screenshot) ----------
  const results = new WeakMap();
  let active = null, last = null;
  function process(file, opts = {}) {
    if (results.has(file)) return results.get(file);
    if (active && active.file !== file) active.ctrl.abort();
    const ctrl = new AbortController();
    const ui = makeUi(() => ctrl.abort());
    const p = (async () => {
      const r = { file, at: Date.now(), qr: [], ocr: null, screenshot: null, notes: [], consumed: false };
      try {
        ui.info('Looking for a QR code and text in the image…');
        const u8 = new Uint8Array(await file.slice(0, 1 << 20).arrayBuffer());
        const bmp = await bitmapOf(file);
        const small = canvasOf(bmp, 360), px = pixelFeatures(small.getContext('2d').getImageData(0, 0, small.width, small.height));
        r.screenshot = screenshotScore({ width: bmp.width || bmp.naturalWidth, height: bmp.height || bmp.naturalHeight, format: formatOf(u8), name: file.name, pixels: px, ...exifCamera(u8) });
        try { const q = await decodeQr(bmp); r.qr = q.values; r.qrBoxes = q.boxes; } catch (e) { r.notes.push('Could not check for a QR code: ' + e.message); }
        r.qr.forEach(q => { const a = analyzeQr(q, { context: (opts.text || '') }); r.notes.push(a.reasons[a.reasons.length - 1].text); });
        // An image that is almost all QR code (a saved code, a cropped photo of one) has no message text to read.
        const imgArea = (bmp.width || bmp.naturalWidth) * (bmp.height || bmp.naturalHeight);
        const qrOnly = (r.qrBoxes || []).some(b => b.w * b.h > 0.3 * imgArea);
        if (r.screenshot.isScreenshot && !qrOnly && opts.ocr !== false) {
          try {
            r.ocr = await runOcr(bmp, ui, ctrl.signal, r.qrBoxes);
            r.notes.unshift(r.ocr.text ? `Read ${wordCount(r.ocr.text)} words from the screenshot on this device (English + Bangla).` : 'This looks like a screenshot, but no readable text was found in it.');
          } catch (e) {
            if (e.name === 'AbortError' || ctrl.signal.aborted) { r.cancelled = true; r.notes.unshift('Reading the text was cancelled. You can paste the text from the screenshot instead.'); }
            else r.notes.unshift('Could not read the text in the screenshot (' + e.message + '). You can paste the text instead.');
          }
        }
        if (bmp.close) bmp.close();
      } catch (e) { r.notes.push('Could not read this image: ' + e.message); }
      ui.done(summaryLine(r), foundHtml(r));
      if (active && active.file === file) active = null;
      if (r.cancelled) results.delete(file);
      last = r;
      return r;
    })();
    results.set(file, p); active = { file, ctrl, p };
    return p;
  }
  const wordCount = t => (t.match(/[\p{L}\p{N}]+/gu) || []).length;
  function summaryLine(r) {
    const bits = [];
    if (r.qr.length) bits.push(r.qr.length > 1 ? `Found ${r.qr.length} QR codes.` : 'Found a QR code.');
    if (r.ocr && r.ocr.text) bits.push(`Read ${wordCount(r.ocr.text)} words from the screenshot.`);
    else if (r.cancelled) bits.push('Reading the text was cancelled.');
    else if (r.screenshot && r.screenshot.isScreenshot && !r.ocr) bits.push('Could not read the text in the screenshot. You can paste it instead.');
    if (!bits.length) return '';
    return bits.join(' ') + ' It will be checked together with the image.';
  }
  function foundHtml(r) {
    const items = r.qr.map(q => { const a = classifyPayload(q); const shown = a.kind === 'url' ? (safeHost(a.url) || q) : q; return `<li><span class="im-tag">QR code</span> ${a.kind === 'url' ? 'opens' : 'contains'} <code>${esc(short(shown, 90))}</code></li>`; });
    return items.length ? `<ul class="im-list">${items.join('')}</ul>` : '';
  }
  const safeHost = u => { try { return new URL(u).hostname; } catch { return ''; } };

  // The shell picks one adapter per input, so either adapter returns both the QR and the OCR findings. The image itself
  // stays in `attachments`, so the normal image forensics still run on it.
  function toExtraction(r, file) {
    const text = [r.ocr && r.ocr.text, ...r.qr.map(q => analyzeQr(q).caseText)].filter(Boolean).join('\n\n');
    const urls = r.qr.map(classifyPayload).filter(p => p.kind === 'url').map(p => p.url);
    r.via = 'adapter';
    return { text, url: urls[0], notes: r.notes.slice(), attachments: [file, { type: 'intake-media', qr: r.qr.slice(), ocrText: r.ocr ? r.ocr.text : '', screenshot: r.screenshot }] };
  }

  // ---------- Contributing reasons to the case ----------
  const WEIGHTS = { strong: 'strong', moderate: 'moderate', weak: 'weak' };
  function domainAgeFor(domain, signal) {
    const sb = SB();
    if (!domain || /^\d+(\.\d+){3}$/.test(domain)) return Promise.resolve(null);
    const t = new Promise(res => setTimeout(() => res(null), 9000));
    const q = (sb.isStatic && sb.isStatic()) || !(sb.server && sb.server().online)
      ? fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { headers: { Accept: 'application/rdap+json, application/json' }, signal }).then(r => r.ok ? r.json() : null).then(j => j && rdapAge(j))
      : sb.post('/api/osint/domain', { domain }).then(j => j && j.ageDays != null ? { ageDays: j.ageDays, registeredAt: j.registeredAt } : null);
    return Promise.race([q.catch(() => null), t]);
  }
  function addObs(v, ob) { if (v && Array.isArray(v.observations) && !v.observations.some(o => o.fact === ob.fact)) v.observations.unshift(ob); }
  function applyToCase(c, r) {
    const context = [c.text, r.ocr && r.ocr.text].filter(Boolean).join('\n');
    const H = window.DeduceHeuristics;
    const analyse = age => r.qr.map((q, i) => analyzeQr(q, { context, analyzeUrl: H && H.analyzeUrl, domainAge: age[i] }));
    const commit = list => {
      const obs = [];
      if (r.ocr && r.ocr.text) obs.push({ fact: `Text read from the screenshot (${wordCount(r.ocr.text)} words, English + Bangla, read on this device)`, inference: 'The screenshot text was checked like a pasted message. OCR can misread words, so check the text box and correct it if needed.', weight: 'weak', source: 'ocr', intakeMedia: true });
      list.forEach(a => a.reasons.forEach(x => obs.push({ fact: x.text, inference: x.weight === 'strong' ? 'QR codes hide where they lead, which is why scammers stick them on parking meters, posters, letters and emails.' : 'Decoded on this device from the QR code in the image.', weight: WEIGHTS[x.weight] || 'weak', source: 'qr', intakeMedia: true })));
      c._intakeMediaObs = obs;
      [c.local, c.final].forEach(v => { if (!v) return; v.observations = (v.observations || []).filter(o => !o.intakeMedia); obs.slice().reverse().forEach(ob => addObs(v, ob)); });
      const q = list.find(a => a.quishing === 'strong') || list.find(a => a.quishing);
      if (q && c.local) {
        const v = c.local, low = ['No strong red flags', 'Insufficient evidence', 'Suspicious', 'Edited image'];
        if (q.quishing === 'strong') { v.risk = Math.max(+v.risk || 0, 62); if (low.includes(v.verdict)) { v.verdict = 'Likely scam'; v.category = 'QR code phishing (quishing)'; v.headline = 'The QR code leads somewhere it should not. Do not scan it, log in or pay through it.'; } }
        else { v.risk = Math.max(+v.risk || 0, 35); if (['No strong red flags', 'Insufficient evidence'].includes(v.verdict)) { v.verdict = 'Suspicious'; v.category = 'Risky QR code'; v.headline = 'Check where the QR code leads before you scan it or pay.'; } }
        if (q.actions[0]) v.advice = q.actions.map(a => a.text).join(' ') + (v.advice ? ' ' + v.advice : '');
      }
      const sb = SB();
      const reasons = list.flatMap(a => a.reasons.map(x => ({ text: x.text, weight: WEIGHTS[x.weight] || 'weak', quote: a.host || '', source: 'qr', intakeMedia: true })));
      if (r.ocr && r.ocr.text) reasons.push({ text: `We read the text in the screenshot on your device and checked it like a pasted message (${wordCount(r.ocr.text)} words). Reading can miss or change words.`, weight: 'info', quote: '', source: 'ocr', intakeMedia: true });
      const actions = list.flatMap(a => a.actions.map(x => ({ ...x, intakeMedia: true })));
      // This runs again when the domain age arrives: replace what we added before instead of adding it twice.
      if (Array.isArray(c.simpleReasons)) c.simpleReasons = c.simpleReasons.filter(x => !x.intakeMedia);
      if (Array.isArray(c.simpleActions)) c.simpleActions = c.simpleActions.filter(x => !x.intakeMedia);
      if (typeof sb.addReasons === 'function' && reasons.length) { try { sb.addReasons(c, reasons); } catch (e) { console.debug('addReasons failed', e); } }
      if (typeof sb.addActions === 'function' && actions.length) { try { sb.addActions(c, actions); } catch (e) { console.debug('addActions failed', e); } }
      c.caseExtras = { ...(c.caseExtras || {}), media_intake: { qr: list.map(a => ({ payload: a.payload, kind: a.kind, host: a.host || null, quishing: a.quishing, reasons: a.reasons.map(x => x.text) })), screenshot: r.screenshot ? { score: r.screenshot.score, reasons: r.screenshot.reasons } : null, ocr: r.ocr ? { words: wordCount(r.ocr.text), confidence: r.ocr.confidence } : null } };
      persist(c);
      if (sb.current === c && sb.renderAll) sb.renderAll();
    };
    commit(analyse([]));
    const doms = r.qr.map(q => { const p = classifyPayload(q); return p.kind === 'url' ? registrable(safeHost(p.url).replace(/^www\./, '')) : null; });
    if (doms.some(Boolean)) {
      const p = Promise.all(doms.map(d => d ? domainAgeFor(d) : null)).then(ages => { if (ages.some(Boolean)) commit(analyse(ages)); }).catch(() => { });
      (c.pending = c.pending || []).push(p);
    }
  }
  function persist(c) {
    const sb = SB(); if (!sb.store) return;
    const list = sb.store.get('scambunker.cases', []), row = list.find(x => x.id === c.id); if (!row) return;
    ['local', 'final'].forEach(k => { if (row[k] && c[k]) { row[k].observations = c[k].observations; ['verdict', 'category', 'risk', 'headline', 'advice'].forEach(f => { row[k][f] = c[k][f]; }); } });
    if (c.local) { row.verdict = c.local.verdict; row.risk = c.local.risk; row.headline = c.local.headline; }
    row.caseExtras = c.caseExtras; sb.store.set('scambunker.cases', list);
  }
  document.addEventListener('sb:case', e => {
    const c = e.detail, r = last;
    if (!c || !r || r.consumed || !(r.qr.length || (r.ocr && r.ocr.text))) return;
    if (r.via !== 'adapter' && !(c.imagePreview && c.imagePreview === r.previewSrc)) return;
    r.consumed = true;
    try { applyToCase(c, r); } catch (err) { console.debug('intake-media: could not add reasons', err); }
  });
  document.addEventListener('sb:case-complete', e => {
    const c = e.detail; if (!c || !c._intakeMediaObs) return;
    c._intakeMediaObs.slice().reverse().forEach(ob => addObs(c.final, ob));
    persist(c); if (SB().current === c && SB().renderAll) SB().renderAll();
  });

  // ---------- Intake adapters (PRODUCT.md "Module contracts") ----------
  const isImage = f => !!f && (/^image\//.test(f.type || '') || /\.(png|jpe?g|webp|gif|bmp|heic|avif)$/i.test(f.name || ''));
  const ADAPTERS = [
    // Scores sit just above the shell's plain image adapter (0.9): every image is checked for a QR code, and text is
    // read only when the pixels say "screenshot". The image forensics still run because the file is passed through.
    { id: 'screenshot-ocr', label: 'Screenshot',
      detect: input => !isImage(input && input.file) ? 0 : (SCREENSHOT_NAME.test(input.file.name || '') || /png/i.test(input.file.type || '')) ? 0.95 : 0,
      extract: async input => toExtraction(await process(input.file, { text: input.text }), input.file) },
    { id: 'qr-code', label: 'Photo, screenshot or QR code',
      detect: input => isImage(input && input.file) ? 0.92 : 0,
      extract: async input => toExtraction(await process(input.file, { text: input.text }), input.file) },
  ];
  const mode = { registered: false, form: false };
  function register() {
    const sb = SB();
    if (mode.registered || typeof sb.registerIntake !== 'function') return false;
    ADAPTERS.forEach(a => sb.registerIntake(a)); mode.registered = true;
    return true;
  }

  // ---------- Investigator intake form (and shells without registerIntake): read the dropped image, fill the form ----------
  function watchForm() {
    if (mode.form) return;
    const preview = $('#preview'), textEl = $('#text'), urlEl = $('#url'), go = $('#go');
    if (!preview || !textEl) return;
    mode.form = true;
    let waitingGo = false;
    const onImage = async () => {
      const src = preview.getAttribute('src');
      // Simple mode already ran the adapters on this file before handing it to the form.
      if (!src || !/^blob:/.test(src) || $('#drop-full')?.hidden || document.documentElement.dataset.simpleState === 'checking') return;
      let file; try { const b = await (await fetch(src)).blob(); file = new File([b], (($('#file-name')?.textContent || 'image').split(' · ')[0]), { type: b.type }); } catch { return; }
      if (!isImage(file)) return;
      const r = await process(file, { text: textEl.value });
      r.previewSrc = src;
      if (preview.getAttribute('src') !== src) return;
      if (r.ocr && r.ocr.text && !textEl.value.includes(r.ocr.text.slice(0, 40))) textEl.value = textEl.value.trim() ? `${textEl.value.trim()}\n\n${r.ocr.text}` : r.ocr.text;
      r.qr.forEach(q => { const p = classifyPayload(q); if (p.kind === 'url' && urlEl && !urlEl.value.trim()) urlEl.value = p.url; else { const line = analyzeQr(q).caseText; if (!textEl.value.includes(line)) textEl.value = (textEl.value.trim() ? textEl.value.trim() + '\n' : '') + line; } });
      if ((r.ocr && r.ocr.text) || r.qr.length) textEl.dispatchEvent(new Event('input', { bubbles: true }));
      if (waitingGo) { waitingGo = false; go && go.click(); }
    };
    new MutationObserver(onImage).observe(preview, { attributes: true, attributeFilter: ['src'] });
    $('#clear-img')?.addEventListener('click', () => { if (active) active.ctrl.abort(); waitingGo = false; if (box) box.hidden = true; });
    const hold = e => {
      if (!active) return;
      e.preventDefault(); e.stopImmediatePropagation();
      waitingGo = true; SB().toast && SB().toast('Reading your image first. The check starts as soon as it is done');
    };
    go && go.addEventListener('click', e => { if (e.isTrusted) hold(e); }, true);
    document.addEventListener('keydown', e => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') hold(e); }, true);
    if (preview.getAttribute('src')) onImage();
  }

  // The shell may add registerIntake while it starts up, so try now and again on sb:ready.
  register(); watchForm();
  document.addEventListener('sb:ready', () => setTimeout(register, 0), { once: true });
  API.adapters = ADAPTERS; API.process = process; API.mode = mode;
})();
