// Deduce image forensics — runs entirely in the browser.
// Parses JPEG/PNG/WebP/HEIC containers, EXIF, XMP, IPTC, C2PA (Content Credentials), PNG text chunks,
// generator signatures, platform re-encode fingerprints, JPEG quality, and error-level analysis.
(function () {
  const AI_SIGNATURES = [
    { re: /trainedAlgorithmicMedia/i, label: 'IPTC DigitalSourceType = trainedAlgorithmicMedia (declared AI-generated)', strength: 'proof' },
    { re: /compositeWithTrainedAlgorithmicMedia/i, label: 'IPTC DigitalSourceType = composite with AI elements', strength: 'proof' },
    { re: /algorithmicMedia/i, label: 'IPTC DigitalSourceType = algorithmic media', strength: 'strong' },
    { re: /DALL[·\-\s]?E|openai/i, label: 'OpenAI / DALL·E / ChatGPT image signature', strength: 'strong', gen: 'OpenAI DALL·E / GPT image' },
    { re: /midjourney/i, label: 'Midjourney signature', strength: 'strong', gen: 'Midjourney' },
    { re: /stable[\s\-]?diffusion|sd_xl|sdxl/i, label: 'Stable Diffusion signature', strength: 'strong', gen: 'Stable Diffusion' },
    { re: /Steps:\s*\d+.*Sampler:/is, label: 'Diffusion generation parameters (steps / sampler) embedded', strength: 'proof', gen: 'Stable Diffusion (A1111/Forge)' },
    { re: /ComfyUI|"class_type"\s*:/i, label: 'ComfyUI workflow embedded', strength: 'proof', gen: 'ComfyUI (diffusion pipeline)' },
    { re: /NovelAI/i, label: 'NovelAI signature', strength: 'strong', gen: 'NovelAI' },
    { re: /Adobe Firefly|firefly/i, label: 'Adobe Firefly signature', strength: 'strong', gen: 'Adobe Firefly' },
    { re: /Made with Google AI|Imagen|Gemini/i, label: 'Google AI (Imagen/Gemini) credit', strength: 'strong', gen: 'Google Imagen / Gemini' },
    { re: /Microsoft Designer|Bing Image Creator|Microsoft Copilot/i, label: 'Microsoft Designer / Bing Image Creator', strength: 'strong', gen: 'Microsoft Designer / Bing' },
    { re: /\bFLUX\b|black[\s\-]?forest[\s\-]?labs/i, label: 'FLUX (Black Forest Labs) signature', strength: 'strong', gen: 'FLUX' },
    { re: /Leonardo\.?ai/i, label: 'Leonardo.ai signature', strength: 'strong', gen: 'Leonardo.ai' },
    { re: /ideogram/i, label: 'Ideogram signature', strength: 'strong', gen: 'Ideogram' },
    { re: /\bgrok\b|xAI/i, label: 'xAI Grok / Aurora signature', strength: 'moderate', gen: 'xAI Grok' },
    { re: /runwayml|runway gen/i, label: 'Runway signature', strength: 'strong', gen: 'Runway' },
    { re: /\bsora\b/i, label: 'Sora signature', strength: 'moderate', gen: 'OpenAI Sora' },
    { re: /generative fill|GenerativeFill/i, label: 'Photoshop Generative Fill used', strength: 'strong', gen: 'Adobe Generative Fill (AI edit)' },
    { re: /c2pa\.ai_generat|c2pa\.ai_training|"ai_generated"|aigc/i, label: 'C2PA / AIGC assertion of AI generation', strength: 'proof' },
  ];
  const EDITORS = /(Adobe Photoshop[^\0<"]{0,30}|Lightroom[^\0<"]{0,20}|GIMP[^\0<"]{0,10}|Snapseed|Canva|Picsart|PicsArt|FaceApp|Facetune|Meitu|VSCO|Pixelmator[^\0<"]{0,10}|Affinity Photo|Paint\.NET|Remini|Lensa|CapCut|InShot)/i;
  const PLATFORM_DIMS = [
    { test: (w, h) => w === 1080 || h === 1080 || w === 1440, label: 'Instagram-standard dimension (1080/1440 px)' },
    { test: (w, h) => w === 2048 || h === 2048 || w === 960 || h === 960 || w === 720, label: 'Facebook re-encode dimension (2048/960/720 px)' },
    { test: (w, h) => w === 1200 || h === 1200 || w === 680 || w === 4096 || h === 4096, label: 'X/Twitter re-encode dimension (4096/1200/680 px)' },
    { test: (w, h) => w === 1600 || h === 1600 || w === 1280 || h === 1280, label: 'WhatsApp / Telegram compression dimension (1600/1280 px)' },
  ];

  const u8str = (u8, s, e) => { let o = ''; for (let i = s; i < e && i < u8.length; i++) o += String.fromCharCode(u8[i]); return o; };
  const latin = u8 => { let o = ''; const n = Math.min(u8.length, 6e6); for (let i = 0; i < n; i += 8192) o += String.fromCharCode.apply(null, u8.subarray(i, Math.min(i + 8192, n))); return o; };

  function detectFormat(u8) {
    if (u8[0] === 0xFF && u8[1] === 0xD8) return 'JPEG';
    if (u8[0] === 0x89 && u8[1] === 0x50 && u8[2] === 0x4E && u8[3] === 0x47) return 'PNG';
    if (u8str(u8, 0, 4) === 'RIFF' && u8str(u8, 8, 12) === 'WEBP') return 'WEBP';
    if (u8str(u8, 0, 3) === 'GIF') return 'GIF';
    if (u8str(u8, 4, 8) === 'ftyp') { const b = u8str(u8, 8, 12); return /heic|heix|mif1|hevc/.test(b) ? 'HEIC' : /avif/.test(b) ? 'AVIF' : 'ISO-BMFF'; }
    return 'Unknown';
  }

  // ---------- EXIF / TIFF ----------
  const TAGS = { 0x010F: 'Make', 0x0110: 'Model', 0x0131: 'Software', 0x0132: 'DateTime', 0x013B: 'Artist', 0x8298: 'Copyright', 0x010E: 'ImageDescription', 0x0112: 'Orientation', 0xA002: 'PixelXDimension', 0xA003: 'PixelYDimension',
    0x9003: 'DateTimeOriginal', 0x9004: 'DateTimeDigitized', 0x9010: 'OffsetTime', 0x9011: 'OffsetTimeOriginal', 0xA434: 'LensModel', 0xA433: 'LensMake', 0x829A: 'ExposureTime', 0x829D: 'FNumber', 0x8827: 'ISO', 0x920A: 'FocalLength', 0xA431: 'BodySerialNumber', 0xA420: 'ImageUniqueID', 0x9286: 'UserComment', 0xA430: 'CameraOwnerName', 0x9209: 'Flash' };
  const GPS_TAGS = { 1: 'GPSLatitudeRef', 2: 'GPSLatitude', 3: 'GPSLongitudeRef', 4: 'GPSLongitude', 6: 'GPSAltitude', 7: 'GPSTimeStamp', 29: 'GPSDateStamp' };

  function parseTIFF(dv, base) {
    const out = {};
    const le = dv.getUint16(base) === 0x4949;
    const g16 = o => dv.getUint16(base + o, le), g32 = o => dv.getUint32(base + o, le);
    const sizes = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };
    function readVal(type, count, valOff) {
      const sz = (sizes[type] || 1) * count;
      const off = sz > 4 ? g32(valOff) : valOff;
      try {
        if (type === 2) { let s = ''; for (let i = 0; i < count - 1; i++) s += String.fromCharCode(dv.getUint8(base + off + i)); return s.trim(); }
        if (type === 7) { let s = ''; for (let i = 0; i < Math.min(count, 200); i++) { const c = dv.getUint8(base + off + i); if (c >= 32 && c < 127) s += String.fromCharCode(c); } return s.replace(/^(ASCII|UNICODE)\s*/, '').trim(); }
        const vals = [];
        for (let i = 0; i < Math.min(count, 8); i++) {
          if (type === 3) vals.push(g16(off + i * 2));
          else if (type === 4) vals.push(g32(off + i * 4));
          else if (type === 9) vals.push(dv.getInt32(base + off + i * 4, le));
          else if (type === 5 || type === 10) { const n = type === 5 ? g32(off + i * 8) : dv.getInt32(base + off + i * 8, le); const d = type === 5 ? g32(off + i * 8 + 4) : dv.getInt32(base + off + i * 8 + 4, le); vals.push(d ? n / d : 0); }
          else vals.push(dv.getUint8(base + off + i));
        }
        return vals.length === 1 ? vals[0] : vals;
      } catch { return null; }
    }
    function ifd(off, dict, target, depth = 0) {
      if (depth > 3 || off <= 0 || base + off + 2 > dv.byteLength) return;
      const n = g16(off);
      for (let i = 0; i < n && i < 400; i++) {
        const e = off + 2 + i * 12;
        if (base + e + 12 > dv.byteLength) break;
        const tag = g16(e), type = g16(e + 2), count = g32(e + 4);
        if (tag === 0x8769) { ifd(g32(e + 8), TAGS, target, depth + 1); continue; }
        if (tag === 0x8825) { const gps = {}; ifd(g32(e + 8), GPS_TAGS, gps, depth + 1); target.GPS = gps; continue; }
        const name = dict[tag];
        if (name) { const v = readVal(type, count, e + 8); if (v !== null && v !== '') target[name] = v; }
      }
    }
    ifd(g32(4), TAGS, out);
    if (out.GPS && out.GPS.GPSLatitude && out.GPS.GPSLongitude) {
      const dms = a => Array.isArray(a) ? a[0] + (a[1] || 0) / 60 + (a[2] || 0) / 3600 : a;
      let lat = dms(out.GPS.GPSLatitude), lon = dms(out.GPS.GPSLongitude);
      if (out.GPS.GPSLatitudeRef === 'S') lat = -lat; if (out.GPS.GPSLongitudeRef === 'W') lon = -lon;
      if (isFinite(lat) && isFinite(lon) && (lat || lon)) out.GPSDecimal = { lat: +lat.toFixed(6), lon: +lon.toFixed(6) };
    }
    return out;
  }

  // ---------- Containers ----------
  function parseJPEG(u8, dv, r) {
    let p = 2;
    const qtables = [];
    while (p < u8.length - 4) {
      if (u8[p] !== 0xFF) { p++; continue; }
      const m = u8[p + 1];
      if (m === 0xD9 || m === 0xDA) break;
      if (m >= 0xD0 && m <= 0xD7) { p += 2; continue; }
      const len = dv.getUint16(p + 2);
      const s = p + 4, e = p + 2 + len;
      r.segments.push('APP/marker 0x' + m.toString(16).toUpperCase());
      if (m === 0xE1 && u8str(u8, s, s + 4) === 'Exif') { try { Object.assign(r.exif, parseTIFF(dv, s + 6)); } catch (err) { r.notes.push('EXIF present but damaged'); } }
      else if (m === 0xE1 && u8str(u8, s, s + 28).startsWith('http://ns.adobe.com/xap/1.0/')) r.xmp += u8str(u8, s + 29, e);
      else if (m === 0xED) { r.iptcRaw = u8str(u8, s, e); if (/FBMD/.test(r.iptcRaw)) r.platformMarks.push('Facebook "FBMD" IPTC marker — image passed through Facebook/Messenger/Instagram servers'); }
      else if (m === 0xEB) { r.c2pa = true; }
      else if (m === 0xFE) r.comments.push(u8str(u8, s, e).replace(/[^\x20-\x7E]/g, '').slice(0, 300));
      else if (m === 0xDB) { let q = s; while (q < e) { const pq = u8[q] >> 4; const id = u8[q] & 15; const vals = []; for (let i = 0; i < 64; i++) vals.push(pq ? dv.getUint16(q + 1 + i * 2) : u8[q + 1 + i]); qtables.push({ id, vals }); q += 1 + 64 * (pq ? 2 : 1); } }
      else if (m >= 0xC0 && m <= 0xC3) { r.height = dv.getUint16(s + 1); r.width = dv.getUint16(s + 3); r.progressive = m === 0xC2; }
      else if (m === 0xE2 && u8str(u8, s, s + 11) === 'ICC_PROFILE') { const icc = u8str(u8, s, e); const d = /desc[\s\S]{8}([\x20-\x7E]{4,40})/.exec(icc); r.icc = d ? d[1] : 'embedded'; }
      p = e;
    }
    if (qtables.length) {
      // Estimate quality from luminance table vs. standard IJG table
      const std = [16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99];
      const t = qtables[0].vals; const sumT = t.reduce((a, b) => a + b, 0), sumS = std.reduce((a, b) => a + b, 0);
      const scale = (sumT / sumS) * 100;
      const q = scale <= 100 ? Math.round((200 - scale) / 2) : Math.round(5000 / scale);
      r.jpegQuality = Math.max(1, Math.min(100, q));
    }
  }

  async function inflate(u8) {
    try { const ds = new DecompressionStream('deflate'); const out = await new Response(new Blob([u8]).stream().pipeThrough(ds)).arrayBuffer(); return new TextDecoder().decode(out); } catch { return ''; }
  }
  async function parsePNG(u8, dv, r) {
    let p = 8;
    while (p < u8.length - 12) {
      const len = dv.getUint32(p), type = u8str(u8, p + 4, p + 8), s = p + 8, e = s + len;
      if (type === 'IHDR') { r.width = dv.getUint32(s); r.height = dv.getUint32(s + 4); }
      else if (type === 'tEXt') { const z = u8.indexOf(0, s); r.textChunks[u8str(u8, s, z)] = new TextDecoder('latin1').decode(u8.subarray(z + 1, e)).slice(0, 20000); }
      else if (type === 'iTXt') { const z = u8.indexOf(0, s); const key = u8str(u8, s, z); const comp = u8[z + 1]; let q = z + 3; q = u8.indexOf(0, q) + 1; q = u8.indexOf(0, q) + 1; const data = u8.subarray(q, e); r.textChunks[key] = (comp ? await inflate(data) : new TextDecoder().decode(data)).slice(0, 20000); }
      else if (type === 'zTXt') { const z = u8.indexOf(0, s); r.textChunks[u8str(u8, s, z)] = (await inflate(u8.subarray(z + 2, e))).slice(0, 20000); }
      else if (type === 'eXIf') { try { Object.assign(r.exif, parseTIFF(dv, s)); } catch { } }
      else if (type === 'tIME') { r.pngTime = `${dv.getUint16(s)}-${String(u8[s + 2]).padStart(2, '0')}-${String(u8[s + 3]).padStart(2, '0')} ${String(u8[s + 4]).padStart(2, '0')}:${String(u8[s + 5]).padStart(2, '0')}:${String(u8[s + 6]).padStart(2, '0')}`; }
      else if (type === 'caBX') r.c2pa = true;
      r.segments.push(type);
      if (type === 'IEND') break;
      p = e + 4;
    }
    if (r.textChunks['XML:com.adobe.xmp']) r.xmp += r.textChunks['XML:com.adobe.xmp'];
  }
  function parseWEBP(u8, dv, r) {
    let p = 12;
    while (p < u8.length - 8) {
      const type = u8str(u8, p, p + 4), len = dv.getUint32(p + 4, true), s = p + 8;
      r.segments.push(type);
      if (type === 'EXIF') { const off = u8str(u8, s, s + 4) === 'Exif' ? s + 6 : s; try { Object.assign(r.exif, parseTIFF(dv, off)); } catch { } }
      else if (type === 'XMP ') r.xmp += u8str(u8, s, s + len);
      else if (type === 'VP8X') { r.width = 1 + (u8[s + 4] | u8[s + 5] << 8 | u8[s + 6] << 16); r.height = 1 + (u8[s + 7] | u8[s + 8] << 8 | u8[s + 9] << 16); }
      p = s + len + (len & 1);
    }
  }

  function xmpFields(xmp) {
    const f = {};
    const grab = (k) => { const m = new RegExp(`${k}(?:="([^"]*)"|>([^<]*)<)`).exec(xmp); return m ? (m[1] || m[2] || '').trim() : null; };
    ['xmp:CreateDate', 'xmp:ModifyDate', 'xmp:MetadataDate', 'photoshop:DateCreated', 'xmp:CreatorTool', 'Iptc4xmpExt:DigitalSourceType', 'dc:creator', 'photoshop:Credit', 'xmpMM:DocumentID', 'xmpMM:OriginalDocumentID', 'exif:DateTimeOriginal', 'photoshop:City', 'photoshop:Country', 'tiff:Make', 'tiff:Model'].forEach(k => { const v = grab(k); if (v) f[k] = v; });
    const hist = [...xmp.matchAll(/stEvt:action="([^"]+)"[^>]*?stEvt:when="([^"]+)"(?:[^>]*?stEvt:softwareAgent="([^"]+)")?/g)].map(m => ({ action: m[1], when: m[2], agent: m[3] || '' }));
    if (hist.length) f.history = hist.slice(0, 30);
    return f;
  }

  // ---------- Pixel analysis ----------
  async function pixelAnalysis(file, r) {
    const bmp = await createImageBitmap(file);
    r.width = r.width || bmp.width; r.height = r.height || bmp.height;
    const maxW = 900, scale = Math.min(1, maxW / bmp.width);
    const w = Math.round(bmp.width * scale), h = Math.round(bmp.height * scale);
    const c = document.createElement('canvas'); c.width = w; c.height = h;
    const ctx = c.getContext('2d', { willReadFrequently: true }); ctx.drawImage(bmp, 0, 0, w, h);
    const orig = ctx.getImageData(0, 0, w, h);
    // ELA: recompress at q=0.90 and amplify difference
    const blob = await new Promise(res => c.toBlob(res, 'image/jpeg', 0.9));
    const rb = await createImageBitmap(blob);
    const c2 = document.createElement('canvas'); c2.width = w; c2.height = h;
    const x2 = c2.getContext('2d', { willReadFrequently: true }); x2.drawImage(rb, 0, 0);
    const re = x2.getImageData(0, 0, w, h);
    const ela = x2.createImageData(w, h);
    let sum = 0, max = 0; const BS = 16; const bw = Math.ceil(w / BS), bh = Math.ceil(h / BS); const blocks = new Float32Array(bw * bh);
    for (let i = 0; i < orig.data.length; i += 4) {
      const d = (Math.abs(orig.data[i] - re.data[i]) + Math.abs(orig.data[i + 1] - re.data[i + 1]) + Math.abs(orig.data[i + 2] - re.data[i + 2])) / 3;
      sum += d; if (d > max) max = d;
      const v = Math.min(255, d * 18);
      ela.data[i] = v; ela.data[i + 1] = v * 0.75; ela.data[i + 2] = v * 0.35; ela.data[i + 3] = 255;
      const px = (i / 4) % w, py = Math.floor(i / 4 / w); blocks[Math.floor(py / BS) * bw + Math.floor(px / BS)] += d;
    }
    x2.putImageData(ela, 0, 0);
    r.elaUrl = c2.toDataURL('image/png');
    const mean = sum / (w * h);
    const bmeans = Array.from(blocks).map(b => b / (BS * BS)); const bm = bmeans.reduce((a, b) => a + b, 0) / bmeans.length;
    const bsd = Math.sqrt(bmeans.reduce((a, b) => a + (b - bm) ** 2, 0) / bmeans.length);
    const hot = bmeans.filter(b => b > bm + 3 * bsd).length;
    r.ela = { mean: +mean.toFixed(2), max: +max.toFixed(1), blockCV: +(bsd / (bm || 1)).toFixed(2), hotspotBlocks: hot, hotspotPct: +(100 * hot / bmeans.length).toFixed(1) };
    // Noise residual uniformity (Laplacian), saturation, sharpness
    let lap = 0, lap2 = 0, n = 0, sat = 0;
    const g = (x, y) => { const k = (y * w + x) * 4; return 0.299 * orig.data[k] + 0.587 * orig.data[k + 1] + 0.114 * orig.data[k + 2]; };
    for (let y = 1; y < h - 1; y += 2) for (let x = 1; x < w - 1; x += 2) {
      const L = 4 * g(x, y) - g(x - 1, y) - g(x + 1, y) - g(x, y - 1) - g(x, y + 1); lap += Math.abs(L); lap2 += L * L; n++;
      const k = (y * w + x) * 4; const mx = Math.max(orig.data[k], orig.data[k + 1], orig.data[k + 2]), mn = Math.min(orig.data[k], orig.data[k + 1], orig.data[k + 2]); sat += mx ? (mx - mn) / mx : 0;
    }
    r.pixels = { noiseLevel: +(lap / n).toFixed(2), sharpnessVar: +(lap2 / n - (lap / n) ** 2).toFixed(0), meanSaturation: +(sat / n).toFixed(3) };
    // Thumbnail for vision agent
    const vs = Math.min(1, 1400 / Math.max(bmp.width, bmp.height));
    const vc = document.createElement('canvas'); vc.width = Math.round(bmp.width * vs); vc.height = Math.round(bmp.height * vs);
    vc.getContext('2d').drawImage(bmp, 0, 0, vc.width, vc.height);
    r.visionData = vc.toDataURL('image/jpeg', 0.86);
  }

  async function sha256(buf) { const h = await crypto.subtle.digest('SHA-256', buf); return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join(''); }

  function exifDate(s) { if (!s || typeof s !== 'string') return null; const m = /(\d{4})[:\-](\d{2})[:\-](\d{2})[ T](\d{2}):(\d{2}):?(\d{2})?/.exec(s); return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] || '00'}` : (/^\d{4}-\d{2}-\d{2}/.test(s) ? s : null); }

  // ---------- Main ----------
  async function analyze(file) {
    const buf = await file.arrayBuffer();
    const u8 = new Uint8Array(buf), dv = new DataView(buf);
    const r = { name: file.name, size: file.size, type: file.type, format: detectFormat(u8), exif: {}, xmp: '', textChunks: {}, comments: [], segments: [], platformMarks: [], notes: [], c2pa: false };
    r.sha256 = await sha256(buf);
    try {
      if (r.format === 'JPEG') parseJPEG(u8, dv, r);
      else if (r.format === 'PNG') await parsePNG(u8, dv, r);
      else if (r.format === 'WEBP') parseWEBP(u8, dv, r);
      else if (r.format === 'HEIC' || r.format === 'AVIF') { const i = latin(u8).indexOf('Exif\0\0'); if (i > 0) try { Object.assign(r.exif, parseTIFF(dv, i + 6)); } catch { } }
    } catch (e) { r.notes.push('Container parse error: ' + e.message); }
    try { await pixelAnalysis(file, r); } catch (e) { r.notes.push('Pixel analysis unavailable for this format in this browser'); }

    const blob = latin(u8);
    if (/jumb|c2pa/i.test(blob)) r.c2pa = true;
    if (!r.xmp) { const xi = blob.indexOf('<x:xmpmeta'); if (xi >= 0) r.xmp = blob.slice(xi, blob.indexOf('</x:xmpmeta>', xi) + 12); }
    r.xmpFields = r.xmp ? xmpFields(r.xmp) : {};
    if (r.c2pa) { const issuers = [...new Set((blob.match(/(Adobe|OpenAI|Google|Microsoft|Truepic|Leica|Sony|Nikon|Samsung|Qualcomm|Meta|TikTok|LinkedIn|BBC|Canon)[^\0]{0,0}/g) || []))]; r.c2paIssuers = issuers.slice(0, 6); }

    // AI signals
    const haystack = [blob.slice(0, 3e6), JSON.stringify(r.textChunks), r.xmp, JSON.stringify(r.exif)].join('\n');
    const ai = []; const gens = new Set();
    for (const s of AI_SIGNATURES) if (s.re.test(haystack)) { ai.push({ label: s.label, strength: s.strength }); if (s.gen) gens.add(s.gen); }
    if (r.textChunks.parameters) { ai.push({ label: 'PNG "parameters" chunk holds the generation prompt', strength: 'proof' }); r.prompt = r.textChunks.parameters.slice(0, 1500); }
    if (r.textChunks.prompt && !r.prompt) r.prompt = r.textChunks.prompt.slice(0, 1500);
    if (r.textChunks.Description && /prompt|--ar|--v \d/i.test(r.textChunks.Description)) r.prompt = r.prompt || r.textChunks.Description.slice(0, 1500);
    const w = r.width, h = r.height;
    const hasCamera = !!(r.exif.Make || r.exif.Model);
    const weak = [];
    if (w && h && w % 64 === 0 && h % 64 === 0 && !hasCamera) weak.push('Both dimensions are multiples of 64 with no camera data — common diffusion-model output size');
    if (w && h && [512, 768, 832, 896, 1024, 1152, 1216, 1344, 1536, 1792].includes(w) && [512, 768, 832, 896, 1024, 1152, 1216, 1344, 1536, 1792].includes(h)) weak.push(`${w}×${h} matches a standard AI generator canvas`);
    if (r.format === 'PNG' && !hasCamera && w * h > 500000) weak.push('Large PNG with no camera metadata — photos are rarely saved this way');
    if (r.pixels && r.pixels.noiseLevel < 2.2 && !hasCamera) weak.push('Very low sensor noise — unusually clean, typical of synthetic or heavily processed images');
    if (r.format === 'WEBP' && !hasCamera) weak.push('WebP with no camera data — the default output format of several AI services');
    r.ai = { signals: ai, weak, generators: [...gens] };
    const proof = ai.some(s => s.strength === 'proof'), strong = ai.some(s => s.strength === 'strong');
    r.ai.verdict = proof ? 'confirmed' : strong ? 'likely' : weak.length >= 2 ? 'possible' : weak.length ? 'weak indicators' : 'none detected';

    // Editing software
    const ed = new Set(); [r.exif.Software, r.xmpFields['xmp:CreatorTool'], ...(r.xmpFields.history || []).map(h => h.agent)].filter(Boolean).forEach(s => { const m = EDITORS.exec(s); if (m) ed.add(m[1].trim()); });
    const em = EDITORS.exec(blob.slice(0, 2e6)); if (em) ed.add(em[1].trim());
    r.editors = [...ed];

    // Platform fingerprints
    if (!Object.keys(r.exif).length && r.format === 'JPEG') r.platformMarks.push('All EXIF stripped — consistent with a download from a social platform or messaging app, or deliberate scrubbing');
    if (w && h) PLATFORM_DIMS.forEach(d => { if (d.test(w, h)) r.platformMarks.push(d.label); });
    if (/Instagram/i.test(blob.slice(0, 5e5))) r.platformMarks.push('Instagram string found in file');
    if (r.progressive && !hasCamera) r.platformMarks.push('Progressive JPEG — typical of web/platform re-encoding, not camera output');
    if (r.jpegQuality && r.jpegQuality < 86 && !hasCamera) r.platformMarks.push(`JPEG quality ≈${r.jpegQuality} — recompressed at least once`);

    // Hidden / sensitive info
    const hidden = [];
    if (r.exif.GPSDecimal) hidden.push(`GPS location: ${r.exif.GPSDecimal.lat}, ${r.exif.GPSDecimal.lon}`);
    if (r.exif.BodySerialNumber) hidden.push(`Camera serial number: ${r.exif.BodySerialNumber}`);
    if (r.exif.CameraOwnerName) hidden.push(`Camera owner name: ${r.exif.CameraOwnerName}`);
    if (r.exif.Artist) hidden.push(`Artist field: ${r.exif.Artist}`);
    if (r.exif.Copyright) hidden.push(`Copyright: ${r.exif.Copyright}`);
    if (r.xmpFields['dc:creator']) hidden.push(`XMP creator: ${r.xmpFields['dc:creator'].replace(/<[^>]+>/g, ' ').trim()}`);
    if (r.xmpFields['photoshop:City'] || r.xmpFields['photoshop:Country']) hidden.push(`Location in XMP: ${[r.xmpFields['photoshop:City'], r.xmpFields['photoshop:Country']].filter(Boolean).join(', ')}`);
    if (r.exif.Make || r.exif.Model) hidden.push(`Device: ${[r.exif.Make, r.exif.Model].filter(Boolean).join(' ')}${r.exif.LensModel ? ' · ' + r.exif.LensModel : ''}`);
    if (r.prompt) hidden.push('The AI prompt used to generate the image is embedded in the file');
    if (r.xmpFields['xmpMM:OriginalDocumentID']) hidden.push(`Original document ID (links derivatives to the source file): ${r.xmpFields['xmpMM:OriginalDocumentID']}`);
    r.comments.forEach(c => c && hidden.push(`Embedded comment: "${c.slice(0, 120)}"`));
    r.hidden = hidden;

    // Timeline
    const tl = [];
    const add = (when, what, src, trust) => { const d = exifDate(when); if (d) tl.push({ when: d, what, src, trust }); };
    add(r.exif.DateTimeOriginal, 'Shutter pressed / image captured', 'EXIF DateTimeOriginal', 'high');
    add(r.exif.DateTimeDigitized, 'Digitised', 'EXIF DateTimeDigitized', 'high');
    add(r.exif.DateTime, 'Last written by software', 'EXIF DateTime', 'medium');
    add(r.xmpFields['xmp:CreateDate'], 'Created', 'XMP CreateDate', 'medium');
    add(r.xmpFields['photoshop:DateCreated'], 'Created (Photoshop)', 'XMP DateCreated', 'medium');
    add(r.xmpFields['xmp:ModifyDate'], 'Modified', 'XMP ModifyDate', 'medium');
    add(r.pngTime, 'PNG last-modified chunk', 'PNG tIME', 'medium');
    add(r.exif.GPS && r.exif.GPS.GPSDateStamp ? r.exif.GPS.GPSDateStamp.replace(/:/g, '-') + ' 00:00:00' : null, 'GPS satellite date', 'GPS DateStamp', 'high');
    (r.xmpFields.history || []).forEach(hh => add(hh.when, `Edit history: ${hh.action}${hh.agent ? ' in ' + hh.agent : ''}`, 'XMP history', 'medium'));
    if (file.lastModified) tl.push({ when: new Date(file.lastModified).toISOString().slice(0, 19), what: 'File last modified on this device (download/save time, not creation)', src: 'Filesystem', trust: 'low' });
    tl.sort((a, b) => a.when.localeCompare(b.when));
    r.timeline = tl;
    const firm = tl.filter(t => t.trust !== 'low');
    r.earliest = firm.length ? firm[0] : null;
    if (r.exif.DateTimeOriginal && r.exif.DateTime && exifDate(r.exif.DateTime) < exifDate(r.exif.DateTimeOriginal)) r.notes.push('Modification date is EARLIER than capture date — clock tampering or metadata forgery');
    if (r.exif.Software && hasCamera && EDITORS.test(r.exif.Software)) r.notes.push(`Camera original was re-saved in ${r.exif.Software}`);

    // Overall integrity score (0 = clean, 100 = highly suspect)
    let s = 0;
    if (r.ai.verdict === 'confirmed') s += 70; else if (r.ai.verdict === 'likely') s += 50; else if (r.ai.verdict === 'possible') s += 25; else if (weak.length) s += 10;
    if (r.editors.length) s += 12;
    if (r.ela && r.ela.hotspotPct > 2.5 && r.ela.blockCV > 1.1) s += 15;
    if (r.notes.some(n => /EARLIER/.test(n))) s += 15;
    if (!Object.keys(r.exif).length) s += 5;
    r.suspicion = Math.min(100, s);
    r.reverse = reverseLinks();
    return r;
  }

  function reverseLinks() {
    return [
      { name: 'Google Lens', url: 'https://lens.google.com/', how: 'Upload the image — strongest for finding the earliest copy and places' },
      { name: 'TinEye', url: 'https://tineye.com/', how: 'Sort results by "Oldest" to date the image' },
      { name: 'Bing Visual Search', url: 'https://www.bing.com/visualsearch', how: 'Good for stock photos and products' },
      { name: 'Yandex Images', url: 'https://yandex.com/images/', how: 'Best for faces and Eastern European / Russian sources' },
      { name: 'Content Credentials', url: 'https://contentcredentials.org/verify', how: 'Verifies C2PA signatures and edit history cryptographically' },
      { name: 'FotoForensics', url: 'https://fotoforensics.com/', how: 'Second-opinion ELA and metadata' },
    ];
  }

  // Compact summary for agents (no big data URLs)
  function summarize(r) {
    const { elaUrl, visionData, xmp, iptcRaw, segments, reverse, ...rest } = r;
    return { ...rest, xmpPresent: !!xmp, segmentCount: segments.length, textChunks: Object.fromEntries(Object.entries(r.textChunks).map(([k, v]) => [k, String(v).slice(0, 800)])) };
  }

  window.DeduceForensics = { analyze, summarize };
})();
