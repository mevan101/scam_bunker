// Scam Bunker — image provenance / original-source trace.
// Finds the original copy of a re-uploaded, cropped, re-encoded or re-dated image, its true capture date and the
// earliest evidence that it existed. Perceptual hashing runs in the browser; the server only fetches candidate files
// (SSRF-guarded) and queries the Wayback Machine.
//
// The pure functions (hashing, comparison, verdict) are exported on window.ScamBunkerProvenance and are unit-tested
// under node's vm with fake pixel arrays (test/provenance.test.js). The UI only boots when window.ScamBunker exists.
(function () {
  'use strict';

  // ======================= Perceptual hashing =======================
  // A "gray" image is { w, h, data: Float64Array(w*h) } holding luminance 0-255.
  function toGray(rgba, w, h) {
    const g = new Float64Array(w * h);
    for (let i = 0, j = 0; j < g.length; i += 4, j++) {
      const a = rgba[i + 3] === undefined ? 255 : rgba[i + 3];
      const l = 0.299 * rgba[i] + 0.587 * rgba[i + 1] + 0.114 * rgba[i + 2];
      g[j] = (l * a + 255 * (255 - a)) / 255; // transparent pixels composite on white
    }
    return { w, h, data: g };
  }

  // Area-average resample of rect (source pixel coords, may be fractional) to tw×th. Works for down- and up-scaling.
  const { min, max, floor, ceil } = Math; // locals: hot loops below (also much faster under node's vm in tests)
  function resizeGray(src, tw, th, rect) {
    const r = rect || { x: 0, y: 0, w: src.w, h: src.h };
    const out = new Float64Array(tw * th), sx = r.w / tw, sy = r.h / th;
    for (let ty = 0; ty < th; ty++) {
      const y0 = r.y + ty * sy, y1 = y0 + sy;
      for (let tx = 0; tx < tw; tx++) {
        const x0 = r.x + tx * sx, x1 = x0 + sx;
        let sum = 0, ws = 0;
        const ya = max(0, floor(y0)), yb = min(src.h, ceil(y1)), xa = max(0, floor(x0)), xb = min(src.w, ceil(x1));
        for (let y = ya; y < yb; y++) {
          const wy = min(y + 1, y1) - max(y, y0); if (wy <= 0) continue;
          const row = y * src.w;
          for (let x = xa; x < xb; x++) {
            const wx = min(x + 1, x1) - max(x, x0); if (wx <= 0) continue;
            sum += src.data[row + x] * wx * wy; ws += wx * wy;
          }
        }
        out[ty * tw + tx] = ws ? sum / ws : 0;
      }
    }
    return { w: tw, h: th, data: out };
  }

  function flipGray(src) {
    const d = new Float64Array(src.data.length);
    for (let y = 0; y < src.h; y++) for (let x = 0; x < src.w; x++) d[y * src.w + x] = src.data[y * src.w + (src.w - 1 - x)];
    return { w: src.w, h: src.h, data: d };
  }

  const bitsToHex = bits => { let s = ''; for (let i = 0; i < bits.length; i += 4) s += ((bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3]).toString(16); return s; };

  // dHash: 9×8 thumbnail, one bit per horizontal neighbour pair (is the left pixel brighter?). 64 bits → 16 hex chars.
  function dHash(src, rect) {
    const r = resizeGray(src, 9, 8, rect), bits = [];
    for (let y = 0; y < 8; y++) for (let x = 0; x < 8; x++) bits.push(r.data[y * 9 + x] > r.data[y * 9 + x + 1] ? 1 : 0);
    return bitsToHex(bits);
  }

  // pHash: 32×32 thumbnail → 2-D DCT-II → the 8×8 lowest frequencies → one bit per coefficient (above the median?).
  const COS = (() => { const t = []; for (let u = 0; u < 8; u++) { t[u] = new Float64Array(32); for (let x = 0; x < 32; x++) t[u][x] = Math.cos(((2 * x + 1) * u * Math.PI) / 64); } return t; })();
  function pHash(src, rect) {
    const r = resizeGray(src, 32, 32, rect), f = r.data;
    const rows = new Float64Array(32 * 8); // rows[y*8+u] = Σx f(x,y)·cos(u)
    for (let y = 0; y < 32; y++) for (let u = 0; u < 8; u++) { let s = 0; for (let x = 0; x < 32; x++) s += f[y * 32 + x] * COS[u][x]; rows[y * 8 + u] = s; }
    const coef = [];
    for (let v = 0; v < 8; v++) for (let u = 0; u < 8; u++) { let s = 0; for (let y = 0; y < 32; y++) s += rows[y * 8 + u] * COS[v][y]; coef.push(s); }
    const ac = coef.slice(1).sort((a, b) => a - b), med = (ac[31] + ac[32]) / 2; // median of the 63 AC terms (DC excluded)
    return bitsToHex(coef.map((c, i) => (i === 0 ? 0 : c > med ? 1 : 0)));
  }

  const POP = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];
  function hamming(a, b) {
    if (!a || !b || a.length !== b.length) return 64;
    let n = 0; for (let i = 0; i < a.length; i++) n += POP[parseInt(a[i], 16) ^ parseInt(b[i], 16)];
    return n;
  }

  // ---- Similarity thresholds (Hamming distance out of 64 bits; d = dHash, p = pHash, combined = mean of both) ----
  // Unrelated photographs land around 32 bits apart on both hashes (each bit is a coin toss).
  //   0–6   SAME image: identical, resized, or re-encoded (JPEG quality changes move only a few bits)
  //   7–10  LIKELY SAME: light edits on top (heavy recompression, small colour/contrast change, small watermark)
  //   11–18 RELATED: heavy filter, overlay text, a crop of a few percent; confirm by eye
  //   >18   DIFFERENT image
  // matchPct = 100 × (1 − combined/32), floored at 0: 100 % identical structure, 0 % no better than chance.
  const T = { same: 6, likely: 10, related: 18 };
  function classifyDistance(combined) { return combined <= T.same ? 'same' : combined <= T.likely ? 'likely-same' : combined <= T.related ? 'related' : 'different'; }
  const matchPct = combined => Math.max(0, Math.round(100 * (1 - combined / 32)));

  function hashGray(g) { const m = flipGray(g); return { d: dHash(g), p: pHash(g), dm: dHash(m), pm: pHash(m), w: g.w, h: g.h }; }

  function compareHashes(a, b) {
    const d = hamming(a.d, b.d), p = hamming(a.p, b.p);
    const dm = hamming(a.d, b.dm), pm = hamming(a.p, b.pm);
    return { d, p, combined: Math.round((d + p) / 2), mirrored: Math.round((dm + pm) / 2) };
  }

  // Is `small` a crop of `big`? Slides windows with small's aspect ratio over big (coarse grid, then local
  // refinement) and keeps the best combined distance. rect is returned as fractions of big.
  function findCrop(big, small, smallHash) {
    const sh = smallHash || { d: dHash(small), p: pHash(small) };
    const aspect = small.w / small.h;
    let fitW = big.w, fitH = fitW / aspect; if (fitH > big.h) { fitH = big.h; fitW = fitH * aspect; }
    const evalAt = (s, fx, fy) => {
      s = Math.min(1, Math.max(0.3, s)); fx = Math.min(1, Math.max(0, fx)); fy = Math.min(1, Math.max(0, fy));
      const w = fitW * s, h = fitH * s, x = (big.w - w) * fx, y = (big.h - h) * fy;
      const rect = { x, y, w, h };
      const d = hamming(dHash(big, rect), sh.d), p = hamming(pHash(big, rect), sh.p);
      return { s, fx, fy, d, p, combined: (d + p) / 2, rect };
    };
    let best = null;
    for (const s of [1, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4]) for (const fx of [0, 0.25, 0.5, 0.75, 1]) for (const fy of [0, 0.25, 0.5, 0.75, 1]) {
      const r = evalAt(s, fx, fy); if (!best || r.combined < best.combined) best = r;
    }
    let ds = 0.05, dp = 0.125;
    for (let round = 0; round < 3; round++, ds /= 2, dp /= 2) {
      const c = best;
      for (const a of [-1, 0, 1]) for (const b of [-1, 0, 1]) for (const e of [-1, 0, 1]) {
        if (!a && !b && !e) continue;
        const r = evalAt(c.s + a * ds, c.fx + b * dp, c.fy + e * dp); if (r.combined < best.combined) best = r;
      }
    }
    const r = best.rect;
    return { d: best.d, p: best.p, combined: Math.round(best.combined), areaFraction: +((r.w * r.h) / (big.w * big.h)).toFixed(3), rect: { x: +(r.x / big.w).toFixed(3), y: +(r.y / big.h).toFixed(3), w: +(r.w / big.w).toFixed(3), h: +(r.h / big.h).toFixed(3) } };
  }

  // Full comparison of the case image against a candidate. Each side: { hash: hashGray(..), gray, width, height, sha256 }
  function compareImages(caseImg, cand) {
    const aspectCase = caseImg.width / caseImg.height, aspectCand = cand.width / cand.height;
    const base = { aspectCase: +aspectCase.toFixed(3), aspectCand: +aspectCand.toFixed(3), scale: +((cand.width * cand.height) / (caseImg.width * caseImg.height)).toFixed(2) };
    if (caseImg.sha256 && caseImg.sha256 === cand.sha256) return { ...base, relation: 'identical', label: 'Byte-identical file', d: 0, p: 0, combined: 0, matchPct: 100 };
    const g = compareHashes(caseImg.hash, cand.hash);
    const out = { ...base, d: g.d, p: g.p, combined: g.combined };
    const sameAspect = Math.abs(aspectCase - aspectCand) / aspectCase < 0.03;
    if (g.combined <= T.likely) {
      const k = classifyDistance(g.combined);
      return { ...out, relation: 'same', strength: k, matchPct: matchPct(g.combined), label: (k === 'same' ? 'Same image' : 'Likely the same image') + (sameAspect ? (base.scale > 1.05 ? ', larger copy' : base.scale < 0.95 ? ', smaller copy' : '') : ', slightly cropped or padded') };
    }
    if (g.mirrored <= T.likely) return { ...out, relation: 'mirrored', combined: g.mirrored, matchPct: matchPct(g.mirrored), label: 'Mirror image (flipped left–right)' };
    // Crop either way round. Candidate containing the case image = the candidate shows more of the scene.
    if (caseImg.gray && cand.gray) {
      const caseInCand = findCrop(cand.gray, caseImg.gray, caseImg.hash);
      const candInCase = findCrop(caseImg.gray, cand.gray, cand.hash);
      const pick = caseInCand.combined <= candInCase.combined ? ['case-is-crop', caseInCand] : ['crop-of-case', candInCase];
      const [rel, c] = pick;
      if (c.combined <= T.likely && c.areaFraction < 0.97) {
        return { ...out, relation: rel, crop: c, matchPct: matchPct(c.combined), label: rel === 'case-is-crop' ? `Uncropped version: the case image is ${Math.round(c.areaFraction * 100)} % of this frame` : `Crop of the case image (${Math.round(c.areaFraction * 100)} % of its frame)` };
      }
    }
    const k = classifyDistance(g.combined);
    return { ...out, relation: k === 'related' ? 'related' : 'different', matchPct: matchPct(g.combined), label: k === 'related' ? 'Related: heavily edited or a different frame of the same scene. Check by eye' : 'Different image' };
  }
  const MATCHING = ['identical', 'same', 'mirrored', 'case-is-crop', 'crop-of-case'];

  // ======================= Dates =======================
  // EXIF "2019:03:14 12:00:00" or ISO → "2019-03-14T12:00:00". EXIF has no time zone, so date comparisons below use a
  // one-day tolerance.
  function normDate(s) {
    if (!s || typeof s !== 'string') return null;
    const m = /(\d{4})[:\-](\d{2})[:\-](\d{2})(?:[ T](\d{2}):(\d{2}):?(\d{2})?)?/.exec(s);
    if (!m || +m[1] < 1970 || m[1] === '0000') return null;
    return `${m[1]}-${m[2]}-${m[3]}T${m[4] || '00'}:${m[5] || '00'}:${m[6] || '00'}`;
  }
  const ms = s => Date.parse(String(s).replace(/Z?$/, 'Z'));
  const DAY = 864e5;
  const fmtDate = s => s ? String(s).replace(/\.\d+(?=Z?$)/, '').replace(/Z$/, '').replace('T00:00:00', '').replace('T', ' ') : '—';

  const MONTHS = 'jan feb mar apr may jun jul aug sep oct nov dec'.split(' ');
  // What date does the post claim the pictured event happened? Returns the latest date mentioned (the claim is usually
  // "this is happening now"), or the case date when the text says today / breaking / just now.
  function parseClaimedDate(text, caseAt) {
    const t = String(text || ''), found = [];
    const mon = s => MONTHS.indexOf(s.slice(0, 3).toLowerCase()) + 1;
    const pad = n => String(n).padStart(2, '0');
    for (const m of t.matchAll(/\b(19[89]\d|20\d\d)-(\d{2})-(\d{2})\b/g)) found.push({ date: `${m[1]}-${m[2]}-${m[3]}`, precision: 'day', basis: m[0] });
    for (const m of t.matchAll(/\b(\d{1,2})(?:st|nd|rd|th)?\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?\s+(19[89]\d|20\d\d)\b/gi)) found.push({ date: `${m[3]}-${pad(mon(m[2]))}-${pad(m[1])}`, precision: 'day', basis: m[0] });
    for (const m of t.matchAll(/\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(19[89]\d|20\d\d)\b/gi)) found.push({ date: `${m[3]}-${pad(mon(m[1]))}-${pad(m[2])}`, precision: 'day', basis: m[0] });
    for (const m of t.matchAll(/\b(january|february|march|april|may|june|july|august|september|october|november|december)\s+(19[89]\d|20\d\d)\b/gi)) found.push({ date: `${m[2]}-${pad(mon(m[1]))}-01`, precision: 'month', basis: m[0] });
    if (!found.length) for (const m of t.matchAll(/\b(?:in|since|of|year)\s+(19[89]\d|20\d\d)\b/gi)) found.push({ date: `${m[1]}-01-01`, precision: 'year', basis: m[0] });
    const valid = found.filter(f => !isNaN(ms(f.date)));
    if (valid.length) return valid.sort((a, b) => b.date.localeCompare(a.date))[0];
    const rel = /\b(today|tonight|this (?:morning|afternoon|evening)|just now|right now|happening now|breaking|live now|yesterday|moments ago|hours ago)\b/i.exec(t);
    if (rel && caseAt) {
      const d = new Date(ms(String(caseAt).slice(0, 19)) - (/yesterday/i.test(rel[1]) ? DAY : 0));
      return { date: d.toISOString().slice(0, 10), precision: 'day', basis: `“${rel[1]}” in a post examined on ${String(caseAt).slice(0, 10)}` };
    }
    return null;
  }

  // ======================= Items & verdict =======================
  // Flatten a DeduceForensics result (full or summarized) into the fields provenance needs.
  function itemFromForensics(f) {
    const ex = f.exif || {}, xf = f.xmpFields || {};
    return {
      width: f.width || 0, height: f.height || 0, format: f.format, size: f.size, jpegQuality: f.jpegQuality || null, sha256: f.sha256,
      camera: (ex.Model && ex.Make && String(ex.Model).toLowerCase().startsWith(String(ex.Make).toLowerCase()) ? ex.Model : [ex.Make, ex.Model].filter(Boolean).join(' ')) || null, serial: ex.BodySerialNumber || null,
      exifCapture: normDate(ex.DateTimeOriginal) || normDate(ex.DateTimeDigitized), exifModify: normDate(ex.DateTime), xmpCreate: normDate(xf['xmp:CreateDate']) || normDate(xf['photoshop:DateCreated']),
      gpsDate: ex.GPS && ex.GPS.GPSDateStamp ? normDate(String(ex.GPS.GPSDateStamp).replace(/:/g, '-')) : null,
      editors: f.editors || [], platformMarks: (f.platformMarks || []).length, ai: f.ai ? f.ai.verdict : null, c2pa: !!f.c2pa,
      fbmd: (f.platformMarks || []).some(m => /FBMD/.test(m)),
    };
  }

  // Closeness to the original file. Bigger, less compressed, camera EXIF, no editor, more of the scene = closer.
  function originalityScore(it) {
    let s = 0; const why = [];
    const px = (it.width || 0) * (it.height || 0);
    if (px) { const v = Math.max(0, Math.min(40, 10 * Math.log2(px / 1e5))); s += v; why.push(`${it.width}×${it.height} px`); }
    if (it.camera) { s += 25; why.push(`camera EXIF (${it.camera})`); }
    if (it.exifCapture) { s += 8; why.push('capture timestamp present'); }
    if (it.jpegQuality) { const v = Math.max(-10, Math.min(15, (it.jpegQuality - 75) / 1.5)); s += v; why.push(`JPEG quality ≈${it.jpegQuality}`); }
    if (it.editors && it.editors.length) { s -= 10; why.push(`re-saved in ${it.editors[0]}`); }
    if (it.platformMarks) { s -= Math.min(12, 3 * it.platformMarks); why.push('platform re-encode traces'); }
    const rel = it.compare && it.compare.relation;
    if (rel === 'case-is-crop') { s += 15; why.push('shows more of the scene than the case image'); }
    if (rel === 'crop-of-case') { s -= 15; why.push('cropped copy'); }
    if (rel === 'mirrored') { s -= 10; why.push('mirrored copy'); }
    return { score: Math.round(s), why };
  }

  const TRUST_RANK = { high: 3, medium: 2, low: 1 };
  // items[0] is the case image; the rest are fetched candidates (each with .compare). claimed: parseClaimedDate() result.
  function synthesize(items, claimed) {
    const matching = items.filter(it => it.isCase || (it.compare && MATCHING.includes(it.compare.relation)));
    matching.forEach(it => { const o = originalityScore(it); it.score = o.score; it.scoreWhy = o.why; });
    const ranked = [...matching].sort((a, b) => b.score - a.score);
    const best = ranked[0] || null;

    // Every dated piece of evidence about the matching copies
    const dates = [];
    const add = (iso, kind, trust, source, it, note) => { const n = normDate(iso); if (n) dates.push({ date: n, kind, trust, source, item: it.label, itemId: it.id, note: note || '' }); };
    for (const it of matching) {
      if (it.exifCapture) add(it.exifCapture, 'capture', it.camera && !(it.editors || []).length ? 'medium' : 'low', 'EXIF DateTimeOriginal (embedded, editable)', it);
      if (it.gpsDate) add(it.gpsDate, 'capture', 'medium', 'GPS date stamp (embedded)', it);
      if (it.xmpCreate) add(it.xmpCreate, 'created', 'low', 'XMP CreateDate (embedded, editable)', it);
      if (it.lastModified) add(it.lastModified, 'existed', 'medium', 'HTTP Last-Modified of the copy (server-reported)', it);
      if (it.archiveOrigLastModified) add(it.archiveOrigLastModified, 'existed', 'medium', 'Last-Modified recorded by the Wayback Machine', it);
      const wi = it.wayback && it.wayback.image, wp = it.wayback && it.wayback.page;
      // The Availability API (static mode) cannot tell file versions apart: its date is URL history, weak evidence only.
      if (wi && wi.firstSeen) add(wi.firstSeen, 'existed', wi.approximate ? 'low' : 'high', wi.approximate ? 'Wayback Machine first capture of the image URL (URL history only: the archived file may be a different picture)' : 'Wayback Machine first capture of the image URL (independent archive)', it, wi.firstSnapshot);
      if (wp && wp.firstSeen) add(wp.firstSeen, 'page', 'medium', 'Wayback Machine first capture of the page (the image may have been added later)', it, wp.firstSnapshot);
      if (it.pageDate && it.pageDate.published) add(it.pageDate.published.iso, 'page', 'medium', `Page publish date (${it.pageDate.published.source}, set by the publisher)`, it);
    }
    dates.sort((a, b) => a.date.localeCompare(b.date));

    // True capture date: the best-ranked matching copy that carries camera EXIF
    const capItem = ranked.find(it => it.exifCapture && it.camera) || ranked.find(it => it.exifCapture);
    const capture = capItem ? { date: capItem.exifCapture, item: capItem.label, itemId: capItem.id, trust: capItem.camera ? 'medium' : 'low', basis: capItem.camera ? `EXIF DateTimeOriginal written by ${capItem.camera}` : 'EXIF DateTimeOriginal with no camera make/model (weaker)' } : null;

    // Earliest evidence of existence: earliest date over trustworthy (high/medium) evidence of any kind.
    const trusted = dates.filter(d => TRUST_RANK[d.trust] >= 2);
    const earliest = trusted[0] || null;
    const independent = dates.find(d => d.trust === 'high') || null;

    const contradictions = [];
    const flag = (weight, text) => contradictions.push({ weight, text });
    // Recycled image: evidence of existence well before the event the post claims to show
    if (claimed && claimed.date) {
      const start = ms(claimed.date) - DAY;
      const before = trusted.filter(d => ms(d.date) < start && d.kind !== 'page');
      const pageBefore = trusted.filter(d => ms(d.date) < start && d.kind === 'page');
      const ev = before[0] || pageBefore[0];
      if (ev) flag(ev.trust === 'high' || before.length > 1 ? 'strong' : 'moderate', `Recycled image: the post claims ${claimed.precision === 'year' ? 'an event in ' + claimed.date.slice(0, 4) : claimed.precision === 'month' ? 'an event in ' + claimed.date.slice(0, 7) : 'an event on ' + claimed.date}, but a matching copy existed by ${fmtDate(ev.date)} (${ev.source}, ${ev.item}).`);
    }
    for (const it of matching) {
      if (it.exifCapture && it.exifModify && ms(it.exifModify) < ms(it.exifCapture) - 60e3) flag('moderate', `${it.label}: EXIF modify date ${fmtDate(it.exifModify)} is earlier than its capture date ${fmtDate(it.exifCapture)}. The clock or the metadata was tampered with.`);
      if (it.exifCapture) {
        const prior = trusted.filter(d => d.kind === 'existed' && ms(d.date) < ms(it.exifCapture) - DAY);
        if (prior.length) flag('strong', `${it.label}: EXIF says it was captured ${fmtDate(it.exifCapture)}, yet a copy already existed by ${fmtDate(prior[0].date)} (${prior[0].source}). The capture date is forged or the camera clock was wrong.`);
      }
      const wi = it.wayback && it.wayback.image;
      if (wi && wi.distinctDigests > 1) flag('weak', `${it.label}: the file served at this image URL changed ${wi.distinctDigests - 1}× in the archive. The first archived version may differ from what is served today. Fetch the first archived copy to compare.`);
      if (it.compare && it.compare.relation === 'mirrored') flag('weak', `${it.label} is a mirror image of the case image. Flipping is a common trick to defeat reverse image search.`);
    }
    const caps = matching.filter(it => it.exifCapture);
    for (let i = 0; i < caps.length; i++) for (let j = i + 1; j < caps.length; j++) {
      if (Math.abs(ms(caps[i].exifCapture) - ms(caps[j].exifCapture)) > DAY) { flag('moderate', `Copies disagree on the capture date: ${caps[i].label} says ${fmtDate(caps[i].exifCapture)}, ${caps[j].label} says ${fmtDate(caps[j].exifCapture)}. At least one was re-dated.`); i = caps.length; break; }
    }
    if (capture && claimed && claimed.date && ms(capture.date) < ms(claimed.date) - DAY && !contradictions.some(c => /^Recycled/.test(c.text))) flag('moderate', `Capture date ${fmtDate(capture.date)} (${capture.item}) is before the claimed event date ${claimed.date}.`);

    const original = best ? { item: best.label, itemId: best.id, isCase: !!best.isCase, score: best.score, why: best.scoreWhy, url: best.imageUrl || null, pageUrl: best.pageUrl || null } : null;
    let summary;
    if (matching.length <= 1) summary = 'No matching copy found yet. Add candidate URLs from a reverse image search.';
    else summary = `${matching.length - 1} matching cop${matching.length > 2 ? 'ies' : 'y'} found. ${original.isCase ? 'Your file is the closest to the original of those found.' : `Closest to the original: ${original.item}.`}${earliest ? ` Earliest evidence it existed: ${fmtDate(earliest.date)} (${earliest.source}).` : ''}${contradictions.some(c => c.weight === 'strong') ? ' Contradictions found.' : ''}`;
    return { original, capture, earliest, independent, dates, contradictions, summary, matches: matching.length - 1, claimed: claimed || null };
  }

  // Plain-text lines for the exported case report
  const urlHistory = i => [['image URL', i.wayback && i.wayback.image], ['page', i.wayback && i.wayback.page]].filter(([, w]) => w && w.firstSeen)
    .map(([k, w]) => `; Wayback URL history (${k}, not proof of this image): first ${fmtDate(w.firstSeen)} <${w.firstSnapshot}>${w.lastSeen && w.lastSeen !== w.firstSeen ? `, last ${fmtDate(w.lastSeen)} <${w.lastSnapshot}>` : ''}`).join('');
  function reportLines(p) {
    if (!p || !p.verdict) return [];
    const v = p.verdict, L = ['', 'IMAGE PROVENANCE', v.summary];
    if (v.original) L.push(`Likely original copy: ${v.original.item}${v.original.url ? ' <' + v.original.url + '>' : ''} (${v.original.why.join(', ')})`);
    if (v.capture) L.push(`True capture date: ${fmtDate(v.capture.date)}, ${v.capture.basis}, from ${v.capture.item} (trust ${v.capture.trust})`);
    if (v.earliest) L.push(`Earliest evidence of existence: ${fmtDate(v.earliest.date)}, ${v.earliest.source}, ${v.earliest.item} (trust ${v.earliest.trust})`);
    if (v.claimed) L.push(`Claimed event date: ${v.claimed.date} (${v.claimed.basis})`);
    if (v.dates.length) L.push('Dated evidence:', ...v.dates.map(d => `- ${fmtDate(d.date)} · ${d.source} · ${d.item} · trust ${d.trust}${d.note ? ' · ' + d.note : ''}`));
    if (v.contradictions.length) L.push('Contradictions:', ...v.contradictions.map(c => `- [${c.weight}] ${c.text}`));
    const cands = (p.items || []).filter(i => !i.isCase);
    if (cands.length) L.push('Copies compared:', ...cands.map(i => `- ${i.label}: ${i.error ? 'error: ' + i.error : i.localOnly ? 'not compared (needs the local app): ' + i.localOnly + urlHistory(i) : `${i.compare.label} (${i.compare.matchPct} % match, dHash ${i.compare.d}/64, pHash ${i.compare.p}/64), ${i.width}×${i.height}`} <${i.imageUrl}>${i.pageUrl ? ' on <' + i.pageUrl + '>' : ''}`));
    return L;
  }

  const api = { toGray, resizeGray, flipGray, dHash, pHash, hamming, hashGray, compareHashes, findCrop, compareImages, classifyDistance, matchPct, THRESHOLDS: T, normDate, parseClaimedDate, itemFromForensics, originalityScore, synthesize, reportLines };
  if (typeof window !== 'undefined') window.ScamBunkerProvenance = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof document === 'undefined' || typeof window === 'undefined' || !window.ScamBunker) return;

  // ======================= Browser: decode & hash =======================
  const HASH_MAX = 192; // working resolution for hashing and crop search
  async function hashBlob(blob) {
    const bmp = await createImageBitmap(blob);
    const s = Math.min(1, HASH_MAX / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * s)), h = Math.max(1, Math.round(bmp.height * s));
    const c = document.createElement('canvas'); c.width = w; c.height = h;
    const x = c.getContext('2d', { willReadFrequently: true });
    x.fillStyle = '#fff'; x.fillRect(0, 0, w, h); x.drawImage(bmp, 0, 0, w, h);
    const gray = toGray(x.getImageData(0, 0, w, h).data, w, h);
    const ts = Math.min(1, 160 / Math.max(bmp.width, bmp.height));
    const tc = document.createElement('canvas'); tc.width = Math.max(1, Math.round(bmp.width * ts)); tc.height = Math.max(1, Math.round(bmp.height * ts));
    tc.getContext('2d').drawImage(bmp, 0, 0, tc.width, tc.height);
    const out = { gray, hash: hashGray(gray), width: bmp.width, height: bmp.height, thumb: tc.toDataURL('image/jpeg', 0.75) };
    bmp.close && bmp.close();
    return out;
  }
  // Exposed so the hashing/compare logic can be exercised in the page with canvas-made blobs.
  api.hashBlob = hashBlob;
  api.compareBlobs = async (a, b) => { const [x, y] = await Promise.all([hashBlob(a), hashBlob(b)]); return compareImages(x, y); };

  // ======================= UI =======================
  const SB = window.ScamBunker;
  const esc = SB.esc;
  const $ = s => document.querySelector(s);
  const safeHref = u => /^https?:\/\//i.test(String(u || '')) ? esc(u) : '#';
  const host = u => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return u; } };
  const kb = n => n ? (n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.round(n / 1024) + ' KB') : '—';
  const thumbs = new Map(); // item id → data URL (kept out of the case object so saved cases stay small)
  let caseImg = null, caseImgFor = null, busy = false, statusMsg = '';
  const setStatus = m => { statusMsg = m; const el = $('#prov-status'); if (el) el.textContent = m; };

  async function postJson(path, body) {
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(j.error || `HTTP ${r.status}`); e.code = j.code; e.contentType = j.contentType; throw e; }
    return j;
  }
  const waybackCache = new Map();
  // Static mode (GitHub Pages, no /api): Wayback via the CORS-enabled Availability API, candidate images straight
  // from hosts that allow it. Page fetching and SerpApi need the local app (public/shared/direct.js).
  const direct = window.ScamBunkerDirect;
  const isStatic = () => !!(SB.isStatic && SB.isStatic());
  const isSimple = () => typeof SB.mode === 'function' && SB.mode() === 'simple';
  const addReasons = (c, r) => { if (typeof SB.addReasons === 'function' && r.length) SB.addReasons(c, r); };
  const localAppHtml = (what, detail) => direct ? direct.localAppHtml(esc, what, detail) : `<p class="muted">${esc(what)}: available in the local app.</p>`;
  const waybackLookup = url => isStatic() ? (direct ? direct.wayback(url) : Promise.resolve({ ok: false, url, error: 'Needs the local app' })) : postJson('/api/provenance/wayback', { url }).catch(e => ({ ok: false, url, error: e.message }));
  const wayback = url => { if (!url) return Promise.resolve(null); if (!waybackCache.has(url)) waybackCache.set(url, waybackLookup(url)); return waybackCache.get(url); };
  async function fetchCandidate(it, entry) {
    if (!isStatic()) return null;
    try { return await direct.image(entry.url); }
    catch (e) {
      // The page/host cannot be read from a browser page. Keep the URL, date it through the archive, explain.
      it.localOnly = e.message;
      const [wi, wp] = await Promise.all([wayback(it.imageUrl), wayback(it.pageUrl)]);
      it.wayback = { image: wi, page: wp };
      return 'local';
    }
  }

  function tab() { return $('#tab-provenance'); }
  function sync(c) {
    const t = tab(); if (!t) return;
    const has = !!(c && c.forensics);
    t.hidden = !has || isSimple();
    if (!has && t.getAttribute('aria-selected') === 'true') SB.showTab('deduction');
    render(c);
  }

  async function ensureCaseImage(c) {
    if (caseImg && caseImgFor === c.id) return caseImg;
    if (!c.imagePreview) throw new Error('The original image is not available for this saved case. Open it again from the intake panel to trace it');
    const blob = await (await fetch(c.imagePreview)).blob();
    caseImg = await hashBlob(blob); caseImg.sha256 = c.forensics.sha256; caseImgFor = c.id;
    return caseImg;
  }

  function caseItem(c) {
    return { id: 'case', isCase: true, label: 'Case image (your file)', ...itemFromForensics(c.forensics), imageUrl: null };
  }

  function parseLines(text) {
    const out = [];
    for (const line of String(text || '').split(/\n+/)) {
      const urls = line.match(/https?:\/\/[^\s<>"']+/g); if (!urls) continue;
      out.push({ url: urls[0], pageUrl: urls[1] || null });
    }
    return out.slice(0, 25);
  }

  function b64ToBytes(b64) { const bin = atob(b64), u8 = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i); return u8; }

  async function processCandidate(c, entry, n) {
    const it = { id: 'c' + Date.now().toString(36) + n, label: `Copy ${n}`, imageUrl: entry.url, pageUrl: entry.pageUrl, from: entry.from || 'manual' };
    try {
      let img = await fetchCandidate(it, entry);
      if (img === 'local') return it;
      if (img) { /* fetched directly by the browser */ }
      else try { img = await postJson('/api/provenance/fetch-image', { url: entry.url }); }
      catch (e) {
        if (e.code !== 'bad_type' || !/html|xml/.test(e.contentType || '')) throw e;
        // A page, not an image: take its preview image (og:image) and the page's publish date
        const pd = await postJson('/api/provenance/page-date', { url: entry.url });
        if (!pd.ogImage) throw new Error('This is a web page with no preview image (og:image). Open it, right-click the picture, copy the image address and paste that instead');
        it.pageUrl = entry.url; it.pageDate = pd; it.imageUrl = pd.ogImage;
        img = await postJson('/api/provenance/fetch-image', { url: pd.ogImage });
      }
      it.label = `Copy ${n} · ${host(it.pageUrl || it.imageUrl)}`;
      it.finalUrl = img.finalUrl; it.contentType = img.contentType; it.lastModified = img.lastModified; it.archiveOrigLastModified = img.archiveOrigLastModified;
      const bytes = img.blob || b64ToBytes(img.dataBase64);
      const file = new File([bytes], (new URL(img.finalUrl).pathname.split('/').pop() || 'candidate').slice(0, 80), { type: img.contentType, lastModified: 0 });
      const [f, h] = await Promise.all([DeduceForensics.analyze(file), hashBlob(file)]);
      Object.assign(it, itemFromForensics(f), { width: h.width || f.width, height: h.height || f.height, size: img.size });
      h.sha256 = f.sha256; thumbs.set(it.id, h.thumb);
      it.hash = { d: h.hash.d, p: h.hash.p };
      it.compare = compareImages(caseImg, h);
      const [wi, wp, pd] = await Promise.all([wayback(it.imageUrl), wayback(it.pageUrl), it.pageUrl && !it.pageDate && !isStatic() ? postJson('/api/provenance/page-date', { url: it.pageUrl }).catch(e => ({ error: e.message })) : null]);
      it.wayback = { image: wi, page: wp }; if (pd) it.pageDate = pd;
    } catch (e) { it.error = e.message; }
    return it;
  }

  async function trace() {
    const c = SB.current; if (!c || !c.forensics || busy) return;
    const entries = parseLines($('#prov-cands').value);
    const p = c.provenance = c.provenance || { items: [] };
    const known = new Set(p.items.map(i => i.imageUrl).concat(p.items.map(i => i.requested)));
    const todo = entries.filter(e => !known.has(e.url));
    p.claimed = readClaimed(c);
    if (!todo.length && p.items.length) { finish(c); setStatus('Verdict updated.'); return; }
    if (!todo.length) { setStatus('Paste at least one image or page URL first.'); $('#prov-cands').focus(); return; }
    busy = true; $('#prov-run').disabled = true;
    try {
      setStatus('Hashing the case image…');
      await ensureCaseImage(c);
      let n = p.items.filter(i => !i.isCase).length, done = 0;
      const queue = todo.map(e => ({ e, n: ++n }));
      const worker = async () => {
        for (let job; (job = queue.shift());) {
          setStatus(`Fetching and comparing ${done + 1} of ${todo.length}: ${host(job.e.url)}…`);
          const it = await processCandidate(c, job.e, job.n); it.requested = job.e.url;
          p.items.push(it); done++; finish(c, true);
        }
      };
      await Promise.all([worker(), worker(), worker()]);
      const ok = p.items.filter(i => !i.isCase && !i.error && !i.localOnly), local = p.items.filter(i => i.localOnly).length, m = ok.filter(i => MATCHING.includes(i.compare.relation)).length;
      setStatus(`Done. ${ok.length} cop${ok.length === 1 ? 'y' : 'ies'} analysed, ${m} matching.${local ? ` ${local} need${local === 1 ? 's' : ''} the local app.` : ''}`);
    } catch (e) { setStatus('Could not run the trace: ' + e.message); SB.toast(e.message); }
    finally { busy = false; $('#prov-run').disabled = false; finish(c); }
  }

  function readClaimed(c) {
    const v = $('#prov-claimed') && $('#prov-claimed').value;
    const auto = parseClaimedDate([c.text, c.page && c.page.markdown ? c.page.markdown.slice(0, 4000) : ''].join('\n'), c.at);
    if (v) return { date: v, precision: 'day', basis: auto && auto.date === v ? auto.basis : 'entered by the investigator' };
    return auto;
  }

  // Recompute the verdict, store it on the case, feed it into the main report, re-render.
  function finish(c, partial) {
    const p = c.provenance; if (!p) return;
    const items = [caseItem(c), ...p.items.filter(i => !i.isCase && !i.error && !i.localOnly)];
    p.verdict = synthesize(items, p.claimed);
    // keep scores on stored items
    p.items.forEach(i => { const s = items.find(x => x.id === i.id); if (s) { i.score = s.score; i.scoreWhy = s.scoreWhy; } });
    p.caseScore = items[0].score; p.caseScoreWhy = items[0].scoreWhy;
    p.at = new Date().toISOString();
    p.reportLines = reportLines(p);
    const v = c.final || c.local;
    if (v && !partial) {
      v.observations = (v.observations || []).filter(o => !o.provenance);
      p.verdict.contradictions.filter(x => x.weight !== 'weak').forEach(x => v.observations.unshift({ fact: 'Image provenance trace', inference: x.text, weight: x.weight, provenance: true }));
      const e = p.verdict.earliest;
      if (v.image_dating && !p.fileDating) p.fileDating = { ...v.image_dating }; // what the file alone said, before the trace
      const fd = p.fileDating;
      if (fd) v.image_dating = e && (!fd.earliest || e.date.slice(0, 10) < fd.earliest.slice(0, 10)) ? { ...fd, earliest: fmtDate(e.date), basis: `Earliest evidence of existence from the provenance trace: ${e.source} (${e.item}), trust ${e.trust}` } : { ...fd };
      SB.renderAll();
      persist(c);
      document.dispatchEvent(new CustomEvent('sb:provenance', { detail: c }));
    }
    render(c);
  }

  function persist(c) {
    const list = SB.store.get('scambunker.cases', []);
    const row = list.find(x => x.id === c.id); if (!row) return;
    row.provenance = c.provenance; if (row.local && c.local) row.local = c.local;
    SB.store.set('scambunker.cases', list);
  }

  // ---------- Render ----------
  const B = (cls, text) => `<span class="w ${esc(cls)}">${esc(text)}</span>`;
  const W = w => B(w, w);
  const REL_W = { identical: 'ok', same: 'ok', 'case-is-crop': 'ok', 'crop-of-case': 'moderate', mirrored: 'moderate', related: 'weak', different: 'weak' };

  function manualSearchLinks(url) {
    const e = encodeURIComponent(url);
    return [
      ['Google Lens', url ? `https://lens.google.com/uploadbyurl?url=${e}` : 'https://lens.google.com/', 'Best overall. Use “Find image source” and open “Exact matches”'],
      ['TinEye', url ? `https://tineye.com/search?url=${e}` : 'https://tineye.com/', 'Sort by “Oldest” to see the first crawl date'],
      ['Bing Visual Search', url ? `https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:${e}` : 'https://www.bing.com/visualsearch', 'Open “Pages with this image”'],
      ['Yandex Images', url ? `https://yandex.com/images/search?rpt=imageview&url=${e}` : 'https://yandex.com/images/', 'Strong on faces, crops and Eastern European sources'],
    ];
  }

  function dateRow(d) {
    return `<li><b>${esc(fmtDate(d.date))}</b> · ${esc(d.source)} · <span class="muted">${esc(d.item)}</span> ${B(d.trust === 'high' ? 'ok' : d.trust === 'medium' ? 'moderate' : 'weak', 'trust ' + d.trust)}${d.note && /^https?:/.test(d.note) ? ` <a href="${safeHref(d.note)}" target="_blank" rel="noopener">snapshot ↗</a>` : ''}</li>`;
  }

  function wbLine(label, w) {
    if (!w) return '';
    if (!w.ok) return `<div>${label}</div><div>Unavailable: ${esc(w.error || 'error')}</div>`;
    if (w.approximate) return `<div>${label}</div><div><a href="${safeHref(w.firstSnapshot)}" target="_blank" rel="noopener">${esc(fmtDate(w.firstSeen))} ↗</a> · first capture, last <a href="${safeHref(w.lastSnapshot)}" target="_blank" rel="noopener">${esc(fmtDate(w.lastSeen))} ↗</a> <span class="muted">(capture count in the local app)</span></div>`;
    if (!w.captures) return `<div>${label}</div><div>Not archived. <a href="${safeHref(w.saveUrl)}" target="_blank" rel="noopener">Save it now ↗</a></div>`;
    return `<div>${label}</div><div><a href="${safeHref(w.firstSnapshot)}" target="_blank" rel="noopener">${esc(fmtDate(w.firstSeen))} ↗</a> · ${w.captures}${w.capturesCapped ? '+' : ''} capture${w.captures === 1 ? '' : 's'}, last ${esc(fmtDate(w.lastSeen))}${w.distinctDigests > 1 ? ` · ${w.distinctDigests} different file versions` : ''}</div>`;
  }

  function card(it, p) {
    if (it.localOnly) {
      const wb = wbLine('Wayback: URL', it.wayback && it.wayback.image) + (it.pageUrl ? wbLine('Wayback: page', it.wayback && it.wayback.page) : '');
      return `<article class="linkcard prov-card" data-id="${esc(it.id)}" aria-label="${esc(it.label)}"><div class="top"><code>${esc(it.imageUrl)}</code><span class="tag">not compared</span><button type="button" class="link" data-prov-remove="${esc(it.id)}" aria-label="Remove ${esc(it.label)}">Remove</button></div>
        ${localAppHtml('Comparing this copy', `${it.localOnly}. Fetching copies from any website, with their preview image and publish date, needs the Scam Bunker server.`)}
        ${wb ? `<div class="kv">${wb}</div>` : ''}
        <p class="prov-links"><a href="${safeHref(it.imageUrl)}" target="_blank" rel="noopener">Open ↗</a> · Search this copy: ${manualSearchLinks(it.imageUrl).map(([n, u]) => `<a href="${safeHref(u)}" target="_blank" rel="noopener">${n} ↗</a>`).join(' ')}</p></article>`;
    }
    if (it.error) return `<article class="linkcard prov-card" data-id="${esc(it.id)}"><div class="top"><code>${esc(it.imageUrl)}</code>${B('strong', 'failed')}<button type="button" class="link" data-prov-remove="${esc(it.id)}" aria-label="Remove ${esc(it.label)}">Remove</button></div><ul><li>${esc(it.error)}</li></ul></article>`;
    const c = it.compare, th = thumbs.get(it.id);
    const best = p.verdict && p.verdict.original && p.verdict.original.itemId === it.id;
    const rows = [
      ['Match', c.crop ? `${c.matchPct} % inside a crop window (dHash ${c.crop.d}/64 · pHash ${c.crop.p}/64), window at ${Math.round(c.crop.rect.x * 100)} %, ${Math.round(c.crop.rect.y * 100)} % covering ${Math.round(c.crop.areaFraction * 100)} % of the larger frame · whole-frame distance ${c.combined}/64` : `${c.matchPct} % · dHash ${c.d}/64 · pHash ${c.p}/64`],
      ['Dimensions', `${it.width}×${it.height} (${c.scale}× the case image's pixels) · ${esc(it.format || '')}${it.jpegQuality ? ' q≈' + it.jpegQuality : ''} · ${kb(it.size)}`],
      ['Camera', it.camera ? `${esc(it.camera)}${it.serial ? ' · serial ' + esc(it.serial) : ''}` : 'No camera EXIF'],
      ['EXIF captured', esc(fmtDate(it.exifCapture))],
      it.exifModify ? ['EXIF modified', esc(fmtDate(it.exifModify))] : null,
      ['Last-Modified', esc(fmtDate(it.lastModified))],
      it.archiveOrigLastModified ? ['Archived Last-Modified', esc(fmtDate(it.archiveOrigLastModified))] : null,
      it.editors && it.editors.length ? ['Software', esc(it.editors.join(', '))] : null,
      it.pageDate && it.pageDate.published ? ['Page published', `${esc(fmtDate(it.pageDate.published.iso))} · ${esc(it.pageDate.published.source)}`] : null,
    ].filter(Boolean);
    const wb = wbLine('Wayback: image URL', it.wayback && it.wayback.image) + (it.pageUrl ? wbLine('Wayback: page', it.wayback && it.wayback.page) : '');
    const raw = it.wayback && it.wayback.image && it.wayback.image.firstRaw;
    return `<article class="linkcard prov-card${best ? ' prov-best' : ''}" data-id="${esc(it.id)}" aria-label="${esc(it.label)}">
      <div class="top"><b>${esc(it.label)}</b>${B(REL_W[c.relation] || 'weak', c.relation.replace(/-/g, ' '))}${best ? '<span class="tag">closest to original</span>' : ''}<button type="button" class="link" data-prov-remove="${esc(it.id)}" aria-label="Remove ${esc(it.label)}">Remove</button></div>
      <div class="prov-row">
        ${th ? `<img class="prov-thumb" src="${th}" alt="Thumbnail of ${esc(it.label)}">` : '<div class="prov-thumb prov-nothumb" aria-hidden="true">no preview</div>'}
        <div class="prov-body"><p class="muted" style="margin:0 0 6px">${esc(c.label)}${it.scoreWhy ? ` · originality score ${it.score}` : ''}</p>
          <div class="kv">${rows.map(([k, v]) => `<div>${k}</div><div>${v}</div>`).join('')}${wb}</div>
          <p class="prov-links"><a href="${safeHref(it.imageUrl)}" target="_blank" rel="noopener">Image ↗</a>${it.pageUrl ? ` · <a href="${safeHref(it.pageUrl)}" target="_blank" rel="noopener">Page ↗</a>` : ''} · Search this copy: ${manualSearchLinks(it.imageUrl).map(([n, u]) => `<a href="${safeHref(u)}" target="_blank" rel="noopener">${n} ↗</a>`).join(' ')}${raw ? ` · <button type="button" class="link" data-prov-add="${esc(raw)}">Compare the first archived copy</button>` : ''}</p>
        </div>
      </div></article>`;
  }

  function verdictHtml(p) {
    const v = p.verdict; if (!v) return '';
    const o = v.original;
    return `<section aria-labelledby="prov-v-h"><h3 id="prov-v-h">Provenance verdict</h3>
      <p>${esc(v.summary)}</p>
      <div class="grid2 prov-grid3">
        <div class="box"><div class="k">Likely original copy</div><div class="big">${esc(o ? o.item : '—')}</div><p>${o ? esc(o.why.join(' · ')) : ''}${o && o.url ? ` · <a href="${safeHref(o.url)}" target="_blank" rel="noopener">open ↗</a>` : ''}</p></div>
        <div class="box"><div class="k">True capture date</div><div class="big">${esc(v.capture ? fmtDate(v.capture.date) : 'Unknown')}</div><p>${v.capture ? `${esc(v.capture.basis)}, from ${esc(v.capture.item)} · trust ${esc(v.capture.trust)}` : 'No matching copy carries a capture timestamp. Look for the camera original or date the scene itself (below).'}</p></div>
        <div class="box"><div class="k">Earliest evidence of existence</div><div class="big">${esc(v.earliest ? fmtDate(v.earliest.date) : 'Unknown')}</div><p>${v.earliest ? `${esc(v.earliest.source)} · ${esc(v.earliest.item)} · trust ${esc(v.earliest.trust)}` : 'No trustworthy date yet.'}${v.independent && v.independent !== v.earliest ? `<br>Earliest independent (archive) evidence: ${esc(fmtDate(v.independent.date))}` : ''}</p></div>
      </div>
      ${v.contradictions.length ? `<h3 style="margin-top:18px">Contradictions</h3><div class="obs">${v.contradictions.map(x => `<div class="ob"><div><p>${esc(x.text)}</p></div><div></div>${W(x.weight)}</div>`).join('')}</div>` : ''}
      ${v.dates.length ? `<h3 style="margin-top:18px">Dated evidence, oldest first</h3><ul class="list">${v.dates.map(dateRow).join('')}</ul>` : ''}
    </section>`;
  }

  function render(c) {
    const el = SB.panel('provenance'); if (!el) return;
    if (!c || !c.forensics) { el.innerHTML = '<p class="empty">Add an image to the case to trace where it came from.</p>'; return; }
    const p = c.provenance || { items: [] };
    const f = c.forensics, srv = SB.server() || {};
    const auto = parseClaimedDate([c.text, c.page && c.page.markdown ? c.page.markdown.slice(0, 4000) : ''].join('\n'), c.at);
    const same = el.dataset.caseId === c.id; // keep what the investigator typed while re-rendering the same case
    if (!same) statusMsg = '';
    const claimedVal = same && $('#prov-claimed') ? $('#prov-claimed').value : (p.claimed && p.claimed.date) || (auto && auto.date) || '';
    const prevCands = same && $('#prov-cands') ? $('#prov-cands').value : (p.items || []).filter(i => !i.isCase).map(i => [i.requested || i.imageUrl, i.pageUrl].filter(Boolean).join(' ')).join('\n');
    const focusId = el.contains(document.activeElement) && document.activeElement.id;
    el.dataset.caseId = c.id;
    const caseTh = c.imagePreview || '';
    el.innerHTML = `
      <section><p class="muted" style="margin-top:0">Find the original of a re-uploaded, cropped, re-encoded or re-dated image. Each copy you find is fetched, read by the same forensics engine and compared with your file by perceptual hash (dHash + pHash, which survive resizing and recompression), then dated through its EXIF, server headers and the Wayback Machine.</p>
        <div class="prov-row"><img class="prov-thumb" src="${esc(caseTh)}" alt="Case image"><div class="prov-body"><div class="kv">
          <div>Case image</div><div>${f.width}×${f.height} · ${esc(f.format)}${f.jpegQuality ? ' q≈' + f.jpegQuality : ''} · ${kb(f.size)}</div>
          <div>Camera</div><div>${esc([f.exif && f.exif.Make, f.exif && f.exif.Model].filter(Boolean).join(' ') || 'No camera EXIF')}</div>
          <div>EXIF captured</div><div>${esc(fmtDate(normDate(f.exif && (f.exif.DateTimeOriginal || f.exif.DateTimeDigitized))))}</div>
          ${caseImg && caseImgFor === c.id ? `<div>Perceptual hashes</div><div><code>d ${caseImg.hash.d} · p ${caseImg.hash.p}</code></div>` : ''}
        </div></div></div>
      </section>
      <section aria-labelledby="prov-find-h"><h3 id="prov-find-h">1 · Find copies</h3>
        ${srv.reverseSearch ? `<div class="callout"><label class="field" style="margin:0 0 8px"><span>Public URL of this image, if it is published somewhere (automatic Google Lens search via SerpApi)</span><input type="url" id="prov-rev-url" placeholder="https://…/image.jpg"></label><button type="button" class="primary sm" id="prov-rev-run">Search automatically</button> <span class="muted" id="prov-rev-status" role="status"></span><div id="prov-rev-results"></div></div>`
          : isStatic() ? `${localAppHtml('Automatic reverse search', 'Google Lens search through SerpApi needs a secret API key, which only the local server can hold.')}<p class="muted">Search by hand:</p>`
          : `<p class="muted">Automatic reverse search is off (set <code>SERPAPI_API_KEY</code> on the server to enable it). Search by hand:</p>`}
        <ol class="prov-steps"><li>Open each engine below and upload the case image (drag the file in).</li><li>Look for the <b>largest</b> and <b>oldest</b> copies: TinEye → sort by “Oldest”; Google Lens → “Exact matches”; Bing → “Pages with this image”.</li><li>Right-click each promising result's picture → “Copy image address”, and paste it below. Add the page it appeared on after a space; a page URL on its own also works.</li></ol>
        <div class="rev">${manualSearchLinks(null).map(([n, u, how]) => `<a href="${safeHref(u)}" target="_blank" rel="noopener"><b>${n} ↗</b><span>${esc(how)}</span></a>`).join('')}</div>
      </section>
      <section aria-labelledby="prov-trace-h"><h3 id="prov-trace-h">2 · Compare and date them</h3>
        <label class="field"><span>Candidate image or page URLs, one per line (optionally: image URL, a space, then the page it was on)</span>
          <textarea id="prov-cands" rows="4" placeholder="https://cdn.example.com/photo.jpg https://example.com/article-2019&#10;https://example.org/post/123">${esc(prevCands)}</textarea></label>
        <div class="row">
          <label class="field"><span>Date of the event the post claims to show</span><input type="date" id="prov-claimed" value="${esc(claimedVal)}" aria-describedby="prov-claimed-hint"></label>
          <p class="muted grow" id="prov-claimed-hint" style="align-self:center;margin:0 0 14px">${auto ? `Detected from the post: ${esc(auto.basis)}. Change it if that is wrong.` : 'Not detected in the post text. Enter it to test for a recycled image.'}</p>
        </div>
        <button type="button" class="primary sm" id="prov-run"${busy ? ' disabled' : ''}>Trace sources</button>
        <span class="muted" id="prov-status" role="status" aria-live="polite" style="margin-left:10px">${esc(statusMsg)}</span>
      </section>
      ${verdictHtml(p)}
      ${(p.items || []).length ? `<section aria-labelledby="prov-copies-h"><h3 id="prov-copies-h">Copies compared</h3>${p.items.filter(i => !i.isCase).map(i => card(i, p)).join('')}<p class="muted">Similarity thresholds (bits that differ, out of 64): 0–6 same image, 7–10 likely the same with light edits, 11–18 related or heavily edited, above 18 different. Bigger, less compressed copies with camera EXIF are closer to the original.</p></section>` : ''}
      <section><details class="prov-help"><summary>Chronolocation: date the scene itself (manual next steps)</summary>
        <p class="muted">Metadata and archives give the latest date by which a picture existed. The scene can confirm or rule out the claimed date. These steps are manual on purpose. Scam Bunker does not pretend to automate them.</p>
        <ul class="list">
          <li><b>Shadows and sun position.</b> Find the location, then open <a href="https://www.suncalc.org/" target="_blank" rel="noopener">SunCalc ↗</a>. Set the claimed date and drag the time until the sun's azimuth matches the shadow direction. Check that the shadow length fits the sun's altitude. If no time on the claimed date fits, the claim is false.</li>
          <li><b>Weather history.</b> Compare rain, snow, cloud cover and wet ground with the weather records for that place and day, for example <a href="https://meteostat.net/" target="_blank" rel="noopener">Meteostat ↗</a>, <a href="https://open-meteo.com/en/docs/historical-weather-api" target="_blank" rel="noopener">Open-Meteo historical ↗</a> or Weather Underground history.</li>
          <li><b>Season and vegetation.</b> Leaves, blossom, crops and snow cover narrow the month.</li>
          <li><b>Things that changed.</b> Shopfronts, construction, road markings and vehicles can be checked against Google Earth historical imagery and the Street View time slider.</li>
        </ul></details></section>`;
    if (focusId && document.getElementById(focusId)) document.getElementById(focusId).focus();
  }

  // ---------- Events ----------
  // Simple mode: say it plainly when the trace found an old photo (the shell already links reverse image search).
  function simpleReasons(c) {
    const v = c.provenance && c.provenance.verdict, claimed = v && v.claimed;
    const recycled = v && v.contradictions.find(x => /^Recycled/.test(x.text));
    if (!recycled || !v.earliest || c._provReason === v.earliest.date) return;
    c._provReason = v.earliest.date;
    addReasons(c, [{ text: `This picture was already online on ${fmtDate(v.earliest.date).slice(0, 10)}, before the event the post says it shows (${claimed.date}). It is probably an old photo being reused.`, weight: recycled.weight, source: v.earliest.source }]);
  }
  document.addEventListener('sb:case', e => sync(e.detail));
  document.addEventListener('sb:mode', () => sync(SB.current));
  document.addEventListener('sb:provenance', e => simpleReasons(e.detail));
  document.addEventListener('click', e => {
    if (e.target.closest('#history-list .hist')) { setTimeout(() => sync(SB.current), 0); return; }
    const c = SB.current; if (!c) return;
    if (e.target.closest('#prov-run')) { trace(); return; }
    const add = e.target.closest('[data-prov-add]');
    if (add) { const ta = $('#prov-cands'); ta.value = (ta.value.trim() + '\n' + add.dataset.provAdd + (add.dataset.provPage ? ' ' + add.dataset.provPage : '')).trim(); if (add.closest('.prov-card')) trace(); else { ta.focus(); SB.toast('Added. Press “Trace sources” to compare it'); } return; }
    const rm = e.target.closest('[data-prov-remove]');
    if (rm && c.provenance) { const it = c.provenance.items.find(i => i.id === rm.dataset.provRemove); c.provenance.items = c.provenance.items.filter(i => i !== it); if (it) { const ta = $('#prov-cands'); ta.value = ta.value.split('\n').filter(l => !l.includes(it.requested || it.imageUrl)).join('\n'); } finish(c); $('#prov-run') && $('#prov-run').focus(); return; }
    if (e.target.closest('#prov-rev-run')) reverseSearch(c);
  });

  async function reverseSearch(c) {
    const u = $('#prov-rev-url').value.trim(), st = $('#prov-rev-status'), out = $('#prov-rev-results');
    if (!/^https?:\/\//i.test(u)) { st.textContent = 'Enter the public URL of the image first.'; return; }
    if (isStatic()) { st.textContent = 'Automatic search needs the local app.'; return; }
    st.textContent = 'Searching…';
    try {
      const r = await postJson('/api/provenance/reverse', { imageUrl: u });
      if (!r.available) { st.textContent = 'Automatic search is not configured on the server.'; return; }
      if (!r.ok) { st.textContent = r.reason; return; }
      st.textContent = `${r.results.length} result${r.results.length === 1 ? '' : 's'}. Add the ones worth comparing.`;
      out.innerHTML = `<ul class="list prov-rev">${r.results.map(x => `<li><a href="${safeHref(x.link)}" target="_blank" rel="noopener"><b>${esc(x.title || x.link)}</b></a> <span class="muted">${esc(x.source)}</span>${x.imageUrl || x.link ? ` <button type="button" class="link" data-prov-add="${esc(x.imageUrl || x.link)}"${x.imageUrl ? ` data-prov-page="${esc(x.link)}"` : ''}>Add to candidates</button>` : ''}</li>`).join('')}</ul>`;
    } catch (e) { st.textContent = 'Search failed: ' + e.message; }
  }

  sync(SB.current);
})();
