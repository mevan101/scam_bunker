// Scam Bunker video intake: MP4 / MOV / WebM. Runs entirely in the browser.
// Parses container metadata in pure JS (MP4/QuickTime atoms, Matroska/WebM EBML), extracts evenly spaced and
// scene-change keyframes through <video> + canvas, and runs each frame through the image pipeline
// (perceptual hash via window.ScamBunkerProvenance, pixel weak signals via window.DeduceForensics).
// The pure functions are exported on window.ScamBunkerVideo / module.exports and unit-tested in test/video.test.js.
(function () {
  const MAC_EPOCH = 2082844800;       // seconds from 1904-01-01 (QuickTime / ISO-BMFF epoch) to 1970-01-01
  const MKV_EPOCH = 978307200;        // seconds from 1970-01-01 to 2001-01-01 (Matroska DateUTC epoch)

  // ======================= Byte helpers =======================
  const str4 = (u8, o) => String.fromCharCode(u8[o], u8[o + 1], u8[o + 2], u8[o + 3]);
  const u16 = (u8, o) => (u8[o] << 8) | u8[o + 1];
  const u32 = (u8, o) => ((u8[o] << 24) >>> 0) + (u8[o + 1] << 16) + (u8[o + 2] << 8) + u8[o + 3];
  const u64 = (u8, o) => u32(u8, o) * 2 ** 32 + u32(u8, o + 4);
  function utf8(u8, s, e) {
    const b = u8.subarray(Math.max(0, s), Math.min(u8.length, e));
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(b).replace(/\0+$/, '').trim();
    let o = ''; for (const c of b) o += String.fromCharCode(c); return o.replace(/\0+$/, '').trim();
  }
  const latin = (u8, max = 4e6) => { let o = ''; const n = Math.min(u8.length, max); for (let i = 0; i < n; i += 8192) o += String.fromCharCode.apply(null, u8.subarray(i, Math.min(i + 8192, n))); return o; };
  const printable = s => String(s || '').replace(/[\u0000-\u001f\u007f]/g, '').trim();

  // ======================= Dates =======================
  function macToIso(sec) {
    if (!sec || !isFinite(sec)) return null; // 0 = "not set" (FFmpeg and most platform transcoders write 0)
    const ms = (sec - MAC_EPOCH) * 1000, d = new Date(ms);
    return isNaN(d) ? null : d.toISOString().slice(0, 19);
  }
  // Some writers put Unix seconds in a 1904-epoch field: the value then decodes to 1904–1970.
  function unixMisread(sec) { if (!sec || sec >= MAC_EPOCH) return null; const d = new Date(sec * 1000); return d.getUTCFullYear() >= 1995 ? d.toISOString().slice(0, 19) : null; }
  // "2026-03-14T09:26:53+0100" → { local: '2026-03-14T09:26:53', offset: '+01:00', utc: '2026-03-14T08:26:53' }
  function parseIsoTz(s) {
    const m = /^(\d{4})-?(\d{2})-?(\d{2})[T ](\d{2}):?(\d{2}):?(\d{2})?(?:\.\d+)?\s*(Z|[+-]\d{2}:?\d{2})?/.exec(String(s || '').trim());
    if (!m) { const y = /^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?$/.exec(String(s || '').trim()); return y ? { local: `${y[1]}-${y[2] || '01'}-${y[3] || '01'}T00:00:00`, offset: null, utc: null, dateOnly: true } : null; }
    const local = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] || '00'}`;
    if (!m[7]) return { local, offset: null, utc: null };
    const off = m[7] === 'Z' ? '+00:00' : m[7].replace(/^([+-]\d{2}):?(\d{2})$/, '$1:$2');
    const utc = new Date(local + 'Z').getTime() - (off[0] === '-' ? -1 : 1) * (+off.slice(1, 3) * 60 + +off.slice(4, 6)) * 60000;
    return { local, offset: off, utc: new Date(utc).toISOString().slice(0, 19) };
  }

  // ======================= ISO 6709 location (©xyz, com.apple.quicktime.location.ISO6709) =======================
  function parseISO6709(s) {
    const m = /^([+-])(\d+(?:\.\d+)?)([+-])(\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)?/.exec(String(s || '').trim());
    if (!m) return null;
    const conv = (sign, v, dd) => {
      const [i, f] = v.split('.'), frac = f ? '.' + f : '';
      let d;
      if (i.length <= dd) d = +v;
      else if (i.length === dd + 2) d = +i.slice(0, dd) + +(i.slice(dd) + frac) / 60;
      else if (i.length === dd + 4) d = +i.slice(0, dd) + +i.slice(dd, dd + 2) / 60 + +(i.slice(dd + 2) + frac) / 3600;
      else return NaN;
      return sign === '-' ? -d : d;
    };
    const lat = conv(m[1], m[2], 2), lon = conv(m[3], m[4], 3);
    if (!isFinite(lat) || !isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
    return { lat: +lat.toFixed(6), lon: +lon.toFixed(6), alt: m[5] ? +m[5] : null, raw: String(s).trim() };
  }

  // ======================= MP4 / QuickTime atoms =======================
  function boxes(u8, start, end) {
    const out = []; let o = start;
    while (o + 8 <= end) {
      let size = u32(u8, o), hdr = 8; const type = str4(u8, o + 4);
      if (size === 1) { if (o + 16 > end) break; size = u64(u8, o + 8); hdr = 16; } else if (size === 0) size = end - o;
      if (size < hdr) break;
      const e = o + size;
      out.push({ type, start: o, data: o + hdr, end: Math.min(e, end), size, truncated: e > end });
      if (e > end) break;
      o = e;
    }
    return out;
  }
  const CODECS = { avc1: 'H.264 / AVC', avc3: 'H.264 / AVC', hvc1: 'H.265 / HEVC', hev1: 'H.265 / HEVC', dvh1: 'Dolby Vision (HEVC)', dvhe: 'Dolby Vision (HEVC)', av01: 'AV1', vp08: 'VP8', vp09: 'VP9', mp4v: 'MPEG-4 Part 2', jpeg: 'Motion JPEG', mjpa: 'Motion JPEG', apch: 'Apple ProRes 422 HQ', apcn: 'Apple ProRes 422', apcs: 'Apple ProRes 422 LT', apco: 'Apple ProRes 422 Proxy', ap4h: 'Apple ProRes 4444', ap4x: 'Apple ProRes 4444 XQ', mp4a: 'AAC', 'ac-3': 'Dolby Digital (AC-3)', 'ec-3': 'Dolby Digital Plus', Opus: 'Opus', fLaC: 'FLAC', alac: 'Apple Lossless', lpcm: 'PCM', sowt: 'PCM', twos: 'PCM', ipcm: 'PCM', tmcd: 'Timecode', mebx: 'Timed metadata' };
  const UDTA_LABELS = { '©xyz': 'Location (ISO 6709)', '©too': 'Encoder', '©swr': 'Software', '©mak': 'Make', '©mod': 'Model', '©day': 'Date', '©nam': 'Title', '©cmt': 'Comment', '©des': 'Description', '©ART': 'Artist', '©aut': 'Author', '©cpy': 'Copyright', '©inf': 'Information', '©enc': 'Encoded by', '©fmt': 'Format', '©src': 'Source', '©wrt': 'Writer', '©dir': 'Director', '©prd': 'Producer', '©req': 'Requirements' };

  function fullTimes(u8, d) { // mvhd / mdhd share the layout of their first fields
    const v = u8[d];
    return v === 1 ? { c: u64(u8, d + 4), m: u64(u8, d + 12), ts: u32(u8, d + 20), dur: u64(u8, d + 24), next: d + 32 }
      : { c: u32(u8, d + 4), m: u32(u8, d + 8), ts: u32(u8, d + 12), dur: u32(u8, d + 16), next: d + 20 };
  }
  function dataValue(u8, b) { // iTunes-style 'data' box: type indicator, locale, value
    const t = u32(u8, b.data) & 0xffffff, s = b.data + 8, e = b.end;
    if (t === 1 || t === 4) return utf8(u8, s, e);
    if (t === 2 || t === 5) { let o = ''; for (let i = s; i + 1 < e; i += 2) o += String.fromCharCode(u16(u8, i)); return o.trim(); }
    if (t === 23) return +new DataView(u8.buffer, u8.byteOffset + s, 4).getFloat32(0).toFixed(6);
    if (t === 24) return new DataView(u8.buffer, u8.byteOffset + s, 8).getFloat64(0);
    if (t === 21 || t === 22) { const n = e - s; const dv = new DataView(u8.buffer, u8.byteOffset + s, n); return n === 1 ? (t === 21 ? dv.getInt8(0) : dv.getUint8(0)) : n === 2 ? (t === 21 ? dv.getInt16(0) : dv.getUint16(0)) : n === 4 ? (t === 21 ? dv.getInt32(0) : dv.getUint32(0)) : n === 8 ? u64(u8, s) : null; }
    if (t === 13 || t === 14 || t === 27) return '[embedded picture]';
    const txt = utf8(u8, s, Math.min(e, s + 200)); return /^[\x20-\x7e\u00a0-\uffff]+$/.test(txt) ? txt : `[${e - s} bytes binary]`;
  }
  function parseMeta(u8, b, r) {
    // ISO 'meta' is a full box (4 bytes version/flags); QuickTime 'meta' is not. If 'hdlr' follows directly, it is QuickTime-style.
    const start = str4(u8, b.data + 4) === 'hdlr' ? b.data : b.data + 4;
    const kids = boxes(u8, start, b.end);
    let handler = '', keys = null;
    for (const k of kids) {
      if (k.type === 'hdlr') handler = str4(u8, k.data + 8);
      if (k.type === 'keys') {
        keys = []; const n = u32(u8, k.data + 4); let o = k.data + 8;
        for (let i = 0; i < n && o + 8 <= k.end; i++) { const sz = u32(u8, o); if (sz < 8) break; keys.push(utf8(u8, o + 8, o + sz)); o += sz; }
      }
      if (k.type === 'XMP_' || k.type === 'xml ') r.xmp = r.xmp || utf8(u8, k.data + (k.type === 'xml ' ? 4 : 0), k.end);
    }
    for (const k of kids) {
      if (k.type !== 'ilst') continue;
      for (const item of boxes(u8, k.data, k.end)) {
        const name = keys && handler !== 'mdir' ? keys[u32(u8, item.start + 4) - 1] : item.type;
        const data = boxes(u8, item.data, item.end).find(x => x.type === 'data');
        if (!name || !data) continue;
        const val = dataValue(u8, data);
        if (keys && handler !== 'mdir') r.keys[name] = val; else r.udta[name] = val;
      }
    }
  }
  function parseUdta(u8, b, r) {
    for (const k of boxes(u8, b.data, b.end)) {
      if (k.type === 'meta') { parseMeta(u8, k, r); continue; }
      if (k.type === 'XMP_') { r.xmp = r.xmp || utf8(u8, k.data, k.end); continue; }
      if (k.type.charCodeAt(0) === 0xA9) {
        if (str4(u8, k.data + 4) === 'data') { const d = boxes(u8, k.data, k.end)[0]; r.udta[k.type] = dataValue(u8, d); continue; }
        const len = u16(u8, k.data); // classic QuickTime text: u16 length, u16 language, text
        if (len && k.data + 4 + len <= k.end) r.udta[k.type] = utf8(u8, k.data + 4, k.data + 4 + len);
        else r.udta[k.type] = utf8(u8, k.data, k.end);
      }
    }
  }
  function parseTrak(u8, b, r) {
    const t = { id: null, handler: '', codec: '', codecName: '', width: 0, height: 0, created: null, modified: null, mediaCreated: null, mediaModified: null, duration: 0, language: '', samples: 0, compressor: '' };
    const raw = {};
    for (const k of boxes(u8, b.data, b.end)) {
      if (k.type === 'tkhd') {
        const d = k.data, v = u8[d];
        const c = v === 1 ? u64(u8, d + 4) : u32(u8, d + 4), m = v === 1 ? u64(u8, d + 12) : u32(u8, d + 8);
        t.id = v === 1 ? u32(u8, d + 20) : u32(u8, d + 12);
        const wOff = d + (v === 1 ? 88 : 76);
        if (wOff + 8 <= k.end) { t.tkhdWidth = Math.round(u32(u8, wOff) / 65536); t.tkhdHeight = Math.round(u32(u8, wOff + 4) / 65536); }
        t.created = macToIso(c); t.modified = macToIso(m); raw.tkhd = { c, m };
      }
      if (k.type === 'udta') parseUdta(u8, k, r);
      if (k.type !== 'mdia') continue;
      let ts = 0;
      for (const m of boxes(u8, k.data, k.end)) {
        if (m.type === 'mdhd') {
          const x = fullTimes(u8, m.data); ts = x.ts;
          t.mediaCreated = macToIso(x.c); t.mediaModified = macToIso(x.m); t.duration = x.ts ? x.dur / x.ts : 0; raw.mdhd = { c: x.c, m: x.m };
          const l = u16(u8, x.next); if (l >= 0x400) t.language = String.fromCharCode(((l >> 10) & 31) + 0x60, ((l >> 5) & 31) + 0x60, (l & 31) + 0x60);
        }
        if (m.type === 'hdlr') t.handler = str4(u8, m.data + 8);
        if (m.type !== 'minf') continue;
        const stbl = boxes(u8, m.data, m.end).find(x => x.type === 'stbl'); if (!stbl) continue;
        for (const s of boxes(u8, stbl.data, stbl.end)) {
          if (s.type === 'stsd' && s.data + 16 <= s.end) {
            const e = s.data + 8; t.codec = str4(u8, e + 4).replace(/\0/g, ''); t.codecName = CODECS[t.codec] || t.codec;
            if (t.handler === 'vide' && e + 82 <= s.end) {
              t.width = u16(u8, e + 32); t.height = u16(u8, e + 34);
              const n = Math.min(31, u8[e + 50]); t.compressor = printable(utf8(u8, e + 51, e + 51 + n));
            }
          }
          if (s.type === 'stts') { const n = u32(u8, s.data + 4); let sum = 0; for (let i = 0, o = s.data + 8; i < n && o + 8 <= s.end; i++, o += 8) sum += u32(u8, o); t.samples = sum; }
        }
      }
      if (t.samples && t.duration && t.handler === 'vide') t.fps = +(t.samples / t.duration).toFixed(3);
      void ts;
    }
    if (!t.width && t.tkhdWidth) { t.width = t.tkhdWidth; t.height = t.tkhdHeight; }
    t.raw = raw;
    r.tracks.push(t);
  }
  function parseMP4(u8) {
    const r = { family: 'mp4', brand: '', compatible: [], movie: null, tracks: [], udta: {}, keys: {}, xmp: '', topLevel: [], c2pa: false, mdatSize: 0 };
    const top = boxes(u8, 0, u8.length);
    for (const b of top) {
      r.topLevel.push(b.type);
      if (b.type === 'ftyp') { r.brand = str4(u8, b.data).trim(); for (let o = b.data + 8; o + 4 <= b.end; o += 4) r.compatible.push(str4(u8, o).trim()); }
      else if (b.type === 'moov') {
        for (const k of boxes(u8, b.data, b.end)) {
          if (k.type === 'mvhd') { const x = fullTimes(u8, k.data); r.movie = { created: macToIso(x.c), modified: macToIso(x.m), timescale: x.ts, duration: x.ts ? x.dur / x.ts : 0, raw: { c: x.c, m: x.m } }; }
          else if (k.type === 'trak') parseTrak(u8, k, r);
          else if (k.type === 'udta') parseUdta(u8, k, r);
          else if (k.type === 'meta') parseMeta(u8, k, r);
        }
      }
      else if (b.type === 'meta') parseMeta(u8, b, r);
      else if (b.type === 'mdat') r.mdatSize += b.size;
      if (b.type !== 'mdat' && /jumb|c2pa/.test(latin(u8.subarray(b.start, b.end), 2e6))) r.c2pa = true;
      if (b.type === 'uuid' && !r.xmp) { const s = latin(u8.subarray(b.start, b.end), 2e6), i = s.indexOf('<x:xmpmeta'); if (i >= 0) r.xmp = s.slice(i, s.indexOf('</x:xmpmeta>', i) + 12); }
    }
    return r;
  }

  // ======================= Matroska / WebM (EBML) =======================
  function vint(u8, o, keepMarker) {
    const b = u8[o]; if (b === undefined || b === 0) return null;
    let len = 1, mask = 0x80; while (!(b & mask)) { mask >>= 1; len++; }
    let v = keepMarker ? b : b & (mask - 1);
    for (let i = 1; i < len; i++) v = v * 256 + u8[o + i];
    const unknown = !keepMarker && v === 2 ** (7 * len) - 1;
    return { len, value: unknown ? -1 : v };
  }
  const EBML = { HEADER: 0x1A45DFA3, DOCTYPE: 0x4282, SEGMENT: 0x18538067, INFO: 0x1549A966, TRACKS: 0x1654AE6B, TAGS: 0x1254C367, CLUSTER: 0x1F43B675, TIMESCALE: 0x2AD7B1, DURATION: 0x4489, DATEUTC: 0x4461, TITLE: 0x7BA9, MUXING: 0x4D80, WRITING: 0x5741, TRACKENTRY: 0xAE, TRACKTYPE: 0x83, CODECID: 0x86, VIDEO: 0xE0, PIXW: 0xB0, PIXH: 0xBA, TAG: 0x7373, SIMPLETAG: 0x67C8, TAGNAME: 0x45A3, TAGSTRING: 0x4487 };
  function ebmlKids(u8, s, e) {
    const out = []; let o = s;
    while (o < e) {
      const id = vint(u8, o, true); if (!id) break;
      const sz = vint(u8, o + id.len); if (!sz) break;
      const data = o + id.len + sz.len, end = sz.value < 0 ? e : Math.min(e, data + sz.value);
      out.push({ id: id.value, data, end, truncated: sz.value >= 0 && data + sz.value > e });
      if (sz.value < 0 || data + sz.value > e) break;
      o = data + sz.value;
    }
    return out;
  }
  const ebUint = (u8, el) => { let v = 0; for (let i = el.data; i < el.end; i++) v = v * 256 + u8[i]; return v; };
  const ebFloat = (u8, el) => { const n = el.end - el.data, dv = new DataView(u8.buffer, u8.byteOffset + el.data, n); return n === 4 ? dv.getFloat32(0) : n === 8 ? dv.getFloat64(0) : 0; };
  function parseWebM(u8) {
    const r = { family: 'mkv', docType: '', title: '', muxingApp: '', writingApp: '', created: null, duration: 0, tracks: [], tags: {}, c2pa: false };
    let segment = null;
    for (const el of ebmlKids(u8, 0, u8.length)) {
      if (el.id === EBML.HEADER) for (const h of ebmlKids(u8, el.data, el.end)) if (h.id === EBML.DOCTYPE) r.docType = utf8(u8, h.data, h.end);
      if (el.id === EBML.SEGMENT) segment = el;
    }
    if (!segment) return r;
    let scale = 1e6, durRaw = 0;
    // Walk segment children without trusting a truncated Cluster: stop at the first cluster we cannot skip.
    let o = segment.data; const e = segment.end;
    while (o < e) {
      const id = vint(u8, o, true); if (!id) break; const sz = vint(u8, o + id.len); if (!sz) break;
      const data = o + id.len + sz.len, end = sz.value < 0 ? e : data + sz.value;
      if (id.value === EBML.CLUSTER && (sz.value < 0 || end > e)) break;
      const el = { id: id.value, data, end: Math.min(end, e) };
      if (el.id === EBML.INFO) for (const k of ebmlKids(u8, el.data, el.end)) {
        if (k.id === EBML.TIMESCALE) scale = ebUint(u8, k);
        else if (k.id === EBML.DURATION) durRaw = ebFloat(u8, k);
        else if (k.id === EBML.TITLE) r.title = utf8(u8, k.data, k.end);
        else if (k.id === EBML.MUXING) r.muxingApp = utf8(u8, k.data, k.end);
        else if (k.id === EBML.WRITING) r.writingApp = utf8(u8, k.data, k.end);
        else if (k.id === EBML.DATEUTC && k.end - k.data === 8) {
          const hi = new DataView(u8.buffer, u8.byteOffset + k.data, 8).getInt32(0), lo = u32(u8, k.data + 4);
          r.created = new Date((MKV_EPOCH + (hi * 2 ** 32 + lo) / 1e9) * 1000).toISOString().slice(0, 19);
        }
      }
      if (el.id === EBML.TRACKS) for (const te of ebmlKids(u8, el.data, el.end)) {
        if (te.id !== EBML.TRACKENTRY) continue;
        const t = { handler: '', codec: '', codecName: '', width: 0, height: 0 };
        for (const k of ebmlKids(u8, te.data, te.end)) {
          if (k.id === EBML.TRACKTYPE) t.handler = { 1: 'vide', 2: 'soun', 17: 'sbtl' }[ebUint(u8, k)] || 'other';
          if (k.id === EBML.CODECID) { t.codec = utf8(u8, k.data, k.end); t.codecName = { V_VP8: 'VP8', V_VP9: 'VP9', V_AV1: 'AV1', 'V_MPEG4/ISO/AVC': 'H.264 / AVC', 'V_MPEGH/ISO/HEVC': 'H.265 / HEVC', A_OPUS: 'Opus', A_VORBIS: 'Vorbis', A_AAC: 'AAC' }[t.codec] || t.codec; }
          if (k.id === EBML.VIDEO) for (const v of ebmlKids(u8, k.data, k.end)) { if (v.id === EBML.PIXW) t.width = ebUint(u8, v); if (v.id === EBML.PIXH) t.height = ebUint(u8, v); }
        }
        r.tracks.push(t);
      }
      if (el.id === EBML.TAGS) for (const tag of ebmlKids(u8, el.data, el.end)) {
        if (tag.id !== EBML.TAG) continue;
        for (const st of ebmlKids(u8, tag.data, tag.end)) {
          if (st.id !== EBML.SIMPLETAG) continue; let n = '', v = '';
          for (const k of ebmlKids(u8, st.data, st.end)) { if (k.id === EBML.TAGNAME) n = utf8(u8, k.data, k.end); if (k.id === EBML.TAGSTRING) v = utf8(u8, k.data, k.end); }
          if (n && !(n in r.tags)) r.tags[n] = v;
        }
      }
      if (sz.value < 0 || end > e) break;
      o = end;
    }
    r.duration = durRaw * scale / 1e9;
    return r;
  }

  function detect(u8) {
    if (u8.length >= 4 && u32(u8, 0) === EBML.HEADER) return 'mkv';
    if (u8.length >= 8 && /^(ftyp|moov|mdat|wide|free|skip|pnot)$/.test(str4(u8, 4))) return 'mp4';
    return null;
  }

  // ======================= Interpretation (dates, hidden data, AI signals) =======================
  const VIDEO_GENERATORS = [
    { re: /\bsora\b/i, gen: 'OpenAI Sora' }, { re: /runway(ml)?|gen-?[234]\b/i, gen: 'Runway' }, { re: /\bpika(\s?labs)?\b/i, gen: 'Pika' },
    { re: /\bkling\b|kuaishou/i, gen: 'Kling' }, { re: /luma(\s?ai|\s?dream\s?machine)/i, gen: 'Luma Dream Machine' }, { re: /\bveo\s?\d?\b|google\s?deepmind/i, gen: 'Google Veo' },
    { re: /hailuo|minimax/i, gen: 'MiniMax Hailuo' }, { re: /synthesia/i, gen: 'Synthesia' }, { re: /heygen/i, gen: 'HeyGen' }, { re: /\bd-id\b/i, gen: 'D-ID' },
    { re: /\bhedra\b/i, gen: 'Hedra' }, { re: /haiper/i, gen: 'Haiper' }, { re: /stable[\s-]?video|\bSVD\b/i, gen: 'Stable Video Diffusion' }, { re: /\bwan\s?2\.\d|\bhunyuan/i, gen: 'Open-weights video model (Wan / Hunyuan)' },
  ];
  function interpret(raw, opts = {}) {
    const v = { container: '', format: '', brand: raw.brand || raw.docType || '', compatible: raw.compatible || [], duration: 0, width: 0, height: 0, fps: null, videoCodec: '', audioCodec: '', hasAudio: false, tracks: [],
      make: '', model: '', software: '', encoder: '', title: '', created: null, gps: null, c2pa: !!raw.c2pa, fields: [], timeline: [], hidden: [], notes: [], platformMarks: [], ai: { signals: [], weak: [], generators: [], verdict: 'none detected' } };
    const tl = (when, what, src, trust) => when && v.timeline.push({ when, what, src, trust });
    const vt = raw.tracks.find(t => t.handler === 'vide'), at = raw.tracks.find(t => t.handler === 'soun');
    v.tracks = raw.tracks.map(({ raw: _r, ...t }) => t);
    if (vt) { v.width = vt.width; v.height = vt.height; v.videoCodec = vt.codecName; v.fps = vt.fps || null; }
    if (at) { v.hasAudio = true; v.audioCodec = at.codecName; }
    if (raw.family === 'mp4') {
      v.container = raw.brand === 'qt' ? 'QuickTime MOV' : /^3g/.test(raw.brand) ? '3GPP' : raw.brand === 'M4V' ? 'M4V' : 'MP4';
      v.format = v.container === 'QuickTime MOV' ? 'MOV' : 'MP4';
      v.duration = raw.movie ? raw.movie.duration : (vt ? vt.duration : 0);
      const K = raw.keys, U = raw.udta, q = k => K['com.apple.quicktime.' + k] ?? K[k]; // FFmpeg's use_metadata_tags writes unprefixed mdta keys
      v.make = q('make') || U['©mak'] || ''; v.model = q('model') || U['©mod'] || '';
      v.software = q('software') || U['©swr'] || K['com.android.version'] && `Android ${K['com.android.version']}` || '';
      v.encoder = U['©too'] || q('encoder') || (vt && vt.compressor) || '';
      v.title = q('title') || U['©nam'] || '';
      v.gps = parseISO6709(q('location.ISO6709') || q('location') || U['©xyz']);
      v.fields.push(['Brand', `${raw.brand || '(none)'}${raw.compatible.length ? ' · compatible ' + raw.compatible.join(', ') : ''}`]);
      if (raw.movie) {
        v.fields.push(['mvhd creation', raw.movie.created ? raw.movie.created.replace('T', ' ') + ' UTC' : 'not set (0)'], ['mvhd modification', raw.movie.modified ? raw.movie.modified.replace('T', ' ') + ' UTC' : 'not set (0)']);
        tl(raw.movie.created, 'Container created (movie header)', 'MP4 mvhd creation_time (UTC by spec, 1904 epoch)', 'medium');
        if (raw.movie.modified && raw.movie.modified !== raw.movie.created) tl(raw.movie.modified, 'Container last modified', 'MP4 mvhd modification_time', 'medium');
        if (raw.movie.modified && raw.movie.created && raw.movie.modified < raw.movie.created) v.notes.push('Container modification time is EARLIER than its creation time: clock error or edited metadata');
        const um = unixMisread(raw.movie.raw.c); if (um) v.notes.push(`mvhd creation time decodes to ${macToIso(raw.movie.raw.c) || 'before 1970'}; read as Unix time it is ${um.replace('T', ' ')}. The writer probably used the wrong epoch`);
        if (!raw.movie.created) v.platformMarks.push('Creation time is zero: typical of FFmpeg re-muxing, screen recorders and platform transcodes (or deliberate scrubbing)');
      }
      raw.tracks.forEach(t => {
        const label = t.handler === 'vide' ? 'Video track' : t.handler === 'soun' ? 'Audio track' : `Track (${t.handler || '?'})`;
        if (t.created && t.created !== (raw.movie && raw.movie.created)) tl(t.created, `${label} ${t.id ?? ''} created`, 'MP4 tkhd creation_time', 'medium');
        if (t.mediaCreated && t.mediaCreated !== (raw.movie && raw.movie.created) && t.mediaCreated !== t.created) tl(t.mediaCreated, `${label} media created`, 'MP4 mdhd creation_time', 'medium');
      });
      const cd = parseIsoTz(q('creationdate'));
      if (cd) {
        tl(cd.utc || cd.local, cd.offset ? `Recorded (device local time ${cd.local.replace('T', ' ')}, UTC${cd.offset})` : 'Recorded (device local time, zone unknown)', 'Apple com.apple.quicktime.creationdate', 'high');
        v.created = cd.utc || cd.local;
        if (cd.utc && raw.movie && raw.movie.created) {
          const diff = Math.abs(new Date(cd.utc + 'Z') - new Date(raw.movie.created + 'Z')) / 3600e3;
          if (diff > 24) v.notes.push(`Apple creation date (${cd.utc.replace('T', ' ')} UTC) and the container creation time (${raw.movie.created.replace('T', ' ')} UTC) differ by ${Math.round(diff / 24)} days: the file was re-exported or its metadata edited`);
        }
      }
      const day = parseIsoTz(U['©day']); if (day) tl(day.local, 'Date tag', 'QuickTime ©day', 'medium');
      if (!v.created && raw.movie && raw.movie.created) v.created = raw.movie.created;
      Object.entries(U).forEach(([k, val]) => v.fields.push([`${k} ${UDTA_LABELS[k] ? '(' + UDTA_LABELS[k] + ')' : ''}`.trim(), String(val)]));
      Object.entries(K).forEach(([k, val]) => v.fields.push([k, String(val)]));
    } else {
      v.container = /webm/i.test(raw.docType) ? 'WebM' : 'Matroska'; v.format = v.container === 'WebM' ? 'WEBM' : 'MKV';
      v.duration = raw.duration; v.encoder = raw.writingApp || ''; v.software = raw.muxingApp || ''; v.title = raw.title || '';
      v.fields.push(['DocType', raw.docType || '—'], ['MuxingApp', raw.muxingApp || '—'], ['WritingApp', raw.writingApp || '—']);
      Object.entries(raw.tags || {}).forEach(([k, val]) => v.fields.push([`Tag ${k}`, String(val)]));
      if (raw.created) { tl(raw.created, 'Container created', 'Matroska DateUTC (2001 epoch)', 'medium'); v.created = raw.created; }
      const ct = parseIsoTz(raw.tags && (raw.tags.CREATION_TIME || raw.tags.DATE_RECORDED || raw.tags.DATE)); if (ct) tl(ct.utc || ct.local, 'Creation tag', 'Matroska tag', 'medium');
      if (/Chrome|Firefox|WebRTC|whammy|MediaRecorder/i.test(raw.muxingApp + raw.writingApp)) v.platformMarks.push(`Recorded in a browser (${raw.writingApp || raw.muxingApp}): screen or webcam capture via MediaRecorder`);
    }
    if (/Lavf|Lavc|ffmpeg/i.test(v.encoder + v.software)) v.platformMarks.push(`Muxed by FFmpeg (${v.encoder || v.software}): used by most platforms, downloaders and editors; this is not the camera original`);
    if (/TikTok|CapCut|InShot|VN Video|KineMaster|Premiere|Final Cut|DaVinci|iMovie|Clipchamp|Instagram|WhatsApp|Telegram/i.test([v.encoder, v.software, v.title, ...v.fields.map(f => f[1])].join(' '))) v.platformMarks.push('An editing app or platform name appears in the metadata: the clip was processed after recording');
    if (v.width && v.height) {
      const s = `${v.width}×${v.height}`;
      if ([[576, 1024], [720, 1280], [1080, 1920]].some(([a, b]) => v.width === a && v.height === b)) v.platformMarks.push(`${s} portrait: standard TikTok / Reels / Shorts export size`);
    }
    if (opts.lastModified) tl(new Date(opts.lastModified).toISOString().slice(0, 19), 'File last modified on this device (download/save time, not creation)', 'Filesystem', 'low');
    v.timeline.sort((a, b) => a.when.localeCompare(b.when));
    const now = opts.now || Date.now();
    v.timeline.forEach(t => { if (t.trust !== 'low' && new Date(t.when + 'Z').getTime() > now + 864e5) v.notes.push(`${t.src} is in the future (${t.when.replace('T', ' ')}): wrong device clock or forged metadata`); });
    if (v.gps) v.hidden.push(`GPS location: ${v.gps.lat}, ${v.gps.lon}${v.gps.alt != null ? ` (altitude ${v.gps.alt} m)` : ''}`);
    if (v.make || v.model) v.hidden.push(`Device: ${[v.make, v.model].filter(Boolean).join(' ')}${v.software ? ' · ' + v.software : ''}`);
    else if (v.software && raw.family === 'mp4') v.hidden.push(`Software: ${v.software}`);
    const K = raw.keys || {};
    if (K['com.apple.quicktime.content.identifier']) v.hidden.push(`Apple content identifier (links this clip to its Live Photo or other exports): ${K['com.apple.quicktime.content.identifier']}`);
    if (K['com.apple.quicktime.author'] || (raw.udta || {})['©aut'] || (raw.udta || {})['©ART']) v.hidden.push(`Author field: ${K['com.apple.quicktime.author'] || raw.udta['©aut'] || raw.udta['©ART']}`);
    if (v.title) v.hidden.push(`Title: ${v.title}`);

    // AI signals: declared metadata first, statistics only as weak hints.
    const hay = [raw.xmp || '', JSON.stringify(raw.udta || {}), JSON.stringify(raw.keys || {}), JSON.stringify(raw.tags || {}), v.encoder, v.software, v.title, raw.writingApp || '', raw.muxingApp || ''].join('\n');
    if (/trainedAlgorithmicMedia/i.test(hay) || /c2pa\.ai_generat|"ai_generated"/i.test(hay)) v.ai.signals.push({ label: 'Metadata declares AI generation (IPTC trainedAlgorithmicMedia / C2PA assertion)', strength: 'proof' });
    for (const g of VIDEO_GENERATORS) if (g.re.test(hay)) { v.ai.signals.push({ label: `${g.gen} named in the metadata`, strength: 'strong' }); v.ai.generators.push(g.gen); }
    if (v.c2pa) v.notes.push('Content Credentials (C2PA) marker present but not validated. Check it at contentcredentials.org/verify');
    if (v.duration && v.duration <= 10.5 && !v.hasAudio && !v.make && !v.model) v.ai.weak.push(`Short (${v.duration.toFixed(1)} s), silent clip with no device metadata: typical of AI video generators, but also of GIF conversions and edited clips`);
    if (v.fps && [8, 16, 24].includes(Math.round(v.fps)) && !v.make && !v.model && v.duration <= 12) v.ai.weak.push(`${Math.round(v.fps)} fps with no device metadata: a common frame rate for generated clips; phones usually record 30 or 60 fps`);
    const proof = v.ai.signals.some(s => s.strength === 'proof'), strong = v.ai.signals.some(s => s.strength === 'strong');
    v.ai.verdict = proof ? 'confirmed' : strong ? 'likely' : v.ai.weak.length >= 2 ? 'possible' : v.ai.weak.length ? 'weak indicators' : 'none detected';
    const firm = v.timeline.filter(t => t.trust !== 'low');
    v.earliest = firm.length ? firm[0] : null;
    return v;
  }
  function parseContainer(u8, opts) {
    const kind = detect(u8);
    if (!kind) return null;
    return interpret(kind === 'mp4' ? parseMP4(u8) : parseWebM(u8), opts);
  }

  // Reads the parts of a (possibly huge) file that hold metadata. MP4: every top-level box except mdat.
  // Matroska: the first 16 MB (Info/Tracks/Tags normally precede the first Cluster). readAt(offset, length) → Promise<Uint8Array>.
  async function readMetadataBytes(readAt, size) {
    const head = await readAt(0, Math.min(size, 16));
    if (detect(head) === 'mkv') return readAt(0, Math.min(size, 16 * 1048576));
    const parts = []; let o = 0, total = 0;
    for (let guard = 0; o + 8 <= size && guard < 10000; guard++) {
      const h = await readAt(o, 16); let sz = u32(h, 0); const type = str4(h, 4);
      if (sz === 1) sz = u64(h, 8); else if (sz === 0) sz = size - o;
      if (sz < 8) break;
      if (type !== 'mdat' && sz <= 64 * 1048576) { const b = await readAt(o, Math.min(sz, size - o)); parts.push(b); total += b.length; }
      else { const fake = new Uint8Array(8); const dv = new DataView(fake.buffer); dv.setUint32(0, 8); fake.set([...type].map(c => c.charCodeAt(0)), 4); parts.push(fake); total += 8; }
      o += sz;
    }
    const out = new Uint8Array(total); let p = 0; for (const b of parts) { out.set(b, p); p += b.length; }
    return out;
  }

  // ======================= Keyframe selection (pure) =======================
  function frameDiff(a, b) { // a, b: equal-length grayscale arrays (0–255); returns mean absolute difference in 0–1
    if (!a || !b || a.length !== b.length || !a.length) return 0;
    let s = 0; for (let i = 0; i < a.length; i++) s += Math.abs(a[i] - b[i]);
    return s / a.length / 255;
  }
  function sampleTimes(duration, maxSamples = 60) {
    if (!(duration > 0)) return [0];
    const step = Math.max(0.25, duration / maxSamples), out = [];
    for (let t = Math.min(0.05, duration / 2); t < duration - 0.02; t += step) out.push(+t.toFixed(3));
    return out.length ? out : [0];
  }
  // samples: [{ t, diff }] (diff vs the previous sample). Returns [{ t, kind: 'scene'|'interval', diff }] sorted by t.
  function pickKeyframes(samples, duration, { even = 8, maxScene = 8, minThreshold = 0.12 } = {}) {
    const diffs = samples.slice(1).map(s => s.diff);
    const mean = diffs.length ? diffs.reduce((a, b) => a + b, 0) / diffs.length : 0;
    const sd = diffs.length ? Math.sqrt(diffs.reduce((a, b) => a + (b - mean) ** 2, 0) / diffs.length) : 0;
    const thr = Math.max(minThreshold, mean + 2.5 * sd);
    const minGap = Math.max(0.5, duration / (even * 4 || 1));
    const scene = [];
    samples.slice(1).filter(s => s.diff >= thr).sort((a, b) => b.diff - a.diff).forEach(s => { if (scene.length < maxScene && scene.every(x => Math.abs(x.t - s.t) >= minGap)) scene.push({ t: s.t, kind: 'scene', diff: +s.diff.toFixed(3) }); });
    const out = [...scene];
    const n = duration > 0 ? Math.max(1, Math.min(even, Math.floor(duration / 0.5) || 1)) : 1;
    for (let i = 0; i < n; i++) { const t = duration > 0 ? +(duration * (i + 0.5) / n).toFixed(3) : 0; if (out.every(x => Math.abs(x.t - t) >= minGap)) out.push({ t, kind: 'interval', diff: null }); }
    return { frames: out.sort((a, b) => a.t - b.t), threshold: +thr.toFixed(3) };
  }
  const fmtT = t => { const s = Math.max(0, t || 0), m = Math.floor(s / 60); return `${String(m).padStart(2, '0')}:${(s - m * 60).toFixed(1).padStart(4, '0')}`; };

  // Compact, JSON-safe summary for agents and saved cases (no images)
  function summarize(v) {
    if (!v) return null;
    const { fields, frames, ...rest } = v;
    return { ...rest, fields: (fields || []).slice(0, 60), frames: (frames || []).map(f => ({ t: f.t, kind: f.kind, diff: f.diff, hash: f.hash ? { d: f.hash.d, p: f.hash.p } : null, dupOf: f.dupOf ?? null, weak: f.weak || [], noise: f.noise ?? null, width: f.width, height: f.height })) };
  }
  function report(v) {
    const l = [`${v.container} · ${v.width || '?'}×${v.height || '?'} · ${v.duration ? v.duration.toFixed(1) + ' s' : 'duration unknown'}${v.fps ? ' · ' + v.fps + ' fps' : ''} · ${v.videoCodec || 'codec unknown'}${v.hasAudio ? ' + ' + v.audioCodec : ' · no audio'}`,
      `AI involvement (metadata): ${v.ai.verdict}${v.ai.generators.length ? ' (' + v.ai.generators.join(', ') + ')' : ''}`, `Earliest firm timestamp: ${v.earliest ? v.earliest.when + ' via ' + v.earliest.src : 'none'}`];
    if (v.encoder) l.push(`Encoder: ${v.encoder}`);
    if (v.platformMarks.length) l.push('', 'Processing fingerprints:', ...v.platformMarks.map(x => '• ' + x));
    if (v.hidden.length) l.push('', 'Exposed data:', ...v.hidden.map(x => '• ' + x));
    if (v.notes.length) l.push('', 'Anomalies:', ...v.notes.map(x => '• ' + x));
    return l.join('\n');
  }

  const api = { macToIso, unixMisread, parseIsoTz, parseISO6709, boxes, parseMP4, parseWebM, detect, interpret, parseContainer, readMetadataBytes, frameDiff, sampleTimes, pickKeyframes, summarize, report, fmtT, MAC_EPOCH };
  const isVideo = f => !!f && (/^video\//.test(f.type || '') || /\.(mp4|m4v|mov|qt|webm|mkv|3gp)$/i.test(f.name || ''));
  api.isVideo = isVideo;
  if (typeof window !== 'undefined') window.ScamBunkerVideo = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof document === 'undefined' || typeof window === 'undefined' || !window.ScamBunker) return;

  // ======================= Browser: analysis =======================
  const SB = window.ScamBunker, esc = SB.esc, $ = s => document.querySelector(s);
  let file = null, previewUrl = null;
  const frameUrls = new Map(); // case id → [{ url, mirrorUrl }] (kept out of the case object so saved cases stay small)

  async function analyze(f) {
    const readAt = async (o, n) => new Uint8Array(await f.slice(o, o + n).arrayBuffer());
    const bytes = await readMetadataBytes(readAt, f.size);
    let v = null;
    try { v = parseContainer(bytes, { lastModified: f.lastModified }); } catch (e) { v = null; }
    if (!v) v = interpret({ family: 'mp4', brand: '', compatible: [], movie: null, tracks: [], udta: {}, keys: {} }, { lastModified: f.lastModified });
    if (!detect(bytes)) { v.container = (f.type || 'video').replace('video/', '').toUpperCase(); v.notes.push('Container not recognised as MP4/MOV or WebM/Matroska, so no metadata was read'); }
    v.name = f.name; v.size = f.size; v.type = f.type;
    if (f.size <= 512 * 1048576) { try { const h = await crypto.subtle.digest('SHA-256', await f.arrayBuffer()); v.sha256 = [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join(''); } catch { } }
    v.frames = []; v.frameStatus = 'pending';
    return v;
  }

  const once = (el, ok, ms = 8000) => new Promise((res, rej) => {
    const t = setTimeout(() => { cleanup(); rej(new Error('timed out')); }, ms);
    const good = () => { cleanup(); res(); }, bad = () => { cleanup(); rej(new Error('the browser cannot decode this video')); };
    const cleanup = () => { clearTimeout(t); el.removeEventListener(ok, good); el.removeEventListener('error', bad); };
    el.addEventListener(ok, good); el.addEventListener('error', bad);
  });
  async function openVideo(f) {
    const vid = document.createElement('video'); vid.muted = true; vid.preload = 'auto'; vid.playsInline = true; vid.crossOrigin = 'anonymous';
    vid.src = URL.createObjectURL(f);
    await once(vid, 'loadeddata', 15000);
    if (!isFinite(vid.duration)) { vid.currentTime = 1e7; await once(vid, 'seeked').catch(() => { }); } // MediaRecorder WebM has no duration until seeked to the end
    if (!vid.videoWidth) throw new Error('no decodable video track');
    return vid;
  }
  async function seek(vid, t) { if (Math.abs(vid.currentTime - t) < 0.001) return; vid.currentTime = t; await once(vid, 'seeked', 8000); }
  function grayThumb(vid, cv, cx) { cx.drawImage(vid, 0, 0, cv.width, cv.height); const d = cx.getImageData(0, 0, cv.width, cv.height).data, g = new Uint8Array(d.length / 4); for (let i = 0; i < g.length; i++) g[i] = 0.299 * d[i * 4] + 0.587 * d[i * 4 + 1] + 0.114 * d[i * 4 + 2]; return g; }

  async function extractFrames(c, f, onStep) {
    const v = c.video; v.frameStatus = 'running'; v.progress = 'Opening the video…'; onStep();
    let vid;
    try { vid = await openVideo(f); } catch (e) { v.frameStatus = 'error'; v.frameError = `Frames unavailable: ${e.message}${v.videoCodec ? ` (${v.videoCodec})` : ''}. Try Chrome or Safari, or convert the file to H.264 MP4. The metadata above is still valid.`; onStep(); return; }
    const duration = isFinite(vid.duration) ? vid.duration : (v.duration || 0);
    if (!v.duration) v.duration = duration;
    v.width = v.width || vid.videoWidth; v.height = v.height || vid.videoHeight;
    // Pass 1: low-resolution scan for scene changes
    const sc = document.createElement('canvas'); sc.width = 48; sc.height = Math.max(8, Math.round(48 * vid.videoHeight / vid.videoWidth));
    const sx = sc.getContext('2d', { willReadFrequently: true });
    const times = sampleTimes(duration, 60), samples = []; let prev = null;
    for (let i = 0; i < times.length; i++) {
      try { await seek(vid, times[i]); } catch { continue; }
      const g = grayThumb(vid, sc, sx); samples.push({ t: times[i], diff: prev ? frameDiff(prev, g) : 0 }); prev = g;
      if (i % 6 === 0) { v.progress = `Scanning for scene changes… ${Math.round(100 * i / times.length)} %`; onStep(); }
    }
    const pick = pickKeyframes(samples, duration, { even: 8, maxScene: 8 });
    v.sceneThreshold = pick.threshold;
    // Pass 2: full frames
    const max = 1280, s = Math.min(1, max / Math.max(vid.videoWidth, vid.videoHeight));
    const fc = document.createElement('canvas'); fc.width = Math.round(vid.videoWidth * s); fc.height = Math.round(vid.videoHeight * s);
    const fx = fc.getContext('2d'); const urls = [];
    const P = window.ScamBunkerProvenance, F = window.DeduceForensics;
    for (let i = 0; i < pick.frames.length; i++) {
      const fr = { ...pick.frames[i], width: fc.width, height: fc.height };
      v.progress = `Capturing keyframe ${i + 1} of ${pick.frames.length}…`; onStep();
      try { await seek(vid, fr.t); } catch { continue; }
      fx.setTransform(1, 0, 0, 1, 0, 0); fx.drawImage(vid, 0, 0, fc.width, fc.height);
      const blob = await new Promise(r => fc.toBlob(r, 'image/jpeg', 0.92));
      fx.setTransform(-1, 0, 0, 1, fc.width, 0); fx.drawImage(vid, 0, 0, fc.width, fc.height); fx.setTransform(1, 0, 0, 1, 0, 0);
      const mblob = await new Promise(r => fc.toBlob(r, 'image/jpeg', 0.92));
      urls.push({ url: URL.createObjectURL(blob), mirrorUrl: URL.createObjectURL(mblob), blob });
      fr.idx = urls.length - 1;
      try { if (P && P.hashBlob) { const h = await P.hashBlob(blob); fr.hash = h.hash; } } catch { }
      try {
        if (F) {
          const r = await F.analyze(new File([blob], `frame-${fmtT(fr.t).replace(/[:.]/g, '-')}.jpg`, { type: 'image/jpeg' }));
          // Container-level signals (missing EXIF, JPEG re-encode) describe our own capture, not the video, so keep only pixel statistics.
          fr.weak = (r.ai.weak || []).filter(x => /noise|AI generator canvas|multiples of 64/i.test(x)).map(x => x.replace(/ with no camera data/, ''));
          fr.noise = r.pixels ? r.pixels.noiseLevel : null; fr.vision = r.visionData;
        }
      } catch { }
      if (fr.hash && P) { const j = v.frames.findIndex(o => o.hash && P.compareHashes(o.hash, fr.hash).combined <= P.THRESHOLDS.same); if (j >= 0) fr.dupOf = j; }
      v.frames.push(fr); onStep();
    }
    frameUrls.set(c.id, urls);
    const lowNoise = v.frames.filter(x => (x.weak || []).some(w => /noise/i.test(w))).length;
    if (v.frames.length >= 3 && lowNoise / v.frames.length >= 0.6 && !v.make && !v.model) v.ai.weak.push(`${lowNoise} of ${v.frames.length} keyframes are unusually clean (very low sensor noise): consistent with synthetic or heavily processed video`);
    const proof = v.ai.signals.some(x => x.strength === 'proof'), strong = v.ai.signals.some(x => x.strength === 'strong');
    v.ai.verdict = proof ? 'confirmed' : strong ? 'likely' : v.ai.weak.length >= 2 ? 'possible' : v.ai.weak.length ? 'weak indicators' : 'none detected';
    v.frameStatus = 'done'; v.progress = ''; URL.revokeObjectURL(vid.src); onStep();
  }

  // Feed video findings into the local verdict (the same way app.js treats image forensics)
  function mergeIntoVerdict(c) {
    const L = c.local, v = c.video; if (!L || !v || c.final) return;
    L.observations = (L.observations || []).filter(o => !o.fromVideo && !(o.fact === 'No pattern matched' && (v.ai.signals.length || v.ai.weak.length || v.hidden.length)));
    v.ai.signals.forEach(s => L.observations.push({ fact: 'Video metadata', inference: s.label, weight: s.strength === 'proof' ? 'strong' : s.strength, fromVideo: true }));
    v.ai.weak.forEach(s => L.observations.push({ fact: 'Video frames / container', inference: s, weight: 'weak', fromVideo: true }));
    v.platformMarks.slice(0, 2).forEach(s => L.observations.push({ fact: 'Video container', inference: s, weight: 'weak', fromVideo: true }));
    L.hidden_info = [...(c.forensics ? c.forensics.hidden : []), ...v.hidden];
    L.video_dating = { earliest: v.earliest ? v.earliest.when.replace('T', ' ') : null, basis: v.earliest ? `${v.earliest.src} (${v.earliest.what.toLowerCase()})` : 'No embedded timestamps survived. Reverse-search the keyframes and sort by oldest.' };
    if (['confirmed', 'likely'].includes(v.ai.verdict) && !['Scam', 'Likely scam'].includes(L.verdict)) { L.verdict = 'AI-generated content'; L.category = v.ai.generators[0] || 'Synthetic video'; L.risk = Math.max(L.risk, v.ai.verdict === 'confirmed' ? 72 : 58); }
    if (!(L.next_steps || []).some(s => /keyframe/.test(s))) (L.next_steps = L.next_steps || []).unshift('Reverse-search the video keyframes (Video lab tab) on Google Lens, TinEye and Yandex. Sort by oldest to find the first upload.');
  }

  // ======================= UI =======================
  const css = `.vid-strip{display:grid;grid-auto-flow:column;grid-auto-columns:minmax(220px,1fr);gap:12px;overflow-x:auto;padding:2px 2px 10px;scroll-snap-type:x proximity}
.vid-frame{scroll-snap-align:start;margin:0;border:1px solid var(--line);border-radius:12px;background:var(--bg-2);overflow:hidden;display:flex;flex-direction:column}
.vid-frame img{display:block;width:100%;aspect-ratio:16/9;object-fit:contain;background:var(--bg)}
.vid-frame figcaption{padding:10px 12px;display:flex;flex-direction:column;gap:6px;font-size:12.5px;color:var(--ink-2)}
.vid-frame .vid-top{display:flex;gap:6px;align-items:center;flex-wrap:wrap}.vid-frame time{font:600 13px var(--mono);color:var(--ink)}
.vid-frame code{font:11px var(--mono);color:var(--muted);overflow-wrap:anywhere}.vid-acts{display:flex;flex-wrap:wrap;gap:4px 10px}
.vid-acts a,.vid-acts button{font-size:12.5px}.vid-acts a{color:var(--accent)}
.vid-acts a:focus-visible,.vid-acts button:focus-visible,.vid-strip:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.vid-vision{white-space:pre-wrap;font-size:12.5px;border-top:1px solid var(--line);padding-top:6px;max-height:220px;overflow:auto}`;
  const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);

  const ENGINES = [['Google Lens', 'https://lens.google.com/'], ['TinEye', 'https://tineye.com/'], ['Yandex', 'https://yandex.com/images/'], ['Bing', 'https://www.bing.com/visualsearch']];
  const kb = n => n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.round(n / 1024) + ' KB';
  const W = w => `<span class="w ${esc(w)}">${esc(w)}</span>`;

  function frameCard(c, fr, i) {
    const u = (frameUrls.get(c.id) || [])[fr.idx];
    const name = `video-frame-${fr.t.toFixed(2)}s`;
    const srv = SB.server() || {};
    const vis = (c.video.vision || {})[i];
    return `<figure class="vid-frame" aria-label="Keyframe at ${esc(fmtT(fr.t))}">
      ${u ? `<img src="${esc(u.url)}" alt="Video frame at ${esc(fmtT(fr.t))}" loading="lazy">` : '<div class="prov-thumb prov-nothumb" style="width:100%" aria-hidden="true">frame not kept</div>'}
      <figcaption>
        <div class="vid-top"><time>${esc(fmtT(fr.t))}</time><span class="tag">${fr.kind === 'scene' ? `scene change Δ${esc(fr.diff)}` : 'interval'}</span>${fr.dupOf != null ? `<span class="tag">same shot as ${esc(fmtT(c.video.frames[fr.dupOf].t))}</span>` : ''}</div>
        ${fr.hash ? `<code title="Perceptual hashes (dHash · pHash)">d ${esc(fr.hash.d)} · p ${esc(fr.hash.p)}</code>` : ''}
        ${(fr.weak || []).length ? fr.weak.map(w => `<span>${W('weak')} ${esc(w)}</span>`).join('') : `<span class="muted">No pixel-level AI hints${fr.noise != null ? ` · noise ${esc(fr.noise)}` : ''}</span>`}
        ${u ? `<div class="vid-acts"><a href="${esc(u.url)}" download="${esc(name)}.jpg">Download frame</a><a href="${esc(u.mirrorUrl)}" download="${esc(name)}-mirrored.jpg">Mirrored</a><button type="button" class="link" data-vid-copy="${i}">Copy</button></div>
        <div class="vid-acts" aria-label="Reverse search this frame">${ENGINES.map(([n, href]) => `<a href="${href}" target="_blank" rel="noopener" data-vid-search="${i}" aria-label="${esc(n)}: reverse-search the frame at ${esc(fmtT(fr.t))} (copies the frame first)">${esc(n)} ↗</a>`).join('')}</div>
        ${srv.ai && fr.vision ? `<div class="vid-acts"><button type="button" class="link" data-vid-vision="${i}">${vis ? 'Ask the vision agent again' : 'Send this frame to the vision agent'}</button></div>` : ''}` : ''}
        ${vis ? `<div class="vid-vision" role="status">${esc(vis)}</div>` : ''}
      </figcaption></figure>`;
  }

  function render(c) {
    const el = SB.panel('video'), tab = $('#tab-video'); if (!el || !tab) return;
    const v = c && c.video;
    tab.hidden = !v;
    if (!v) { if (tab.getAttribute('aria-selected') === 'true') SB.showTab('deduction'); el.innerHTML = '<p class="empty">No video in this case.</p>'; return; }
    const rows = [['File', `${v.name || '—'}${v.size ? ' · ' + kb(v.size) : ''}`], ['SHA-256', v.sha256 || (v.size > 512 * 1048576 ? 'not computed (file over 512 MB)' : '—')], ['Container', v.container || '—'], ['Duration', v.duration ? `${v.duration.toFixed(2)} s` : '—'], ['Video', `${v.videoCodec || '—'}${v.width ? ` · ${v.width}×${v.height}` : ''}${v.fps ? ` · ${v.fps} fps` : ''}`], ['Audio', v.hasAudio ? v.audioCodec || 'yes' : 'none'], ['Device', [v.make, v.model].filter(Boolean).join(' ') || '—'], ['Software', v.software || '—'], ['Encoder', v.encoder || '—'], ...v.fields];
    const gps = v.gps;
    const fs = v.frameStatus;
    el.innerHTML = `
      <section class="grid2">
        <div class="box"><div class="k">Video dates back to</div><div class="big">${esc(v.earliest ? v.earliest.when.replace('T', ' ') : 'Unknown from file')}</div><p>${esc(v.earliest ? `${v.earliest.src}, trust ${v.earliest.trust}` : 'No embedded timestamps survived. Reverse-search the keyframes and sort by oldest.')}</p></div>
        <div class="box"><div class="k">AI involvement</div><div class="big">${esc(v.ai.verdict)}</div><p>${v.ai.generators.length ? 'Generator: ' + esc(v.ai.generators.join(', ')) : 'No generator named in the metadata.'} Pixel statistics are leads, not proof.</p></div>
      </section>
      <section aria-labelledby="vid-kf-h"><h3 id="vid-kf-h">Keyframes</h3>
        <p class="muted">Evenly spaced frames plus frames where the picture changes sharply (scene cuts${v.sceneThreshold ? `, threshold Δ${esc(v.sceneThreshold)}` : ''}). Reverse-search them to find earlier uploads of the same footage. The engine buttons copy the frame to your clipboard first, so you can paste it (Ctrl/⌘ V) on the search page; or download it and upload it. Nothing is sent anywhere until you do.</p>
        ${fs === 'running' || fs === 'pending' ? `<p class="muted" role="status" aria-live="polite">${esc(v.progress || 'Preparing…')}</p>` : ''}
        ${fs === 'error' ? `<div class="callout" role="status">${esc(v.frameError)}</div>` : ''}
        ${fs === 'saved' ? '<div class="callout">Frames are not stored with saved cases. Add the video file again to extract keyframes.</div>' : ''}
        ${(v.frames || []).length ? `<div class="vid-strip" role="list" tabindex="0" aria-label="Keyframe filmstrip (scroll sideways)">${v.frames.map((fr, i) => `<div role="listitem">${frameCard(c, fr, i)}</div>`).join('')}</div>` : ''}
      </section>
      ${v.ai.signals.length || v.ai.weak.length ? `<section><h3>AI signals</h3><div class="obs">${v.ai.signals.map(s => `<div class="ob"><div><p>${esc(s.label)}</p></div><div></div>${W(s.strength)}</div>`).join('')}${v.ai.weak.map(s => `<div class="ob"><div><p>${esc(s)}</p></div><div></div>${W('weak')}</div>`).join('')}</div></section>` : ''}
      ${v.platformMarks.length ? `<section><h3>Where it has been</h3><ul class="list">${v.platformMarks.map(x => `<li>${esc(x)}</li>`).join('')}</ul></section>` : ''}
      ${v.hidden.length ? `<section><h3>Hidden information exposed</h3><ul class="list red">${v.hidden.map(x => `<li>${esc(x)}</li>`).join('')}</ul>${gps ? `<p><a href="https://www.openstreetmap.org/?mlat=${encodeURIComponent(gps.lat)}&amp;mlon=${encodeURIComponent(gps.lon)}#map=15/${encodeURIComponent(gps.lat)}/${encodeURIComponent(gps.lon)}" target="_blank" rel="noopener">Open the location on OpenStreetMap ↗</a> <span class="muted">(GPS can be forged; treat it as a lead)</span></p>` : ''}</section>` : ''}
      ${v.notes.length ? `<section><h3>Anomalies and notes</h3><ul class="list red">${v.notes.map(x => `<li>${esc(x)}</li>`).join('')}</ul></section>` : ''}
      <section><h3>Container metadata</h3><p class="muted">MP4/MOV times count seconds from 1 January 1904 and should be UTC; many cameras write local time instead. Apple's creationdate carries the device's time-zone offset.</p><div class="kv">${rows.map(([k, val]) => `<div>${esc(k)}</div><div>${esc(val)}</div>`).join('')}</div></section>`;
  }

  async function copyFrame(c, i) {
    const fr = c.video.frames[i], u = (frameUrls.get(c.id) || [])[fr.idx]; if (!u) return false;
    try {
      const bmp = await createImageBitmap(u.blob), cv = document.createElement('canvas'); cv.width = bmp.width; cv.height = bmp.height; cv.getContext('2d').drawImage(bmp, 0, 0);
      const png = await new Promise(r => cv.toBlob(r, 'image/png'));
      await navigator.clipboard.write([new ClipboardItem({ 'image/png': png })]); return true;
    } catch { return false; }
  }
  async function vision(c, i) {
    const fr = c.video.frames[i]; c.video.vision = c.video.vision || {};
    c.video.vision[i] = 'The vision agent is examining this frame…'; render(c);
    try {
      const r = await SB.post('/api/agent', { agent: 'forensics', case: { persona: c.persona, platform: c.platform, url: c.url, text: `${c.text || ''}\n\n[Keyframe at ${fmtT(fr.t)} of a ${c.video.container} video. Examine the frame visually.]`.trim(), video: summarize(c.video), imageData: fr.vision } });
      c.video.vision[i] = r.report || '(empty report)';
    } catch (e) { c.video.vision[i] = 'Vision agent failed: ' + e.message; }
    render(c);
  }

  // ---------- Intake ----------
  function setFile(f) {
    file = f && isVideo(f) ? f : null;
    if (!file) { const img = $('#preview'); if (img && /^Video preview/.test(img.alt)) img.alt = 'Evidence preview'; return; }
    $('#file-name').textContent = `${f.name} · ${kb(f.size)} · video`;
    $('#drop-full').hidden = false; $('#drop-empty').hidden = true;
    const img = $('#preview'); img.alt = 'Video preview (first frame)'; img.removeAttribute('src');
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    openVideo(f).then(async vid => { await seek(vid, Math.min(0.1, vid.duration / 2 || 0)).catch(() => { }); const cv = document.createElement('canvas'); const s = Math.min(1, 640 / vid.videoWidth); cv.width = Math.round(vid.videoWidth * s); cv.height = Math.round(vid.videoHeight * s); cv.getContext('2d').drawImage(vid, 0, 0, cv.width, cv.height); if (file === f) { previewUrl = cv.toDataURL('image/jpeg', 0.8); img.src = previewUrl; } URL.revokeObjectURL(vid.src); }).catch(() => { img.alt = 'Video preview unavailable: this browser cannot decode the codec'; });
  }
  api.setFile = setFile;
  Object.defineProperty(api, 'file', { get: () => file });
  api.analyze = analyze;

  document.addEventListener('click', e => {
    if (e.target.closest('#history-list .hist')) { setTimeout(() => { const c = SB.current; if (c && c.video) c.video.frameStatus = (frameUrls.get(c.id) ? c.video.frameStatus : 'saved'); render(c); }, 0); return; }
    const c = SB.current; if (!c || !c.video) return;
    const cp = e.target.closest('[data-vid-copy]');
    if (cp) { copyFrame(c, +cp.dataset.vidCopy).then(ok => SB.toast(ok ? 'Frame copied. Paste it into any reverse image search' : 'Clipboard blocked. Use “Download frame” instead')); return; }
    const se = e.target.closest('[data-vid-search]');
    if (se) { copyFrame(c, +se.dataset.vidSearch).then(ok => SB.toast(ok ? 'Frame copied. Paste it (Ctrl/⌘ V) on the search page' : 'Download the frame, then upload it on the search page')); return; }
    const vi = e.target.closest('[data-vid-vision]');
    if (vi) vision(c, +vi.dataset.vidVision);
  });

  document.addEventListener('sb:case', e => {
    const c = e.detail; render(c);
    if (!c || !c.video) return;
    mergeIntoVerdict(c); SB.renderAll(); render(c);
    if (c.video.frameStatus === 'pending' && file) {
      const f = file;
      let pend = false; const step = () => { if (SB.current !== c || pend) return; pend = true; requestAnimationFrame(() => { pend = false; render(c); }); };
      extractFrames(c, f, step).then(() => { if (SB.current === c) { mergeIntoVerdict(c); SB.renderAll(); render(c); persist(c); } });
    }
  });
  function persist(c) {
    const list = SB.store.get('scambunker.cases', []), x = list.find(i => i.id === c.id); if (!x) return;
    x.video = summarize(c.video); SB.store.set('scambunker.cases', list);
  }
  document.addEventListener('sb:case-complete', e => e.detail && e.detail.video && persist(e.detail));
  render(SB.current);
})();
