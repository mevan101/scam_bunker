// Scam Bunker: dating timeline (BACKLOG P1-6). Merges every dated item the case knows about (embedded file dates,
// video container dates, provenance copies, archive captures, corroboration checks, domain records, event listings,
// the claimed event date and the case itself) into one sorted, graded list with an SVG axis, a date interval and
// inline contradictions. Pure logic is exported on window.ScamBunkerTimeline and unit-tested in test/timeline.test.js;
// the UI only boots when window.ScamBunker and a document exist.
(function () {
  'use strict';

  const H = 3600e3, DAY = 864e5, ZONE_SLACK = 14 * H; // a wall-clock time with no zone can be up to UTC±14 h
  const MONTH = 31 * DAY, YEAR = 366 * DAY;

  // ---------- Admiralty grades (docs/METHODOLOGY.md 3.1, AJP-2.1: E unreliable, F cannot be judged) ----------
  const SOURCE = { A: 'completely reliable', B: 'usually reliable', C: 'fairly reliable', D: 'not usually reliable', E: 'unreliable', F: 'reliability cannot be judged' };
  const CRED = { 1: 'confirmed', 2: 'probably true', 3: 'possibly true', 4: 'doubtful', 5: 'improbable', 6: 'truth cannot be judged' };
  const gradeText = g => `Source ${g[0]}: ${SOURCE[g[0]] || '?'}; information ${g[1]}: ${CRED[g[1]] || '?'}`;

  // ---------- Time parsing ----------
  // Returns { when (wall clock as recorded, YYYY-MM-DDTHH:MM:SS), zone, precision, ms (UTC ms; zone-less = as if UTC) }.
  // zone: { kind: 'utc' | 'offset' | 'unknown', offsetMin?, label? }
  const pad = n => String(n).padStart(2, '0');
  function parseOffset(s) {
    if (s == null) return null;
    const m = /^\s*(?:UTC|GMT)?\s*([+-−])(\d{1,2}):?(\d{2})?\s*$/i.exec(String(s));
    if (!m) return /^\s*(Z|UTC|GMT)\s*$/i.test(String(s)) ? 0 : null;
    const v = (+m[2]) * 60 + (+(m[3] || 0)); return m[1] === '+' ? v : -v;
  }
  const fmtOffset = min => `${min < 0 ? '−' : '+'}${pad(Math.floor(Math.abs(min) / 60))}:${pad(Math.abs(min) % 60)}`;
  function parseWhen(s, zoneHint, precision) {
    if (s == null || s === '') return null;
    if (typeof s === 'number' || s instanceof Date) { const d = new Date(s); return isNaN(d) ? null : { when: d.toISOString().slice(0, 19), zone: { kind: 'utc' }, precision: precision || 'second', ms: d.getTime() }; }
    const m = /(\d{4})[:\-](\d{2})(?:[:\-](\d{2}))?(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*(Z|[+-−]\d{2}:?\d{2})?/.exec(String(s));
    if (!m || +m[1] < 1970 || +m[2] < 1 || +m[2] > 12) return null;
    const hasTime = m[4] != null;
    const prec = precision || (hasTime ? 'second' : m[3] ? 'day' : 'month');
    const when = `${m[1]}-${m[2]}-${m[3] || '01'}T${hasTime ? `${m[4]}:${m[5]}:${m[6] || '00'}` : '00:00:00'}`;
    let zone;
    const own = m[7] != null ? parseOffset(m[7]) : null;
    if (own != null) zone = own === 0 && /Z/i.test(m[7]) ? { kind: 'utc' } : { kind: 'offset', offsetMin: own };
    else if (zoneHint === 'utc') zone = { kind: 'utc' };
    else if (zoneHint && zoneHint.kind) zone = zoneHint;
    else if (typeof zoneHint === 'string' && parseOffset(zoneHint) != null) zone = { kind: 'offset', offsetMin: parseOffset(zoneHint) };
    else zone = { kind: 'unknown' };
    const wall = Date.parse(when + 'Z'); if (isNaN(wall)) return null;
    const ms = zone.kind === 'offset' ? wall - zone.offsetMin * 60e3 : wall;
    return { when, zone, precision: prec, ms };
  }
  // The interval of instants a row could mean: zone slack + the width of its precision.
  function span(r) {
    const z = r.zone && r.zone.kind === 'unknown' ? ZONE_SLACK : 0;
    const w = { year: YEAR, month: MONTH, day: DAY }[r.precision] || 0;
    return [r.ms - z, r.ms + w + z];
  }
  function zoneLabel(r) {
    const z = r.zone || {};
    if (z.label) return z.label;
    if (z.kind === 'utc') return 'UTC';
    if (z.kind === 'offset') return 'UTC' + fmtOffset(z.offsetMin);
    return 'timezone unknown';
  }
  function fmtWhen(r) {
    const d = r.when.slice(0, 10), t = r.when.slice(11, 19);
    if (r.precision === 'year') return d.slice(0, 4);
    if (r.precision === 'month') return d.slice(0, 7);
    if (r.precision === 'day') return d;
    return `${d} ${t}`;
  }
  const safeHref = u => { try { const x = new URL(String(u)); return /^https?:$/.test(x.protocol) && !x.username && !x.password ? x.href : null; } catch { return null; } };

  // ---------- Collect ----------
  // opts: { listings: normalised event listings, parseClaimedDate: fn, now }
  function collect(c, opts = {}) {
    const rows = [];
    let n = 0;
    const add = (raw, zoneHint, o) => {
      const p = parseWhen(raw, zoneHint, o.precision); if (!p) return null;
      const r = { id: 'r' + (++n), ...p, kind: o.kind, what: o.what, src: o.src, origin: o.origin, grade: o.grade, group: o.group || null, href: safeHref(o.href) || null, tab: o.tab || null, flags: [], note: o.note || '', media: !!o.media, confirmed: !!o.confirmed };
      rows.push(r); return r;
    };

    // Image file (EXIF / XMP / PNG / GPS / filesystem), as decoded by forensics.js
    const f = c.forensics;
    if (f) {
      const ex = f.exif || {}, xf = f.xmpFields || {}, camera = !!(ex.Make || ex.Model), edited = (f.editors || []).length > 0;
      const xmpZone = k => { const v = xf[k]; const m = v && /(Z|[+-]\d{2}:?\d{2})\s*$/.exec(String(v)); return m ? m[1] : null; };
      const MAP = {
        'EXIF DateTimeOriginal': { kind: 'capture', grade: camera && !edited ? 'C3' : 'D4', zone: ex.OffsetTimeOriginal },
        'EXIF DateTimeDigitized': { kind: 'capture', grade: camera && !edited ? 'C3' : 'D4', zone: ex.OffsetTimeDigitized },
        'EXIF DateTime': { kind: 'modified', grade: 'D3', zone: ex.OffsetTime },
        'XMP CreateDate': { kind: 'created', grade: 'D3', zone: xmpZone('xmp:CreateDate') },
        'XMP DateCreated': { kind: 'created', grade: 'D3', zone: xmpZone('photoshop:DateCreated') },
        'XMP ModifyDate': { kind: 'modified', grade: 'D3', zone: xmpZone('xmp:ModifyDate') },
        'XMP history': { kind: 'modified', grade: 'D3' },
        'PNG tIME': { kind: 'modified', grade: 'D3', zone: 'utc' }, // PNG spec: tIME is UTC
        'GPS DateStamp': { kind: 'capture', grade: 'C2', zone: 'utc', precision: 'day' }, // satellite UTC date
        'Filesystem': { kind: 'device', grade: 'B2', zone: 'utc' },
      };
      for (const t of f.timeline || []) {
        const m = MAP[t.src] || { kind: /modif|edit/i.test(t.what) ? 'modified' : 'created', grade: 'D4' };
        add(t.when, m.zone || null, { kind: m.kind, what: t.what, src: t.src, origin: 'Image file', grade: m.grade, group: m.kind === 'device' ? null : 'image', tab: 'image', precision: m.precision });
      }
    }

    // Video container (video.js already resolved UTC where the format defines it)
    if (c.video) {
      for (const t of c.video.timeline || []) {
        const s = String(t.src || '');
        const utc = /mvhd|tkhd|mdhd|DateUTC|Filesystem/.test(s) || /UTC[+-−]/.test(t.what || '');
        const kind = s === 'Filesystem' ? 'device' : /modif/i.test(t.what) ? 'modified' : /Recorded/.test(t.what) ? 'capture' : 'created';
        add(t.when, utc ? 'utc' : null, { kind, what: t.what, src: s, origin: 'Video file', grade: s === 'Filesystem' ? 'B2' : t.trust === 'high' ? 'C3' : 'D3', group: kind === 'device' ? null : 'video', tab: 'video' });
      }
    }

    // Provenance trace: matching copies' dates, archive captures, page publish dates
    const pv = c.provenance && c.provenance.verdict;
    if (pv) {
      const items = new Map((c.provenance.items || []).map(i => [i.id, i]));
      const seenItems = new Set();
      for (const d of pv.dates || []) {
        if (d.itemId === 'case') continue; // the case file's own dates are listed above
        const it = items.get(d.itemId) || {};
        seenItems.add(d.itemId);
        const rel = it.compare && it.compare.relation, confirmed = rel === 'identical' || rel === 'same'; // provenance match verdict same / likely same
        const s = d.source || '';
        const grade = /Wayback Machine first capture of the image/.test(s) ? 'B2' : /Wayback Machine first capture of the page/.test(s) ? 'B3' : /recorded by the Wayback/.test(s) ? 'C2'
          : /HTTP Last-Modified/.test(s) ? 'C3' : /GPS/.test(s) ? 'C2' : /Page publish/.test(s) ? 'D3' : d.trust === 'medium' ? 'C3' : 'D4';
        const utc = /Wayback|Last-Modified|GPS/.test(s);
        const raw = /Page publish/.test(s) && it.pageDate && it.pageDate.published ? it.pageDate.published.iso : d.date;
        const what = { capture: 'Copy captured', created: 'Copy created', existed: 'A matching copy existed', page: 'Page carrying a copy existed' }[d.kind] || 'Dated copy';
        add(raw, utc ? 'utc' : null, { kind: d.kind === 'page' ? 'page' : d.kind, what: `${what}: ${d.item}`, src: s, origin: 'Provenance', grade, group: 'copy:' + d.itemId, href: safeHref(d.note) || it.pageUrl || it.imageUrl, tab: 'provenance', precision: /GPS/.test(s) ? 'day' : null, confirmed });
      }
      for (const id of seenItems) {
        const it = items.get(id); if (!it || !it.exifModify) continue;
        add(it.exifModify, null, { kind: 'modified', what: `Copy last written by software: ${it.label}`, src: 'EXIF DateTime of the copy', origin: 'Provenance', grade: 'D3', group: 'copy:' + id, href: it.imageUrl, tab: 'provenance' });
      }
    }

    // Claimed event date in the post
    let claimed = c.provenance && c.provenance.claimed;
    if (!claimed && opts.parseClaimedDate) { try { const txt = [c.text || '', c.page && c.page.markdown ? String(c.page.markdown).slice(0, 4000) : ''].join('\n'); claimed = new Set(txt.match(/\b(19[89]\d|20\d\d)\b/g) || []).size > 1 ? null : opts.parseClaimedDate([c.text || '', c.page && c.page.markdown ? String(c.page.markdown).slice(0, 4000) : ''].join('\n'), c.at); } catch { claimed = null; } }
    if (claimed && claimed.date) add(claimed.date, null, { kind: 'claimed', what: `Event date the post claims (“${String(claimed.basis || '').slice(0, 80)}”)`, src: 'The post under investigation', origin: 'Claim', grade: 'F6', precision: claimed.precision || 'day', href: c.url });

    // Corroboration checks (corroborate.js stores the inputs of the last run)
    const co = c.corroborate || {};
    if (co.sun && co.sun.date) {
      const z = parseOffset(co.sun.offset);
      add(`${co.sun.date}T${co.sun.time || '00:00'}:00`, z != null ? { kind: 'offset', offsetMin: z } : null, { kind: 'check', what: `Sun position and shadows checked for ${co.sun.lat}, ${co.sun.lon}`, src: 'Solar geometry (NOAA algorithm)', origin: 'Corroboration', grade: 'B3', precision: co.sun.time ? 'minute' : 'day', tab: 'corroborate' });
    }
    if (co.wx && co.wx.date) {
      const z = co.wx.offsetMin;
      const r = add(`${co.wx.date}T${co.wx.time || '00:00'}:00`, z != null ? { kind: 'offset', offsetMin: z, label: co.wx.timezone ? `${co.wx.timezone} (UTC${fmtOffset(z)})` : null } : null,
        { kind: 'check', what: `Historical weather: ${co.wx.text || 'looked up'}${co.wx.claim ? ` · claim “${co.wx.claim}” ${co.wx.result || 'checked'}` : ''}`, src: 'Open-Meteo reanalysis (gridded model)', origin: 'Corroboration', grade: 'B2', precision: co.wx.time ? 'minute' : 'day', href: co.wx.url, tab: 'corroborate' });
      if (r && co.wx.result === 'contradicted') r.flags.push({ weight: 'moderate', text: `The weather on this date contradicts the claim “${co.wx.claim}”.` });
    }
    if (co.crt && co.crt.firstSeen) add(co.crt.firstSeen, 'utc', { kind: 'domain', what: `First TLS certificate logged for ${co.crt.domain}`, src: 'crt.sh Certificate Transparency logs', origin: 'Corroboration', grade: 'A2', href: co.crt.url || `https://crt.sh/?q=${encodeURIComponent(co.crt.domain)}`, tab: 'corroborate' });

    // Domain registrations (osint.js RDAP lookup)
    for (const [d, r] of Object.entries(c.domainAges || {})) {
      if (r && r.registeredAt) add(r.registeredAt, 'utc', { kind: 'domain', what: `Domain ${d} registered${r.registrar ? ' via ' + r.registrar : ''}`, src: 'RDAP registry record', origin: 'Domain', grade: 'A2', href: `https://rdap.org/domain/${encodeURIComponent(d)}`, tab: 'links' });
    }

    // Event listings (events.js comparison), if any
    const norm = u => { const h = safeHref(u); if (!h) return null; const x = new URL(h), q = new URLSearchParams([...x.searchParams].filter(([k]) => !/^(utm_|fbclid$|gclid$)/.test(k))); q.sort(); const qs = String(q); return `${x.origin}${x.pathname.replace(/\/+$/, '')}${qs ? '?' + qs : ''}`; };
    const caseLinks = new Set([c.url, ...((c.page && c.page.redirects) || []).map(r => r.url), ...((c.heuristics && c.heuristics.links) || []).map(x => x.url || x)].map(norm).filter(Boolean));
    const linked = l => [l.url, l.finalUrl].map(norm).some(u => u && caseLinks.has(u));
    for (const l of opts.listings || []) {
      if (l.startUtc == null || !linked(l)) continue; // the Events comparison is shared; only listings this case links to
      const sl = l.startLocal, o = { kind: 'event', what: `Event listing starts: ${l.title || l.id}${l.city ? ' (' + l.city + ')' : ''}`, src: `${l.platform || 'Listing'} ${l.id}`, origin: 'Events', grade: l.manual ? 'D3' : 'C3', href: l.finalUrl || l.url, tab: 'events', precision: l.allDay ? 'day' : 'minute' };
      if (sl && !sl.floating && sl.offsetMin != null) add(`${sl.date}T${sl.time}:00`, { kind: 'offset', offsetMin: sl.offsetMin, label: l.tz ? `${l.tz} (UTC${fmtOffset(sl.offsetMin)})` : null }, o);
      else add(new Date(l.startUtc), 'utc', o);
    }

    // Case opened
    if (c.at) add(c.at, 'utc', { kind: 'case', what: 'Case opened in Scam Bunker', src: 'This investigation', origin: 'Case', grade: 'A1', media: !!(c.forensics || c.video) });

    const ORDER = { capture: 0, created: 1, modified: 2, existed: 3, page: 4, domain: 5, claimed: 6, check: 7, event: 8, device: 9, case: 10 };
    rows.sort((a, b) => a.ms - b.ms || (ORDER[a.kind] ?? 99) - (ORDER[b.kind] ?? 99));
    contradictions(rows, opts.now);
    return rows;
  }

  // ---------- Contradictions (attached to the rows they concern) ----------
  const fmt = r => `${fmtWhen(r)}${r.precision === 'second' || r.precision === 'minute' ? ' ' + zoneLabel(r) : ''}`;
  function contradictions(rows, now) {
    const flag = (r, weight, text, other) => { if (!r.flags.some(f => f.text === text)) r.flags.push({ weight, text, other: other ? other.id : null }); };
    // Only dates about the case's own media count: the case file, or a copy confirmed as the same image (match verdict
    // same / likely same). An unconfirmed copy only ever gives a weak, labelled lead. Page dates never count (the image
    // may have been added to the page later). False alarms are worse than misses (METHODOLOGY combination rules).
    const own = r => r.origin === 'Image file' || r.origin === 'Video file';
    const sameMedia = r => own(r) || (r.origin === 'Provenance' && r.confirmed);
    const RANK = { strong: 0, moderate: 1, weak: 2 };
    const pick = (list, w) => list.map(e => [e, w(e)]).sort((a, b) => RANK[a[1]] - RANK[b[1]] || a[0].ms - b[0].ms)[0];
    const unconf = e => (sameMedia(e) || own(e) ? '' : ' Unconfirmed: this copy is not a confirmed visual match of the case media.');
    const existedW = e => !sameMedia(e) ? 'weak' : e.grade[0] <= 'B' ? 'strong' : 'moderate';
    const existed = rows.filter(r => r.kind === 'existed');
    // 1. Capture after a copy of the same media was already seen (EXIF forged, re-dated, or the wrong camera clock)
    for (const cap of rows.filter(r => r.kind === 'capture' && sameMedia(r))) {
      const hit = pick(existed.filter(e => span(cap)[0] > span(e)[1]), existedW);
      if (hit) flag(cap, hit[1], `Captured after a copy already existed (${hit[0].src}, ${fmt(hit[0])}). The capture date is forged or the clock was wrong.${unconf(hit[0])}`, hit[0]);
    }
    // 2. Claimed event date after the same media already existed (recycled media)
    const claimW = r => r.kind === 'existed' ? existedW(r) : sameMedia(r) ? 'moderate' : 'weak';
    for (const cl of rows.filter(r => r.kind === 'claimed')) {
      const hit = pick(rows.filter(r => (r.kind === 'existed' || (r.kind === 'capture' && (own(r) || r.origin === 'Provenance'))) && span(cl)[0] > span(r)[1]), claimW);
      if (hit) flag(cl, hit[1], `The post claims ${fmtWhen(cl)}, but ${hit[0].kind === 'capture' ? 'the media was captured' : 'a matching copy existed'} by ${fmt(hit[0])} (${hit[0].src}). Possibly recycled media.${unconf(hit[0])}`, hit[0]);
    }
    // 3. Modified before captured/created, within the same file (same clock, so no zone slack)
    const groups = new Map();
    rows.filter(r => r.group).forEach(r => { if (!groups.has(r.group)) groups.set(r.group, []); groups.get(r.group).push(r); });
    for (const g of groups.values()) {
      const caps = g.filter(r => r.kind === 'capture' && r.precision !== 'day');
      const firstCap = caps.length ? caps.reduce((a, b) => (a.ms <= b.ms ? a : b)) : g.filter(r => r.kind === 'created').sort((a, b) => a.ms - b.ms)[0];
      if (!firstCap) continue;
      const sameZone = r => (r.zone.kind === 'unknown') === (firstCap.zone.kind === 'unknown');
      for (const m of g.filter(r => r.kind === 'modified' && sameZone(r) && r.ms < firstCap.ms - 60e3)) flag(m, 'moderate', `Modified before it was ${firstCap.kind === 'capture' ? 'captured' : 'created'} (${firstCap.src}, ${fmt(firstCap)}). The clock or the metadata was tampered with.`, firstCap);
    }
    // 4. File dates after the case was opened (impossible unless the device clock was wrong or the dates forged)
    const opened = rows.find(r => r.kind === 'case');
    const limit = opened ? opened.ms : now;
    if (limit) for (const r of rows.filter(r => ['capture', 'created', 'modified'].includes(r.kind) && span(r)[0] > limit + DAY)) flag(r, 'moderate', `Dated after the case was opened (${opened ? fmt(opened) : 'now'}): wrong device clock or forged metadata.`, opened);
    return rows;
  }

  // ---------- Interval: earliest and latest possible date of the content ----------
  function bounds(rows) {
    const media = rows.some(r => r.media || r.origin === 'Image file' || r.origin === 'Video file'); // a domain record never dates media
    const ok = r => !r.flags.some(f => f.weight === 'strong');
    const rank = g => 'ABCDEF'.indexOf(g[0]) * 10 + (+g[1]);
    // Latest possible: the earliest evidence that this very file existed (archived/served copies, the case). Page dates are
    // excluded: the image may have been added to the page later.
    const late = rows.filter(r => ['existed', 'case'].includes(r.kind)).sort((a, b) => a.ms - b.ms || rank(a.grade) - rank(b.grade))[0] || null;
    // Earliest possible: the earliest date the file itself claims (editable) or, for text cases, the linked domain's registration.
    const fileClaims = rows.filter(r => ['capture', 'created'].includes(r.kind) && ok(r)).sort((a, b) => a.ms - b.ms);
    const early = fileClaims[0] || (media ? null : rows.filter(r => r.kind === 'domain').sort((a, b) => a.ms - b.ms)[0]) || null;
    return { early: early && (!late || early.ms <= late.ms) ? early : null, late };
  }

  // ---------- SVG axis ----------
  const STEPS = [[H, 'hour'], [6 * H, 'hour'], [DAY, 'day'], [7 * DAY, 'day'], [30 * DAY, 'month'], [91 * DAY, 'month'], [YEAR, 'year'], [2 * YEAR, 'year'], [5 * YEAR, 'year'], [10 * YEAR, 'year'], [20 * YEAR, 'year']];
  function ticks(lo, hi, max = 6) {
    const [step, unit] = STEPS.find(([s]) => (hi - lo) / s <= max) || STEPS[STEPS.length - 1];
    const out = [];
    const d = new Date(lo);
    let t;
    if (unit === 'year') { const ys = Math.round(step / YEAR); let y = d.getUTCFullYear(); y = Math.ceil(y / ys) * ys; for (; (t = Date.UTC(y, 0, 1)) <= hi; y += ys) if (t >= lo) out.push({ t, label: String(y) }); }
    else if (unit === 'month') { const ms = Math.round(step / (30 * DAY)); let y = d.getUTCFullYear(), m = d.getUTCMonth() + 1; for (; (t = Date.UTC(y, m, 1)) <= hi; m += ms) if (t >= lo) out.push({ t, label: new Date(t).toISOString().slice(0, 7) }); }
    else { const start = Math.ceil(lo / step) * step; for (t = start; t <= hi; t += step) out.push({ t, label: unit === 'day' ? new Date(t).toISOString().slice(0, 10) : new Date(t).toISOString().slice(5, 13).replace('T', ' ') + ':00' }); }
    return { unit, ticks: out };
  }
  function svg(rows, b, esc) {
    if (!rows.length) return '';
    const W = 720, L = 24, R = 24, AX = 92;
    let lo = Math.min(...rows.map(r => r.ms)), hi = Math.max(...rows.map(r => r.ms));
    if (hi - lo < H) { lo -= DAY / 2; hi += DAY / 2; }
    const padT = (hi - lo) * 0.04; lo -= padT; hi += padT;
    const x = t => L + (W - L - R) * (t - lo) / (hi - lo);
    const lanes = [];
    const pts = rows.map(r => {
      const px = x(r.ms); let lane = lanes.findIndex(last => px - last >= 12); if (lane < 0) { lane = lanes.length < 4 ? lanes.length : lanes.indexOf(Math.min(...lanes)); }
      lanes[lane] = px; return { r, px, py: AX - 12 - lane * 14 };
    });
    const tk = ticks(lo, hi);
    const band = b && (b.early || b.late) ? (() => {
      const a = b.early ? x(b.early.ms) : L, z = b.late ? x(b.late.ms) : W - R;
      return `<rect class="tlv-band" x="${Math.min(a, z).toFixed(1)}" y="20" width="${Math.max(2, Math.abs(z - a)).toFixed(1)}" height="${AX - 20}"></rect>
        ${b.early ? `<line class="tlv-bound" x1="${a.toFixed(1)}" x2="${a.toFixed(1)}" y1="18" y2="${AX}"></line><text class="tlv-bl" x="${a.toFixed(1)}" y="14" text-anchor="${a > W - 140 ? 'end' : 'start'}">earliest possible</text>` : ''}
        ${b.late ? `<line class="tlv-bound" x1="${z.toFixed(1)}" x2="${z.toFixed(1)}" y1="18" y2="${AX}"></line><text class="tlv-bl" x="${z.toFixed(1)}" y="${b.early && Math.abs(z - a) < 120 ? 30 : 14}" text-anchor="${z > W - 140 ? 'end' : 'start'}">existed by</text>` : ''}`;
    })() : '';
    const contra = rows.filter(r => r.flags.length).length;
    const desc = `${rows.length} dated items from ${fmtWhen(rows[0])} to ${fmtWhen(rows[rows.length - 1])}${contra ? `; ${contra} with contradictions, drawn as diamonds` : ''}. The list below has every item.`;
    return `<figure class="tlv-fig"><svg class="tlv-svg" viewBox="0 0 ${W} 134" role="img" aria-labelledby="tlv-t tlv-d" preserveAspectRatio="xMidYMid meet">
      <title id="tlv-t">Dating timeline axis</title><desc id="tlv-d">${esc(desc)}</desc>
      ${band}
      <line class="tlv-axis" x1="${L}" x2="${W - R}" y1="${AX}" y2="${AX}"></line>
      ${tk.ticks.map(t => `<line class="tlv-tick" x1="${x(t.t).toFixed(1)}" x2="${x(t.t).toFixed(1)}" y1="${AX}" y2="${AX + 5}"></line><text class="tlv-tl" x="${x(t.t).toFixed(1)}" y="${AX + 19}" text-anchor="middle">${esc(t.label)}</text>`).join('')}
      ${pts.map(({ r, px, py }) => `<g class="tlv-pt${r.flags.length ? ' bad' : ''}${['device', 'case'].includes(r.kind) ? ' ctx' : ''}"><title>${esc(`${fmtWhen(r)} ${zoneLabel(r)} · ${r.what} · ${r.grade}`)}</title><line x1="${px.toFixed(1)}" x2="${px.toFixed(1)}" y1="${py}" y2="${AX}"></line>${r.flags.length ? `<path d="M${px.toFixed(1)} ${py - 6} l6 6 l-6 6 l-6 -6 z"></path>` : `<circle cx="${px.toFixed(1)}" cy="${py}" r="4.5"></circle>`}</g>`).join('')}
      <g class="tlv-legend" transform="translate(${L} 128)"><circle cx="4" cy="-4" r="4"></circle><text x="14" y="0">dated item</text><path transform="translate(104 -4)" d="M0 -6 l6 6 l-6 6 l-6 -6 z"></path><text x="116" y="0">contradiction</text><rect x="220" y="-10" width="14" height="12"></rect><text x="240" y="0">possible date interval</text></g>
    </svg></figure>`;
  }

  // ---------- Plain-text lines for the exported case report ----------
  function reportLines(rows) {
    if (!rows || !rows.length) return [];
    const b = bounds(rows), L = ['', 'DATING TIMELINE'];
    L.push(`Earliest possible: ${b.early ? `${fmt(b.early)}, ${b.early.src} (${b.early.grade})` : 'not bounded by the evidence'}`);
    L.push(`Existed by: ${b.late ? `${fmt(b.late)}, ${b.late.src} (${b.late.grade})` : 'not bounded by the evidence'}`);
    for (const r of rows) {
      L.push(`- ${fmtWhen(r)} ${zoneLabel(r)} · ${r.what} · ${r.origin}: ${r.src} · ${r.grade}${r.href ? ' <' + r.href + '>' : ''}`);
      r.flags.forEach(f => L.push(`    ! [${f.weight}] ${f.text}`));
    }
    L.push('Grades: Admiralty source reliability (A-F) and information credibility (1-6). Embedded file dates are editable and say what the file claims.');
    return L;
  }

  // Plain-language reasons and actions for the Simple result (ScamBunker.addReasons / addActions). Weak leads never surface there.
  function plain(rows) {
    const reasons = [], actions = [];
    const has = (kind, re) => rows.some(r => r.kind === kind && r.flags.some(f => f.weight !== 'weak' && re.test(f.text)));
    if (has('claimed', /claims/)) reasons.push({ text: 'This picture or video already existed before the event the post talks about. It may be old media reused to tell a new story.', weight: rows.some(r => r.kind === 'claimed' && r.flags.some(f => f.weight === 'strong')) ? 'strong' : 'moderate', source: 'timeline' });
    if (has('capture', /already existed/)) reasons.push({ text: 'The date saved inside the file is later than the date a copy was first seen online, so that date was probably changed.', weight: 'strong', source: 'timeline' });
    if (rows.some(r => r.kind === 'modified' && r.flags.some(f => f.weight !== 'weak'))) reasons.push({ text: 'The dates saved inside the file do not make sense (it was edited before it was taken), so they may have been changed.', weight: 'moderate', source: 'timeline' });
    if (reasons.length) actions.push({ text: 'Before you share it, search for older copies of the picture (Google Lens or TinEye, sorted by oldest) to see where and when it first appeared.', href: 'https://tineye.com/' });
    return { reasons, actions };
  }

  const api = { parseWhen, parseOffset, span, zoneLabel, fmtWhen, collect, contradictions, bounds, ticks, svg, reportLines, gradeText, plain };
  if (typeof window !== 'undefined') window.ScamBunkerTimeline = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;

  // ======================= UI =======================
  if (typeof document === 'undefined' || typeof window === 'undefined' || !window.ScamBunker) return;
  const SB = window.ScamBunker, { esc } = SB;
  const host = () => SB.panel('timeline');

  const listings = () => { const C = window.SBEventsCore; if (!C) return []; try { return SB.store.get('scambunker.events', []).map((l, i) => C.normalizeListing(l, i)); } catch { return []; } };
  const parseClaimedDate = (...a) => window.ScamBunkerProvenance && window.ScamBunkerProvenance.parseClaimedDate ? window.ScamBunkerProvenance.parseClaimedDate(...a) : null;
  const rowsFor = c => collect(c, { listings: listings(), parseClaimedDate, now: Date.now() });
  api.rowsFor = rowsFor;
  api.caseReportLines = c => (c ? reportLines(rowsFor(c)) : []);

  const TAB_LABEL = { image: 'Image lab', video: 'Video lab', provenance: 'Provenance', corroborate: 'Corroborate', events: 'Events', links: 'Links & entities' };
  function evidence(r) {
    if (r.href) return `<a href="${esc(r.href)}" target="_blank" rel="noopener noreferrer">evidence ↗<span class="sr-only"> for ${esc(r.what)} (opens in a new tab)</span></a>`;
    if (r.tab && document.getElementById('tab-' + r.tab) && !document.getElementById('tab-' + r.tab).hidden) return `<a href="#panel-${esc(r.tab)}" data-tlv-tab="${esc(r.tab)}">${esc(TAB_LABEL[r.tab] || r.tab)}<span class="sr-only"> (evidence for ${esc(r.what)})</span></a>`;
    return '';
  }
  const boundBox = (k, r, empty) => `<div class="box"><div class="k">${k}</div><div class="big">${r ? esc(fmtWhen(r)) : 'Not bounded'}</div><p>${r ? `${esc(zoneLabel(r))} · ${esc(r.src)} · <abbr title="${esc(gradeText(r.grade))}">${esc(r.grade)}</abbr>` : esc(empty)}</p></div>`;

  function render(c) {
    const el = host(); if (!el || !c || !c.at) return;
    const rows = rowsFor(c), b = bounds(rows), f = c.forensics;
    contribute(c, rows);
    const nContra = rows.filter(r => r.flags.length).length;
    const note = !f && c.video ? (c.video.earliest ? '' : '<div class="callout">The video has no surviving embedded timestamps, which is typical after platform re-encoding. Reverse-search its keyframes (Video lab) and use the earliest indexed copy.</div>')
      : !f && !c.video ? '<p class="muted">Add an image or video to rebuild its timeline from embedded timestamps. Archive, domain, claim and corroboration dates appear here as you collect them.</p>'
      : f && !f.earliest ? '<div class="callout">The file has no surviving embedded timestamps, which is typical after social-media upload. To date it, run a reverse image search and use the earliest indexed copy (TinEye: sort by Oldest), then trace it in Provenance.</div>' : '';
    el.innerHTML = `
      <section class="tlv">
        <h3>Dating timeline</h3>
        <p class="muted">Every dated item in this case, merged and sorted. Grades are Admiralty pairs: source reliability (A–F) and information credibility (1–6). Embedded file dates are editable and only say what the file claims.</p>
        ${note}
        <div class="grid2 tlv-bounds">${boundBox('Earliest possible', b.early, 'No capture date or domain record that survives the contradictions.')}${boundBox('Existed by', b.late, 'No independent evidence of existence yet.')}</div>
        ${nContra ? `<div class="callout tlv-alert" role="note"><b>${nContra} item${nContra > 1 ? 's' : ''} contradict${nContra > 1 ? '' : 's'} other evidence.</b> They are marked below. A contradiction is a lead to check, not proof of intent.</div>` : ''}
        ${svg(rows, b, esc)}
        <ol class="tl tlv-list" aria-label="Dated items, oldest first">${rows.map(r => `<li class="tl-item${['device', 'case'].includes(r.kind) ? ' low' : ''}${r.flags.length ? ' tlv-bad' : ''}">
          <time datetime="${esc(r.zone.kind === 'unknown' ? r.when : new Date(r.ms).toISOString())}">${esc(fmtWhen(r).replace(' ', ' · '))}<span class="tlv-zone${r.zone.kind === 'unknown' ? ' unk' : ''}">${esc(zoneLabel(r))}</span></time>
          <p>${esc(r.what)}</p>
          <small>${esc(r.origin)} · ${esc(r.src)} · <abbr title="${esc(gradeText(r.grade))}">${esc(r.grade)}</abbr>${evidence(r) ? ' · ' + evidence(r) : ''}</small>
          ${r.flags.map(x => `<p class="tlv-flag"><span class="w ${esc(x.weight)}">${esc(x.weight)}</span> <span class="sr-only">Contradiction: </span>${esc(x.text)}</p>`).join('')}
        </li>`).join('')}</ol>
        ${rows.some(r => r.zone.kind === 'unknown') ? '<p class="muted tlv-foot">Items marked “timezone unknown” are placed as if they were UTC. Their real instant can be up to 14 hours either way, so comparisons with them allow that margin.</p>' : ''}
      </section>`;
  }
  api.render = render;

  function contribute(c, rows) {
    if (!c || (!SB.addReasons && !SB.addActions)) return;
    const { reasons, actions } = plain(rows);
    const done = c._tlvPlain || (c._tlvPlain = new Set());
    const fresh = reasons.filter(r => !done.has(r.text)), freshA = actions.filter(a => !done.has(a.text));
    try { if (fresh.length && SB.addReasons) SB.addReasons(c, fresh); if (freshA.length && SB.addActions) SB.addActions(c, freshA); } catch (e) { console.debug('timeline: could not add reasons', e); return; }
    fresh.concat(freshA).forEach(x => done.add(x.text));
  }

  document.addEventListener('click', e => {
    const a = e.target.closest('[data-tlv-tab]'); if (!a) return;
    e.preventDefault(); SB.showTab(a.dataset.tlvTab); const t = document.getElementById('tab-' + a.dataset.tlvTab); if (t) t.focus();
  });
  // Re-render when the section is opened (corroboration or event listings may have changed) and after provenance runs.
  const p = host();
  if (p) new MutationObserver(() => { if (!p.hidden && SB.current) render(SB.current); }).observe(p, { attributes: true, attributeFilter: ['hidden'] });
  ['sb:provenance', 'sb:case-complete'].forEach(ev => document.addEventListener(ev, e => { if (e.detail && e.detail === SB.current) render(e.detail); }));
  window.addEventListener('storage', e => { if (e.key === 'scambunker.events' && SB.current) render(SB.current); });
  if (SB.current) render(SB.current);
})();
