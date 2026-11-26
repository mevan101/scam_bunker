// Scam Bunker: event-listing overlap detector, pure logic (no DOM).
// Shared by the browser (window.SBEventsCore) and the server/tests (require).
// Everything here produces scheduling observations, never findings of misconduct.
(function (root) {
  'use strict';

  // ---------- Time zones (Intl only, no tz database shipped) ----------
  const dtfCache = new Map();
  function dtf(tz) {
    if (!dtfCache.has(tz)) dtfCache.set(tz, new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', weekday: 'short' }));
    return dtfCache.get(tz);
  }
  function isValidTz(tz) {
    if (!tz || typeof tz !== 'string') return false;
    try { dtf(tz); return true; } catch { return false; }
  }
  function wallParts(utcMs, tz) {
    const o = {};
    for (const p of dtf(tz).formatToParts(new Date(utcMs))) o[p.type] = p.value;
    return { y: +o.year, mo: +o.month, d: +o.day, h: +o.hour % 24, mi: +o.minute, s: +o.second, wd: o.weekday };
  }
  function tzOffsetMinutes(tz, utcMs) {
    const t = Math.floor(utcMs / 1000) * 1000, p = wallParts(t, tz);
    return Math.round((Date.UTC(p.y, p.mo - 1, p.d, p.h, p.mi, p.s) - t) / 60000);
  }
  const pad = n => String(n).padStart(2, '0');
  function fmtOffset(min) {
    if (min == null || !Number.isFinite(min)) return '';
    const s = min < 0 ? '-' : '+', a = Math.abs(min);
    return `${s}${pad(Math.floor(a / 60))}:${pad(a % 60)}`;
  }

  // 'YYYY-MM-DD', 'YYYY-MM-DDTHH:mm[:ss[.sss]]', optional 'Z' / '+06:00' / '+0600'
  const ISO_RE = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$/i;
  function parseIso(str) {
    const m = ISO_RE.exec(String(str ?? '').trim());
    if (!m) return null;
    const [, y, mo, d, h, mi, s] = m, tzs = m[7];
    if (+mo < 1 || +mo > 12 || +d < 1 || +d > 31 || +(h || 0) > 23 || +(mi || 0) > 59) return null;
    const dateOnly = h === undefined;
    let offsetMin = null;
    if (tzs) offsetMin = /z/i.test(tzs) ? 0 : (tzs[0] === '-' ? -1 : 1) * (+tzs.slice(1, 3) * 60 + +tzs.slice(-2));
    const wallMs = Date.UTC(+y, +mo - 1, +d, +(h || 0), +(mi || 0), +(s || 0));
    return { local: `${y}-${mo}-${d}T${h || '00'}:${mi || '00'}:${s || '00'}`, dateOnly, offsetMin, wallMs, utcMs: offsetMin == null ? null : wallMs - offsetMin * 60000 };
  }

  // Wall-clock time in an IANA zone -> UTC. Reports DST gaps ('nonexistent') and repeats ('ambiguous').
  function zonedToUtc(local, tz) {
    const p = parseIso(local);
    if (!p || !isValidTz(tz)) return null;
    const w = p.wallMs, H = 3600000;
    const cands = [...new Set([tzOffsetMinutes(tz, w - 14 * H), tzOffsetMinutes(tz, w), tzOffsetMinutes(tz, w + 14 * H)])];
    const valid = cands.map(o => ({ o, t: w - o * 60000 })).filter(c => tzOffsetMinutes(tz, c.t) === c.o).sort((a, b) => a.t - b.t);
    if (valid.length === 0) { // spring-forward gap: interpret with the pre-transition offset (clock moves forward)
      const o = tzOffsetMinutes(tz, w - 14 * H), t = w - o * 60000;
      return { utcMs: t, offsetMin: tzOffsetMinutes(tz, t), status: 'nonexistent' };
    }
    const uniq = valid.filter((c, i) => i === 0 || c.t !== valid[i - 1].t);
    return { utcMs: uniq[0].t, offsetMin: uniq[0].o, status: uniq.length > 1 ? 'ambiguous' : 'ok' };
  }

  // zone: { tz } (IANA) or { offsetMin } (fixed). Returns local wall clock and offset at that instant.
  function utcToZoned(utcMs, zone) {
    if (utcMs == null || !zone) return null;
    let y, mo, d, h, mi, s, wd, off;
    if (zone.tz) { ({ y, mo, d, h, mi, s, wd } = wallParts(utcMs, zone.tz)); off = tzOffsetMinutes(zone.tz, utcMs); }
    else {
      off = zone.offsetMin || 0; const x = new Date(utcMs + off * 60000);
      y = x.getUTCFullYear(); mo = x.getUTCMonth() + 1; d = x.getUTCDate(); h = x.getUTCHours(); mi = x.getUTCMinutes(); s = x.getUTCSeconds();
      wd = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][x.getUTCDay()];
    }
    const date = `${y}-${pad(mo)}-${pad(d)}`, time = `${pad(h)}:${pad(mi)}`;
    return { date, time, hour: h, minute: mi, weekday: wd, offsetMin: off, iso: `${date}T${time}:${pad(s)}${fmtOffset(off)}` };
  }
  function zoneLabel(zone) { return !zone ? 'unknown zone' : zone.tz ? zone.tz : `UTC${fmtOffset(zone.offsetMin)}`; }
  function fmtUtc(ms) { return ms == null ? '' : new Date(ms).toISOString().replace(/:\d\d\.\d+Z$/, 'Z'); }

  // ---------- URLs: platforms, programs, event IDs ----------
  const PLATFORMS = [
    [/(^|\.)(lu\.ma|luma\.com)$/i, 'Luma', null],
    [/(^|\.)meetup\.com$/i, 'Meetup', null],
    [/(^|\.)eventbrite\.[a-z.]+$/i, 'Eventbrite', null],
    [/(^|\.)developer\.microsoft\.com$/i, 'Microsoft Reactor', 'Microsoft Reactor', /\/reactor\//i],
    [/(^|\.)mlh\.io$/i, 'MLH', 'MLH'],
    [/(^|\.)globalai\.community$/i, 'Global AI Community', 'Global AI Community'],
    [/(^|\.)stripe\.(com|events|dev)$/i, 'Stripe', 'Stripe'],
    [/(^|\.)(facebook|fb)\.com$/i, 'Facebook', null],
  ];
  const SHORTENERS = /(^|\.)(bit\.ly|tinyurl\.com|t\.co|lnkd\.in|aka\.ms|buff\.ly|ow\.ly|rebrand\.ly|cutt\.ly|shorturl\.at|is\.gd|goo\.gl|tiny\.cc|rb\.gy|s\.id)$/i;
  function safeUrl(u) { try { const x = new URL(u); return /^https?:$/.test(x.protocol) ? x : null; } catch { return null; } }
  function platformOf(u) {
    const x = safeUrl(u); if (!x) return { platform: null, program: null };
    for (const [re, name, program, path] of PLATFORMS) if (re.test(x.hostname) && (!path || path.test(x.pathname))) return { platform: name, program };
    return { platform: x.hostname.replace(/^www\./, ''), program: null };
  }
  function isShortener(u) { const x = safeUrl(u); return !!x && SHORTENERS.test(x.hostname); }
  function eventIdFromUrl(u) {
    const x = safeUrl(u); if (!x || isShortener(u)) return null;
    const host = x.hostname.replace(/^www\./, ''), segs = x.pathname.split('/').filter(Boolean).map(s => decodeURIComponent(s));
    const { platform } = platformOf(u);
    const out = (id, kind) => id ? { platform, id: String(id), kind } : null;
    let m;
    if (/(^|\.)(lu\.ma|luma\.com)$/i.test(host)) {
      if (segs[0] === 'event' && segs[1]) return out(segs[1], 'opaque');
      if (segs.length === 1 && !/^(discover|calendar|home|signin|login|create|explore|pricing|u|user)$/i.test(segs[0])) return out(segs[0], /^evt-/i.test(segs[0]) ? 'opaque' : 'slug');
      return null;
    }
    if ((m = /\/events\/(\d{4,})/.exec(x.pathname))) return out(m[1], 'numeric'); // Meetup, Reactor, Facebook, MLH
    if (/eventbrite\./i.test(host) && (m = /(?:-|\/e\/)(\d{6,})(?:\/|$|\?)/.exec(x.pathname + '/'))) return out(m[1], 'numeric');
    for (const k of ['event_id', 'eventId', 'eventid', 'eid', 'event', 'id']) { const v = x.searchParams.get(k); if (v && /^[\w-]{3,}$/.test(v)) return out(v, /^\d+$/.test(v) ? 'numeric' : 'opaque'); }
    const num = segs.slice().reverse().map(s => /(?:^|-)(\d{5,})(?:-|$)/.exec(s)).find(Boolean);
    if (num) return out(num[1], 'numeric');
    const ev = segs.indexOf('events');
    if (ev >= 0 && segs[ev + 1]) return out(segs[ev + 1].toLowerCase(), 'slug');
    const last = segs[segs.length - 1];
    if (last && /^(?=.*\d)[a-z0-9_-]{6,}$/i.test(last)) return out(last, 'slug');
    return null;
  }

  // ---------- Text similarity ----------
  const ABBR = { rd: 'road', st: 'street', ave: 'avenue', av: 'avenue', blvd: 'boulevard', bldg: 'building', fl: 'floor', univ: 'university', ctr: 'centre', center: 'centre', hq: 'headquarters', no: '', nr: '' };
  const STOP = new Set(['the', 'of', 'at', 'and', 'a', 'an', 'in', 'on', 'for', 'to', 'with', '&', '-']);
  function norm(s) { return String(s ?? '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim(); }
  function tokens(s) { return norm(s).split(' ').map(t => ABBR[t] ?? t).filter(t => t && !STOP.has(t)); }
  function jaccard(a, b) {
    const A = new Set(a), B = new Set(b); if (!A.size || !B.size) return 0;
    let i = 0; for (const t of A) if (B.has(t)) i++;
    return i / (A.size + B.size - i);
  }
  function containment(a, b) {
    const A = new Set(a), B = new Set(b); if (!A.size || !B.size) return 0;
    let i = 0; for (const t of A) if (B.has(t)) i++;
    return i / Math.min(A.size, B.size);
  }
  function haversineM(a, b) {
    const R = 6371000, r = x => x * Math.PI / 180, dLat = r(b.lat - a.lat), dLon = r(b.lon - a.lon);
    const h = Math.sin(dLat / 2) ** 2 + Math.cos(r(a.lat)) * Math.cos(r(b.lat)) * Math.sin(dLon / 2) ** 2;
    return 2 * R * Math.asin(Math.sqrt(h));
  }
  const ONLINE = /\b(online|virtual|zoom|teams|livestream|live stream|webinar|youtube|google meet|remote)\b/i;
  function isOnline(l) { return !l.venueAddress && !l.geo && ONLINE.test(l.venueName || ''); }
  function venueMatch(a, b) {
    if (isOnline(a) || isOnline(b)) return { score: 0, basis: 'online event' };
    const geoOk = g => g && Number.isFinite(g.lat) && Number.isFinite(g.lon);
    if (geoOk(a.geo) && geoOk(b.geo)) {
      const d = haversineM(a.geo, b.geo);
      if (d <= 100) return { score: 0.95, basis: `coordinates ${Math.round(d)} m apart` };
      if (d <= 300) return { score: 0.7, basis: `coordinates ${Math.round(d)} m apart` };
      if (d > 1000) return { score: 0, basis: `coordinates ${(d / 1000).toFixed(1)} km apart` };
    }
    const na = norm(a.venueAddress), nb = norm(b.venueAddress);
    if (na && na === nb) return { score: 1, basis: 'identical address' };
    const ta = tokens(`${a.venueName || ''} ${a.venueAddress || ''}`), tb = tokens(`${b.venueName || ''} ${b.venueAddress || ''}`);
    const nameA = norm(a.venueName), nameB = norm(b.venueName);
    if (nameA && nameA === nameB && nameA.length > 3) {
      const aa = tokens(a.venueAddress), ab = tokens(b.venueAddress);
      if (aa.length && ab.length && !jaccard(aa, ab)) return { score: 0.5, basis: 'same venue name, different addresses' };
      return { score: 0.85, basis: 'identical venue name' };
    }
    const s = Math.max(jaccard(ta, tb), 0.85 * containment(tokens(a.venueName), tokens(b.venueName)) * (tokens(a.venueName).length >= 2 && tokens(b.venueName).length >= 2 ? 1 : 0));
    return { score: Math.round(s * 100) / 100, basis: s ? `venue text ${Math.round(s * 100)}% similar` : 'no venue match' };
  }
  function titleSimilarity(a, b) {
    const ta = tokens(a), tb = tokens(b);
    return Math.max(jaccard(ta, tb), Math.min(ta.length, tb.length) >= 3 ? 0.9 * containment(ta, tb) : 0);
  }

  // ---------- Listing normalisation ----------
  const uniqCI = arr => { const seen = new Set(); return (arr || []).map(s => String(s ?? '').trim()).filter(s => s && !seen.has(s.toLowerCase()) && seen.add(s.toLowerCase())); };
  function resolveTime(str, tz) {
    const p = parseIso(str); if (!p) return null;
    if (p.dateOnly) return { ...p, allDay: true, utcMs: tz ? zonedToUtc(p.local, tz)?.utcMs ?? p.utcMs : p.utcMs, status: 'ok' };
    if (p.offsetMin != null) return { ...p, status: 'ok' };
    if (tz) { const z = zonedToUtc(p.local, tz); return { ...p, utcMs: z.utcMs, offsetMin: z.offsetMin, status: z.status, interpreted: true }; }
    return { ...p, status: 'floating' };
  }
  function normalizeListing(raw, idx = 0) {
    const l = { ...raw };
    l.id = l.id || `L${idx + 1}`;
    l.tz = isValidTz(l.tz) ? l.tz : null;
    l.warnings = [];
    if (raw.tz && !l.tz) l.warnings.push(`“${raw.tz}” is not a recognised IANA time zone; using the listing's own offset instead`);
    const s = resolveTime(l.start, l.tz), e = resolveTime(l.end, l.tz);
    const plat = platformOf(l.finalUrl || l.url);
    l.platform = l.platform || plat.platform || (l.manual ? 'manual entry' : null);
    l.programs = uniqCI([...(l.programs || []), plat.program]);
    l.organizers = uniqCI(l.organizers);
    l.zone = l.tz ? { tz: l.tz } : s && s.offsetMin != null && !s.interpreted ? { offsetMin: s.offsetMin } : null;
    l.startUtc = s ? s.utcMs : null;
    l.allDay = !!(s && s.allDay);
    if (s && s.status === 'floating') l.warnings.push('Start time has no time zone or offset; set the venue time zone to compare it');
    if (s && s.status === 'nonexistent') l.warnings.push(`${s.local.slice(0, 16)} does not exist in ${l.tz} (clocks jump forward); interpreted as ${utcToZoned(s.utcMs, l.zone).time}`);
    if (s && s.status === 'ambiguous') l.warnings.push(`${s.local.slice(0, 16)} occurs twice in ${l.tz} (clocks go back); the earlier one is used`);
    if (s && l.tz && s.offsetMin != null && !s.interpreted && l.startUtc != null) {
      const zo = tzOffsetMinutes(l.tz, l.startUtc);
      if (zo !== s.offsetMin) l.offsetMismatch = { listed: s.offsetMin, zone: zo };
    }
    if (e && e.utcMs != null) { l.endUtc = e.allDay ? e.utcMs + 86400000 : e.utcMs; l.endAssumed = false; }
    else if (l.startUtc != null) { l.endUtc = l.startUtc + (l.allDay ? 86400000 : 2 * 3600000); l.endAssumed = true; }
    else l.endUtc = null;
    l.startLocal = l.startUtc != null && l.zone ? utcToZoned(l.startUtc, l.zone) : s ? { date: s.local.slice(0, 10), time: s.local.slice(11, 16), hour: +s.local.slice(11, 13), minute: +s.local.slice(14, 16), floating: true } : null;
    l.endLocal = l.endUtc != null && l.zone ? utcToZoned(l.endUtc, l.zone) : null;
    l.cityKey = norm(l.city);
    l.eventId = { cited: l.citedId ? { id: String(l.citedId).trim(), kind: 'manual', platform: null } : eventIdFromUrl(l.url), final: eventIdFromUrl(l.finalUrl || l.url) };
    return l;
  }

  // ---------- Flags ----------
  const STRENGTH_ORDER = { strong: 0, moderate: 1, weak: 2 };
  const H = 3600000;
  function overlapMinutes(a0, a1, b0, b1) { return Math.max(0, Math.min(a1, b1) - Math.max(a0, b0)) / 60000; }
  const progKey = l => l.programs.map(p => p.toLowerCase()).sort();
  function programsDiffer(a, b) {
    const A = progKey(a), B = progKey(b);
    if (!A.length || !B.length) return false;
    return A.join('|') !== B.join('|');
  }
  const describe = l => `${l.id} “${l.title || 'untitled'}”${l.programs.length ? ` (${l.programs.join(', ')})` : ''}`;
  const localStr = l => l.startLocal ? `${l.startLocal.weekday ? l.startLocal.weekday + ' ' : ''}${l.startLocal.date} ${l.startLocal.time}${l.zone ? ' ' + zoneLabel(l.zone) : ' (no zone)'}` : 'no start time';

  function flagSameVenueOverlap(L) {
    const out = [];
    for (let i = 0; i < L.length; i++) for (let j = i + 1; j < L.length; j++) {
      const a = L[i], b = L[j];
      if (a.startUtc == null || b.startUtc == null || !programsDiffer(a, b)) continue;
      const v = venueMatch(a, b); if (v.score < 0.5) continue;
      const ov = overlapMinutes(a.startUtc, a.endUtc, b.startUtc, b.endUtc); if (ov <= 0) continue;
      const frac = ov / Math.min((a.endUtc - a.startUtc) / 60000, (b.endUtc - b.startUtc) / 60000);
      const assumed = a.endAssumed || b.endAssumed;
      const strength = v.score >= 0.85 && frac >= 0.5 && !assumed ? 'strong' : v.score >= 0.6 && frac >= 0.25 ? 'moderate' : 'weak';
      out.push({
        type: 'a', code: 'same-venue-overlap', strength, listings: [a.id, b.id],
        title: 'Same venue, overlapping time, different programs',
        explanation: `${describe(a)} and ${describe(b)} are at the same venue (${v.basis}) and overlap by ${Math.round(ov)} min (${Math.round(frac * 100)}% of the shorter listing). ${a.programs.join(', ')} vs ${b.programs.join(', ')}.${assumed ? ' At least one end time was missing, so a 2-hour duration was assumed.' : ''}`,
        innocent: ['One co-hosted session can be legitimately listed on each partner’s platform (co-branding is common at community events).', 'Large venues run several rooms or tracks at the same time.', 'Venue fields are often filled with a default or placeholder address.'],
      });
    }
    return out;
  }

  function sameReference(a, b) {
    const fa = a.eventId.final, fb = b.eventId.final;
    if (fa && fb && fa.platform === fb.platform && fa.id.toLowerCase() === fb.id.toLowerCase()) return { strength: 'strong', basis: `same ${fa.platform} event ID ${fa.id}` };
    if (a.finalUrl && b.finalUrl && a.finalUrl.replace(/[?#].*$/, '') === b.finalUrl.replace(/[?#].*$/, '')) return { strength: 'strong', basis: 'same final URL' };
    const t = titleSimilarity(a.title, b.title); if (t < 0.75) return null;
    const v = venueMatch(a, b).score, o = jaccard(a.organizers.flatMap(tokens), b.organizers.flatMap(tokens));
    if (v >= 0.6 || o >= 0.5) return { strength: 'moderate', basis: `titles ${Math.round(t * 100)}% similar and ${v >= 0.6 ? 'same venue' : 'same organiser'}` };
    return { strength: 'weak', basis: `titles ${Math.round(t * 100)}% similar` };
  }
  function timeDiffHint(d) {
    const h = Math.abs(d) / H;
    if (Math.abs(h - 12) < 0.01) return 'The difference is exactly 12 hours, which often means an AM/PM mix-up.';
    if (Math.abs(h - Math.round(h)) < 0.01 && h <= 14) return `The difference is exactly ${Math.round(h)} h, which often means one listing was entered in a different time zone (e.g. UTC instead of venue time).`;
    if (Math.abs(h * 2 - Math.round(h * 2)) < 0.01 && h <= 14) return `The difference is ${h} h; some time zones use half-hour offsets, so this can be a time-zone entry error.`;
    return '';
  }
  function flagConflictingTimes(L) {
    const out = [];
    for (let i = 0; i < L.length; i++) for (let j = i + 1; j < L.length; j++) {
      const a = L[i], b = L[j], ref = sameReference(a, b); if (!ref) continue;
      let diff = null;
      if (a.startUtc != null && b.startUtc != null) diff = b.startUtc - a.startUtc;
      else if (a.startLocal && b.startLocal) diff = parseIso(`${b.startLocal.date}T${b.startLocal.time}`).wallMs - parseIso(`${a.startLocal.date}T${a.startLocal.time}`).wallMs;
      if (diff == null || Math.abs(diff) < 15 * 60000) continue;
      out.push({
        type: 'b', code: 'conflicting-times', strength: ref.strength, listings: [a.id, b.id],
        title: 'Same listing, conflicting dates/times',
        explanation: `${describe(a)} and ${describe(b)} appear to reference the same event (${ref.basis}) but give different start times: ${localStr(a)} vs ${localStr(b)} (${Math.round(Math.abs(diff) / 60000)} min apart${a.startUtc != null && b.startUtc != null ? ` in UTC: ${fmtUtc(a.startUtc)} vs ${fmtUtc(b.startUtc)}` : ''}). ${timeDiffHint(diff)}`.trim(),
        innocent: ['The event may have been rescheduled and only one platform was updated.', 'One platform may display times in the viewer’s zone or have the wrong organiser time zone set.', 'Recurring series can share a title while each session has its own date.'],
      });
    }
    for (const l of L) for (const d of (l.discrepancies || [])) {
      out.push({
        type: 'b', code: 'internal-discrepancy', strength: 'moderate', listings: [l.id],
        title: 'Listing page disagrees with itself',
        explanation: `${describe(l)}: the ${d.field} differs between sources on the same page: ${d.values.map(v => `${v.value} [${v.source}${v.via ? ' · ' + v.via : ''}]`).join(' vs ')}.`,
        innocent: ['Structured data and calendar links are often generated separately and can go stale after an edit.', 'Some pages emit the time without an offset, which software then reads in a different zone.'],
      });
    }
    return out;
  }

  function flagImplausibleHours(L) {
    const out = [];
    const innocent = ['Most often a time-zone setting or AM/PM entry mistake by whoever created the listing.', 'Overnight hackathons and events in other regions can legitimately start at unusual hours.', 'This is explicitly not evidence of wrongdoing.'];
    for (const l of L) {
      if (l.offsetMismatch) out.push({
        type: 'c', code: 'offset-mismatch', strength: 'moderate', listings: [l.id], title: 'Listed offset does not match the venue time zone',
        explanation: `${describe(l)} gives its start with offset ${fmtOffset(l.offsetMismatch.listed)}, but ${l.tz} is ${fmtOffset(l.offsetMismatch.zone)} on that date. The local time shown uses the venue zone (${localStr(l)}). This looks like a time-zone entry error.`, innocent,
      });
      if (!l.startLocal || l.allDay) continue;
      const h = l.startLocal.hour;
      let strength = null;
      if (h < 5) strength = 'moderate'; else if (h < 7 || h >= 23) strength = 'weak';
      if (strength) {
        const alt = [];
        if (h < 12) alt.push(`as PM it would be ${pad(h + 12)}:${pad(l.startLocal.minute)} local`);
        if (l.startUtc != null && l.zone) alt.push(`the same instant is ${fmtUtc(l.startUtc).slice(11, 16)} UTC; if the organiser’s account was set to another zone the intended local time may differ`);
        out.push({
          type: 'c', code: 'implausible-hour', strength, listings: [l.id], title: 'Implausible local start time',
          explanation: `${describe(l)} starts at ${localStr(l)}, an unusual hour for an in-person session. Likely a time-zone or AM/PM entry error${alt.length ? ` (${alt.join('; ')})` : ''}. Not evidence of wrongdoing.`, innocent,
        });
      }
      if (l.endUtc != null && !l.endAssumed) {
        const dur = (l.endUtc - l.startUtc) / H;
        if (dur <= 0 || dur > 16) out.push({
          type: 'c', code: 'implausible-duration', strength: 'weak', listings: [l.id], title: 'Implausible duration',
          explanation: `${describe(l)} ${dur <= 0 ? 'ends before it starts' : `lasts ${Math.round(dur)} h`}. Usually a date or AM/PM entry error.`, innocent,
        });
      }
    }
    return out;
  }

  function flagRedirects(L) {
    const out = [];
    for (const l of L) {
      const c = l.eventId.cited, f = l.eventId.final;
      if (!c || !f || c.id.toLowerCase() === f.id.toLowerCase()) continue;
      if (!l.citedId && (!l.finalUrl || l.finalUrl === l.url)) continue;
      const strength = c.kind !== 'slug' && f.kind !== 'slug' && (c.kind === 'manual' || c.platform === f.platform) ? 'strong' : 'moderate';
      out.push({
        type: 'd', code: 'redirect-different-id', strength, listings: [l.id], title: 'Link resolves to a different event ID',
        explanation: `${describe(l)} was cited as ${c.platform ? c.platform + ' ' : ''}event ${c.id}${l.citedId ? ' (entered manually)' : ''} but the final URL after ${Math.max(0, (l.redirects || []).length - 1)} redirect(s) is ${f.platform || ''} event ${f.id}: ${l.finalUrl || l.url}.`,
        innocent: ['Platforms redirect when an event is duplicated, merged, or re-created after a change.', 'Event slugs can be renamed while the old link keeps working.', 'A short link may have been reused or edited by its owner.'],
      });
    }
    return out;
  }

  function flagSameDayCity(L) {
    const groups = new Map();
    for (const l of L) {
      if (!l.cityKey || !l.startLocal || !l.programs.length) continue;
      const k = `${l.cityKey}|${l.startLocal.date}`;
      if (!groups.has(k)) groups.set(k, []); groups.get(k).push(l);
    }
    const out = [];
    for (const g of groups.values()) {
      const progs = new Set(g.map(l => progKey(l).join('|')));
      if (g.length < 2 || progs.size < 2) continue;
      out.push({
        type: 'e', code: 'same-day-city', strength: 'weak', listings: g.map(l => l.id), title: 'Same day, same city, several programs',
        explanation: `${g.length} listings from ${progs.size} different program combinations fall on ${g[0].startLocal.date} in ${g[0].city}: ${g.map(describe).join('; ')}.`,
        innocent: ['Multi-track community days and conferences routinely host several programs on the same day.', 'Cities with active tech communities often have many unrelated events on the same day.'],
      });
    }
    return out;
  }

  function detectFlags(listings) {
    const L = listings.map((l, i) => l.startUtc === undefined ? normalizeListing(l, i) : l);
    return [...flagSameVenueOverlap(L), ...flagConflictingTimes(L), ...flagImplausibleHours(L), ...flagRedirects(L), ...flagSameDayCity(L)]
      .sort((a, b) => STRENGTH_ORDER[a.strength] - STRENGTH_ORDER[b.strength] || a.type.localeCompare(b.type));
  }

  // ---------- SHA-256 (WebCrypto when available, pure-JS fallback for non-secure contexts) ----------
  function sha256Fallback(bytes) {
    const K = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
    const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const len = bytes.length, total = Math.ceil((len + 9) / 64) * 64, buf = new Uint8Array(total);
    buf.set(bytes); buf[len] = 0x80;
    const dv = new DataView(buf.buffer); dv.setUint32(total - 8, Math.floor(len / 0x20000000)); dv.setUint32(total - 4, (len * 8) >>> 0);
    const w = new Uint32Array(64), rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let o = 0; o < total; o += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
      for (let i = 16; i < 64; i++) { const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0; }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    return [...h].map(x => x.toString(16).padStart(8, '0')).join('');
  }
  async function sha256Hex(str) {
    const bytes = new TextEncoder().encode(str);
    const subtle = typeof crypto !== 'undefined' && crypto.subtle;
    if (subtle) { const d = await subtle.digest('SHA-256', bytes); return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join(''); }
    return sha256Fallback(bytes);
  }

  // ---------- Claims ledger (printable HTML) ----------
  const escH = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const DISCLAIMER = 'These are scheduling observations, not findings of misconduct. Overlaps and inconsistencies usually have ordinary explanations (co-hosting, rescheduling, time-zone settings, data-entry errors). Only the sponsoring programs can verify funding or approval.';
  const LEDGER_BEGIN = '<!--ledger:begin-->', LEDGER_END = '<!--ledger:end-->';
  function ledgerContent(listings, flags, generatedAt) {
    const L = listings.map((l, i) => l.startUtc === undefined ? normalizeListing(l, i) : l);
    const src = (l, k) => escH((l.sources || {})[k] || (l.manual ? 'manual' : '—'));
    const row = (label, value, source) => `<tr><th scope="row">${escH(label)}</th><td>${value === '' || value == null ? '<span class="na">not found</span>' : escH(value)}</td><td>${source}</td></tr>`;
    const items = L.map(l => `<section class="listing"><h2>${escH(l.id)} · ${escH(l.title || 'Untitled listing')}</h2>
<table><thead><tr><th scope="col">Field</th><th scope="col">Exact extracted value</th><th scope="col">Source</th></tr></thead><tbody>
${row('Cited URL', l.url || '', l.manual ? 'manual' : 'input')}
${row('Final URL', l.finalUrl || '', l.redirects && l.redirects.length ? 'http' : '—')}
${row('Redirect chain', (l.redirects || []).map(r => `${r.status} ${r.url}`).join('  →  '), l.redirects && l.redirects.length ? 'http' : '—')}
${row('Event ID (cited → final)', [l.eventId.cited?.id || '?', l.eventId.final?.id || '?'].join(' → '), 'url')}
${row('Platform', l.platform || '', 'url')}
${row('Title', l.title, src(l, 'title'))}
${row('Start (as listed)', l.start, src(l, 'start'))}
${row('End (as listed)', l.end, src(l, 'end'))}
${row('Time zone (as listed)', l.tz || '', src(l, 'timeZone'))}
${row('Start, venue local', l.startLocal ? `${l.startLocal.date} ${l.startLocal.time} ${l.zone ? zoneLabel(l.zone) : '(no zone)'}` : '', 'computed')}
${row('Start, UTC', fmtUtc(l.startUtc), 'computed')}
${row('End, UTC', l.endUtc != null ? fmtUtc(l.endUtc) + (l.endAssumed ? ' (assumed: +2 h)' : '') : '', 'computed')}
${row('Venue', l.venueName, src(l, 'venueName'))}
${row('Address', l.venueAddress, src(l, 'venueAddress'))}
${row('City', l.city, src(l, 'city'))}
${row('Geo', l.geo ? `${l.geo.lat}, ${l.geo.lon}` : '', src(l, 'geo'))}
${row('Organiser / host', (l.organizers || []).join('; '), src(l, 'organizers'))}
${row('Sponsors / programs / brands', (l.programs || []).join('; '), src(l, 'programs'))}
${row('Attendees (public)', l.attendees ?? '', src(l, 'attendees'))}
</tbody></table>${l.warnings.length ? `<ul class="warn">${l.warnings.map(w => `<li>${escH(w)}</li>`).join('')}</ul>` : ''}</section>`).join('\n');
    const fl = flags.length ? flags.map(f => `<li><p><b class="s ${escH(f.strength)}">${escH(f.strength)}</b> <b>${escH(f.title)}</b> <span class="ids">[${escH(f.listings.join(', '))}]</span></p><p>${escH(f.explanation)}</p><p class="inn"><b>Innocent explanations:</b> ${escH(f.innocent.join(' '))}</p></li>`).join('\n') : '<li>No scheduling flags were raised for these listings.</li>';
    return `<header><p class="eyebrow">Scam Bunker · claims ledger</p><h1>Event listing comparison</h1><p>Generated ${escH(generatedAt)} · ${L.length} listing(s) · ${flags.length} flag(s)</p><p class="disclaimer"><b>Disclaimer.</b> ${escH(DISCLAIMER)}</p></header>
${items}
<section><h2>Flags</h2><ol class="flags">${fl}</ol></section>
<section class="method"><h2>Method</h2><p>Values are copied exactly as extracted. Source key: jsonld = schema.org Event structured data; meta = OpenGraph/meta tags or embedded page data; ics = calendar file or Google Calendar link; text = visible page text; manual = typed in by the investigator; computed = derived by this tool. Times are normalised to UTC and to the venue's local zone using the browser's time-zone database. Strength labels (strong / moderate / weak) describe how solid the scheduling observation is, not anyone's intent.</p></section>`;
  }
  async function buildLedger(listings, flags, generatedAt = new Date().toISOString()) {
    const content = ledgerContent(listings, flags, generatedAt);
    const hash = await sha256Hex(content);
    const css = 'body{font:14px/1.5 Georgia,serif;color:#1b1d22;max-width:900px;margin:32px auto;padding:0 20px}h1{font-size:26px;margin:4px 0}h2{font-size:18px;margin:24px 0 8px}.eyebrow{font:12px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.1em;color:#7a4a08;margin:0}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #d2c9b5;padding:5px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}thead th{background:#f2ede2}tbody th{width:28%;font-weight:600}td:last-child{font:12px ui-monospace,monospace;width:11%}.na{color:#5f6673;font-style:italic}.disclaimer{border:2px solid #7a4a08;padding:10px 12px;background:#fbf6ea}.s{font:600 11px ui-monospace,monospace;text-transform:uppercase;padding:1px 6px;border:1px solid currentColor}.strong{color:#a8241d}.moderate{color:#7a5000}.weak{color:#2259b8}.inn{color:#3f4450}.flags li{margin-bottom:10px}.warn{color:#7a5000}footer{margin-top:28px;border-top:1px solid #d2c9b5;padding-top:10px;font:12px ui-monospace,monospace;overflow-wrap:anywhere}.listing{break-inside:avoid}@media print{body{margin:0}a{color:inherit}}';
    const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Claims ledger · ${escH(generatedAt)}</title><meta name="sha256-content" content="${hash}"><style>${css}</style></head><body>${LEDGER_BEGIN}${content}${LEDGER_END}<footer><p>SHA-256 of report content: <b>${hash}</b></p><p>The hash covers the exact UTF-8 text between the <code>&lt;!--ledger:begin--&gt;</code> and <code>&lt;!--ledger:end--&gt;</code> markers in this file's source. Any edit to the content changes the hash.</p></footer></body></html>`;
    return { html, hash, content };
  }

  const api = { isValidTz, tzOffsetMinutes, fmtOffset, parseIso, zonedToUtc, utcToZoned, zoneLabel, fmtUtc, platformOf, isShortener, eventIdFromUrl, venueMatch, titleSimilarity, normalizeListing, overlapMinutes, detectFlags, sha256Hex, sha256Fallback, buildLedger, ledgerContent, LEDGER_BEGIN, LEDGER_END, DISCLAIMER, norm };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.SBEventsCore = api;
})(typeof window !== 'undefined' ? window : null);
