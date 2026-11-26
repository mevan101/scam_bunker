// Event-listing extraction: fetch a listing page through the SSRF guard and pull out scheduling facts.
// Preference order per field: schema.org Event JSON-LD > OpenGraph/meta > .ics / Google Calendar link > visible text.
// Every field carries its source so the UI and the claims ledger can show provenance.
const { assertPublicUrl, httpError } = require('./net-guard');
const core = require('../public/events-core');

const UA = 'Mozilla/5.0 (compatible; ScamBunkerEventCheck/1.0; +https://github.com/mevan101/scam_bunker)';
const MAX_HOPS = 8;

// ---------- Fetch (guard re-checked on every hop, chain recorded) ----------
async function readCapped(res, maxBytes) {
  const reader = res.body?.getReader(); if (!reader) return '';
  const chunks = []; let size = 0;
  while (true) {
    const { done, value } = await reader.read(); if (done) break;
    size += value.length; chunks.push(value);
    if (size >= maxBytes) { await reader.cancel().catch(() => {}); break; }
  }
  return Buffer.concat(chunks.map(c => Buffer.from(c))).subarray(0, maxBytes).toString('utf8');
}
async function fetchFollow(url, { maxBytes = 1500000, fetchImpl = fetch, guard = assertPublicUrl } = {}) {
  const chain = []; let cur = url, metaRefreshUsed = false;
  for (let i = 0; i < MAX_HOPS; i++) {
    await guard(cur);
    const r = await fetchImpl(cur, { redirect: 'manual', headers: { 'User-Agent': UA, Accept: 'text/html,application/xhtml+xml,text/calendar;q=0.9,*/*;q=0.5' }, signal: AbortSignal.timeout(12000) });
    const loc = r.headers.get('location');
    chain.push({ url: cur, status: r.status });
    if (r.status >= 300 && r.status < 400 && loc) { cur = new URL(loc, cur).href; continue; }
    const contentType = r.headers.get('content-type') || '';
    const body = await readCapped(r, maxBytes);
    const refresh = !metaRefreshUsed && /html/i.test(contentType) && /<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d+\s*;\s*url=([^"'>\s]+)/i.exec(body);
    if (refresh) { metaRefreshUsed = true; chain[chain.length - 1].status = `${r.status} meta-refresh`; cur = new URL(decodeEntities(refresh[1]), cur).href; continue; }
    return { chain, finalUrl: cur, status: r.status, contentType, body };
  }
  throw new Error(`Too many redirects (more than ${MAX_HOPS})`);
}

// ---------- HTML helpers ----------
function decodeEntities(s) {
  return String(s ?? '').replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|nbsp|#39);/gi, (m, e) => {
    const k = e.toLowerCase();
    if (k[0] === '#') { const n = k[1] === 'x' ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10); return Number.isFinite(n) && n < 0x110000 ? String.fromCodePoint(n) : m; }
    return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' }[k] ?? m;
  });
}
function attrs(tag) {
  const o = {};
  for (const m of tag.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)) o[m[1].toLowerCase()] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? '');
  return o;
}
const clean = s => decodeEntities(String(s ?? '').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
const IANA_RE = /^(?:Africa|America|Antarctica|Asia|Atlantic|Australia|Europe|Indian|Pacific|Etc)\/[A-Za-z0-9_+\-/]+$|^UTC$/;

// ---------- Compact calendar date-times (ics, Google Calendar) ----------
// 20241024T163000Z | 20241024T163000 | 20241024
function compactToIso(v) {
  const m = /^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})?(Z)?)?$/i.exec(String(v || '').trim());
  if (!m) return null;
  if (!m[4]) return { iso: `${m[1]}-${m[2]}-${m[3]}`, dateOnly: true };
  return { iso: `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] || '00'}${m[7] ? 'Z' : ''}`, floating: !m[7] };
}
// Turn a floating local time + zone into an ISO string with offset
function withOffset(iso, tz) {
  const p = core.parseIso(iso); if (!p || p.offsetMin != null || p.dateOnly || !core.isValidTz(tz)) return iso;
  const z = core.zonedToUtc(p.local, tz); return core.utcToZoned(z.utcMs, { tz }).iso;
}

// ---------- JSON-LD ----------
const isEventType = t => [].concat(t || []).some(x => /Event$|^Hackathon$/i.test(String(x)));
function* walk(node, depth = 0) {
  if (!node || typeof node !== 'object' || depth > 8) return;
  if (Array.isArray(node)) { for (const n of node) yield* walk(n, depth + 1); return; }
  yield node;
  if (node['@graph']) yield* walk(node['@graph'], depth + 1);
  for (const k of ['subEvent', 'mainEntity', 'itemListElement', 'item']) if (node[k]) yield* walk(node[k], depth + 1);
}
const names = v => [].concat(v || []).map(x => typeof x === 'string' ? x : x?.name || x?.legalName).filter(Boolean).map(s => clean(s));
function addressText(a) {
  if (!a) return '';
  if (typeof a === 'string') return clean(a);
  return [a.name, a.streetAddress, a.addressLocality, a.addressRegion, a.postalCode, a.addressCountry?.name || a.addressCountry].filter(Boolean).map(clean).join(', ');
}
function parseJsonLd(html) {
  const out = [];
  for (const m of html.matchAll(/<script\b[^>]*type\s*=\s*["']?application\/ld\+json["']?[^>]*>([\s\S]*?)<\/script>/gi)) {
    let data; const raw = m[1].replace(/^\s*<!\[CDATA\[|\]\]>\s*$/g, '').trim();
    try { data = JSON.parse(raw); } catch { try { data = JSON.parse(raw.replace(/[\u0000-\u001f]+/g, ' ')); } catch { continue; } }
    for (const n of walk(data)) {
      if (!isEventType(n['@type'])) continue;
      const loc = [].concat(n.location || [])[0] || {};
      const place = typeof loc === 'string' ? { name: loc } : loc;
      const addr = place.address;
      const geo = place.geo && Number.isFinite(+place.geo.latitude) && Number.isFinite(+place.geo.longitude) ? { lat: +place.geo.latitude, lon: +place.geo.longitude } : null;
      out.push({
        title: clean(n.name), start: n.startDate ? String(n.startDate).trim() : '', end: n.endDate ? String(n.endDate).trim() : '',
        timeZone: n.eventSchedule?.scheduleTimezone || n.timezone || n.timeZone || '',
        venueName: /VirtualLocation/i.test(place['@type'] || '') ? 'Online' : clean(place.name),
        venueAddress: typeof addr === 'string' ? clean(addr) : addressText(addr && { ...addr, name: undefined }),
        city: typeof addr === 'object' && addr ? clean(addr.addressLocality) : '',
        geo, organizers: names(n.organizer), programs: [...names(n.sponsor), ...names(n.funder)],
        attendees: n.maximumAttendeeCapacity != null && Number.isFinite(+n.maximumAttendeeCapacity) ? { value: +n.maximumAttendeeCapacity, detail: 'capacity' } : null,
        url: typeof n.url === 'string' ? n.url : '', id: n['@id'] || '',
      });
    }
  }
  return out;
}

// ---------- OpenGraph / meta / embedded page data ----------
function parseMeta(html) {
  const meta = {};
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    const a = attrs(m[0]); const k = (a.property || a.name || a.itemprop || '').toLowerCase();
    if (k && a.content != null && !(k in meta)) meta[k] = a.content.trim();
  }
  const canonical = /<link\b[^>]*rel=["']?canonical["']?[^>]*>/i.exec(html);
  const lat = +(meta['event:location:latitude'] || meta['place:location:latitude'] || meta['og:latitude']);
  const lon = +(meta['event:location:longitude'] || meta['place:location:longitude'] || meta['og:longitude']);
  const tzm = /["'](?:timezone|time_zone|timeZone|tz|event_timezone|ctz)["']\s*:\s*["']([A-Za-z_]+\/[A-Za-z0-9_+\-/]+|UTC)["']/.exec(html);
  return {
    title: meta['og:title'] || meta['twitter:title'] || '',
    start: meta['event:start_time'] || meta['og:start_time'] || meta['startdate'] || '',
    end: meta['event:end_time'] || meta['og:end_time'] || meta['enddate'] || '',
    timeZone: tzm && IANA_RE.test(tzm[1]) ? tzm[1] : '', timeZoneVia: tzm ? 'embedded page data' : '',
    venueName: meta['og:site_name'] && meta['event:location'] ? meta['event:location'] : meta['event:location'] || '',
    venueAddress: meta['og:street-address'] || '', city: meta['og:locality'] || '',
    geo: Number.isFinite(lat) && Number.isFinite(lon) && (lat || lon) ? { lat, lon } : null,
    url: (canonical && attrs(canonical[0]).href) || meta['og:url'] || '',
  };
}

// ---------- iCalendar ----------
function icsUnescape(s) { return String(s).replace(/\\n/gi, ' ').replace(/\\([,;\\])/g, '$1').trim(); }
function parseIcs(text) {
  const lines = String(text).replace(/\r\n?/g, '\n').replace(/\n[ \t]/g, '').split('\n');
  const events = []; let cur = null; let calTz = '';
  for (const line of lines) {
    const m = /^([A-Z-]+)((?:;[^:]*)?):(.*)$/i.exec(line); if (!m) continue;
    const name = m[1].toUpperCase(), params = {}, value = m[3];
    for (const p of m[2].split(';').filter(Boolean)) { const [k, ...v] = p.split('='); params[k.toUpperCase()] = v.join('=').replace(/^"|"$/g, ''); }
    if (name === 'X-WR-TIMEZONE') calTz = value.trim();
    if (name === 'BEGIN' && /^VEVENT$/i.test(value)) cur = { organizers: [] };
    else if (name === 'END' && /^VEVENT$/i.test(value)) { if (cur) events.push(cur); cur = null; }
    else if (cur) {
      if (name === 'SUMMARY') cur.title = icsUnescape(value);
      else if (name === 'DTSTART' || name === 'DTEND') {
        const c = compactToIso(value); if (!c) continue;
        const tz = params.TZID || '';
        const key = name === 'DTSTART' ? 'start' : 'end';
        cur[key] = c.floating && core.isValidTz(tz) ? withOffset(c.iso, tz) : c.iso;
        if (tz) cur.timeZone = tz;
      } else if (name === 'LOCATION') cur.location = icsUnescape(value);
      else if (name === 'GEO') { const [la, lo] = value.split(/[;,]/).map(Number); if (Number.isFinite(la) && Number.isFinite(lo)) cur.geo = { lat: la, lon: lo }; }
      else if (name === 'ORGANIZER' && params.CN) cur.organizers.push(icsUnescape(params.CN));
      else if (name === 'URL') cur.url = value.trim();
      else if (name === 'UID') cur.uid = value.trim();
    }
  }
  for (const e of events) {
    if (!e.timeZone && calTz) e.timeZone = calTz;
    for (const k of ['start', 'end']) if (e[k] && core.parseIso(e[k])?.offsetMin == null && core.isValidTz(e.timeZone)) e[k] = withOffset(e[k], e.timeZone);
  }
  return events;
}
function findIcsLinks(html, baseUrl) {
  const out = [];
  for (const m of html.matchAll(/<a\b[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*>/gi)) {
    let href = decodeEntities(m[1] ?? m[2] ?? '').trim();
    if (/^data:text\/calendar/i.test(href)) { out.push({ inline: href }); continue; }
    if (/^webcal:/i.test(href)) href = href.replace(/^webcal:/i, 'https:');
    if (!/\.ics(\?|#|$)|[?&](format|output)=ics\b|\/ical\b/i.test(href)) continue;
    try { const u = new URL(href, baseUrl); if (/^https?:$/.test(u.protocol)) out.push({ url: u.href }); } catch { }
  }
  return out;
}
function decodeDataUri(uri) {
  const m = /^data:[^,]*?(;base64)?,(.*)$/is.exec(uri); if (!m) return '';
  try { return m[1] ? Buffer.from(m[2], 'base64').toString('utf8') : decodeURIComponent(m[2]); } catch { return ''; }
}

// ---------- Google Calendar "add to calendar" links ----------
function parseGoogleCalendar(html) {
  const out = [];
  for (const m of html.matchAll(/(?:href|data-href|content)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)) {
    const raw = decodeEntities(m[1] ?? m[2] ?? '');
    if (!/^https?:\/\/(calendar\.google\.com|www\.google\.com\/calendar)\//i.test(raw) || !/[?&]dates=/i.test(raw)) continue;
    let u; try { u = new URL(raw); } catch { continue; }
    const [a, b] = (u.searchParams.get('dates') || '').split('/');
    const s = compactToIso(a), e = compactToIso(b); if (!s) continue;
    const ctz = u.searchParams.get('ctz') || '';
    const fix = c => c && (c.floating && core.isValidTz(ctz) ? withOffset(c.iso, ctz) : c.iso);
    out.push({ title: u.searchParams.get('text') || '', start: fix(s), end: fix(e) || '', timeZone: ctz, location: u.searchParams.get('location') || '' });
  }
  return out;
}

// ---------- Visible text ----------
const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, sept: 9, oct: 10, nov: 11, dec: 12 };
const MON = '(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sept?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\\.?';
const TIME = '(\\d{1,2})(?:[:.](\\d{2}))?\\s*([ap]\\.?m\\.?)?';
const DATE_RES = [
  new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+${MON},?\\s*(\\d{4})?`, 'i'), // 24 Oct 2024
  new RegExp(`\\b${MON}\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s*(\\d{4})?`, 'i'), // Oct 24, 2024
];
const to24 = (h, ap) => { h = +h; if (!ap) return h; const pm = /^p/i.test(ap); return h === 12 ? (pm ? 12 : 0) : pm ? h + 12 : h; };
function visibleText(html) {
  return decodeEntities(html.replace(/<head[\s\S]*?<\/head>|<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>|<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<\/(p|div|li|h\d|tr|section|header|footer|article|dt|dd)>|<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, ' '))
    .replace(/[ \t\u00a0]+/g, ' ').replace(/\n\s*/g, '\n').trim();
}
function parseTextDate(text, fallbackYear) {
  let best = null;
  for (const [i, re] of DATE_RES.entries()) {
    const m = re.exec(text); if (!m) continue;
    const day = +(i === 0 ? m[1] : m[2]), mon = MONTHS[(i === 0 ? m[2] : m[1]).toLowerCase().slice(0, 3)], year = m[3];
    if (!mon || day < 1 || day > 31) continue;
    if (!best || m.index < best.index) best = { index: m.index, end: m.index + m[0].length, day, mon, year: year ? +year : null };
  }
  if (!best) return null;
  const after = text.slice(best.end, best.end + 80);
  const tm = new RegExp(`^[^\\n\\d]{0,12}?(?:at|@|·|,|-|–|\\|)?\\s*${TIME}(?:\\s*(?:-|–|—|to|until)\\s*${TIME})?(?:\\s*(?:\\(?\\s*(?:GMT|UTC)\\s*([+-]\\d{1,2})(?::?(\\d{2}))?\\)?))?`, 'i').exec(after);
  const year = best.year || fallbackYear;
  const pad = n => String(n).padStart(2, '0');
  const date = `${year}-${pad(best.mon)}-${pad(best.day)}`;
  const detail = best.year ? '' : 'year assumed';
  if (!tm || (!tm[2] && !tm[3])) return { start: date, end: '', detail };
  let sh = to24(tm[1], tm[3]); const sm = +(tm[2] || 0);
  let eh = tm[4] != null ? to24(tm[4], tm[6] || (tm[3] && +tm[4] < +tm[1] ? 'pm' : tm[3])) : null; const em = +(tm[5] || 0);
  if (sh > 23 || sm > 59 || (eh != null && eh > 23)) return { start: date, end: '', detail };
  const off = tm[7] != null ? `${tm[7][0] === '-' ? '-' : '+'}${pad(Math.abs(+tm[7]))}:${pad(+(tm[8] || 0))}` : '';
  return { start: `${date}T${pad(sh)}:${pad(sm)}:00${off}`, end: eh != null ? `${date}T${pad(eh)}:${pad(em)}:00${off}` : '', detail };
}
function splitNames(s) { return s.split(/\s*(?:,|;|\band\b|&|\+|\|)\s*/i).map(x => x.trim()).filter(x => x.length >= 2 && x.length <= 60); }
function parseText(html, fallbackYear) {
  const text = visibleText(html);
  const h1 = /<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(html);
  const title = h1 ? clean(h1[1]) : clean((/<title[^>]*>([\s\S]*?)<\/title>/i.exec(html) || [])[1] || '');
  const d = parseTextDate(text, fallbackYear) || {};
  const att = /(\d[\d,.]*)\s*(k)?\s+(?:people\s+)?(?:going|attending|attendees|registered|rsvps?|participants|joined|signed up)\b/i.exec(text);
  const programs = [], organizers = [];
  for (const m of text.matchAll(/\b(?:sponsored by|in partnership with|presented by|powered by|supported by|in collaboration with|part of)\s*:?\s*([^\n.!?•·|]{2,90})/gi)) programs.push(...splitNames(m[1]));
  for (const m of text.matchAll(/\b(?:hosted by|organi[sz]ed by|organi[sz]er)\s*:?\s*([^\n.!?•·|]{2,90})/gi)) organizers.push(...splitNames(m[1]));
  const venue = /\b(?:venue|location|where)\s*:\s*([^\n]{3,120})/i.exec(text);
  return {
    title, start: d.start || '', end: d.end || '', startDetail: d.detail || '',
    venueName: venue ? venue[1].split(/,\s*/)[0].trim() : '', venueAddress: venue && venue[1].includes(',') ? venue[1].trim() : '',
    organizers, programs,
    attendees: att ? { value: Math.round(parseFloat(att[1].replace(/,/g, '')) * (att[2] ? 1000 : 1)), detail: 'public count in page text' } : null,
    text,
  };
}

// ---------- Merge with provenance ----------
function timeKey(v, tz) {
  const p = core.parseIso(v); if (!p) return null;
  if (p.dateOnly) return 'D' + p.local.slice(0, 10);
  if (p.offsetMin != null) return 'U' + p.utcMs;
  if (core.isValidTz(tz)) return 'U' + core.zonedToUtc(p.local, tz).utcMs;
  return 'L' + p.local.slice(0, 16);
}
function merge(cands) {
  // cands: [{ source, via?, data }] in preference order
  const fields = {}, discrepancies = [];
  const pick = (field, get) => {
    for (const c of cands) {
      const v = get(c.data);
      if (v != null && v !== '' && !(Array.isArray(v) && !v.length)) { fields[field] = { value: v, source: c.source, ...(c.via ? { via: c.via } : {}) }; return; }
    }
  };
  pick('title', d => d.title);
  pick('timeZone', d => d.timeZone);
  const tz = fields.timeZone?.value;
  for (const f of ['start', 'end']) {
    pick(f, d => d[f]);
    if (fields[f]) {
      const p = core.parseIso(fields[f].value);
      if (p && p.offsetMin == null && !p.dateOnly && core.isValidTz(tz)) { fields[f].listed = fields[f].value; fields[f].value = withOffset(fields[f].value, tz); fields[f].note = `listed without an offset; interpreted in ${tz}`; }
      const detailSrc = cands.find(c => c.source === fields[f].source && c.via === fields[f].via);
      if (detailSrc?.data[f + 'Detail']) fields[f].note = detailSrc.data[f + 'Detail'];
    }
    const vals = cands.filter(c => c.data[f] && !(c.source === 'text' && c.data[f + 'Detail'])).map(c => ({ value: c.data[f], source: c.source, via: c.via, key: timeKey(c.data[f], tz) })).filter(v => v.key && !v.key.startsWith('D'));
    if (new Set(vals.map(v => v.key)).size > 1) discrepancies.push({ field: f, values: vals.map(({ key, ...v }) => v) });
  }
  pick('venueName', d => d.venueName);
  pick('venueAddress', d => d.venueAddress || d.location);
  pick('city', d => d.city);
  pick('geo', d => d.geo);
  pick('organizers', d => d.organizers);
  pick('programs', d => d.programs);
  pick('attendees', d => d.attendees?.value);
  if (fields.attendees) fields.attendees.detail = cands.find(c => c.source === fields.attendees.source)?.data.attendees?.detail;
  pick('canonicalUrl', d => d.url);
  return { fields, discrepancies };
}

function extractFromHtml(html, { baseUrl = '', fetchedYear = new Date().getUTCFullYear(), icsText = null, icsVia = '' } = {}) {
  const cands = [];
  for (const j of parseJsonLd(html).slice(0, 1)) cands.push({ source: 'jsonld', data: j });
  const meta = parseMeta(html);
  cands.push({ source: 'meta', via: meta.timeZoneVia || undefined, data: meta });
  const inline = findIcsLinks(html, baseUrl).find(l => l.inline);
  const icsSrc = icsText || (inline ? decodeDataUri(inline.inline) : '');
  if (icsSrc) { const e = parseIcs(icsSrc)[0]; if (e) cands.push({ source: 'ics', via: icsVia || (inline ? 'inline calendar link' : 'calendar file'), data: e }); }
  for (const g of parseGoogleCalendar(html).slice(0, 1)) cands.push({ source: 'ics', via: 'google-calendar link', data: g });
  const yearHint = +((cands.map(c => c.data.start).find(Boolean) || '').slice(0, 4)) || fetchedYear;
  const text = parseText(html, yearHint);
  cands.push({ source: 'text', data: text });
  const r = merge(cands);
  r.loginWall = !r.fields.start && /\b(log ?in|sign ?in|sign up to see|members only|join to view)\b/i.test(text.text.slice(0, 4000));
  return r;
}

async function extractFromUrl(url, opts = {}) {
  if (!/^https?:\/\//i.test(url || '')) throw httpError(400, 'Only http(s) listing URLs can be fetched');
  const page = await fetchFollow(url, opts);
  const out = { url, finalUrl: page.finalUrl, redirects: page.chain, status: page.status, contentType: page.contentType, fetchedAt: new Date().toISOString() };
  let r;
  if (/text\/calendar/i.test(page.contentType) || /^BEGIN:VCALENDAR/m.test(page.body.slice(0, 200))) {
    const e = parseIcs(page.body)[0] || {};
    r = merge([{ source: 'ics', via: 'calendar file', data: e }]);
  } else {
    let icsText = null, icsVia = '';
    const link = findIcsLinks(page.body, page.finalUrl).find(l => l.url);
    if (link) {
      try { const ics = await fetchFollow(link.url, { ...opts, maxBytes: 256000 }); if (/BEGIN:VCALENDAR/.test(ics.body)) { icsText = ics.body; icsVia = `calendar file ${ics.finalUrl}`; } } catch { /* optional */ }
    }
    r = extractFromHtml(page.body, { baseUrl: page.finalUrl, icsText, icsVia });
  }
  if (page.status === 401 || page.status === 403 || /\/(login|signin|sign-in|auth)\b/i.test(new URL(page.finalUrl).pathname)) r.loginWall = true;
  return { ...out, ...r, eventId: { cited: core.eventIdFromUrl(url), final: core.eventIdFromUrl(page.finalUrl) } };
}

module.exports = { extractFromUrl, extractFromHtml, fetchFollow, parseJsonLd, parseMeta, parseIcs, findIcsLinks, parseGoogleCalendar, parseText, parseTextDate, compactToIso, decodeEntities };
