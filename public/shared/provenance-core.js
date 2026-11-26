// Shared between the Node server (server/provenance.js) and the browser (static mode, public/provenance.js).
// Wayback CDX parsing/summary, the Wayback Availability API summary used in the browser (CDX sends no CORS
// headers, the Availability API does), page publish-date extraction and the Google Lens result mapper. UMD.
(function (root) {
'use strict';
const httpDate = v => { const t = Date.parse(v || ''); return isNaN(t) ? null : new Date(t).toISOString(); };

// ---------- Wayback CDX ----------
// CDX JSON output is an array of rows; row 0 is the field-name header.
function parseCdx(json) {
  if (!Array.isArray(json) || json.length < 2 || !Array.isArray(json[0])) return [];
  const head = json[0];
  return json.slice(1).filter(Array.isArray).map(row => Object.fromEntries(head.map((h, i) => [h, row[i]])));
}
// 14-digit Wayback timestamp (yyyyMMddhhmmss, may be truncated) → ISO 8601 UTC
function tsToIso(ts) {
  const s = String(ts || '');
  if (!/^\d{4,14}$/.test(s)) return null;
  const p = s + '00000101000000'.slice(s.length); // missing month/day default to 01, missing time to 00
  return `${p.slice(0, 4)}-${p.slice(4, 6)}-${p.slice(6, 8)}T${p.slice(8, 10)}:${p.slice(10, 12)}:${p.slice(12, 14)}Z`;
}
const snapshot = (ts, original, raw) => `https://web.archive.org/web/${ts}${raw ? 'im_' : ''}/${original}`;
const isOk = r => /^2\d\d$/.test(String(r.statuscode));

function summarizeWayback(url, rows, latestRows = [], capped = false) {
  if (!rows.length) return { ok: true, url, captures: 0, firstSeen: null, lastSeen: null, saveUrl: `https://web.archive.org/save/${url}`, note: 'Not in the Wayback Machine' };
  const first = rows.find(isOk) || rows[0];
  const pool = capped && latestRows.length ? latestRows : rows;
  const last = [...pool].reverse().find(isOk) || pool[pool.length - 1];
  const digests = new Set(rows.filter(isOk).map(r => r.digest).filter(Boolean));
  const isImage = /^image\//.test(first.mimetype || '');
  return {
    ok: true, url, captures: rows.length, capturesCapped: capped,
    firstSeen: tsToIso(first.timestamp), firstTimestamp: first.timestamp, firstStatus: first.statuscode, firstMime: first.mimetype,
    firstSnapshot: snapshot(first.timestamp, first.original), firstRaw: isImage ? snapshot(first.timestamp, first.original, true) : null,
    firstDigest: first.digest || null,
    firstAnyCapture: tsToIso(rows[0].timestamp), // may be a redirect / error capture
    lastSeen: tsToIso(last.timestamp), lastSnapshot: snapshot(last.timestamp, last.original),
    distinctDigests: digests.size, // >1 for an image URL: the file served at this URL changed over time
    mimetypes: [...new Set(rows.map(r => r.mimetype).filter(Boolean))].slice(0, 5),
  };
}

// ---------- Wayback Availability API (browser) ----------
// https://archive.org/wayback/available?url=<u>&timestamp=<ts> returns the single capture closest to <ts>.
// Asking for 1990 gives the earliest capture, asking without a timestamp gives the latest. It cannot count
// captures or tell file versions apart, so the summary says so (captures: null, approximate: true).
const AVAILABILITY = 'https://archive.org/wayback/available';
const EARLIEST_TS = '19900101';
const availabilityUrl = (url, timestamp) => `${AVAILABILITY}?${new URLSearchParams(timestamp ? { url, timestamp } : { url })}`;
function closestSnapshot(j) {
  const c = j && j.archived_snapshots && j.archived_snapshots.closest;
  return c && c.available !== false && /^\d{4,14}$/.test(String(c.timestamp || '')) ? c : null;
}
function summarizeAvailability(url, earliestJson, latestJson) {
  const first = closestSnapshot(earliestJson), last = closestSnapshot(latestJson) || first;
  if (!first) return { ok: true, url, captures: 0, firstSeen: null, lastSeen: null, saveUrl: `https://web.archive.org/save/${url}`, note: 'Not in the Wayback Machine', source: 'wayback-availability' };
  return {
    ok: true, url, captures: null, approximate: true, source: 'wayback-availability',
    firstSeen: tsToIso(first.timestamp), firstTimestamp: String(first.timestamp), firstStatus: first.status || null,
    firstSnapshot: snapshot(first.timestamp, url), firstRaw: null,
    lastSeen: tsToIso(last.timestamp), lastSnapshot: snapshot(last.timestamp, url),
    note: 'Earliest and latest capture from the Wayback Availability API. Capture counts and file-version changes need the local app (CDX API).',
  };
}

// ---------- Page publish date ----------
const DATE_META = ['article:published_time', 'og:published_time', 'og:article:published_time', 'datepublished', 'date', 'dc.date', 'dc.date.issued', 'dcterms.created', 'pubdate', 'publishdate', 'publish-date', 'parsely-pub-date', 'sailthru.date', 'article.published', 'cxenseparse:recs:publishtime', 'datecreated'];
function extractPageDates(html) {
  html = String(html || '').slice(0, 3e6);
  const found = [];
  const push = (source, value) => { const iso = httpDate(value) || (/^\d{4}-\d{2}-\d{2}/.test(value) ? httpDate(value.slice(0, 10)) : null); if (iso && +iso.slice(0, 4) >= 1990) found.push({ source, value: String(value).trim().slice(0, 64), iso }); };
  const meta = {};
  for (const tag of html.matchAll(/<meta\b[^>]*>/gi)) {
    const t = tag[0];
    const key = (/(?:property|name|itemprop)\s*=\s*["']([^"']+)["']/i.exec(t) || [])[1];
    const val = (/content\s*=\s*["']([^"']*)["']/i.exec(t) || [])[1];
    if (!key || val == null) continue;
    const k = key.toLowerCase(); if (!(k in meta)) meta[k] = val;
    if (DATE_META.includes(k)) push(`meta ${key}`, val);
  }
  for (const m of html.matchAll(/"datePublished"\s*:\s*"([^"]+)"/g)) push('JSON-LD datePublished', m[1]);
  for (const m of html.matchAll(/"(?:uploadDate|dateCreated)"\s*:\s*"([^"]+)"/g)) push('JSON-LD uploadDate/dateCreated', m[1]);
  const time = /<time\b[^>]*datetime\s*=\s*["']([^"']+)["']/i.exec(html); if (time) push('<time datetime>', time[1]);
  const modified = httpDate(meta['article:modified_time'] || meta['og:updated_time'] || (/"dateModified"\s*:\s*"([^"]+)"/.exec(html) || [])[1]);
  found.sort((a, b) => a.iso.localeCompare(b.iso));
  const title = (/<title[^>]*>([^<]*)<\/title>/i.exec(html) || [])[1];
  return { published: found[0] || null, candidates: found.slice(0, 8), modified, ogImage: meta['og:image'] || meta['og:image:url'] || meta['twitter:image'] || meta['twitter:image:src'] || null, title: title ? title.trim().slice(0, 200) : meta['og:title'] || null };
}

// ---------- Reverse image search results (SerpApi Google Lens) ----------
function mapLens(j) {
  const rows = [...(j.exact_matches || []), ...(j.visual_matches || [])];
  const seen = new Set();
  return rows.filter(m => m && m.link && !seen.has(m.link) && seen.add(m.link)).slice(0, 40)
    .map(m => ({ title: m.title || '', link: m.link, source: m.source || '', thumbnail: m.thumbnail || null, imageUrl: m.image || m.original || null, date: m.date || null }));
}

const api = { httpDate, parseCdx, tsToIso, snapshot, isOk, summarizeWayback, AVAILABILITY, EARLIEST_TS, availabilityUrl, closestSnapshot, summarizeAvailability, DATE_META, extractPageDates, mapLens };
if (typeof module === 'object' && module.exports) module.exports = api;
else root.ScamBunkerProvenanceCore = api;
})(typeof window !== 'undefined' ? window : globalThis);
