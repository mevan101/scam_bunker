// Image provenance / original-source endpoints. Zero dependencies.
//   POST /api/provenance/fetch-image {url}              → candidate image bytes for in-browser forensics + hashing
//   POST /api/provenance/wayback     {url}              → Wayback Machine CDX: first/last seen, captures, snapshot
//   POST /api/provenance/page-date   {url}              → publish date + og:image of a page that shows the image
//   POST /api/provenance/reverse     {imageUrl|dataBase64} → automatic reverse search (SerpApi Google Lens) if SERPAPI_API_KEY
const { guardedRequest, assertPublicUrl, httpError } = require('./net-guard');

const SERPAPI_KEY = process.env.SERPAPI_API_KEY || '';
const IMAGE_MAX = 15 * 1024 * 1024;
const CDX = 'https://web.archive.org/cdx/search/cdx';
const CDX_LIMIT = 5000;

function requireUrl(u) {
  if (typeof u !== 'string' || u.length > 4096 || !/^https?:\/\//i.test(u)) throw httpError(400, 'A full http(s) URL is required', 'bad_url');
  try { return new URL(u).href; } catch { throw httpError(400, 'Invalid URL', 'bad_url'); }
}
const httpDate = v => { const t = Date.parse(v || ''); return isNaN(t) ? null : new Date(t).toISOString(); };

// ---------- fetch-image ----------
async function fetchImage(body, opts = {}) {
  const url = requireUrl(body && body.url);
  const r = await guardedRequest(url, { maxBytes: IMAGE_MAX, timeoutMs: 15000, accept: /^image\//, headers: { Accept: 'image/avif,image/webp,image/*;q=0.9,*/*;q=0.1' }, ...opts });
  return {
    url, finalUrl: r.finalUrl, redirects: r.redirects, contentType: r.contentType.split(';')[0], size: r.buffer.length,
    lastModified: httpDate(r.headers['last-modified']),
    // Wayback raw-image snapshots replay the original server's header here
    archiveOrigLastModified: httpDate(r.headers['x-archive-orig-last-modified']),
    dataBase64: r.buffer.toString('base64'),
  };
}

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

async function cdxQuery(params, fetchImpl) {
  const qs = new URLSearchParams({ output: 'json', fl: 'timestamp,original,statuscode,mimetype,digest', ...params });
  const r = await fetchImpl(`${CDX}?${qs}`, { headers: { 'User-Agent': 'ScamBunkerProvenance/1.0' }, signal: AbortSignal.timeout(20000) });
  const text = await r.text();
  if (!r.ok) throw new Error(`Wayback CDX answered HTTP ${r.status}${/blocked/i.test(text) ? ' (site excluded from the archive)' : ''}`);
  if (!text.trim()) return [];
  let json; try { json = JSON.parse(text); } catch { throw new Error('Wayback CDX returned an unreadable response'); }
  return parseCdx(json);
}

async function wayback(body, { fetchImpl = fetch } = {}) {
  const url = requireUrl(body && body.url);
  try {
    const rows = await cdxQuery({ url, limit: String(CDX_LIMIT) }, fetchImpl); // default order is ascending → rows[0] = earliest
    const capped = rows.length >= CDX_LIMIT;
    const latest = capped ? await cdxQuery({ url, limit: '-1', fastLatest: 'true' }, fetchImpl).catch(() => []) : [];
    return summarizeWayback(url, rows, latest, capped);
  } catch (e) {
    return { ok: false, url, error: e.cause?.code ? `Wayback Machine unreachable (${e.cause.code})` : e.name === 'TimeoutError' ? 'Wayback Machine timed out' : e.message };
  }
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

async function pageDate(body, opts = {}) {
  const url = requireUrl(body && body.url);
  const r = await guardedRequest(url, { maxBytes: 2 * 1024 * 1024, truncate: true, timeoutMs: 15000, accept: /html|xml/, headers: { Accept: 'text/html,application/xhtml+xml' }, ...opts });
  const d = extractPageDates(r.buffer.toString('utf8'));
  let ogImage = null; try { ogImage = d.ogImage ? new URL(d.ogImage, r.finalUrl).href : null; } catch { }
  return { url, finalUrl: r.finalUrl, lastModified: httpDate(r.headers['last-modified']), ...d, ogImage };
}

// ---------- Reverse image search (optional, SerpApi) ----------
function mapLens(j) {
  const rows = [...(j.exact_matches || []), ...(j.visual_matches || [])];
  const seen = new Set();
  return rows.filter(m => m && m.link && !seen.has(m.link) && seen.add(m.link)).slice(0, 40)
    .map(m => ({ title: m.title || '', link: m.link, source: m.source || '', thumbnail: m.thumbnail || null, imageUrl: m.image || m.original || null, date: m.date || null }));
}
async function reverse(body, { fetchImpl = fetch } = {}) {
  if (!SERPAPI_KEY) return { available: false };
  const { imageUrl, dataBase64 } = body || {};
  if (!imageUrl) {
    return { available: true, ok: false, reason: dataBase64 ? 'Google Lens through SerpApi needs a public image URL. Scam Bunker does not upload your file to a third-party host on its own: search it manually, or give the URL where the image is published.' : 'imageUrl is required' };
  }
  const url = requireUrl(imageUrl);
  await assertPublicUrl(url);
  try {
    const qs = new URLSearchParams({ engine: 'google_lens', url, api_key: SERPAPI_KEY });
    const r = await fetchImpl(`https://serpapi.com/search.json?${qs}`, { signal: AbortSignal.timeout(30000) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.error) return { available: true, ok: false, reason: j.error || `SerpApi HTTP ${r.status}` };
    return { available: true, ok: true, engine: 'google_lens', results: mapLens(j) };
  } catch (e) {
    return { available: true, ok: false, reason: e.cause?.code ? `SerpApi unreachable (${e.cause.code})` : e.message };
  }
}

const routes = {
  '/api/provenance/fetch-image': b => fetchImage(b),
  '/api/provenance/wayback': b => wayback(b),
  '/api/provenance/page-date': b => pageDate(b),
  '/api/provenance/reverse': b => reverse(b),
};

module.exports = { routes, fetchImage, wayback, pageDate, reverse, parseCdx, summarizeWayback, tsToIso, extractPageDates, mapLens, reverseAvailable: () => !!SERPAPI_KEY };
