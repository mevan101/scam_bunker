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
// Parsers shared with the browser (static mode): public/shared/provenance-core.js
const { httpDate, parseCdx, tsToIso, summarizeWayback, extractPageDates, mapLens } = require('../public/shared/provenance-core');

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
async function pageDate(body, opts = {}) {
  const url = requireUrl(body && body.url);
  const r = await guardedRequest(url, { maxBytes: 2 * 1024 * 1024, truncate: true, timeoutMs: 15000, accept: /html|xml/, headers: { Accept: 'text/html,application/xhtml+xml' }, ...opts });
  const d = extractPageDates(r.buffer.toString('utf8'));
  let ogImage = null; try { ogImage = d.ogImage ? new URL(d.ogImage, r.finalUrl).href : null; } catch { }
  return { url, finalUrl: r.finalUrl, lastModified: httpDate(r.headers['last-modified']), ...d, ogImage };
}

// ---------- Reverse image search (optional, SerpApi) ----------
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
