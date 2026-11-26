// Browser-direct lookups for static mode (GitHub Pages, no /api). Only public, no-key APIs that answer a
// cross-origin browser request with CORS headers (checked with a real browser on an https origin):
//   rdap.org (redirects to the registry's RDAP server; both send Access-Control-Allow-Origin: *)
//   mempool.space /api/address/:a and /txs · TronGrid /v1/accounts/:a and /transactions/trc20
//   archive.org/wayback/available (the CDX API sends no CORS header, so it stays server-only)
// Not possible from a browser: the username sweep (platforms send no CORS headers), fetching arbitrary pages,
// SerpApi (needs a secret key). Those show localAppHtml(). Parsing and lookup flows are the server's own code
// (public/shared/osint-core.js, provenance-core.js), so the results match the local app.
(function (root) {
'use strict';
const isNode = typeof module === 'object' && module.exports;
const core = isNode ? require('./osint-core') : root.ScamBunkerOsintCore;
const pcore = isNode ? require('./provenance-core') : root.ScamBunkerProvenanceCore;
const LOCAL_APP_URL = 'https://github.com/mevan101/scam_bunker#quick-start';
const IMAGE_MAX = 15 * 1024 * 1024;
const host = u => { try { return new URL(u).hostname; } catch { return 'The service'; } };
const sleep = ms => new Promise(r => setTimeout(r, ms));

function create({ fetchImpl = (...a) => root.fetch(...a), rdapMax = 8, rdapWindowMs = 10000, rdapBackoffMs = 30000 } = {}) {
  let rdapCooldownUntil = 0;
  async function request(url, { headers = {}, timeout = 12000 } = {}) {
    try {
      // No cookies, no referrer, only CORS-safelisted headers (no preflight).
      return await fetchImpl(url, { headers, mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(timeout) });
    } catch (e) {
      const msg = e && e.name === 'TimeoutError' ? `${host(url)} timed out` : `${host(url)} could not be reached from the browser (offline, or blocked by an extension or network filter)`;
      throw Object.assign(new Error(msg), { status: 502 });
    }
  }
  // Same contract as the server's getJson: {status, json|null}. No API keys ever leave the browser.
  async function getJson(url, { headers = {}, timeout } = {}) {
    const r = await request(url, { headers: { Accept: 'application/json', ...headers }, timeout });
    let json = null; try { json = await r.json(); } catch { /* not JSON */ }
    if (r.status === 429 && /^https:\/\/rdap\.org\//.test(url)) rdapCooldownUntil = Date.now() + rdapBackoffMs;
    return { status: r.status, json };
  }
  // rdap.org allows ~10 requests / 10 s per client: stay under it, and back off after a 429.
  const rdapLimit = core.rateLimiter(rdapMax, rdapWindowMs);
  const rdapSlot = async () => { const wait = rdapCooldownUntil - Date.now(); if (wait > 0) await sleep(wait); return rdapLimit(); };
  const cached = core.createCache(200);
  const waybackLimit = core.rateLimiter(10, 10000);

  const domain = body => core.domainLookup(body, { getJson, slot: rdapSlot, cached });
  const wallet = body => core.walletLookup(body, { getJson, cached, noKeyNote: 'Ethereum lookups need an Etherscan API key, so they run in the local app only. Open the explorer link instead.' });

  async function wayback(url) {
    try {
      if (!/^https?:\/\//i.test(String(url || ''))) throw new Error('A full http(s) URL is required');
      return await cached('wb:' + url, 30 * 60e3, async () => {
        const ask = async ts => {
          await waybackLimit();
          const r = await getJson(pcore.availabilityUrl(url, ts), { timeout: 20000 });
          if (r.status !== 200 || !r.json) throw new Error(`Wayback Availability API answered HTTP ${r.status}`);
          return r.json;
        };
        const earliest = await ask(pcore.EARLIEST_TS);
        const latest = pcore.closestSnapshot(earliest) ? await ask(null).catch(() => null) : null;
        return pcore.summarizeAvailability(url, earliest, latest);
      });
    } catch (e) { return { ok: false, url, error: e.message }; }
  }

  // Candidate image straight from its host. Works only where the host sends CORS headers (many CDNs and
  // Wikimedia do); otherwise throws code 'local_only'. Same shape as /api/provenance/fetch-image, with a Blob.
  async function image(url) {
    const localOnly = why => Object.assign(new Error(why), { code: 'local_only' });
    if (!/^https?:\/\//i.test(String(url || ''))) throw Object.assign(new Error('A full http(s) URL is required'), { code: 'bad_url' });
    let r;
    try { r = await fetchImpl(url, { mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer', headers: { Accept: 'image/avif,image/webp,image/*;q=0.9,*/*;q=0.1' }, signal: AbortSignal.timeout(15000) }); }
    catch (e) { throw localOnly(e && e.name === 'TimeoutError' ? `${host(url)} timed out` : `${host(url)} does not allow other websites to load this file (no CORS headers)`); }
    if (!r.ok) throw localOnly(`${host(url)} answered HTTP ${r.status}`);
    const type = (r.headers.get('content-type') || '').split(';')[0].trim();
    if (!/^image\//.test(type)) throw localOnly(/html|xml/.test(type) ? 'This is a web page. Reading its preview image and publish date needs the local app' : `Not an image (${type || 'unknown type'})`);
    const blob = await r.blob();
    if (blob.size > IMAGE_MAX) throw localOnly('The image is larger than 15 MB');
    return { url, finalUrl: r.url || url, redirects: [], contentType: type, size: blob.size, lastModified: pcore.httpDate(r.headers.get('last-modified')), archiveOrigLastModified: null, blob, direct: true };
  }

  return { getJson, domain, wallet, wayback, image };
}

// The designed "needs the local app" state. `esc` is ScamBunker.esc; `what` names the feature.
function localAppHtml(esc, what, detail) {
  return `<div class="callout handoff sb-local-only" role="note"><div><b>${esc(what)}: available in the local app</b> ${esc(detail || '')} It runs on your own computer in a minute, with no dependencies to install.</div><a class="primary sm" style="color:var(--on-btn);text-decoration:none" href="${LOCAL_APP_URL}" target="_blank" rel="noopener">Quick start ↗</a></div>`;
}

const api = { LOCAL_APP_URL, create, localAppHtml };
if (typeof window !== 'undefined' && typeof window.fetch === 'function') Object.assign(api, create());
if (isNode) module.exports = api;
else root.ScamBunkerDirect = api;
})(typeof window !== 'undefined' ? window : globalThis);
