'use strict';
// Corroboration lookups (docs/BACKLOG.md ii-3, ii-7, ii-9). Parsers and validation live in public/shared/corroborate-core.js
// (also used by the browser in static mode). Every fetch goes through guardedRequest
// (assertPublicUrl-equivalent DNS check at connect time, re-checked on each redirect), with timeouts and caching.
// Results are leads: each one carries an honest strength and its limitation.
const { guardedRequest, httpError } = require('./net-guard');

const UA = 'ScamBunker/0.1 (+https://github.com/mevan101/scam_bunker)';
const HOUR = 3600e3, DAY = 24 * HOUR;

function makeCache(ttlMs, max = 500) {
  const m = new Map();
  return {
    get(k) { const e = m.get(k); if (!e) return; if (Date.now() - e.t > ttlMs) { m.delete(k); return; } return e.v; },
    set(k, v) { if (m.size >= max) m.delete(m.keys().next().value); m.set(k, { t: Date.now(), v }); return v; },
    clear() { m.clear(); },
  };
}
const caches = { crt: makeCache(DAY), weather: makeCache(7 * DAY) };

let request = guardedRequest; // swapped in tests
function _setRequest(fn) { request = fn || guardedRequest; caches.crt.clear(); caches.weather.clear(); scamList = null; scamLoading = null; }

async function getJson(url, opts) {
  const r = await request(url, { headers: { 'user-agent': UA, accept: 'application/json' }, ...opts });
  if (r.status < 200 || r.status >= 300) throw httpError(502, `Upstream returned HTTP ${r.status}`, 'upstream');
  try { return JSON.parse(r.buffer.toString('utf8')); } catch { throw httpError(502, 'Upstream returned invalid JSON', 'upstream'); }
}

const core = require('../public/shared/corroborate-core');
const { normalizeDomain, summarizeCrt, summarizeWeather, checkClaim, matchDomain, wmoText, SCAMSNIFFER_URL } = core;

// ---------- ii-3 crt.sh certificate transparency ----------
async function crtsh(body = {}) {
  const domain = normalizeDomain(body.domain);
  const hit = caches.crt.get(domain);
  if (hit) return { ...hit, cached: true };
  let records;
  try { records = await getJson(core.crtUrl(domain), { timeoutMs: 20000, maxBytes: 25 * 1024 * 1024 }); }
  catch (e) {
    if (e.status === 400) throw e;
    throw httpError(504, 'crt.sh is slow or unavailable right now (it often times out); try again later.', 'upstream');
  }
  return caches.crt.set(domain, core.crtResult(records, domain));
}

// ---------- ii-7 Open-Meteo historical weather ----------
async function weather(body = {}) {
  const p = core.parseWeatherInput(body);
  const key = core.weatherKey(p);
  let j = caches.weather.get(key);
  const cached = !!j;
  if (!j) {
    try { j = await getJson(core.weatherUrl(p), { timeoutMs: 15000, maxBytes: 2 * 1024 * 1024 }); }
    catch { throw httpError(504, 'Open-Meteo is unavailable right now; try again later.', 'upstream'); }
    const bad = core.weatherApiError(j); if (bad) throw bad;
    caches.weather.set(key, j);
  }
  return core.weatherResult(p, j, cached);
}

// ---------- ii-9 ScamSniffer phishing-domain list (GPL-3.0, fetched at runtime, never vendored) ----------
const SCAM_TTL = 6 * HOUR;
let scamList = null, scamLoading = null;

async function loadScamList() {
  if (scamList && Date.now() - scamList.t < SCAM_TTL) return scamList;
  if (!scamLoading) {
    scamLoading = getJson(SCAMSNIFFER_URL, { timeoutMs: 30000, maxBytes: 40 * 1024 * 1024 })
      .then(arr => (scamList = { t: Date.now(), set: core.scamSet(arr) }))
      .finally(() => { scamLoading = null; });
  }
  try { return await scamLoading; }
  catch (e) { if (scamList) return scamList; throw httpError(504, 'Could not download the ScamSniffer list right now.', 'upstream'); }
}

async function scamsniffer(body = {}) {
  const domains = core.scamDomains(body);
  return core.scamResult(domains, await loadScamList());
}

const routes = {
  '/api/corroborate/crtsh': b => crtsh(b),
  '/api/corroborate/weather': b => weather(b),
  '/api/corroborate/scamsniffer': b => scamsniffer(b),
};

module.exports = { routes, crtsh, weather, scamsniffer, normalizeDomain, summarizeCrt, summarizeWeather, checkClaim, matchDomain, wmoText, _setRequest, SCAMSNIFFER_URL };
