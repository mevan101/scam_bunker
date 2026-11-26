// Scam Bunker — existing fact-check lookup (BACKLOG P1-7).
// Extracts up to three checkable claims from the post text and searches published fact-checks (ClaimReview) through the
// Google Fact Check Tools API (claims:search). Optional: GOOGLE_FACTCHECK_API_KEY (FACTCHECK_API_KEY also accepted).
// Without a key no third-party call is made; the UI links each claim to Google Fact Check Explorer instead.
// Results are leads: a search hit may be a different claim, so the investigator must confirm it is the same one.
const { assertPublicUrl } = require('./net-guard');

const KEY = process.env.GOOGLE_FACTCHECK_API_KEY || process.env.FACTCHECK_API_KEY || '';
const ENDPOINT = 'https://factchecktools.googleapis.com/v1alpha1/claims:search';
const { EXPLORER, extractClaims, toQuery, sentences, caseFileSections } = require('../public/shared/claims');
const CACHE_MS = 6 * 3600 * 1000;
const cache = new Map();

// Claim extraction is shared with the browser (static mode): public/shared/claims.js

// ---------- API response parsing ----------
const httpUrl = u => (/^https?:\/\//i.test(String(u || '')) ? String(u) : null);
const str = (v, n = 300) => (v == null ? '' : String(v).slice(0, n));

function parseClaimSearch(json) {
  if (!json || typeof json !== 'object') return [];
  return (Array.isArray(json.claims) ? json.claims : []).slice(0, 10).map(c => ({
    text: str(c.text, 500),
    claimant: str(c.claimant, 120),
    claimDate: str(c.claimDate, 40),
    reviews: (Array.isArray(c.claimReview) ? c.claimReview : []).map(r => ({
      publisher: str(r.publisher?.name || r.publisher?.site || 'Unknown publisher', 120),
      site: str(r.publisher?.site, 120),
      url: httpUrl(r.url),
      title: str(r.title, 300),
      reviewDate: str(r.reviewDate, 40),
      rating: str(r.textualRating, 120),
      languageCode: str(r.languageCode, 12),
    })).filter(r => r.url),
  })).filter(c => c.reviews.length);
}

function parseApiError(json, status) {
  const e = json && json.error;
  return e ? `Fact Check Tools API: ${str(e.message || e.status, 200)} (HTTP ${e.code || status})` : `Fact Check Tools API HTTP ${status}`;
}

// ---------- Lookup ----------
async function searchClaim(query, { key = KEY, fetchImpl = fetch, guard = assertPublicUrl, languageCode } = {}) {
  const ck = `${languageCode || ''}|${query}`;
  const hit = cache.get(ck); if (hit && Date.now() - hit.at < CACHE_MS) return hit.value;
  const u = new URL(ENDPOINT);
  u.searchParams.set('query', query.slice(0, 200));
  u.searchParams.set('pageSize', '5');
  if (languageCode && /^[a-z]{2}(-[A-Z]{2})?$/.test(languageCode)) u.searchParams.set('languageCode', languageCode);
  await guard(u.href); // fixed Google endpoint, still checked like every outbound fetch
  // Key goes in a header, not the URL, so it never appears in logs or error messages.
  const r = await fetchImpl(u.href, { headers: { 'X-Goog-Api-Key': key, Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(10000) });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(parseApiError(j, r.status));
  const value = parseClaimSearch(j);
  cache.set(ck, { at: Date.now(), value });
  if (cache.size > 500) cache.delete(cache.keys().next().value);
  return value;
}

async function lookup(body = {}, opts = {}) {
  const key = opts.key !== undefined ? opts.key : KEY;
  const claims = extractClaims(String(body.text || '').slice(0, 12000));
  if (!key) return { available: false, service: 'Google Fact Check Explorer (manual)', claims };
  const out = await Promise.all(claims.map(async c => {
    try { return { ...c, matches: await searchClaim(c.query, { ...opts, key, languageCode: body.languageCode }) }; }
    catch (e) { return { ...c, matches: [], error: e.cause?.code ? `Fact Check Tools API unreachable (${e.cause.code})` : e.message }; }
  }));
  return { available: true, service: 'Google Fact Check Tools API', claims: out };
}

// ---------- Case-file sections for the agent team ----------
const routes = { '/api/factcheck': b => lookup(b) };

module.exports = { routes, extractClaims, toQuery, sentences, parseClaimSearch, parseApiError, searchClaim, lookup, caseFileSections, available: () => !!KEY, EXPLORER };
