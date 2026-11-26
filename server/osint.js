// Scam Bunker: subject investigation (OSINT) endpoints. Zero dependencies.
// Public profiles and public ledgers only. No people-search, address, phone-owner or family lookups.
//   POST /api/osint/username {username, stream?}  exact-username sweep across data/sites.json
//   POST /api/osint/domain   {domain}             RDAP registration data (age, registrar, status, nameservers)
//   POST /api/osint/wallet   {chain, address}     public ledger summary (BTC: mempool.space, TRON: TronGrid, ETH: Etherscan with key)
const fs = require('fs');
const path = require('path');
const { assertPublicUrl } = require('./net-guard');

const UA = 'Mozilla/5.0 (compatible; ScamBunker/0.1; open-source scam investigation tool)';
const SITE_TIMEOUT = 8000;
const CONCURRENCY = 8;
const MAX_BODY = 256 * 1024;
const ETHERSCAN_KEY = process.env.ETHERSCAN_API_KEY || '';
const TRONSCAN_KEY = process.env.TRONSCAN_API_KEY || ''; // optional fallback only
const TRONGRID_KEY = process.env.TRONGRID_API_KEY || ''; // optional, raises TronGrid rate limits

const SITES_FILE = path.join(__dirname, '..', 'data', 'sites.json');
let SITES = null;
const sites = () => (SITES ||= JSON.parse(fs.readFileSync(SITES_FILE, 'utf8')).sites);

// Validation, parsers, rate limiter, cache and the domain/wallet lookup flows are shared with the browser
// (static mode on GitHub Pages) so both return the same results: public/shared/osint-core.js.
const core = require('../public/shared/osint-core');
const { bad, USERNAME_RE, validateUsername, validateDomain, WALLET_RE, normalizeChain, parseRdap, domainCandidates, parseMempoolAddress, parseMempoolTxs, parseTronscan, parseTrongridAccount, parseTrc20Transfers, rateLimiter } = core;

// ---------- Guarded fetch: SSRF check on every hop, manual redirects, capped body ----------
async function guardedFetch(url, { timeout = SITE_TIMEOUT, maxRedirects = 5, headers = {}, signal } = {}) {
  const sig = signal || AbortSignal.timeout(timeout);
  const redirects = [];
  let cur = url;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    await assertPublicUrl(cur);
    const r = await fetch(cur, { redirect: 'manual', signal: sig, headers: { 'User-Agent': UA, 'Accept-Language': 'en', ...headers } });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) {
      redirects.push({ url: cur, status: r.status });
      try { await r.body?.cancel(); } catch { /* ignore */ }
      cur = new URL(loc, cur).href;
      continue;
    }
    return { status: r.status, finalUrl: cur, redirects, body: await readCapped(r), headers: r.headers };
  }
  return { status: 310, finalUrl: cur, redirects, body: '', tooManyRedirects: true };
}
async function readCapped(r, max = MAX_BODY) {
  if (!r.body) return '';
  const reader = r.body.getReader(); const chunks = []; let n = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value); n += value.length;
      if (n >= max) { await reader.cancel(); break; }
    }
  } catch { /* partial body is fine */ }
  return Buffer.concat(chunks.map(c => Buffer.from(c))).toString('utf8');
}

// ---------- Username sweep ----------
const BOT_WALL = /captcha|client challenge|checking your browser|<title>\s*(access denied|security check)|cf-chl|cf_chl|challenge-platform|just a moment\.\.\.|attention required|px-captcha|perimeterx|datadome|verify you are (a )?human|are you a robot|unusual traffic/i;
const LOGIN_WALL = /\/(login|signin|sign-in|accounts\/login|auth|checkpoint|consent)\b|consent\.(youtube|google)\.com/i;
const fill = (s, username) => String(s).replace(/\{username\}/g, username);

// Pure classification of one probe response. Returns {status, note?}. Never guesses: anything inconclusive is 'unknown'.
function classify(site, resp, username) {
  const code = resp.status;
  const body = resp.body || '';
  const lower = body.toLowerCase();
  const ok = site.okMsg && lower.includes(fill(site.okMsg, username).toLowerCase());
  const err = site.errorMsg && lower.includes(fill(site.errorMsg, username).toLowerCase());
  if ([401, 403, 429, 999].includes(code)) return { status: 'blocked', note: `HTTP ${code}: the platform refused an anonymous check` };
  if (code >= 500) return { status: code === 503 && BOT_WALL.test(body) ? 'blocked' : 'unknown', note: `HTTP ${code}` };
  if (resp.tooManyRedirects) return { status: 'unknown', note: 'Redirect loop' };
  const movedTo = resp.redirects?.length ? resp.finalUrl : null;
  if (movedTo && LOGIN_WALL.test(new URL(movedTo).pathname + ' ' + new URL(movedTo).hostname)) return { status: 'unknown', note: 'Redirected to a login or consent page' };

  if (site.checkType === 'message') {
    if (ok) return { status: 'found' };
    if (err) return { status: 'not_found' };
    if (code === 404 || code === 410) return { status: 'not_found' };
    if (BOT_WALL.test(body)) return { status: 'blocked', note: 'Bot-check page' };
    if (code >= 200 && code < 300) {
      if (!site.okMsg && site.errorMsg) return { status: 'found' }; // only an error string defined, and it's absent
      if (site.okMsg && site.absentOkMeansNotFound) return { status: 'not_found' };
    }
    return { status: 'unknown', note: 'Page did not match the expected found / not-found text' };
  }
  if (site.checkType === 'redirect') {
    if (code === 404 || code === 410) return { status: 'not_found' };
    if (BOT_WALL.test(body) && code !== 200) return { status: 'blocked', note: 'Bot-check page' };
    if (movedTo && !new URL(movedTo).pathname.toLowerCase().includes(username.toLowerCase())) return { status: 'not_found', note: 'Redirected away from the profile URL' };
    if (code >= 200 && code < 300) return BOT_WALL.test(body) ? { status: 'blocked', note: 'Bot-check page' } : { status: 'found' };
    return { status: 'unknown', note: `HTTP ${code}` };
  }
  // status
  if (code === 404 || code === 410 || (site.notFoundStatus || []).includes(code)) return { status: 'not_found' };
  if (code >= 200 && code < 300) {
    if (BOT_WALL.test(body) && !lower.includes(username.toLowerCase())) return { status: 'blocked', note: 'Bot-check page' };
    if (err) return { status: 'not_found' };
    return { status: 'found' };
  }
  return { status: 'unknown', note: `HTTP ${code}` };
}

async function checkSite(site, username, fetcher = guardedFetch) {
  const url = fill(site.url, username);
  const base = { site: site.name, category: site.category, url, httpStatus: null, ms: 0 };
  if (site.regex && !new RegExp(site.regex).test(username)) return { ...base, status: 'not_found', note: 'Not a valid username format on this platform' };
  if (site.probe === false) return { ...base, status: 'unknown', note: site.notes || 'This platform cannot be checked anonymously. Open the link to verify.' };
  const t0 = Date.now();
  try {
    const resp = await fetcher(fill(site.probeUrl || site.url, username), { timeout: SITE_TIMEOUT, headers: { Accept: site.probeUrl ? 'application/json, text/plain, */*' : 'text/html,application/xhtml+xml,*/*;q=0.8' } });
    const c = classify(site, resp, username);
    return { ...base, status: c.status, httpStatus: resp.status, ms: Date.now() - t0, ...(c.note ? { note: c.note } : {}) };
  } catch (e) {
    const timedOut = e.name === 'TimeoutError' || e.name === 'AbortError';
    return { ...base, status: 'unknown', ms: Date.now() - t0, note: timedOut ? `No answer within ${SITE_TIMEOUT / 1000}s` : `Network error: ${e.cause?.code || e.message}` };
  }
}

// Runs fn over items with at most n in flight; calls onResult as each finishes.
async function pool(items, n, fn, onResult) {
  const out = new Array(items.length); let next = 0;
  const worker = async () => { while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); onResult?.(out[i], i); } };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
}
const summarize = results => results.reduce((a, r) => (a[r.status] = (a[r.status] || 0) + 1, a), { found: 0, not_found: 0, unknown: 0, blocked: 0 });

async function handleUsername(body, res, send) {
  const username = validateUsername(body.username);
  if (!username) throw bad('Username must be 2-40 characters: letters, digits, dot, underscore or hyphen');
  const list = sites();
  if (!body.stream) {
    const results = await pool(list, CONCURRENCY, s => checkSite(s, username));
    return send(res, 200, { username, checked: results.length, summary: summarize(results), results });
  }
  // NDJSON stream so the UI can fill the grid live
  res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-store' });
  let closed = false; res.on('close', () => { closed = true; });
  const line = o => { if (!closed) res.write(JSON.stringify(o) + '\n'); };
  line({ type: 'start', username, sites: list.map(s => ({ site: s.name, category: s.category, url: fill(s.url, username) })) });
  const results = await pool(list, CONCURRENCY, s => closed ? { site: s.name, status: 'unknown', note: 'cancelled' } : checkSite(s, username), r => line({ type: 'result', ...r }));
  line({ type: 'done', summary: summarize(results) });
  res.end();
}

// ---------- RDAP + wallets (flows in public/shared/osint-core.js; this file supplies the guarded transport) ----------
const cached = core.createCache(500);
const rdapSlot = rateLimiter(8, 10000);
async function getJson(url, opts = {}) {
  const r = await guardedFetch(url, { timeout: 12000, maxRedirects: 3, ...opts, headers: { Accept: 'application/json', ...(opts.headers || {}) } });
  let json = null; try { json = JSON.parse(r.body); } catch { /* not JSON */ }
  return { status: r.status, json };
}

async function handleDomain(body, res, send) {
  send(res, 200, await core.domainLookup(body, { getJson, slot: rdapSlot, cached }));
}
async function handleWallet(body, res, send) {
  send(res, 200, await core.walletLookup(body, { getJson, cached, keys: { trongrid: TRONGRID_KEY, tronscan: TRONSCAN_KEY, etherscan: ETHERSCAN_KEY } }));
}

const routes = { '/api/osint/username': handleUsername, '/api/osint/domain': handleDomain, '/api/osint/wallet': handleWallet };

module.exports = { routes, validateUsername, validateDomain, normalizeChain, classify, checkSite, pool, parseRdap, domainCandidates, parseMempoolAddress, parseMempoolTxs, parseTronscan, parseTrongridAccount, parseTrc20Transfers, rateLimiter, sites, USERNAME_RE, WALLET_RE };
