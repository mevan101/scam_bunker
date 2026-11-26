// Scam Bunker: subject investigation (OSINT) endpoints. Zero dependencies.
// Public profiles and public ledgers only. No people-search, address, phone-owner or family lookups.
//   POST /api/osint/username {username, stream?}  exact-username sweep across data/sites.json
//   POST /api/osint/domain   {domain}             RDAP registration data (age, registrar, status, nameservers)
//   POST /api/osint/wallet   {chain, address}     public ledger summary (BTC: mempool.space, TRON: TronGrid, ETH: Etherscan with key)
const fs = require('fs');
const path = require('path');
const { guardedRequest } = require('./net-guard');

const UA = 'Mozilla/5.0 (compatible; ScamBunker/0.1; open-source scam investigation tool)';
const SITE_TIMEOUT = 8000;
const CONCURRENCY = 8;
const MAX_BODY = 256 * 1024;
const YOUNG_DOMAIN_DAYS = 90;
const ETHERSCAN_KEY = process.env.ETHERSCAN_API_KEY || '';
const TRONSCAN_KEY = process.env.TRONSCAN_API_KEY || ''; // optional fallback only
const TRONGRID_KEY = process.env.TRONGRID_API_KEY || ''; // optional, raises TronGrid rate limits

const SITES_FILE = path.join(__dirname, '..', 'data', 'sites.json');
let SITES = null;
const sites = () => (SITES ||= JSON.parse(fs.readFileSync(SITES_FILE, 'utf8')).sites);

const bad = (m, status = 400) => Object.assign(new Error(m), { status });

// ---------- Validation ----------
const USERNAME_RE = /^[A-Za-z0-9._-]{2,40}$/;
function validateUsername(u) {
  const s = String(u ?? '').trim().replace(/^[@$]/, '');
  return USERNAME_RE.test(s) ? s : null;
}
const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
function validateDomain(d) {
  let s = String(d ?? '').trim().toLowerCase();
  if (!s || s.length > 300) return null;
  try { s = new URL(/^[a-z][a-z0-9+.-]*:\/\//.test(s) ? s : 'http://' + s).hostname; } catch { return null; } // also punycodes IDNs
  s = s.replace(/^www\./, '').replace(/\.$/, '');
  return DOMAIN_RE.test(s) ? s : null;
}
const WALLET_RE = { btc: /^(bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/, tron: /^T[1-9A-HJ-NP-Za-km-z]{33}$/, eth: /^0x[a-fA-F0-9]{40}$/ };
function normalizeChain(c, address = '') {
  const s = String(c ?? '').toLowerCase();
  if (/btc|bitcoin/.test(s)) return 'btc';
  if (/tron|trx|trc/.test(s)) return 'tron';
  if (/eth|evm|erc/.test(s)) return 'eth';
  // infer from the address when no chain was given
  return Object.keys(WALLET_RE).find(k => WALLET_RE[k].test(address)) || null;
}
const EXPLORER = { btc: a => `https://mempool.space/address/${a}`, tron: a => `https://tronscan.org/#/address/${a}`, eth: a => `https://etherscan.io/address/${a}` };

// ---------- Guarded fetch: connect-time address check on every hop, manual redirects, capped body ----------
// guardedRequest checks the address each socket actually connects to, so a DNS-rebinding answer cannot slip past.
async function guardedFetch(url, { timeout = SITE_TIMEOUT, maxRedirects = 5, headers = {}, maxBytes = MAX_BODY, isBlocked, resolve } = {}) {
  const deadline = Date.now() + timeout;
  const redirects = [];
  let cur = url;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const r = await guardedRequest(cur, { followRedirects: false, anyStatus: true, decompress: true, truncate: true, maxBytes, timeoutMs: Math.max(1, deadline - Date.now()),
      headers: { 'User-Agent': UA, 'Accept-Language': 'en', ...headers }, ...(isBlocked ? { isBlocked } : {}), ...(resolve ? { resolve } : {}) });
    const hdrs = { get: k => { const v = r.headers[String(k).toLowerCase()]; return Array.isArray(v) ? v.join(', ') : v ?? null; } };
    if (r.status >= 300 && r.status < 400 && r.location) {
      redirects.push({ url: cur, status: r.status });
      cur = new URL(r.location, cur).href;
      continue;
    }
    return { status: r.status, finalUrl: cur, redirects, body: r.buffer.toString('utf8'), headers: hdrs };
  }
  return { status: 310, finalUrl: cur, redirects, body: '', tooManyRedirects: true };
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
    const timedOut = e.code === 'timeout' || e.name === 'TimeoutError' || e.name === 'AbortError';
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

// ---------- RDAP ----------
const iso = t => { if (t == null || t === '') return null; const d = new Date(t); return isNaN(d) ? null : d.toISOString(); };
function vcardField(entity, field) {
  const v = (entity?.vcardArray?.[1] || []).find(x => x[0] === field);
  return v ? String(v[3]) : null;
}
function parseRdap(j, now = Date.now()) {
  const ev = a => (j.events || []).find(e => String(e.eventAction).toLowerCase() === a)?.eventDate || null;
  const registered = iso(ev('registration'));
  const registrar = (j.entities || []).find(e => (e.roles || []).includes('registrar'));
  const abuse = (registrar?.entities || []).find(e => (e.roles || []).includes('abuse'));
  const ageDays = registered ? Math.floor((now - Date.parse(registered)) / 86400000) : null;
  return {
    domain: String(j.ldhName || '').toLowerCase() || null,
    registered: true,
    registeredAt: registered,
    ageDays,
    expiresAt: iso(ev('expiration')),
    updatedAt: iso(ev('last changed')),
    registrar: vcardField(registrar, 'fn') || registrar?.handle || null,
    registrarIanaId: (registrar?.publicIds || []).find(p => /iana/i.test(p.type))?.identifier || null,
    registrarAbuseEmail: vcardField(abuse, 'email'), // for reporting the domain, a registrar role account
    status: j.status || [],
    nameservers: (j.nameservers || []).map(n => String(n.ldhName || '').toLowerCase()).filter(Boolean),
    young: ageDays != null && ageDays < YOUNG_DOMAIN_DAYS,
  };
}
// Registrable-domain candidates without a public-suffix list: try the full host first, then strip labels.
function domainCandidates(d) {
  const p = d.split('.'); const out = [];
  for (let i = 0; i <= p.length - 2 && out.length < 3; i++) out.push(p.slice(i).join('.'));
  return out;
}

const cache = new Map(), inflight = new Map();
async function cached(key, ttl, fn) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < ttl) return hit.value;
  if (inflight.has(key)) return inflight.get(key); // concurrent callers share one upstream request
  const p = (async () => {
    const value = await fn();
    if (cache.size > 500) cache.delete(cache.keys().next().value);
    cache.set(key, { at: Date.now(), value });
    return value;
  })().finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}
// Sliding-window limiter: at most `max` calls per `windowMs`. rdap.org allows roughly 10 requests per 10 s.
function rateLimiter(max, windowMs, now = () => Date.now(), sleep = ms => new Promise(r => setTimeout(r, ms))) {
  const stamps = [];
  let chain = Promise.resolve();
  return () => (chain = chain.then(async () => {
    for (;;) {
      const t = now();
      while (stamps.length && t - stamps[0] >= windowMs) stamps.shift();
      if (stamps.length < max) { stamps.push(t); return; }
      await sleep(windowMs - (t - stamps[0]) + 5);
    }
  }));
}
const rdapSlot = rateLimiter(8, 10000);
async function getJson(url, opts = {}) {
  const r = await guardedFetch(url, { timeout: 12000, maxRedirects: 3, ...opts, headers: { Accept: 'application/json', ...(opts.headers || {}) } });
  let json = null; try { json = JSON.parse(r.body); } catch { /* not JSON */ }
  return { status: r.status, json };
}

async function handleDomain(body, res, send) {
  const domain = validateDomain(body.domain);
  if (!domain) throw bad('Not a valid domain name');
  const result = await cached('rdap:' + domain, 30 * 60e3, async () => {
    for (const d of domainCandidates(domain)) {
      await rdapSlot();
      const { status, json } = await getJson(`https://rdap.org/domain/${d}`, { headers: { Accept: 'application/rdap+json, application/json' } });
      if (status === 404) continue;
      if (status === 429) throw bad('RDAP rate limit reached. Try again in a minute', 503);
      if (status !== 200 || !json) throw bad(`RDAP lookup failed (HTTP ${status})`, 502);
      return { ...parseRdap(json), queried: d, source: 'rdap.org' };
    }
    return { domain, registered: false, source: 'rdap.org', note: 'No RDAP record. The domain may be unregistered, or its registry may not publish RDAP. Check a WHOIS service by hand.' };
  });
  send(res, 200, { ...result, input: domain, lookup: `https://lookup.icann.org/en/lookup?name=${encodeURIComponent(domain)}` });
}

// ---------- Wallets (public ledgers) ----------
function parseMempoolAddress(j) {
  const c = j.chain_stats || {}, m = j.mempool_stats || {};
  const received = (c.funded_txo_sum || 0), sent = (c.spent_txo_sum || 0);
  return {
    chain: 'BTC', address: j.address,
    txCount: (c.tx_count || 0) + (m.tx_count || 0), unconfirmedTxCount: m.tx_count || 0,
    fundedTxo: c.funded_txo_count || 0, spentTxo: c.spent_txo_count || 0,
    totalReceivedSats: received, totalSentSats: sent, balanceSats: received - sent + (m.funded_txo_sum || 0) - (m.spent_txo_sum || 0),
    totalReceivedBtc: +(received / 1e8).toFixed(8), balanceBtc: +((received - sent + (m.funded_txo_sum || 0) - (m.spent_txo_sum || 0)) / 1e8).toFixed(8),
  };
}
// From mempool.space /address/:a/txs (newest first, up to 25 confirmed). firstSeen is exact only if the page holds every tx.
function parseMempoolTxs(txs, totalTx) {
  const times = (txs || []).map(t => t.status?.block_time).filter(Boolean).map(t => t * 1000);
  if (!times.length) return { firstSeen: null, lastSeen: null, firstSeenExact: false };
  return { firstSeen: iso(Math.min(...times)), lastSeen: iso(Math.max(...times)), firstSeenExact: totalTx != null && txs.length >= totalTx };
}
// TronGrid (no key): /v1/accounts/<addr> → {data:[account]}; an empty data array means the address was never activated.
const USDT_TRC20 = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
function parseTrongridAccount(j, address) {
  const a = Array.isArray(j?.data) ? j.data[0] : null;
  if (!a) return { chain: 'TRON', address, activated: false, txCount: null, firstSeen: null, lastSeen: null, balanceTrx: 0, usdtBalance: 0, tokens: [] };
  const trc20 = Object.assign({}, ...(a.trc20 || []));
  const usdtRaw = trc20[USDT_TRC20];
  return {
    chain: 'TRON', address, activated: true,
    balanceTrx: Number(a.balance || 0) / 1e6,
    usdtBalance: usdtRaw != null ? Number(usdtRaw) / 1e6 : 0,
    firstSeen: a.create_time ? iso(a.create_time) : null, firstSeenExact: !!a.create_time, // account activation time
    lastSeen: a.latest_opration_time ? iso(a.latest_opration_time) : a.latest_operation_time ? iso(a.latest_operation_time) : null, // TronGrid spells it "opration"
    trc20Contracts: Object.keys(trc20).length,
  };
}
// TronGrid /v1/accounts/<addr>/transactions/trc20?contract_address=<USDT> → one page of USDT transfers (newest first).
function parseTrc20Transfers(j, address) {
  const rows = Array.isArray(j?.data) ? j.data : [];
  const inc = rows.filter(r => r.to === address), out = rows.filter(r => r.from === address);
  const dec = r => 10 ** Number(r.token_info?.decimals ?? 6);
  const times = rows.map(r => r.block_timestamp).filter(Boolean);
  return {
    usdtTransfersIn: inc.length, usdtTransfersOut: out.length,
    usdtReceived: +inc.reduce((s, r) => s + Number(r.value || 0) / dec(r), 0).toFixed(6),
    uniqueSenders: new Set(inc.map(r => r.from)).size,
    usdtFirstTransfer: times.length ? iso(Math.min(...times)) : null, usdtLastTransfer: times.length ? iso(Math.max(...times)) : null,
    usdtPageComplete: !j?.meta?.fingerprint, // more pages exist when TronGrid returns a fingerprint
  };
}
// Tronscan accountv2: optional fallback, only used when TRONSCAN_API_KEY is set (the public API now answers 401 without a key).
function parseTronscan(j, address) {
  if (!j || (!j.date_created && !j.balance && !j.totalTransactionCount)) return { chain: 'TRON', address, activated: false, txCount: 0, firstSeen: null, lastSeen: null, balanceTrx: 0, usdtBalance: 0, tokens: [] };
  const tokens = (j.withPriceTokens || j.tokens || []).map(t => ({ symbol: t.tokenAbbr || t.tokenName, balance: Number(t.balance || 0) / 10 ** Number(t.tokenDecimal || 0) })).filter(t => t.symbol);
  return {
    chain: 'TRON', address: j.address || address, activated: j.activated !== false,
    txCount: j.totalTransactionCount ?? null, transactionsIn: j.transactions_in ?? null, transactionsOut: j.transactions_out ?? null,
    balanceTrx: Number(j.balance || 0) / 1e6,
    usdtBalance: tokens.find(t => /^usdt$/i.test(t.symbol))?.balance ?? 0,
    firstSeen: j.date_created ? iso(j.date_created) : null, firstSeenExact: !!j.date_created,
    lastSeen: j.latest_operation_time ? iso(j.latest_operation_time) : null,
    tokens: tokens.slice(0, 10),
  };
}

async function handleWallet(body, res, send) {
  let address = String(body.address ?? '').trim();
  if (/^bc1/i.test(address)) address = address.toLowerCase(); // bech32 is case-insensitive
  const chain = normalizeChain(body.chain, address);
  if (!chain) throw bad('Unknown chain. Use btc, tron or eth');
  if (!WALLET_RE[chain].test(address)) throw bad(`Not a valid ${chain.toUpperCase()} address`);
  const explorer = EXPLORER[chain](address);
  const result = await cached(`w:${chain}:${address}`, 10 * 60e3, async () => {
    if (chain === 'btc') {
      const a = await getJson(`https://mempool.space/api/address/${address}`);
      if (a.status !== 200 || !a.json) throw bad(`mempool.space lookup failed (HTTP ${a.status})`, 502);
      const out = { ...parseMempoolAddress(a.json), source: 'mempool.space' };
      if (out.txCount > 0) {
        const t = await getJson(`https://mempool.space/api/address/${address}/txs`).catch(() => ({}));
        if (Array.isArray(t.json)) Object.assign(out, parseMempoolTxs(t.json, out.txCount));
      }
      return out;
    }
    if (chain === 'tron') {
      const h = TRONGRID_KEY ? { 'TRON-PRO-API-KEY': TRONGRID_KEY } : {};
      const a = await getJson(`https://api.trongrid.io/v1/accounts/${address}`, { headers: h }).catch(e => ({ status: 0, error: e }));
      if (a.status === 200 && a.json) {
        const out = { ...parseTrongridAccount(a.json, address), source: 'trongrid' };
        if (out.activated) {
          const t = await getJson(`https://api.trongrid.io/v1/accounts/${address}/transactions/trc20?limit=200&contract_address=${USDT_TRC20}`, { headers: h }).catch(() => ({}));
          if (t.status === 200 && t.json) Object.assign(out, parseTrc20Transfers(t.json, address));
        }
        return out;
      }
      if (TRONSCAN_KEY) {
        const s = await getJson(`https://apilist.tronscanapi.com/api/accountv2?address=${address}`, { headers: { 'TRON-PRO-API-KEY': TRONSCAN_KEY } });
        if (s.status === 200 && s.json) return { ...parseTronscan(s.json, address), source: 'tronscan' };
      }
      if (a.error) throw a.error;
      throw bad(`TronGrid lookup failed (HTTP ${a.status})`, 502);
    }
    if (!ETHERSCAN_KEY) return { chain: 'ETH', address, available: false, note: 'Set ETHERSCAN_API_KEY on the server for Ethereum lookups. Open the explorer link instead.' };
    const q = p => `https://api.etherscan.io/v2/api?chainid=1&${p}&address=${address}&apikey=${ETHERSCAN_KEY}`;
    const [bal, first, last] = await Promise.all([getJson(q('module=account&action=balance&tag=latest')), getJson(q('module=account&action=txlist&sort=asc&page=1&offset=1')), getJson(q('module=account&action=txlist&sort=desc&page=1&offset=1'))]);
    const ts = r => Array.isArray(r.json?.result) && r.json.result[0] ? iso(Number(r.json.result[0].timeStamp) * 1000) : null;
    return { chain: 'ETH', address, balanceEth: bal.json?.status === '1' ? Number(bal.json.result) / 1e18 : null, firstSeen: ts(first), firstSeenExact: !!ts(first), lastSeen: ts(last), source: 'etherscan' };
  });
  send(res, 200, { available: true, ...result, explorer });
}

const routes = { '/api/osint/username': handleUsername, '/api/osint/domain': handleDomain, '/api/osint/wallet': handleWallet };

module.exports = { routes, guardedFetch, validateUsername, validateDomain, normalizeChain, classify, checkSite, pool, parseRdap, domainCandidates, parseMempoolAddress, parseMempoolTxs, parseTronscan, parseTrongridAccount, parseTrc20Transfers, rateLimiter, sites, USERNAME_RE, WALLET_RE };
