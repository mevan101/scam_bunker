// Shared between the Node server (server/osint.js) and the browser (static mode, public/osint.js).
// Validation, RDAP / mempool.space / TronGrid / Tronscan parsers and the lookup flow live here once, so the
// server route and the browser-direct fallback return byte-for-byte the same JSON. The caller supplies the
// transport: getJson(url, {headers}) → {status, json}, and an optional rate-limit slot. No dependencies; UMD.
(function (root) {
'use strict';
const YOUNG_DOMAIN_DAYS = 90;
const bad = (m, status = 400) => Object.assign(new Error(m), { status });
const iso = t => { if (t == null || t === '') return null; const d = new Date(t); return isNaN(d) ? null : d.toISOString(); };

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

// ---------- RDAP ----------
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

// ---------- Rate limiting and caching (used by both transports) ----------
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
// TTL cache; concurrent callers for the same key share one upstream request.
function createCache(maxSize = 500) {
  const cache = new Map(), inflight = new Map();
  return async function cached(key, ttl, fn) {
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < ttl) return hit.value;
    if (inflight.has(key)) return inflight.get(key);
    const p = (async () => {
      const value = await fn();
      if (cache.size > maxSize) cache.delete(cache.keys().next().value);
      cache.set(key, { at: Date.now(), value });
      return value;
    })().finally(() => inflight.delete(key));
    inflight.set(key, p);
    return p;
  };
}
const DOMAIN_TTL = 30 * 60e3, WALLET_TTL = 10 * 60e3;

// ---------- Lookup flows ----------
// deps: { getJson(url, {headers}) → {status, json}, slot?() → Promise (rate limit), cached?(key, ttl, fn) }
async function domainLookup(body, { getJson, slot = async () => { }, cached = (k, t, fn) => fn() }) {
  const domain = validateDomain(body && body.domain);
  if (!domain) throw bad('Not a valid domain name');
  const result = await cached('rdap:' + domain, DOMAIN_TTL, async () => {
    for (const d of domainCandidates(domain)) {
      await slot();
      const { status, json } = await getJson(`https://rdap.org/domain/${d}`, { headers: { Accept: 'application/rdap+json, application/json' } });
      if (status === 404) continue;
      if (status === 429) throw bad('RDAP rate limit reached. Try again in a minute', 503);
      if (status !== 200 || !json) throw bad(`RDAP lookup failed (HTTP ${status})`, 502);
      return { ...parseRdap(json), queried: d, source: 'rdap.org' };
    }
    return { domain, registered: false, source: 'rdap.org', note: 'No RDAP record. The domain may be unregistered, or its registry may not publish RDAP. Check a WHOIS service by hand.' };
  });
  return { ...result, input: domain, lookup: `https://lookup.icann.org/en/lookup?name=${encodeURIComponent(domain)}` };
}

// keys: { trongrid?, tronscan?, etherscan? } (server only; the browser never holds keys)
// noKeyNote: what to say for ETH when no Etherscan key is available
async function walletLookup(body, { getJson, cached = (k, t, fn) => fn(), keys = {}, noKeyNote = 'Set ETHERSCAN_API_KEY on the server for Ethereum lookups. Open the explorer link instead.' }) {
  let address = String(body?.address ?? '').trim();
  if (/^bc1/i.test(address)) address = address.toLowerCase(); // bech32 is case-insensitive
  const chain = normalizeChain(body?.chain, address);
  if (!chain) throw bad('Unknown chain. Use btc, tron or eth');
  if (!WALLET_RE[chain].test(address)) throw bad(`Not a valid ${chain.toUpperCase()} address`);
  const explorer = EXPLORER[chain](address);
  const result = await cached(`w:${chain}:${address}`, WALLET_TTL, async () => {
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
      const h = keys.trongrid ? { 'TRON-PRO-API-KEY': keys.trongrid } : {};
      const a = await getJson(`https://api.trongrid.io/v1/accounts/${address}`, { headers: h }).catch(e => ({ status: 0, error: e }));
      if (a.status === 200 && a.json) {
        const out = { ...parseTrongridAccount(a.json, address), source: 'trongrid' };
        if (out.activated) {
          const t = await getJson(`https://api.trongrid.io/v1/accounts/${address}/transactions/trc20?limit=200&contract_address=${USDT_TRC20}`, { headers: h }).catch(() => ({}));
          if (t.status === 200 && t.json) Object.assign(out, parseTrc20Transfers(t.json, address));
        }
        return out;
      }
      if (keys.tronscan) {
        const s = await getJson(`https://apilist.tronscanapi.com/api/accountv2?address=${address}`, { headers: { 'TRON-PRO-API-KEY': keys.tronscan } });
        if (s.status === 200 && s.json) return { ...parseTronscan(s.json, address), source: 'tronscan' };
      }
      if (a.error) throw a.error;
      throw bad(`TronGrid lookup failed (HTTP ${a.status})`, 502);
    }
    if (!keys.etherscan) return { chain: 'ETH', address, available: false, note: noKeyNote };
    const q = p => `https://api.etherscan.io/v2/api?chainid=1&${p}&address=${address}&apikey=${keys.etherscan}`;
    const [bal, first, last] = await Promise.all([getJson(q('module=account&action=balance&tag=latest')), getJson(q('module=account&action=txlist&sort=asc&page=1&offset=1')), getJson(q('module=account&action=txlist&sort=desc&page=1&offset=1'))]);
    const ts = r => Array.isArray(r.json?.result) && r.json.result[0] ? iso(Number(r.json.result[0].timeStamp) * 1000) : null;
    return { chain: 'ETH', address, balanceEth: bal.json?.status === '1' ? Number(bal.json.result) / 1e18 : null, firstSeen: ts(first), firstSeenExact: !!ts(first), lastSeen: ts(last), source: 'etherscan' };
  });
  return { available: true, ...result, explorer };
}

const api = { YOUNG_DOMAIN_DAYS, bad, iso, USERNAME_RE, validateUsername, DOMAIN_RE, validateDomain, WALLET_RE, normalizeChain, EXPLORER, vcardField, parseRdap, domainCandidates, parseMempoolAddress, parseMempoolTxs, USDT_TRC20, parseTrongridAccount, parseTrc20Transfers, parseTronscan, rateLimiter, createCache, domainLookup, walletLookup };
if (typeof module === 'object' && module.exports) module.exports = api;
else root.ScamBunkerOsintCore = api;
})(typeof window !== 'undefined' ? window : globalThis);
